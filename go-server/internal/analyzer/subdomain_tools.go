package analyzer

import (
        "bufio"
        "context"
        "fmt"
        "io"
        "log/slog"
        "net/http"
        "os/exec"
        "regexp"
        "strings"
        "sync"
        "time"
)

var validDomainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$`)

func isValidFQDNUnder(fqdn, domain string) bool {
        fqdn = strings.ToLower(strings.TrimSpace(fqdn))
        if fqdn == "" || fqdn == domain {
                return false
        }
        if !strings.HasSuffix(fqdn, "."+domain) {
                return false
        }
        if strings.HasPrefix(fqdn, "*.") {
                return false
        }
        return validDomainRe.MatchString(fqdn)
}

func runSubfinder(ctx context.Context, domain string) []string {
        if !validDomainRe.MatchString(domain) {
                slog.Warn("subfinder: invalid domain input", mapKeyDomain, domain)
                return nil
        }

        binPath, err := exec.LookPath("subfinder")
        if err != nil {
                slog.Debug("subfinder not available", mapKeyError, err)
                return nil
        }

        toolCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
        defer cancel()

        cmd := exec.CommandContext(toolCtx, binPath,
                "-d", domain, "-silent", "-timeout", "30")

        out, err := cmd.Output()
        if err != nil {
                slog.Warn("subfinder execution failed", mapKeyDomain, domain, mapKeyError, err)
                return nil
        }

        seen := make(map[string]bool)
        var results []string
        scanner := bufio.NewScanner(strings.NewReader(string(out)))
        for scanner.Scan() {
                line := strings.ToLower(strings.TrimSpace(scanner.Text()))
                if line == "" || seen[line] {
                        continue
                }
                if isValidFQDNUnder(line, domain) {
                        seen[line] = true
                        results = append(results, line)
                }
        }

        slog.Info("subfinder completed", mapKeyDomain, domain, "found", len(results))
        return results
}

func runAmass(ctx context.Context, domain string) []string {
        if !validDomainRe.MatchString(domain) {
                slog.Warn("amass: invalid domain input", mapKeyDomain, domain)
                return nil
        }

        binPath, err := exec.LookPath("amass")
        if err != nil {
                slog.Debug("amass not available", mapKeyError, err)
                return nil
        }

        toolCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
        defer cancel()

        cmd := exec.CommandContext(toolCtx, binPath,
                "enum", "-passive", "-d", domain, "-timeout", "1")

        out, err := cmd.Output()
        if err != nil {
                slog.Warn("amass execution failed", mapKeyDomain, domain, mapKeyError, err)
                return nil
        }

        seen := make(map[string]bool)
        var results []string
        scanner := bufio.NewScanner(strings.NewReader(string(out)))
        for scanner.Scan() {
                line := strings.ToLower(strings.TrimSpace(scanner.Text()))
                if line == "" || seen[line] {
                        continue
                }
                if isValidFQDNUnder(line, domain) {
                        seen[line] = true
                        results = append(results, line)
                }
        }

        slog.Info("amass completed", mapKeyDomain, domain, "found", len(results))
        return results
}

func fetchHackerTarget(ctx context.Context, domain string) []string {
        if !validDomainRe.MatchString(domain) {
                return nil
        }

        reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
        defer cancel()

        url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
        req, err := http.NewRequestWithContext(reqCtx, "GET", url, nil)
        if err != nil {
                return nil
        }

        resp, err := http.DefaultClient.Do(req)
        if err != nil {
                slog.Warn("hackertarget request failed", mapKeyDomain, domain, mapKeyError, err)
                return nil
        }
        defer resp.Body.Close()

        body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
        if err != nil {
                return nil
        }

        text := string(body)
        if strings.Contains(text, "API count exceeded") || strings.Contains(text, "error check your search") || strings.Contains(text, "No records found") {
                slog.Warn("hackertarget rate limited or no results", mapKeyDomain, domain)
                return nil
        }

        seen := make(map[string]bool)
        var results []string
        scanner := bufio.NewScanner(strings.NewReader(text))
        for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if line == "" {
                        continue
                }
                parts := strings.SplitN(line, ",", 2)
                if len(parts) == 0 {
                        continue
                }
                fqdn := strings.ToLower(strings.TrimSpace(parts[0]))
                if !seen[fqdn] && isValidFQDNUnder(fqdn, domain) {
                        seen[fqdn] = true
                        results = append(results, fqdn)
                }
        }

        slog.Info("hackertarget completed", mapKeyDomain, domain, "found", len(results))
        return results
}

func RunExternalTools(ctx context.Context, domain string) []string {
        var mu sync.Mutex
        var wg sync.WaitGroup
        seen := make(map[string]bool)
        var combined []string

        merge := func(results []string) {
                mu.Lock()
                defer mu.Unlock()
                for _, r := range results {
                        if !seen[r] {
                                seen[r] = true
                                combined = append(combined, r)
                        }
                }
        }

        wg.Add(3)

        go func() {
                defer wg.Done()
                merge(runSubfinder(ctx, domain))
        }()

        go func() {
                defer wg.Done()
                merge(runAmass(ctx, domain))
        }()

        go func() {
                defer wg.Done()
                merge(fetchHackerTarget(ctx, domain))
        }()

        wg.Wait()

        slog.Info("external tools completed", mapKeyDomain, domain, "total_unique", len(combined))
        return combined
}
