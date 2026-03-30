// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "bytes"
        "context"
        "encoding/json"
        "io"
        "log/slog"
        "net/http"
        "strings"
        "sync"
        "time"
)

const (
        nmapEnrichMaxSubdomains = 15
        nmapEnrichTimeout       = 90 * time.Second
        nmapEnrichConcurrency   = 3
)

type nmapProbeResponse struct {
        Status     string      `json:"status"`
        Error      string      `json:"error"`
        Parsed     *nmapParsed `json:"parsed"`
        ScriptsRun []string    `json:"scripts_run"`
        Elapsed    float64     `json:"elapsed_seconds"`
}

type nmapParsed struct {
        Hosts []nmapHost `json:"hosts"`
}

type nmapHost struct {
        Status    string     `json:"status"`
        Addresses []nmapAddr `json:"addresses"`
        Hostnames []string   `json:"hostnames"`
        Ports     []nmapPort `json:"ports"`
}

type nmapAddr struct {
        Addr string `json:"addr"`
        Type string `json:"type"`
}

type nmapPort struct {
        Port     int          `json:"port"`
        Protocol string       `json:"protocol"`
        State    string       `json:"state"`
        Service  string       `json:"service"`
        Product  string       `json:"product,omitempty"`
        Version  string       `json:"version,omitempty"`
        Tunnel   string       `json:"tunnel,omitempty"`
        Scripts  []nmapScript `json:"scripts,omitempty"`
}

type nmapScript struct {
        ID     string `json:"id"`
        Output string `json:"output"`
}

func (a *Analyzer) nmapCapableProbe() *ProbeEndpoint {
        for i := range a.Probes {
                if strings.Contains(strings.ToLower(a.Probes[i].Label), "kali") ||
                        strings.Contains(a.Probes[i].ID, "02") ||
                        strings.Contains(a.Probes[i].ID, "kali") {
                        return &a.Probes[i]
                }
        }
        if len(a.Probes) > 0 {
                return &a.Probes[len(a.Probes)-1]
        }
        return nil
}

func (a *Analyzer) enrichSubdomainsWithNmap(ctx context.Context, baseDomain string, subdomains []map[string]any) ([]map[string]any, int) {
        probe := a.nmapCapableProbe()
        if probe == nil {
                return nil, 0
        }

        targets := selectNmapTargets(subdomains, nmapEnrichMaxSubdomains)
        if len(targets) == 0 {
                return nil, 0
        }

        slog.Info("Nmap subdomain enrichment starting",
                "domain", baseDomain,
                "targets", len(targets),
                "probe", probe.Label)

        var mu sync.Mutex
        var wg sync.WaitGroup
        sem := make(chan struct{}, nmapEnrichConcurrency)

        discoveredSANs := make(map[string]bool)
        enriched := 0

        for _, target := range targets {
                wg.Add(1)
                sem <- struct{}{}
                go func(name string) {
                        defer wg.Done()
                        defer func() { <-sem }()

                        result := callNmapProbe(ctx, probe, name)
                        if result == nil || result.Parsed == nil {
                                return
                        }

                        services, sans := extractNmapIntel(result)

                        mu.Lock()
                        defer mu.Unlock()

                        enriched += applyNmapServices(subdomains, name, services)
                        collectDiscoveredSANs(sans, baseDomain, subdomains, discoveredSANs)
                }(target)
        }

        wg.Wait()

        newSubdomains := buildNewSubdomainsFromSANs(discoveredSANs)

        slog.Info("Nmap subdomain enrichment complete",
                "domain", baseDomain,
                "enriched", enriched,
                "new_sans", len(newSubdomains))

        return newSubdomains, enriched
}

func applyNmapServices(subdomains []map[string]any, name string, services []map[string]any) int {
        if len(services) == 0 {
                return 0
        }
        for i := range subdomains {
                if subdomains[i]["name"] == name {
                        subdomains[i]["services"] = services
                        return 1
                }
        }
        return 0
}

func isValidDiscoveredSAN(san, baseDomain string) bool {
        if san == "" || san == baseDomain {
                return false
        }
        if !strings.HasSuffix(san, "."+baseDomain) {
                return false
        }
        if strings.HasPrefix(san, "*.") {
                return false
        }
        return true
}

func isKnownSubdomain(subdomains []map[string]any, san string) bool {
        for _, sd := range subdomains {
                if sd["name"] == san {
                        return true
                }
        }
        return false
}

func collectDiscoveredSANs(sans []string, baseDomain string, subdomains []map[string]any, discoveredSANs map[string]bool) {
        for _, san := range sans {
                san = strings.ToLower(strings.TrimSpace(san))
                if !isValidDiscoveredSAN(san, baseDomain) {
                        continue
                }
                if !isKnownSubdomain(subdomains, san) {
                        discoveredSANs[san] = true
                }
        }
}

func buildNewSubdomainsFromSANs(discoveredSANs map[string]bool) []map[string]any {
        var newSubdomains []map[string]any
        for san := range discoveredSANs {
                newSubdomains = append(newSubdomains, map[string]any{
                        "name":       san,
                        "source":     "nmap_san",
                        "is_current": true,
                        "cert_count": "—",
                        "first_seen": "—",
                        "issuers":    []string{},
                })
        }
        return newSubdomains
}

func selectNmapTargets(subdomains []map[string]any, maxCount int) []string {
        var targets []string
        for _, sd := range subdomains {
                name, ok := sd["name"].(string)
                if !ok || name == "" {
                        continue
                }
                isCurrent, _ := sd["is_current"].(bool)
                if !isCurrent {
                        continue
                }
                targets = append(targets, name)
                if len(targets) >= maxCount {
                        break
                }
        }
        return targets
}

func callNmapProbe(ctx context.Context, probe *ProbeEndpoint, host string) *nmapProbeResponse {
        reqCtx, cancel := context.WithTimeout(ctx, nmapEnrichTimeout)
        defer cancel()

        reqBody, err := json.Marshal(map[string]any{
                "host":    host,
                "ports":   "80,443",
                "scripts": []string{"ssl-cert", "http-title", "banner"},
        })
        if err != nil {
                return nil
        }

        req, err := http.NewRequestWithContext(reqCtx, "POST", probe.URL+"/probe/nmap", bytes.NewReader(reqBody))
        if err != nil {
                return nil
        }
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("X-Probe-Key", probe.Key)

        resp, err := http.DefaultClient.Do(req)
        if err != nil {
                slog.Debug("Nmap probe call failed", "host", host, "error", err)
                return nil
        }
        defer safeClose(resp.Body, "nmap-probe")

        body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
        if err != nil {
                return nil
        }

        var result nmapProbeResponse
        if err := json.Unmarshal(body, &result); err != nil {
                return nil
        }

        return &result
}

func extractNmapIntel(result *nmapProbeResponse) ([]map[string]any, []string) {
        var services []map[string]any
        var sans []string

        if result.Parsed == nil {
                return services, sans
        }

        for _, host := range result.Parsed.Hosts {
                hostServices, hostSANs := extractHostIntel(host)
                services = append(services, hostServices...)
                sans = append(sans, hostSANs...)
        }

        return services, sans
}

func extractHostIntel(host nmapHost) ([]map[string]any, []string) {
        var services []map[string]any
        var sans []string

        for _, port := range host.Ports {
                if port.State != "open" {
                        continue
                }
                svc, portSANs := buildPortService(port)
                services = append(services, svc)
                sans = append(sans, portSANs...)
        }

        return services, sans
}

func buildPortService(port nmapPort) (map[string]any, []string) {
        svc := map[string]any{
                "port":     port.Port,
                "protocol": port.Protocol,
                "service":  port.Service,
        }
        if port.Product != "" {
                svc["product"] = port.Product
        }
        if port.Version != "" {
                svc["version"] = port.Version
        }

        var sans []string
        for _, script := range port.Scripts {
                switch script.ID {
                case "http-title":
                        svc["http_title"] = strings.TrimSpace(script.Output)
                case "ssl-cert":
                        certSANs := extractSANsFromSSLCert(script.Output)
                        sans = append(sans, certSANs...)
                        if len(certSANs) > 0 {
                                svc["cert_sans_count"] = len(certSANs)
                        }
                }
        }

        return svc, sans
}

func extractSANsFromSSLCert(output string) []string {
        var sans []string
        lines := strings.Split(output, "\n")
        for _, line := range lines {
                line = strings.TrimSpace(line)
                if !strings.HasPrefix(line, "Subject Alternative Name:") {
                        continue
                }
                sanPart := strings.TrimPrefix(line, "Subject Alternative Name:")
                entries := strings.Split(sanPart, ",")
                for _, entry := range entries {
                        entry = strings.TrimSpace(entry)
                        if strings.HasPrefix(entry, "DNS:") {
                                name := strings.TrimPrefix(entry, "DNS:")
                                name = strings.TrimSpace(name)
                                if name != "" {
                                        sans = append(sans, name)
                                }
                        }
                }
        }
        return sans
}
