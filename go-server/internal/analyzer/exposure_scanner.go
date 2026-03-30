// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

const (
	mapKeyCritical = "critical"
	mapKeyHighSev  = "high"
)

const categoryServerInfo = "Server Info"

type ExposureScanner struct {
	HTTP HTTPClient
}

type ExposureFinding struct {
	Path        string `json:"path"`
	Status      int    `json:"status"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Detail      string `json:"detail"`
	Risk        string `json:"risk"`
	Remediation string `json:"remediation"`
}

type exposureCheck struct {
	Path         string
	Category     string
	Severity     string
	Risk         string
	Remediation  string
	SuccessOn    []int
	ContentCheck func(body string) bool
}

var exposureChecks = []exposureCheck{
	{
		Path:        "/.env",
		Category:    "Environment File",
		Severity:    mapKeyCritical,
		Risk:        "May contain database credentials, API keys, and application secrets",
		Remediation: "Block access via web server config (deny all for dotfiles) or remove from web root",
		SuccessOn:   []int{200},
		ContentCheck: func(body string) bool {
			lower := strings.ToLower(body)
			return strings.Contains(lower, "db_") || strings.Contains(lower, "database") ||
				strings.Contains(lower, "password") || strings.Contains(lower, "secret") ||
				strings.Contains(lower, "api_key") || strings.Contains(lower, "app_key") ||
				strings.Contains(lower, "=") && (strings.Contains(lower, "host") || strings.Contains(lower, "user"))
		},
	},
	{
		Path:        "/.git/config",
		Category:    "Git Repository",
		Severity:    mapKeyCritical,
		Risk:        "Exposed .git directory allows full source code download including commit history",
		Remediation: "Block access to .git directory in web server config or remove from web root",
		SuccessOn:   []int{200},
		ContentCheck: func(body string) bool {
			return strings.Contains(body, "[core]") || strings.Contains(body, "[remote")
		},
	},
	{
		Path:        "/.git/HEAD",
		Category:    "Git Repository",
		Severity:    mapKeyCritical,
		Risk:        "Confirms .git directory exposure — full repository can likely be reconstructed",
		Remediation: "Block access to .git directory in web server config",
		SuccessOn:   []int{200},
		ContentCheck: func(body string) bool {
			return strings.HasPrefix(strings.TrimSpace(body), "ref: refs/")
		},
	},
	{
		Path:        "/.DS_Store",
		Category:    "Directory Listing",
		Severity:    "medium",
		Risk:        "macOS directory metadata reveals internal file and folder names",
		Remediation: "Remove .DS_Store files from web root and add to .gitignore",
		SuccessOn:   []int{200},
		ContentCheck: func(body string) bool {
			return len(body) > 4 && body[:4] == "\x00\x00\x00\x01"
		},
	},
	{
		Path:        "/server-status",
		Category:    categoryServerInfo,
		Severity:    mapKeyHighSev,
		Risk:        "Apache server-status page reveals active connections, client IPs, and request URLs",
		Remediation: "Restrict mod_status to localhost only or disable in production",
		SuccessOn:   []int{200},
		ContentCheck: func(body string) bool {
			lower := strings.ToLower(body)
			return strings.Contains(lower, "apache server status") || strings.Contains(lower, "server uptime")
		},
	},
	{
		Path:        "/server-info",
		Category:    categoryServerInfo,
		Severity:    mapKeyHighSev,
		Risk:        "Apache server-info page reveals module configuration, loaded modules, and compile settings",
		Remediation: "Restrict mod_info to localhost only or disable in production",
		SuccessOn:   []int{200},
		ContentCheck: func(body string) bool {
			lower := strings.ToLower(body)
			return strings.Contains(lower, "apache server information") || strings.Contains(lower, "server settings")
		},
	},
	{
		Path:        "/wp-config.php.bak",
		Category:    "Backup File",
		Severity:    mapKeyCritical,
		Risk:        "WordPress config backup exposes database credentials and secret keys in plain text",
		Remediation: "Remove all backup files from web root; never store backups in publicly accessible directories",
		SuccessOn:   []int{200},
		ContentCheck: func(body string) bool {
			return strings.Contains(body, "DB_NAME") || strings.Contains(body, "DB_PASSWORD") || strings.Contains(body, "wp-settings.php")
		},
	},
	{
		Path:        "/phpinfo.php",
		Category:    categoryServerInfo,
		Severity:    mapKeyHighSev,
		Risk:        "phpinfo() reveals PHP version, extensions, environment variables, and server paths",
		Remediation: "Remove phpinfo.php from production servers",
		SuccessOn:   []int{200},
		ContentCheck: func(body string) bool {
			lower := strings.ToLower(body)
			return strings.Contains(lower, "php version") || strings.Contains(lower, "phpinfo()")
		},
	},
}

func NewExposureScanner(httpClient HTTPClient) *ExposureScanner {
	return &ExposureScanner{HTTP: httpClient}
}

func (e *ExposureScanner) Scan(ctx context.Context, domain string) map[string]any {
	baseURL := e.resolveBaseURL(ctx, domain)
	if baseURL == "" {
		return map[string]any{
			mapKeyStatus:    "unreachable",
			"message":       "Domain web server is not reachable",
			"finding_count": 0,
			"findings":      []map[string]any{},
			"checked_paths": []string{},
		}
	}

	findings, checkedPaths := e.runExposureChecks(ctx, domain, baseURL)

	status, message := classifyExposureResults(findings, checkedPaths)

	findingsMaps := make([]map[string]any, len(findings))
	for i, f := range findings {
		findingsMaps[i] = map[string]any{
			"path":        f.Path,
			mapKeyStatus:  f.Status,
			"severity":    f.Severity,
			"category":    f.Category,
			"detail":      f.Detail,
			"risk":        f.Risk,
			"remediation": f.Remediation,
		}
	}

	return map[string]any{
		mapKeyStatus:    status,
		"message":       message,
		"finding_count": len(findings),
		"findings":      findingsMaps,
		"checked_paths": checkedPaths,
	}
}

func (e *ExposureScanner) resolveBaseURL(ctx context.Context, domain string) string {
	for _, scheme := range []string{"https", "http"} {
		testURL := fmt.Sprintf("%s://%s/", scheme, domain)
		testCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		resp, err := e.HTTP.Get(testCtx, testURL)
		cancel()
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 500 {
			return fmt.Sprintf("%s://%s", scheme, domain)
		}
	}
	return ""
}

func (e *ExposureScanner) runExposureChecks(ctx context.Context, domain, baseURL string) ([]ExposureFinding, []string) {
	var findings []ExposureFinding
	checkedPaths := make([]string, len(exposureChecks))
	for i, check := range exposureChecks {
		checkedPaths[i] = check.Path
	}

	type indexedFinding struct {
		idx     int
		finding ExposureFinding
	}

	var (
		mu      sync.Mutex
		results []indexedFinding
		wg      sync.WaitGroup
		sem     = make(chan struct{}, 4)
	)

	for i, check := range exposureChecks {
		select {
		case <-ctx.Done():
			slog.Debug("exposure_scanner: context cancelled", "domain", domain)
			break
		default:
		}

		wg.Add(1)
		go func(idx int, chk exposureCheck) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if finding, ok := e.evalSingleCheck(ctx, baseURL, chk); ok {
				mu.Lock()
				results = append(results, indexedFinding{idx: idx, finding: finding})
				mu.Unlock()
			}
		}(i, check)
	}
	wg.Wait()

	for _, r := range results {
		findings = append(findings, r.finding)
	}
	return findings, checkedPaths
}

func (e *ExposureScanner) evalSingleCheck(ctx context.Context, baseURL string, check exposureCheck) (ExposureFinding, bool) {
	fullURL := baseURL + check.Path
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	resp, err := e.HTTP.Get(checkCtx, fullURL)
	cancel()

	if err != nil {
		return ExposureFinding{}, false
	}

	statusCode := resp.StatusCode

	isExpected := false
	for _, code := range check.SuccessOn {
		if statusCode == code {
			isExpected = true
			break
		}
	}

	if !isExpected {
		resp.Body.Close()
		return ExposureFinding{}, false
	}

	body, err := e.HTTP.ReadBody(resp, 512*1024)
	if err != nil {
		return ExposureFinding{}, false
	}
	bodyStr := string(body)

	if check.ContentCheck != nil && !check.ContentCheck(bodyStr) {
		return ExposureFinding{}, false
	}

	finding := ExposureFinding{
		Path:        check.Path,
		Status:      statusCode,
		Severity:    check.Severity,
		Category:    check.Category,
		Risk:        check.Risk,
		Remediation: check.Remediation,
	}

	detail := fmt.Sprintf("HTTP %d response with matching content at %s", statusCode, check.Path)
	if check.ContentCheck != nil {
		detail += " — content validated as genuine exposure"
	}
	finding.Detail = detail

	return finding, true
}

func classifyExposureResults(findings []ExposureFinding, checkedPaths []string) (string, string) {
	if len(findings) == 0 {
		return "clear", fmt.Sprintf("No well-known exposure paths detected (%d paths checked)", len(checkedPaths))
	}
	hasCritical := false
	for _, f := range findings {
		if f.Severity == mapKeyCritical {
			hasCritical = true
			break
		}
	}
	if hasCritical {
		return mapKeyCritical, fmt.Sprintf("%d critical exposure(s) found in well-known paths", len(findings))
	}
	return "exposed", fmt.Sprintf("%d exposure(s) found in well-known paths", len(findings))
}

func (a *Analyzer) ScanWebExposure(ctx context.Context, domain string) map[string]any {
	scanner := NewExposureScanner(a.HTTP)
	return scanner.Scan(ctx, domain)
}
