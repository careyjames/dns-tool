// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var validHostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)

func isValidNmapTarget(target string) bool {
	if net.ParseIP(target) != nil {
		return true
	}
	if len(target) > 253 {
		return false
	}
	return validHostnameRe.MatchString(target)
}

const (
	msgNotTested        = "Not tested"
	msgTestInconclusive = "Test inconclusive"

	mapKeyFound      = "found"
	mapKeyNameserver = "nameserver"
	mapKeyRecursion  = "recursion"
	mapKeyVulnerable = "vulnerable"
	mapKeyOpen       = "open"
	mapKeyNsid       = "nsid"
)

func (a *Analyzer) AnalyzeNmapDNS(ctx context.Context, domain string) map[string]any {
	result := map[string]any{
		mapKeyStatus:       "info",
		"zone_transfer":    map[string]any{mapKeyVulnerable: false, mapKeyMessage: msgNotTested},
		mapKeyRecursion:    map[string]any{mapKeyOpen: false, mapKeyMessage: msgNotTested},
		mapKeyNsid:         map[string]any{mapKeyFound: false, mapKeyMessage: msgNotTested},
		"cache_snoop":      map[string]any{mapKeyVulnerable: false, mapKeyMessage: msgNotTested},
		"nameservers":      []string{},
		mapKeyIssues:       []string{},
		"scan_duration_ms": 0,
	}

	if _, err := exec.LookPath("nmap"); err != nil {
		result[mapKeyMessage] = "Nmap not available"
		return result
	}

	nsRecords := a.DNS.QueryDNS(ctx, "NS", domain)
	if len(nsRecords) == 0 {
		result[mapKeyMessage] = "No nameservers found"
		return result
	}

	nameservers := make([]string, 0, len(nsRecords))
	for _, ns := range nsRecords {
		ns = strings.TrimSuffix(strings.TrimSpace(ns), ".")
		if ns != "" && isValidNmapTarget(ns) {
			nameservers = append(nameservers, ns)
		}
	}
	result["nameservers"] = nameservers

	if len(nameservers) == 0 {
		result[mapKeyMessage] = "No valid nameservers"
		return result
	}

	scanStart := time.Now()
	issues := []string{}

	primaryNS := nameservers[0]

	zoneResult := a.nmapZoneTransfer(ctx, domain, primaryNS)
	result["zone_transfer"] = zoneResult
	if zoneResult[mapKeyVulnerable] == true {
		issues = append(issues, fmt.Sprintf("Zone transfer (AXFR) allowed on %s", primaryNS))
	}

	recursionResult := a.nmapRecursion(ctx, primaryNS)
	result[mapKeyRecursion] = recursionResult
	if recursionResult[mapKeyOpen] == true {
		issues = append(issues, fmt.Sprintf("Open recursion detected on %s — potential DNS amplification risk", primaryNS))
	}

	nsidResult := a.nmapNSID(ctx, primaryNS)
	result[mapKeyNsid] = nsidResult

	cacheResult := a.nmapCacheSnoop(ctx, primaryNS)
	result["cache_snoop"] = cacheResult
	if cacheResult[mapKeyVulnerable] == true {
		issues = append(issues, fmt.Sprintf("DNS cache snooping possible on %s", primaryNS))
	}

	result[mapKeyIssues] = issues
	result["scan_duration_ms"] = time.Since(scanStart).Milliseconds()

	if len(issues) > 0 {
		result[mapKeyStatus] = "warning"
		result[mapKeyMessage] = fmt.Sprintf("%d issue(s) found across %d nameserver(s)", len(issues), len(nameservers))
	} else {
		result[mapKeyStatus] = "good"
		result[mapKeyMessage] = fmt.Sprintf("No DNS server misconfigurations found on %s", primaryNS)
	}

	slog.Info("Nmap DNS scan completed", "domain", domain, "ns", primaryNS, mapKeyIssues, len(issues), "elapsed_ms", time.Since(scanStart).Milliseconds())

	return result
}

func (a *Analyzer) nmapZoneTransfer(ctx context.Context, domain, ns string) map[string]any {
	result := map[string]any{
		mapKeyVulnerable: false,
		mapKeyMessage:    "Zone transfer denied (correct configuration)",
		mapKeyNameserver: ns,
		"record_count":   0,
	}

	if !isValidNmapTarget(domain) {
		result[mapKeyMessage] = msgTestInconclusive
		return result
	}
	output, err := runNmapScript(ctx, ns, "dns-zone-transfer", fmt.Sprintf("dns-zone-transfer.domain=%s", domain), 15*time.Second)
	if err != nil {
		result[mapKeyMessage] = msgTestInconclusive
		return result
	}

	if strings.Contains(output, "Transfer") || strings.Contains(output, "SOA") {
		lines := strings.Split(output, "\n")
		recordCount := 0
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "|") && !strings.HasPrefix(trimmed, "Nmap") && !strings.HasPrefix(trimmed, "Starting") {
				recordCount++
			}
		}
		if recordCount > 3 {
			result[mapKeyVulnerable] = true
			result[mapKeyMessage] = fmt.Sprintf("Zone transfer allowed — %d records exposed", recordCount)
			result["record_count"] = recordCount
		}
	}

	return result
}

func (a *Analyzer) nmapRecursion(ctx context.Context, ns string) map[string]any {
	result := map[string]any{
		mapKeyOpen:       false,
		mapKeyMessage:    "Recursion disabled (correct configuration)",
		mapKeyNameserver: ns,
	}

	output, err := runNmapScript(ctx, ns, "dns-recursion", "", 10*time.Second)
	if err != nil {
		result[mapKeyMessage] = msgTestInconclusive
		return result
	}

	if strings.Contains(strings.ToLower(output), mapKeyRecursion) && strings.Contains(strings.ToLower(output), "enabled") {
		result[mapKeyOpen] = true
		result[mapKeyMessage] = "Recursive queries enabled — authoritative servers should disable recursion to prevent DNS amplification attacks (RFC 5358)"
	}

	return result
}

func (a *Analyzer) nmapNSID(ctx context.Context, ns string) map[string]any {
	result := map[string]any{
		mapKeyFound:      false,
		mapKeyMessage:    "No nameserver identity information disclosed",
		mapKeyNameserver: ns,
		"version":        "",
		"id":             "",
	}

	output, err := runNmapScript(ctx, ns, "dns-nsid", "", 10*time.Second)
	if err != nil {
		result[mapKeyMessage] = msgTestInconclusive
		return result
	}

	if !containsNSIDIndicators(output) {
		return result
	}

	result[mapKeyFound] = true
	result[mapKeyMessage] = "Nameserver identity information disclosed — consider restricting version queries"
	parseNSIDFields(output, result)

	return result
}

func containsNSIDIndicators(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "bind.version") || strings.Contains(lower, "id.server") || strings.Contains(lower, "nsid")
}

func parseNSIDFields(output string, result map[string]any) {
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		lowerLine := strings.ToLower(trimmed)
		if strings.Contains(lowerLine, "bind.version") {
			if parts := strings.SplitN(trimmed, ":", 2); len(parts) == 2 {
				result["version"] = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(lowerLine, "id.server") {
			if parts := strings.SplitN(trimmed, ":", 2); len(parts) == 2 {
				result["id"] = strings.TrimSpace(parts[1])
			}
		}
	}
}

func (a *Analyzer) nmapCacheSnoop(ctx context.Context, ns string) map[string]any {
	result := map[string]any{
		mapKeyVulnerable: false,
		mapKeyMessage:    "Cache snooping not possible (correct configuration)",
		mapKeyNameserver: ns,
	}

	output, err := runNmapScript(ctx, ns, "dns-cache-snoop", "", 10*time.Second)
	if err != nil {
		result[mapKeyMessage] = msgTestInconclusive
		return result
	}

	if strings.Contains(strings.ToLower(output), "positive") || (strings.Contains(strings.ToLower(output), "cache") && strings.Contains(strings.ToLower(output), mapKeyFound)) {
		result[mapKeyVulnerable] = true
		result[mapKeyMessage] = "DNS cache snooping detected — attacker can determine which domains this server has recently resolved"
	}

	return result
}

func runNmapScript(ctx context.Context, target, script, args string, timeout time.Duration) (string, error) {
	if !isValidNmapTarget(target) {
		return "", fmt.Errorf("nmap target %q failed hostname/IP validation", target)
	}

	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmdArgs := []string{"-sn", "-Pn", "-p", "53", "--script", script}
	if args != "" {
		cmdArgs = append(cmdArgs, "--script-args", args)
	}
	cmdArgs = append(cmdArgs, target)

	cmd := exec.CommandContext(cmdCtx, "nmap", cmdArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if cmdCtx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("nmap script %s timed out after %v", script, timeout)
		}
		if len(out) > 0 {
			return string(out), nil
		}
		return "", fmt.Errorf("nmap script %s failed: %w", script, err)
	}

	return string(out), nil
}
