// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package scanner

import (
	"log/slog"
	"net"
	"regexp"
	"strings"
)

const (
	mapKeyDomain = "domain"
)

type Classification struct {
	IsScan bool
	Source string
	IP     string
}

var knownScannerDomains = []struct {
	Pattern *regexp.Regexp
	Source  string
}{
	{regexp.MustCompile(`(?i)\.qualysperiscope\.com$`), "Qualys Periscope"},
	{regexp.MustCompile(`(?i)\.qualys\.com$`), "Qualys"},
	{regexp.MustCompile(`(?i)\.burpcollaborator\.net$`), "Burp Collaborator"},
	{regexp.MustCompile(`(?i)\.oastify\.com$`), "Burp Suite OAST"},
	{regexp.MustCompile(`(?i)\.interact\.sh$`), "Interactsh"},
	{regexp.MustCompile(`(?i)\.bxss\.me$`), "Blind XSS Hunter"},
	{regexp.MustCompile(`(?i)\.canarytokens\.com$`), "Canary Tokens"},
	{regexp.MustCompile(`(?i)\.dnslog\.(cn|link)$`), "DNSLog"},
	{regexp.MustCompile(`(?i)\.ceye\.io$`), "CEYE"},
	{regexp.MustCompile(`(?i)\.nessus\.org$`), "Tenable Nessus"},
	{regexp.MustCompile(`(?i)\.tenablesecurity\.com$`), "Tenable"},
	{regexp.MustCompile(`(?i)\.rapid7\.com$`), "Rapid7"},
	{regexp.MustCompile(`(?i)\.shodan\.io$`), "Shodan"},
	{regexp.MustCompile(`(?i)\.censys\.io$`), "Censys"},
	{regexp.MustCompile(`(?i)\.projectdiscovery\.io$`), "ProjectDiscovery"},
	{regexp.MustCompile(`(?i)\.r87\.me$`), "r87 OAST"},
}

var hexLabelPattern = regexp.MustCompile(`^[0-9a-f]{8,}$`)

func Classify(domain, clientIP string) Classification {
	result := Classification{IP: clientIP}

	for _, entry := range knownScannerDomains {
		if entry.Pattern.MatchString(domain) {
			result.IsScan = true
			result.Source = entry.Source
			slog.Info("Scanner domain detected", mapKeyDomain, domain, "source", result.Source, "ip", clientIP)
			return result
		}
	}

	if source := matchCISAIP(clientIP); source != "" {
		result.IsScan = true
		result.Source = source
		slog.Info("CISA scanner IP detected", mapKeyDomain, domain, "source", result.Source, "ip", clientIP)
		return result
	}

	if isHeuristicScanner(domain) {
		result.IsScan = true
		result.Source = "Heuristic (automated probe pattern)"
		slog.Info("Heuristic scanner pattern detected", mapKeyDomain, domain, "ip", clientIP)
		return result
	}

	return result
}

func isHeuristicScanner(domain string) bool {
	labels := strings.Split(domain, ".")
	if len(labels) < 5 {
		return false
	}

	hexCount := 0
	for _, label := range labels {
		if hexLabelPattern.MatchString(strings.ToLower(label)) && len(label) >= 12 {
			hexCount++
		}
	}

	return hexCount >= 2
}

func matchCISAIP(ip string) string {
	if ip == "" {
		return ""
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ""
	}

	cisaListMu.RLock()
	defer cisaListMu.RUnlock()

	for _, cidr := range cisaIPNets {
		if cidr.Contains(parsedIP) {
			return "CISA Cyber Hygiene"
		}
	}

	return ""
}
