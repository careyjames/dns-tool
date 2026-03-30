// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// ip_investigation.go — Framework only (types, constants, utilities). Always compiled.
// Intelligence functions live in ip_investigation_oss.go / ip_investigation_intel.go.
// dns-tool:scrutiny science
package analyzer

import (
	"io"
	"log/slog"
	"net"
	"regexp"
	"strings"
)

type IPRelationship struct {
	Classification string `json:"classification"`
	Evidence       string `json:"evidence"`
	RecordType     string `json:"record_type,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
}

var (
	ipv4Re = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	ipv6Re = regexp.MustCompile(`(?i)^[0-9a-f:]+$`)

	spfIPv4Re = regexp.MustCompile(`(?i)ip4:([^\s;]+)`)
	spfIPv6Re = regexp.MustCompile(`(?i)ip6:([^\s;]+)`)
)

const (
	neighborhoodDisplayCap = 10

	classCDNEdge       = "CDN/Edge Network"
	classCloudHosting  = "Cloud Hosting"
	classDirectA       = "Direct Asset (A Record)"
	classDirectAAAA    = "Direct Asset (AAAA Record)"
	classDirectReverse = "Direct Asset (Reverse DNS)"
	classEmailMX       = "Email Provider (MX)"
	classDNSNS         = "DNS Provider (NS)"
	classSPFAuth       = "SPF-Authorized Sender"
	classCTSubdomain   = "CT Subdomain Match"
)

func ValidateIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}

func IsPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() || parsed.IsUnspecified()
}

func IsIPv6(ip string) bool {
	return strings.Contains(ip, ":")
}

func buildArpaName(ip string) string {
	if IsIPv6(ip) {
		reversed := reverseIPv6(ip)
		if reversed == "" {
			return ""
		}
		return reversed + ".ip6.arpa"
	}
	reversed := reverseIPv4(ip)
	if reversed == "" {
		return ""
	}
	return reversed + ".in-addr.arpa"
}

func findFirstHostname(rels []map[string]any, classification string) string {
	return ""
}

func extractMXHost(mx string) string {
	return ""
}

func mapGetStr(m map[string]any, key string) string {
	v, ok := m[key].(string)
	if !ok {
		return ""
	}
	return v
}

func safeClose(c io.Closer, label string) {
	if err := c.Close(); err != nil {
		slog.Debug("close error", "resource", label, "error", err)
	}
}
