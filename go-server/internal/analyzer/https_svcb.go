// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/svcb"
)

const (
	mapKeyHasHttps    = "has_https"
	mapKeyHasSvcb     = "has_svcb"
	mapKeySupportsEch = "supports_ech"
	strSupportsHttp3  = "supports_http3"
)

func (a *Analyzer) AnalyzeHTTPSSVCB(ctx context.Context, domain string) map[string]any {
	result := map[string]any{
		"status":          "success",
		mapKeyHasHttps:    false,
		mapKeyHasSvcb:     false,
		"https_records":   []map[string]any{},
		"svcb_records":    []map[string]any{},
		strSupportsHttp3:  false,
		mapKeySupportsEch: false,
		"issues":          []string{},
	}

	httpsRecords := a.queryHTTPSRecords(ctx, domain)
	svcbRecords := a.querySVCBRecords(ctx, domain)

	if len(httpsRecords) > 0 {
		result[mapKeyHasHttps] = true
		parsed := parseHTTPSRecords(httpsRecords)
		result["https_records"] = parsed
		updateSVCBCapabilities(result, parsed)
	}

	if len(svcbRecords) > 0 {
		result[mapKeyHasSvcb] = true
		parsed := parseSVCBRecords(svcbRecords)
		result["svcb_records"] = parsed
	}

	if !result[mapKeyHasHttps].(bool) && !result[mapKeyHasSvcb].(bool) {
		result["status"] = "info"
		result["message"] = "No HTTPS or SVCB records found"
	} else {
		result["message"] = buildHTTPSMessage(result)
	}

	return result
}

func (a *Analyzer) queryHTTPSRecords(ctx context.Context, domain string) []*dns.HTTPS {
	msg := dns.NewMsg(dnsutil.Fqdn(domain), dns.TypeHTTPS)
	msg.RecursionDesired = true

	resp, err := a.DNS.ExchangeContext(ctx, msg)
	if err != nil || resp == nil {
		return nil
	}

	var records []*dns.HTTPS
	for _, rr := range resp.Answer {
		if h, ok := rr.(*dns.HTTPS); ok {
			records = append(records, h)
		}
	}
	return records
}

func (a *Analyzer) querySVCBRecords(ctx context.Context, domain string) []*dns.SVCB {
	msg := dns.NewMsg(dnsutil.Fqdn(domain), dns.TypeSVCB)
	msg.RecursionDesired = true

	resp, err := a.DNS.ExchangeContext(ctx, msg)
	if err != nil || resp == nil {
		return nil
	}

	var records []*dns.SVCB
	for _, rr := range resp.Answer {
		if s, ok := rr.(*dns.SVCB); ok {
			records = append(records, s)
		}
	}
	return records
}

func parseHTTPSRecords(records []*dns.HTTPS) []map[string]any {
	var parsed []map[string]any
	for _, r := range records {
		entry := map[string]any{
			"priority": r.Priority,
			"target":   r.Target,
			"raw":      r.String(),
		}
		parseSvcParams(entry, r.Value)
		parsed = append(parsed, entry)
	}
	return parsed
}

func parseSVCBRecords(records []*dns.SVCB) []map[string]any {
	var parsed []map[string]any
	for _, r := range records {
		entry := map[string]any{
			"priority": r.Priority,
			"target":   r.Target,
			"raw":      r.String(),
		}
		parseSvcParams(entry, r.Value)
		parsed = append(parsed, entry)
	}
	return parsed
}

func parseSvcParams(entry map[string]any, values []svcb.Pair) {
	var alpnList []string
	for _, kv := range values {
		alpnList = applySvcParam(entry, kv, alpnList)
	}
	if hasHTTP3(alpnList) {
		entry["http3"] = true
	}
}

func applySvcParam(entry map[string]any, kv svcb.Pair, alpnList []string) []string {
	switch v := kv.(type) {
	case *svcb.ALPN:
		entry["alpn"] = v.Alpn
		return v.Alpn
	case *svcb.PORT:
		entry["port"] = v.Port
	case *svcb.IPV4HINT:
		entry["ipv4hint"] = ipHintsToStrings(v.Hint)
	case *svcb.IPV6HINT:
		entry["ipv6hint"] = ipHintsToStrings(v.Hint)
	case *svcb.ECHCONFIG:
		entry["ech"] = true
		entry["ech_config_len"] = len(v.ECH)
	case *svcb.MANDATORY:
		keys := make([]string, len(v.Key))
		for i, c := range v.Key {
			keys[i] = svcb.KeyToString(c)
		}
		entry["mandatory"] = keys
	case *svcb.NODEFAULTALPN:
		entry["no_default_alpn"] = true
	}
	return alpnList
}

func ipHintsToStrings(hints []netip.Addr) []string {
	result := make([]string, len(hints))
	for i, ip := range hints {
		result[i] = ip.String()
	}
	return result
}

func hasHTTP3(alpnList []string) bool {
	for _, proto := range alpnList {
		if proto == "h3" || strings.HasPrefix(proto, "h3-") {
			return true
		}
	}
	return false
}

func updateSVCBCapabilities(result map[string]any, parsed []map[string]any) {
	for _, rec := range parsed {
		if h3, ok := rec["http3"].(bool); ok && h3 {
			result[strSupportsHttp3] = true
		}
		if ech, ok := rec["ech"].(bool); ok && ech {
			result[mapKeySupportsEch] = true
		}
	}
}

func buildHTTPSMessage(result map[string]any) string {
	parts := []string{}
	if result[mapKeyHasHttps].(bool) {
		parts = append(parts, "HTTPS records found")
	}
	if result[strSupportsHttp3].(bool) {
		parts = append(parts, "HTTP/3 supported")
	}
	if result[mapKeySupportsEch].(bool) {
		parts = append(parts, "ECH (Encrypted Client Hello) enabled")
	}
	if len(parts) == 0 {
		return "SVCB records found"
	}
	return fmt.Sprintf("%s", strings.Join(parts, ", "))
}
