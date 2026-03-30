// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	mapKeyAsName  = "as_name"
	mapKeyCountry = "country"
	mapKeyASN     = "asn"
)

type ASNInfo struct {
	IP      string `json:"ip"`
	ASN     string `json:"asn"`
	ASName  string `json:"as_name"`
	Country string `json:"country"`
	Prefix  string `json:"prefix"`
}

func (a *Analyzer) LookupASN(ctx context.Context, results map[string]any) map[string]any {
	basicRecords, _ := results["basic_records"].(map[string]any)
	aRecords, _ := basicRecords["A"].([]string)
	aaaaRecords, _ := basicRecords["AAAA"].([]string)

	result := map[string]any{
		"status":      "success",
		"ipv4_asn":    []map[string]any{},
		"ipv6_asn":    []map[string]any{},
		"unique_asns": []map[string]any{},
		"issues":      []string{},
	}

	asnCtx, asnCancel := context.WithTimeout(ctx, 8*time.Second)
	defer asnCancel()

	asnSet := make(map[string]map[string]any)

	ipv4Results := a.lookupIPv4ASNs(asnCtx, aRecords, asnSet)
	ipv6Results := a.lookupIPv6ASNs(asnCtx, aaaaRecords, asnSet)

	result["ipv4_asn"] = ipv4Results
	result["ipv6_asn"] = ipv6Results

	var uniqueASNs []map[string]any
	for _, info := range asnSet {
		uniqueASNs = append(uniqueASNs, info)
	}
	result["unique_asns"] = uniqueASNs

	if len(ipv4Results) == 0 && len(ipv6Results) == 0 {
		result["status"] = "info"
		result["message"] = "No IP addresses to look up"
	} else {
		result["message"] = fmt.Sprintf("Resolved %d unique ASN(s) across %d IP address(es)", len(uniqueASNs), len(ipv4Results)+len(ipv6Results))
	}

	return result
}

func (a *Analyzer) lookupIPv4ASNs(ctx context.Context, ips []string, asnSet map[string]map[string]any) []map[string]any {
	var results []map[string]any
	for _, ip := range ips {
		info := a.lookupIPv4ASN(ctx, ip)
		results = append(results, info)
		mergeASNSet(asnSet, info)
	}
	return results
}

func (a *Analyzer) lookupIPv6ASNs(ctx context.Context, ips []string, asnSet map[string]map[string]any) []map[string]any {
	var results []map[string]any
	for _, ip := range ips {
		info := a.lookupIPv6ASN(ctx, ip)
		results = append(results, info)
		mergeASNSet(asnSet, info)
	}
	return results
}

func (a *Analyzer) lookupIPv4ASN(ctx context.Context, ip string) map[string]any {
	reversed := reverseIPv4(ip)
	if reversed == "" {
		return map[string]any{"ip": ip, mapKeyError: "invalid IPv4"}
	}

	query := fmt.Sprintf("%s.origin.asn.cymru.com", reversed)
	records := a.DNS.QueryDNS(ctx, dnsTypeTXT, query)

	info := map[string]any{
		"ip":         ip,
		"confidence": ConfidenceThirdPartyMap(MethodTeamCymru),
	}

	if len(records) == 0 {
		info[mapKeyError] = "no ASN data"
		return info
	}

	parseTeamCymruResponse(info, records[0])
	enrichASName(ctx, a, info)
	return info
}

func (a *Analyzer) lookupIPv6ASN(ctx context.Context, ip string) map[string]any {
	reversed := reverseIPv6(ip)
	if reversed == "" {
		return map[string]any{"ip": ip, mapKeyError: "invalid IPv6"}
	}

	query := fmt.Sprintf("%s.origin6.asn.cymru.com", reversed)
	records := a.DNS.QueryDNS(ctx, dnsTypeTXT, query)

	info := map[string]any{
		"ip":         ip,
		"confidence": ConfidenceThirdPartyMap(MethodTeamCymru),
	}

	if len(records) == 0 {
		info[mapKeyError] = "no ASN data"
		return info
	}

	parseTeamCymruResponse(info, records[0])
	enrichASName(ctx, a, info)
	return info
}

func parseTeamCymruResponse(info map[string]any, record string) {
	record = strings.Trim(record, "\"")
	parts := strings.Split(record, "|")
	if len(parts) < 3 {
		return
	}
	info[mapKeyASN] = strings.TrimSpace(parts[0])
	info["prefix"] = strings.TrimSpace(parts[1])
	info[mapKeyCountry] = strings.TrimSpace(parts[2])
}

const asnAmazon = "Amazon.com, Inc."

var wellKnownASNames = map[string]string{
	"13335":  "Cloudflare, Inc.",
	"209242": "Cloudflare London, LLC",
	"20940":  "Akamai International B.V.",
	"16625":  "Akamai Technologies, Inc.",
	"32787":  "Prolexic Technologies, Inc. (Akamai)",
	"54113":  "Fastly, Inc.",
	"15169":  "Google LLC",
	"396982": "Google LLC",
	"8075":   "Microsoft Corporation",
	"16509":  asnAmazon,
	"14618":  asnAmazon,
	"38895":  asnAmazon,
	"16510":  asnAmazon,
	"36183":  asnAmazon,
	"14061":  "DigitalOcean, LLC",
	"63949":  "Akamai Connected Cloud (Linode)",
	"24940":  "Hetzner Online GmbH",
	"16276":  "OVH SAS",
	"20473":  "The Constant Company, LLC (Vultr)",
	"13649":  "Rackspace Hosting",
	"36351":  "IBM Cloud (SoftLayer)",
	"2635":   "Automattic, Inc.",
	"394536": "Sucuri Inc.",
	"19551":  "Imperva, Inc.",
	"46489":  "Twitch Interactive, Inc.",
	"394699": "KeyCDN",
	"30148":  "Sucuri Inc.",
	"197540": "Netcup GmbH",
	"4808":   "China Unicom Beijing Province Network",
	"45102":  "Alibaba (US) Technology Co., Ltd.",
	"132203": "Tencent Building, Kejizhongyi Avenue",
	"7922":   "Comcast Cable Communications, LLC",
	"209":    "CenturyLink Communications, LLC",
	"3356":   "Lumen Technologies",
	"174":    "Cogent Communications",
	"6939":   "Hurricane Electric LLC",
	"3491":   "PCCW Global, Inc.",
	"1239":   "Sprint",
	"2914":   "NTT America, Inc.",
	"6461":   "Zayo Bandwidth",
	"701":    "Verizon Business",
	"7018":   "AT&T Services, Inc.",
}

func enrichASName(ctx context.Context, a *Analyzer, info map[string]any) {
	asn, _ := info[mapKeyASN].(string)
	if asn == "" {
		return
	}
	query := fmt.Sprintf("AS%s.peer.asn.cymru.com", asn)
	records := a.DNS.QueryDNS(ctx, dnsTypeTXT, query)
	if len(records) > 0 {
		record := strings.Trim(records[0], "\"")
		parts := strings.Split(record, "|")
		if len(parts) >= 5 {
			name := strings.TrimSpace(parts[4])
			if name != "" {
				info[mapKeyAsName] = name
				return
			}
		}
	}

	if name, ok := wellKnownASNames[asn]; ok {
		info[mapKeyAsName] = name
	}
}

func mergeASNSet(set map[string]map[string]any, info map[string]any) {
	asn, _ := info[mapKeyASN].(string)
	if asn == "" {
		return
	}
	if _, exists := set[asn]; !exists {
		set[asn] = map[string]any{
			mapKeyASN:     asn,
			mapKeyAsName:  info[mapKeyAsName],
			mapKeyCountry: info[mapKeyCountry],
		}
	}
}

func reverseIPv4(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0])
}

func reverseIPv6(ip string) string {
	ip = strings.ToLower(ip)

	parts := strings.Split(ip, ":")
	if len(parts) < 3 {
		return ""
	}

	full := expandIPv6(ip)
	if full == "" {
		return ""
	}

	nibbles := strings.ReplaceAll(full, ":", "")
	if len(nibbles) != 32 {
		return ""
	}

	reversed := make([]byte, 63)
	for i := 0; i < 32; i++ {
		reversed[62-i*2] = nibbles[i]
		if i < 31 {
			reversed[62-i*2-1] = '.'
		}
	}
	return string(reversed)
}

func expandIPv6(ip string) string {
	if strings.Contains(ip, "::") {
		halves := strings.SplitN(ip, "::", 2)
		left := filterEmpty(strings.Split(halves[0], ":"))
		right := filterEmpty(strings.Split(halves[1], ":"))
		missing := 8 - len(left) - len(right)
		if missing < 0 {
			return ""
		}
		var full []string
		full = append(full, left...)
		for i := 0; i < missing; i++ {
			full = append(full, "0000")
		}
		full = append(full, right...)
		for i := range full {
			full[i] = padHex(full[i])
		}
		return strings.Join(full, ":")
	}

	parts := strings.Split(ip, ":")
	if len(parts) != 8 {
		return ""
	}
	for i := range parts {
		parts[i] = padHex(parts[i])
	}
	return strings.Join(parts, ":")
}

func padHex(s string) string {
	for len(s) < 4 {
		s = "0" + s
	}
	return s
}

func filterEmpty(ss []string) []string {
	var result []string
	for _, s := range ss {
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}
