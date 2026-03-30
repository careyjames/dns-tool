// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

type DSRecord struct {
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digest_type"`
	Digest     string `json:"digest"`
	Raw        string `json:"raw"`
}

type DNSKEYRecord struct {
	Flags     uint16 `json:"flags"`
	Protocol  uint8  `json:"protocol"`
	Algorithm uint8  `json:"algorithm"`
	KeyTag    uint16 `json:"key_tag"`
	IsKSK     bool   `json:"is_ksk"`
	IsZSK     bool   `json:"is_zsk"`
	Raw       string `json:"raw"`
}

type DSKeyAlignment struct {
	Aligned       bool           `json:"aligned"`
	MatchedPairs  []DSKeyPair    `json:"matched_pairs"`
	UnmatchedDS   []DSRecord     `json:"unmatched_ds"`
	UnmatchedKeys []DNSKEYRecord `json:"unmatched_keys"`
	Issues        []string       `json:"issues"`
}

type DSKeyPair struct {
	DSKeyTag        uint16 `json:"ds_key_tag"`
	DSAlgorithm     uint8  `json:"ds_algorithm"`
	DNSKEYKeyTag    uint16 `json:"dnskey_key_tag"`
	DNSKEYAlgorithm uint8  `json:"dnskey_algorithm"`
}

type GlueStatus struct {
	NS          string   `json:"ns"`
	InBailiwick bool     `json:"in_bailiwick"`
	HasIPv4Glue bool     `json:"has_ipv4_glue"`
	HasIPv6Glue bool     `json:"has_ipv6_glue"`
	IPv4Addrs   []string `json:"ipv4_addrs,omitempty"`
	IPv6Addrs   []string `json:"ipv6_addrs,omitempty"`
	Complete    bool     `json:"complete"`
}

type GlueAnalysis struct {
	Complete         bool         `json:"complete"`
	InBailiwickCount int          `json:"in_bailiwick_count"`
	GluePresent      int          `json:"glue_present"`
	GlueMissing      int          `json:"glue_missing"`
	Nameservers      []GlueStatus `json:"nameservers"`
	Issues           []string     `json:"issues"`
}

type TTLComparison struct {
	ParentTTL *uint32  `json:"parent_ttl"`
	ChildTTL  *uint32  `json:"child_ttl"`
	Match     bool     `json:"match"`
	DriftSecs int64    `json:"drift_secs"`
	Issues    []string `json:"issues"`
}

type SOAConsistency struct {
	Consistent  bool              `json:"consistent"`
	Serials     map[string]uint32 `json:"serials"`
	UniqueCount int               `json:"unique_count"`
	Issues      []string          `json:"issues"`
}

type DelegationConsistencyResult struct {
	Status         string          `json:"status"`
	Message        string          `json:"message"`
	DSKeyAlignment *DSKeyAlignment `json:"ds_key_alignment,omitempty"`
	GlueAnalysis   *GlueAnalysis   `json:"glue_analysis,omitempty"`
	TTLComparison  *TTLComparison  `json:"ttl_comparison,omitempty"`
	SOAConsistency *SOAConsistency `json:"soa_consistency,omitempty"`
	Issues         []string        `json:"issues"`
}

func parseDSRecordTyped(rr *dns.DS) DSRecord {
	return DSRecord{
		KeyTag:     rr.KeyTag,
		Algorithm:  rr.Algorithm,
		DigestType: rr.DigestType,
		Digest:     rr.Digest,
		Raw:        rr.String(),
	}
}

func parseDNSKEYRecordTyped(rr *dns.DNSKEY) DNSKEYRecord {
	return DNSKEYRecord{
		Flags:     rr.Flags,
		Protocol:  rr.Protocol,
		Algorithm: rr.Algorithm,
		KeyTag:    rr.KeyTag(),
		IsKSK:     rr.Flags == 257,
		IsZSK:     rr.Flags == 256,
		Raw:       rr.String(),
	}
}

func CheckDSKeyAlignment(dsRecords []DSRecord, dnskeyRecords []DNSKEYRecord) DSKeyAlignment {
	result := DSKeyAlignment{
		Aligned:       true,
		MatchedPairs:  []DSKeyPair{},
		UnmatchedDS:   []DSRecord{},
		UnmatchedKeys: []DNSKEYRecord{},
		Issues:        []string{},
	}

	if len(dsRecords) == 0 && len(dnskeyRecords) == 0 {
		return result
	}

	if len(dsRecords) == 0 {
		result.Aligned = false
		result.UnmatchedKeys = dnskeyRecords
		result.Issues = append(result.Issues, "DS records missing at parent — DNSSEC chain of trust is broken")
		return result
	}

	if len(dnskeyRecords) == 0 {
		result.Aligned = false
		result.UnmatchedDS = dsRecords
		result.Issues = append(result.Issues, "DNSKEY records missing at child — DS records at parent have no matching keys")
		return result
	}

	kskKeys := collectKSKKeys(dnskeyRecords)
	dsMatched, keyMatched := matchDSKeyPairs(dsRecords, kskKeys, &result)
	collectUnmatchedRecords(dsRecords, dnskeyRecords, dsMatched, keyMatched, &result)

	if len(result.MatchedPairs) == 0 {
		result.Aligned = false
		result.Issues = append(result.Issues, "No DS/DNSKEY key-tag+algorithm pairs match — chain of trust is broken")
	}

	if len(result.UnmatchedDS) > 0 {
		result.Issues = append(result.Issues,
			fmt.Sprintf("%d DS record(s) at parent have no matching DNSKEY at child", len(result.UnmatchedDS)))
	}

	return result
}

func collectKSKKeys(dnskeyRecords []DNSKEYRecord) map[uint16]DNSKEYRecord {
	kskKeys := map[uint16]DNSKEYRecord{}
	for _, key := range dnskeyRecords {
		if key.IsKSK {
			kskKeys[key.KeyTag] = key
		}
	}
	return kskKeys
}

func matchDSKeyPairs(dsRecords []DSRecord, kskKeys map[uint16]DNSKEYRecord, result *DSKeyAlignment) (map[int]bool, map[uint16]bool) {
	dsMatched := make(map[int]bool)
	keyMatched := make(map[uint16]bool)

	for i, ds := range dsRecords {
		key, ok := kskKeys[ds.KeyTag]
		if !ok {
			continue
		}
		if ds.Algorithm == key.Algorithm {
			result.MatchedPairs = append(result.MatchedPairs, DSKeyPair{
				DSKeyTag:        ds.KeyTag,
				DSAlgorithm:     ds.Algorithm,
				DNSKEYKeyTag:    key.KeyTag,
				DNSKEYAlgorithm: key.Algorithm,
			})
			dsMatched[i] = true
			keyMatched[key.KeyTag] = true
		} else {
			result.Issues = append(result.Issues,
				fmt.Sprintf("DS key-tag %d matches DNSKEY but algorithm mismatch: DS=%d, DNSKEY=%d",
					ds.KeyTag, ds.Algorithm, key.Algorithm))
		}
	}
	return dsMatched, keyMatched
}

func collectUnmatchedRecords(dsRecords []DSRecord, dnskeyRecords []DNSKEYRecord, dsMatched map[int]bool, keyMatched map[uint16]bool, result *DSKeyAlignment) {
	for i, ds := range dsRecords {
		if !dsMatched[i] {
			result.UnmatchedDS = append(result.UnmatchedDS, ds)
		}
	}
	for _, key := range dnskeyRecords {
		if key.IsKSK && !keyMatched[key.KeyTag] {
			result.UnmatchedKeys = append(result.UnmatchedKeys, key)
		}
	}
}

func isInBailiwick(ns, domain string) bool {
	nsLower := strings.ToLower(strings.TrimRight(ns, "."))
	domLower := strings.ToLower(strings.TrimRight(domain, "."))
	return strings.HasSuffix(nsLower, "."+domLower) || nsLower == domLower
}

func CheckGlueCompleteness(nameservers []string, domain string, glueIPv4, glueIPv6 map[string][]string) GlueAnalysis {
	result := GlueAnalysis{
		Complete:    true,
		Nameservers: []GlueStatus{},
		Issues:      []string{},
	}

	for _, ns := range nameservers {
		nsLower := strings.ToLower(strings.TrimRight(ns, "."))
		inBailiwick := isInBailiwick(ns, domain)

		status := GlueStatus{
			NS:          nsLower,
			InBailiwick: inBailiwick,
		}

		if inBailiwick {
			result.InBailiwickCount++
			evaluateInBailiwickGlue(nsLower, glueIPv4, glueIPv6, &status, &result)
		} else {
			status.Complete = true
		}

		result.Nameservers = append(result.Nameservers, status)
	}

	return result
}

func evaluateInBailiwickGlue(nsLower string, glueIPv4, glueIPv6 map[string][]string, status *GlueStatus, result *GlueAnalysis) {
	if addrs, ok := glueIPv4[nsLower]; ok && len(addrs) > 0 {
		status.HasIPv4Glue = true
		status.IPv4Addrs = addrs
	}
	if addrs, ok := glueIPv6[nsLower]; ok && len(addrs) > 0 {
		status.HasIPv6Glue = true
		status.IPv6Addrs = addrs
	}

	if status.HasIPv4Glue || status.HasIPv6Glue {
		result.GluePresent++
		status.Complete = status.HasIPv4Glue && status.HasIPv6Glue
		if !status.HasIPv4Glue {
			result.Issues = append(result.Issues, fmt.Sprintf("In-bailiwick NS %s missing IPv4 (A) glue at parent", nsLower))
		}
		if !status.HasIPv6Glue {
			result.Issues = append(result.Issues, fmt.Sprintf("In-bailiwick NS %s missing IPv6 (AAAA) glue at parent", nsLower))
		}
	} else {
		result.GlueMissing++
		result.Complete = false
		result.Issues = append(result.Issues, fmt.Sprintf("In-bailiwick NS %s has no glue records at parent — resolution may fail", nsLower))
	}
}

func CompareTTLs(parentTTL, childTTL *uint32) TTLComparison {
	result := TTLComparison{
		ParentTTL: parentTTL,
		ChildTTL:  childTTL,
		Match:     true,
		Issues:    []string{},
	}

	if parentTTL == nil || childTTL == nil {
		result.Match = false
		if parentTTL == nil && childTTL == nil {
			result.Issues = append(result.Issues, "Could not retrieve NS TTL from either parent or child")
		} else if parentTTL == nil {
			result.Issues = append(result.Issues, "Could not retrieve NS TTL from parent zone")
		} else {
			result.Issues = append(result.Issues, "Could not retrieve NS TTL from child zone")
		}
		return result
	}

	result.DriftSecs = int64(*parentTTL) - int64(*childTTL)
	if result.DriftSecs < 0 {
		result.DriftSecs = -result.DriftSecs
	}

	if *parentTTL != *childTTL {
		result.Match = false
		result.Issues = append(result.Issues,
			fmt.Sprintf("NS TTL mismatch: parent=%d, child=%d (drift=%ds)",
				*parentTTL, *childTTL, result.DriftSecs))
	}

	return result
}

func CheckSOAConsistency(serials map[string]uint32) SOAConsistency {
	result := SOAConsistency{
		Consistent:  true,
		Serials:     serials,
		UniqueCount: 0,
		Issues:      []string{},
	}

	if len(serials) == 0 {
		result.Issues = append(result.Issues, "Could not retrieve SOA serial from any nameserver")
		return result
	}

	unique := map[uint32][]string{}
	for ns, serial := range serials {
		unique[serial] = append(unique[serial], ns)
	}

	result.UniqueCount = len(unique)
	if len(unique) > 1 {
		result.Consistent = false
		for serial, nsList := range unique {
			result.Issues = append(result.Issues,
				fmt.Sprintf("SOA serial %d seen on: %s", serial, strings.Join(nsList, ", ")))
		}
		result.Issues = append(result.Issues, "SOA serial inconsistency indicates zone data may not be fully synchronized across nameservers")
	}

	return result
}

func (a *Analyzer) queryDSForDelegation(ctx context.Context, domain string) []DSRecord {
	fqdn := dnsutil.Fqdn(domain)
	msg := dns.NewMsg(fqdn, dns.TypeDS)
	msg.RecursionDesired = true

	resp, err := a.DNS.ExchangeContext(ctx, msg)
	if err != nil || resp == nil {
		return nil
	}

	var records []DSRecord
	for _, rr := range resp.Answer {
		if ds, ok := rr.(*dns.DS); ok {
			records = append(records, parseDSRecordTyped(ds))
		}
	}
	return records
}

func (a *Analyzer) queryDNSKEYForDelegation(ctx context.Context, domain string) []DNSKEYRecord {
	fqdn := dnsutil.Fqdn(domain)
	msg := dns.NewMsg(fqdn, dns.TypeDNSKEY)
	msg.RecursionDesired = true

	resp, err := a.DNS.ExchangeContext(ctx, msg)
	if err != nil || resp == nil {
		return nil
	}

	var records []DNSKEYRecord
	for _, rr := range resp.Answer {
		if key, ok := rr.(*dns.DNSKEY); ok {
			records = append(records, parseDNSKEYRecordTyped(key))
		}
	}
	return records
}

func (a *Analyzer) fetchGlueRecords(ctx context.Context, nameservers []string, domain string) (map[string][]string, map[string][]string) {
	parentZone := parentZoneFromDomain(domain)
	if parentZone == "" {
		return map[string][]string{}, map[string][]string{}
	}

	parentNSServers := a.DNS.QueryDNS(ctx, "NS", parentZone)
	if len(parentNSServers) == 0 {
		return map[string][]string{}, map[string][]string{}
	}

	parentServer := strings.TrimRight(parentNSServers[0], ".")
	parentIPs := a.DNS.QueryDNS(ctx, "A", parentServer)
	if len(parentIPs) == 0 {
		return map[string][]string{}, map[string][]string{}
	}

	glueIPv4 := map[string][]string{}
	glueIPv6 := map[string][]string{}

	for _, ns := range nameservers {
		nsLower := strings.ToLower(strings.TrimRight(ns, "."))
		if !isInBailiwick(ns, domain) {
			continue
		}

		aResults, _ := a.DNS.QuerySpecificResolver(ctx, "A", nsLower, parentIPs[0])
		if len(aResults) > 0 {
			glueIPv4[nsLower] = aResults
		}

		aaaaResults, _ := a.DNS.QuerySpecificResolver(ctx, "AAAA", nsLower, parentIPs[0])
		if len(aaaaResults) > 0 {
			glueIPv6[nsLower] = aaaaResults
		}
	}

	return glueIPv4, glueIPv6
}

func (a *Analyzer) fetchNSTTLFromParent(ctx context.Context, domain string) *uint32 {
	parentZone := parentZoneFromDomain(domain)
	if parentZone == "" {
		return nil
	}

	parentNSServers := a.DNS.QueryDNS(ctx, "NS", parentZone)
	if len(parentNSServers) == 0 {
		return nil
	}

	parentServer := strings.TrimRight(parentNSServers[0], ".")
	parentIPs := a.DNS.QueryDNS(ctx, "A", parentServer)
	if len(parentIPs) == 0 {
		return nil
	}

	result := a.DNS.QueryWithTTLFromResolver(ctx, "NS", domain, parentIPs[0])
	return result.TTL
}

func (a *Analyzer) fetchNSTTLFromChild(ctx context.Context, domain string) *uint32 {
	childNS := a.DNS.QueryDNS(ctx, "NS", domain)
	if len(childNS) == 0 {
		return nil
	}

	nsIP := strings.TrimRight(childNS[0], ".")
	ips := a.DNS.QueryDNS(ctx, "A", nsIP)
	if len(ips) == 0 {
		return nil
	}

	result := a.DNS.QueryWithTTLFromResolver(ctx, "NS", domain, ips[0])
	return result.TTL
}

func parseSOASerial(soaStr string) (uint32, bool) {
	parts := strings.Fields(soaStr)
	if len(parts) < 3 {
		return 0, false
	}
	serial, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(serial), true
}

func (a *Analyzer) fetchSOASerials(ctx context.Context, domain string, nameservers []string) map[string]uint32 {
	serials := map[string]uint32{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	soaCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	for _, ns := range nameservers {
		wg.Add(1)
		go func(nsName string) {
			defer wg.Done()
			nsClean := strings.TrimRight(nsName, ".")

			ips := a.DNS.QueryDNS(soaCtx, "A", nsClean)
			if len(ips) == 0 {
				return
			}

			ip := ips[0]
			if net.ParseIP(ip) == nil {
				return
			}

			soaRecords, err := a.DNS.QuerySpecificResolver(soaCtx, "SOA", domain, ip)
			if err != nil || len(soaRecords) == 0 {
				return
			}

			if serial, ok := parseSOASerial(soaRecords[0]); ok {
				mu.Lock()
				serials[nsClean] = serial
				mu.Unlock()
			}
		}(ns)
	}

	wg.Wait()
	return serials
}

func (a *Analyzer) AnalyzeDelegationConsistency(ctx context.Context, domain string) map[string]any {
	childNS := a.queryChildNS(ctx, domain)

	dsRecords := a.queryDSForDelegation(ctx, domain)
	dnskeyRecords := a.queryDNSKEYForDelegation(ctx, domain)

	dsKeyAlign := CheckDSKeyAlignment(dsRecords, dnskeyRecords)

	glueIPv4, glueIPv6 := a.fetchGlueRecords(ctx, childNS, domain)
	glueAnalysis := CheckGlueCompleteness(childNS, domain, glueIPv4, glueIPv6)

	parentTTL := a.fetchNSTTLFromParent(ctx, domain)
	childTTL := a.fetchNSTTLFromChild(ctx, domain)
	ttlComp := CompareTTLs(parentTTL, childTTL)

	soaSerials := a.fetchSOASerials(ctx, domain, childNS)
	soaConsistency := CheckSOAConsistency(soaSerials)

	allIssues := make([]string, 0)
	allIssues = append(allIssues, dsKeyAlign.Issues...)
	allIssues = append(allIssues, glueAnalysis.Issues...)
	allIssues = append(allIssues, ttlComp.Issues...)
	allIssues = append(allIssues, soaConsistency.Issues...)

	status := "success"
	message := "Parent/child delegation is consistent"
	if len(allIssues) > 0 {
		status = "warning"
		message = fmt.Sprintf("Delegation consistency: %d issue(s) found", len(allIssues))
	}

	return map[string]any{
		"status":           status,
		"message":          message,
		"ds_key_alignment": structToMap(dsKeyAlign),
		"glue_analysis":    structToMap(glueAnalysis),
		"ttl_comparison":   structToMap(ttlComp),
		"soa_consistency":  structToMap(soaConsistency),
		mapKeyIssues:       allIssues,
	}
}

func structToMap(v any) map[string]any {
	switch val := v.(type) {
	case DSKeyAlignment:
		return dsKeyAlignmentToMap(val)
	case GlueAnalysis:
		return glueAnalysisToMap(val)
	case TTLComparison:
		return ttlComparisonToMap(val)
	case SOAConsistency:
		return soaConsistencyToMap(val)
	default:
		return map[string]any{}
	}
}

func dsKeyAlignmentToMap(val DSKeyAlignment) map[string]any {
	matchedPairs := make([]map[string]any, 0, len(val.MatchedPairs))
	for _, p := range val.MatchedPairs {
		matchedPairs = append(matchedPairs, map[string]any{
			"ds_key_tag":       p.DSKeyTag,
			"ds_algorithm":     p.DSAlgorithm,
			"dnskey_key_tag":   p.DNSKEYKeyTag,
			"dnskey_algorithm": p.DNSKEYAlgorithm,
		})
	}
	unmatchedDS := make([]map[string]any, 0, len(val.UnmatchedDS))
	for _, d := range val.UnmatchedDS {
		unmatchedDS = append(unmatchedDS, map[string]any{
			mapKeyKeyTag: d.KeyTag, mapKeyAlgorithm: d.Algorithm,
			"digest_type": d.DigestType, mapKeyRaw: d.Raw,
		})
	}
	unmatchedKeys := make([]map[string]any, 0, len(val.UnmatchedKeys))
	for _, k := range val.UnmatchedKeys {
		unmatchedKeys = append(unmatchedKeys, map[string]any{
			"flags": k.Flags, mapKeyAlgorithm: k.Algorithm,
			mapKeyKeyTag: k.KeyTag, "is_ksk": k.IsKSK, mapKeyRaw: k.Raw,
		})
	}
	return map[string]any{
		"aligned":        val.Aligned,
		"matched_pairs":  matchedPairs,
		"unmatched_ds":   unmatchedDS,
		"unmatched_keys": unmatchedKeys,
		mapKeyIssues:     val.Issues,
	}
}

func glueStatusToMap(ns GlueStatus) map[string]any {
	entry := map[string]any{
		"ns":            ns.NS,
		"in_bailiwick":  ns.InBailiwick,
		"has_ipv4_glue": ns.HasIPv4Glue,
		"has_ipv6_glue": ns.HasIPv6Glue,
		mapKeyComplete:  ns.Complete,
	}
	if len(ns.IPv4Addrs) > 0 {
		entry["ipv4_addrs"] = ns.IPv4Addrs
	}
	if len(ns.IPv6Addrs) > 0 {
		entry["ipv6_addrs"] = ns.IPv6Addrs
	}
	return entry
}

func glueAnalysisToMap(val GlueAnalysis) map[string]any {
	nameservers := make([]map[string]any, 0, len(val.Nameservers))
	for _, ns := range val.Nameservers {
		nameservers = append(nameservers, glueStatusToMap(ns))
	}
	return map[string]any{
		mapKeyComplete:       val.Complete,
		"in_bailiwick_count": val.InBailiwickCount,
		"glue_present":       val.GluePresent,
		"glue_missing":       val.GlueMissing,
		"nameservers":        nameservers,
		mapKeyIssues:         val.Issues,
	}
}

func ttlComparisonToMap(val TTLComparison) map[string]any {
	m := map[string]any{
		"match":      val.Match,
		"drift_secs": val.DriftSecs,
		mapKeyIssues: val.Issues,
	}
	if val.ParentTTL != nil {
		m["parent_ttl"] = *val.ParentTTL
	}
	if val.ChildTTL != nil {
		m["child_ttl"] = *val.ChildTTL
	}
	return m
}

func soaConsistencyToMap(val SOAConsistency) map[string]any {
	serialsMap := map[string]any{}
	for k, v := range val.Serials {
		serialsMap[k] = v
	}
	return map[string]any{
		"consistent":   val.Consistent,
		"serials":      serialsMap,
		"unique_count": val.UniqueCount,
		mapKeyIssues:   val.Issues,
	}
}
