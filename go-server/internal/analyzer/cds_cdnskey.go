// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"fmt"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

const (
	mapKeyAutomation     = "automation"
	mapKeyDeleteSignaled = "delete_signaled"
	mapKeyHasCdnskey     = "has_cdnskey"
	mapKeyHasCds         = "has_cds"
)

func (a *Analyzer) AnalyzeCDSCDNSKEY(ctx context.Context, domain string) map[string]any {
	result := map[string]any{
		"status":          "success",
		mapKeyHasCds:      false,
		mapKeyHasCdnskey:  false,
		"cds_records":     []map[string]any{},
		"cdnskey_records": []map[string]any{},
		mapKeyAutomation:  "none",
		"issues":          []string{},
	}

	cdsRecords := a.queryCDS(ctx, domain)
	cdnskeyRecords := a.queryCDNSKEY(ctx, domain)

	if len(cdsRecords) > 0 {
		result[mapKeyHasCds] = true
		result["cds_records"] = parseCDSRecords(cdsRecords)
	}

	if len(cdnskeyRecords) > 0 {
		result[mapKeyHasCdnskey] = true
		result["cdnskey_records"] = parseCDNSKEYRecords(cdnskeyRecords)
	}

	result[mapKeyAutomation] = classifyCDSAutomation(cdsRecords, cdnskeyRecords)

	if !result[mapKeyHasCds].(bool) && !result[mapKeyHasCdnskey].(bool) {
		result["status"] = "info"
		result["message"] = "No CDS/CDNSKEY records found — no automated DNSSEC key rollover signaling"
	} else {
		result["message"] = buildCDSMessage(result)
	}

	return result
}

func (a *Analyzer) queryCDS(ctx context.Context, domain string) []*dns.CDS {
	msg := dns.NewMsg(dnsutil.Fqdn(domain), dns.TypeCDS)
	msg.RecursionDesired = true

	resp, err := a.DNS.ExchangeContext(ctx, msg)
	if err != nil || resp == nil {
		return nil
	}

	var records []*dns.CDS
	for _, rr := range resp.Answer {
		if cds, ok := rr.(*dns.CDS); ok {
			records = append(records, cds)
		}
	}
	return records
}

func (a *Analyzer) queryCDNSKEY(ctx context.Context, domain string) []*dns.CDNSKEY {
	msg := dns.NewMsg(dnsutil.Fqdn(domain), dns.TypeCDNSKEY)
	msg.RecursionDesired = true

	resp, err := a.DNS.ExchangeContext(ctx, msg)
	if err != nil || resp == nil {
		return nil
	}

	var records []*dns.CDNSKEY
	for _, rr := range resp.Answer {
		if key, ok := rr.(*dns.CDNSKEY); ok {
			records = append(records, key)
		}
	}
	return records
}

func parseCDSRecords(records []*dns.CDS) []map[string]any {
	var parsed []map[string]any
	for _, r := range records {
		entry := map[string]any{
			"key_tag":     r.KeyTag,
			"algorithm":   dns.AlgorithmToString[r.Algorithm],
			"digest_type": r.DigestType,
			"raw":         r.String(),
		}
		if r.KeyTag == 0 && r.Algorithm == 0 && r.DigestType == 0 {
			entry["delete_signal"] = true
		}
		parsed = append(parsed, entry)
	}
	return parsed
}

func parseCDNSKEYRecords(records []*dns.CDNSKEY) []map[string]any {
	var parsed []map[string]any
	for _, r := range records {
		entry := map[string]any{
			"flags":     r.Flags,
			"protocol":  r.Protocol,
			"algorithm": dns.AlgorithmToString[r.Algorithm],
			"raw":       r.String(),
		}
		if r.Flags == 0 && r.Protocol == 3 && r.Algorithm == 0 {
			entry["delete_signal"] = true
		}
		parsed = append(parsed, entry)
	}
	return parsed
}

func classifyCDSAutomation(cds []*dns.CDS, cdnskey []*dns.CDNSKEY) string {
	if len(cds) == 0 && len(cdnskey) == 0 {
		return "none"
	}

	for _, r := range cds {
		if r.KeyTag == 0 && r.Algorithm == 0 && r.DigestType == 0 {
			return mapKeyDeleteSignaled
		}
	}
	for _, r := range cdnskey {
		if r.Flags == 0 && r.Protocol == 3 && r.Algorithm == 0 {
			return mapKeyDeleteSignaled
		}
	}

	if len(cds) > 0 && len(cdnskey) > 0 {
		return "full_automation"
	}
	if len(cds) > 0 {
		return "cds_only"
	}
	return "cdnskey_only"
}

func buildCDSMessage(result map[string]any) string {
	automation, _ := result[mapKeyAutomation].(string)
	parts := []string{}

	switch automation {
	case "full_automation":
		parts = append(parts, "Full RFC 8078 automated DNSSEC key rollover signaling detected (CDS + CDNSKEY)")
	case "cds_only":
		parts = append(parts, "CDS records present for automated DS updates")
	case "cdnskey_only":
		parts = append(parts, "CDNSKEY records present for automated key rollover")
	case mapKeyDeleteSignaled:
		parts = append(parts, "DNSSEC deletion signaled via CDS/CDNSKEY (RFC 8078 §4)")
	}

	return fmt.Sprintf("%s", strings.Join(parts, ", "))
}
