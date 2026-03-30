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
	mapKeyHasOpenpgpkey = "has_openpgpkey"
	mapKeyHasSmimea     = "has_smimea"
)

func (a *Analyzer) AnalyzeSMIMEA(ctx context.Context, domain string) map[string]any {
	result := map[string]any{
		"status":             "success",
		mapKeyHasSmimea:      false,
		mapKeyHasOpenpgpkey:  false,
		"smimea_records":     []map[string]any{},
		"openpgpkey_records": []map[string]any{},
		"issues":             []string{},
	}

	smimeaRecords := a.querySMIMEA(ctx, domain)
	openpgpRecords := a.queryOPENPGPKEY(ctx, domain)

	if len(smimeaRecords) > 0 {
		result[mapKeyHasSmimea] = true
		result["smimea_records"] = parseSMIMEARecords(smimeaRecords)
	}

	if len(openpgpRecords) > 0 {
		result[mapKeyHasOpenpgpkey] = true
		result["openpgpkey_records"] = parseOPENPGPKEYRecords(openpgpRecords)
	}

	if !result[mapKeyHasSmimea].(bool) && !result[mapKeyHasOpenpgpkey].(bool) {
		result["status"] = "info"
		result["message"] = "No SMIMEA or OPENPGPKEY records found — email encryption keys not published via DNS"
	} else {
		result["message"] = buildEmailEncryptionMessage(result)
	}

	return result
}

func (a *Analyzer) querySMIMEA(ctx context.Context, domain string) []*dns.SMIMEA {
	queryName := fmt.Sprintf("*._smimecert.%s", domain)
	msg := dns.NewMsg(dnsutil.Fqdn(queryName), dns.TypeSMIMEA)
	msg.RecursionDesired = true

	resp, err := a.DNS.ExchangeContext(ctx, msg)
	if err != nil || resp == nil {
		return nil
	}

	var records []*dns.SMIMEA
	for _, rr := range resp.Answer {
		if s, ok := rr.(*dns.SMIMEA); ok {
			records = append(records, s)
		}
	}
	return records
}

func (a *Analyzer) queryOPENPGPKEY(ctx context.Context, domain string) []*dns.OPENPGPKEY {
	queryName := fmt.Sprintf("*._openpgpkey.%s", domain)
	msg := dns.NewMsg(dnsutil.Fqdn(queryName), dns.TypeOPENPGPKEY)
	msg.RecursionDesired = true

	resp, err := a.DNS.ExchangeContext(ctx, msg)
	if err != nil || resp == nil {
		return nil
	}

	var records []*dns.OPENPGPKEY
	for _, rr := range resp.Answer {
		if o, ok := rr.(*dns.OPENPGPKEY); ok {
			records = append(records, o)
		}
	}
	return records
}

func parseSMIMEARecords(records []*dns.SMIMEA) []map[string]any {
	var parsed []map[string]any
	for _, r := range records {
		parsed = append(parsed, map[string]any{
			"usage":         r.Usage,
			"selector":      r.Selector,
			"matching_type": r.MatchingType,
			"raw":           r.String(),
			"confidence":    ConfidenceObservedMap(MethodDNSRecord),
		})
	}
	return parsed
}

func parseOPENPGPKEYRecords(records []*dns.OPENPGPKEY) []map[string]any {
	var parsed []map[string]any
	for _, r := range records {
		parsed = append(parsed, map[string]any{
			"key_length": len(r.PublicKey),
			"raw":        truncateRecord(r.String(), 120),
			"confidence": ConfidenceObservedMap(MethodDNSRecord),
		})
	}
	return parsed
}

func buildEmailEncryptionMessage(result map[string]any) string {
	var parts []string
	if result[mapKeyHasSmimea].(bool) {
		parts = append(parts, "S/MIME certificates published via SMIMEA (RFC 8162)")
	}
	if result[mapKeyHasOpenpgpkey].(bool) {
		parts = append(parts, "OpenPGP keys published via OPENPGPKEY (RFC 7929)")
	}
	return fmt.Sprintf("%s", strings.Join(parts, "; "))
}
