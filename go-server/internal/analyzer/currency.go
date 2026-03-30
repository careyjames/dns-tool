// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"fmt"
	"math"
)

const (
	rtMTASTS = "MTA-STS"
	rtTLSRPT = "TLS-RPT"
	rtAAAA   = "AAAA"
	rtDKIM   = "DKIM"
	rtBIMI   = "BIMI"
	rtTLSA   = "TLSA"
	rtDANE   = "DANE"
	rtCAA    = "CAA"
	rtSOA    = "SOA"
	rtSPF    = "SPF"
)

type CurrencyEntry struct {
	RecordType      string `json:"record_type"`
	ObservedTTL     uint32 `json:"observed_ttl_seconds"`
	TypicalTTL      uint32 `json:"typical_ttl_seconds"`
	RescanAfter     uint32 `json:"rescan_after_seconds"`
	RescanLabel     string `json:"rescan_label"`
	PropagationNote string `json:"propagation_note"`
}

var typicalTTLs = map[string]uint32{
	"A":        300,
	rtAAAA:     300,
	"MX":       3600,
	dnsTypeTXT: 3600,
	"NS":       86400,
	strCname:   300,
	rtCAA:      3600,
	rtSOA:      3600,
	rtSPF:      3600,
	strDmarc:   3600,
	rtDKIM:     3600,
	rtMTASTS:   86400,
	rtTLSRPT:   3600,
	rtBIMI:     3600,
	rtTLSA:     3600,
	strDnssec:  86400,
	rtDANE:     3600,
}

var propagationNotes = map[string]string{
	"A":        "A records typically propagate within 5 minutes. Some resolvers may cache up to the TTL value.",
	rtAAAA:     "AAAA records follow the same propagation pattern as A records.",
	"MX":       "MX record changes may take up to 1 hour to propagate. Mail delivery may be affected during transition.",
	dnsTypeTXT: "TXT records (including SPF) typically propagate within 1 hour. Verify with multiple resolvers.",
	"NS":       "Nameserver changes can take 24\u201348 hours for full global propagation due to parent zone TTLs.",
	strCname:   "CNAME changes propagate quickly but downstream records inherit the CNAME TTL.",
	rtCAA:      "CAA record changes take effect within TTL. Certificate authorities check at issuance time.",
	rtSOA:      "SOA changes propagate to secondaries based on the Refresh interval in the SOA record.",
	rtSPF:      "SPF record changes propagate within the TXT record TTL. Test with dig before relying on scan results.",
	strDmarc:   "DMARC policy changes at _dmarc subdomain propagate within TTL. Reporting changes take 24\u201348h to reflect in aggregate reports.",
	rtDKIM:     "DKIM selector records propagate within TTL. New selectors are available immediately once published; key rotation requires overlap period.",
	rtMTASTS:   "MTA-STS policy changes require updating both the DNS TXT record AND the policy file at /.well-known/mta-sts.txt. The max_age directive in the policy controls how long senders cache it.",
	rtTLSRPT:   "TLS-RPT changes propagate within TTL. Report delivery changes take effect in the next reporting period (typically 24 hours).",
	rtBIMI:     "BIMI record changes propagate within TTL. VMC certificate validation by mail providers may take additional time.",
	rtTLSA:     "TLSA/DANE records must be published BEFORE rotating TLS certificates. Premature certificate rotation breaks DANE validation.",
	strDnssec:  "DNSSEC signing changes (DS record updates at registrar) can take 24\u201348 hours. Key rollovers require careful timing per RFC 7583.",
	rtDANE:     "DANE/TLSA record updates follow the TLSA TTL. Coordinate with TLS certificate lifecycle.",
}

const (
	currencyFloorSeconds   = 30
	currencyCeilingSeconds = 86400

	strCname  = "CNAME"
	strDmarc  = "DMARC"
	strDnssec = "DNSSEC"
)

func BuildCurrencyMatrix(resolverTTL, authTTL map[string]uint32) map[string]any {
	entries := []CurrencyEntry{}

	allTypes := []string{"A", rtAAAA, "MX", dnsTypeTXT, "NS", strCname, rtCAA, rtSOA}

	protocolTypes := []string{rtSPF, strDmarc, rtDKIM, rtMTASTS, rtTLSRPT, rtBIMI, rtTLSA, strDnssec, rtDANE}
	allTypes = append(allTypes, protocolTypes...)

	for _, rt := range allTypes {
		entry := CurrencyEntry{
			RecordType: rt,
			TypicalTTL: typicalTTLs[rt],
		}

		if ttl, ok := resolverTTL[rt]; ok {
			entry.ObservedTTL = ttl
		} else if ttl, ok := authTTL[rt]; ok {
			entry.ObservedTTL = ttl
		}

		entry.RescanAfter = computeRescanInterval(entry.ObservedTTL, entry.TypicalTTL)
		entry.RescanLabel = formatRescanLabel(entry.RescanAfter)

		if note, ok := propagationNotes[rt]; ok {
			entry.PropagationNote = note
		}

		entries = append(entries, entry)
	}

	matrix := map[string]any{
		"entries":     entries,
		"entry_count": len(entries),
		"min_rescan":  currencyFloorSeconds,
		"max_rescan":  currencyCeilingSeconds,
		"guidance":    "Re-scan times are based on observed TTL values from authoritative and resolver responses. After making DNS changes, wait at least the recommended interval before re-scanning for updated results.",
	}

	return matrix
}

func computeRescanInterval(observed, typical uint32) uint32 {
	ttl := observed
	if ttl == 0 {
		ttl = typical
	}
	if ttl == 0 {
		ttl = 300
	}

	rescan := uint32(math.Ceil(float64(ttl) * 1.1))

	if rescan < currencyFloorSeconds {
		rescan = currencyFloorSeconds
	}
	if rescan > currencyCeilingSeconds {
		rescan = currencyCeilingSeconds
	}

	return rescan
}

func formatRescanLabel(seconds uint32) string {
	if seconds < 60 {
		return fmt.Sprintf("%d seconds", seconds)
	}
	if seconds < 3600 {
		mins := seconds / 60
		if mins == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", mins)
	}
	if seconds < 86400 {
		hours := seconds / 3600
		if hours == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", hours)
	}
	return "24 hours"
}
