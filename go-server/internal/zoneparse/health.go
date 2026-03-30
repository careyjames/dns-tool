// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package zoneparse

import (
        "fmt"
        "sort"
        "strconv"
        "strings"
)

type ZoneHealth struct {
        TypeDistribution []TypeCount `json:"type_distribution"`
        UniqueHostnames  int         `json:"unique_hostnames"`
        TotalRecords     int         `json:"total_records"`

        ZoneProfile     string `json:"zone_profile"`
        ZoneProfileDesc string `json:"zone_profile_desc"`

        HasSOA    bool `json:"has_soa"`
        HasNS     bool `json:"has_ns"`
        HasMX     bool `json:"has_mx"`
        HasA      bool `json:"has_a"`
        HasAAAA   bool `json:"has_aaaa"`
        HasSPF    bool `json:"has_spf"`
        HasDMARC  bool `json:"has_dmarc"`
        HasDKIM   bool `json:"has_dkim"`
        HasCAA    bool `json:"has_caa"`
        HasTLSA   bool `json:"has_tlsa"`
        HasDNSSEC bool `json:"has_dnssec"`

        PolicySignals []PolicySignal `json:"policy_signals,omitempty"`

        StructuralScore   int               `json:"structural_score"`
        StructuralVerdict string            `json:"structural_verdict"`
        StructuralChecks  []StructuralCheck `json:"structural_checks"`

        NSTargets   []string `json:"ns_targets"`
        NSCount     int      `json:"ns_count"`
        HasIPv6Glue bool     `json:"has_ipv6_glue"`

        MinTTL        uint32    `json:"min_ttl"`
        MaxTTL        uint32    `json:"max_ttl"`
        MedianTTL     uint32    `json:"median_ttl"`
        TTLByType     []TypeTTL `json:"ttl_by_type"`
        TTLSpreadHigh bool      `json:"ttl_spread_high"`

        DNSKEYCount     int `json:"dnskey_count"`
        RRSIGCount      int `json:"rrsig_count"`
        DSCount         int `json:"ds_count"`
        NSECCount       int `json:"nsec_count"`
        NSEC3Count      int `json:"nsec3_count"`
        NSEC3ParamCount int `json:"nsec3param_count"`

        SOATimers  *SOATimerAnalysis `json:"soa_timers,omitempty"`
        Duplicates []DuplicateRRset  `json:"duplicates,omitempty"`

        RecordsByType map[string][]ParsedRecord `json:"-"`
}

type PolicySignal struct {
        Label  string `json:"label"`
        Icon   string `json:"icon"`
        Detail string `json:"detail"`
        Status string `json:"status"`
}

type StructuralCheck struct {
        Label    string `json:"label"`
        RFC      string `json:"rfc"`
        Pass     bool   `json:"pass"`
        Severity string `json:"severity"`
        Detail   string `json:"detail"`
}

type SOATimerAnalysis struct {
        Serial   uint32       `json:"serial"`
        Refresh  uint32       `json:"refresh"`
        Retry    uint32       `json:"retry"`
        Expire   uint32       `json:"expire"`
        Minimum  uint32       `json:"minimum"`
        MName    string       `json:"mname"`
        RName    string       `json:"rname"`
        Findings []SOAFinding `json:"findings,omitempty"`
}

type SOAFinding struct {
        Field    string `json:"field"`
        Severity string `json:"severity"`
        Message  string `json:"message"`
}

type DuplicateRRset struct {
        Name  string `json:"name"`
        Type  string `json:"type"`
        Count int    `json:"count"`
        RData string `json:"rdata"`
}

type TypeCount struct {
        Type    string  `json:"type"`
        Count   int     `json:"count"`
        Percent float64 `json:"percent"`
}

type TypeTTL struct {
        Type    string `json:"type"`
        MinTTL  uint32 `json:"min_ttl"`
        MaxTTL  uint32 `json:"max_ttl"`
        Count   int    `json:"count"`
        Uniform bool   `json:"uniform"`
}

const (
        sevCritical = "critical"
        sevWarning  = "warning"
        sevInfo     = "info"

        sigDetected = "detected"
        sigMissing  = "missing"

        profileDelegationOnly = "Delegation-Only"
        profileMinimal        = "Minimal"

        fieldRetry  = "retry"
        fieldExpire = "expire"
)

func AnalyzeHealth(records []ParsedRecord) *ZoneHealth {
        h := &ZoneHealth{
                TypeDistribution: []TypeCount{},
                NSTargets:        []string{},
                TTLByType:        []TypeTTL{},
                RecordsByType:    make(map[string][]ParsedRecord),
        }

        if len(records) == 0 {
                return h
        }

        h.TotalRecords = len(records)

        apex := ""
        for _, r := range records {
                if r.Type == "SOA" {
                        apex = strings.ToLower(r.Name)
                        break
                }
        }

        typeCounts := make(map[string]int)
        hostnames := make(map[string]struct{})
        nsTargets := make(map[string]struct{})
        var allTTLs []uint32
        typeTTLs := make(map[string][]uint32)

        for _, r := range records {
                typeCounts[r.Type]++
                hostnames[r.Name] = struct{}{}
                allTTLs = append(allTTLs, r.TTL)
                typeTTLs[r.Type] = append(typeTTLs[r.Type], r.TTL)
                h.RecordsByType[r.Type] = append(h.RecordsByType[r.Type], r)
                h.classifyRecord(r, apex, nsTargets)
        }

        h.UniqueHostnames = len(hostnames)

        for ns := range nsTargets {
                h.NSTargets = append(h.NSTargets, ns)
        }
        sort.Strings(h.NSTargets)
        h.NSCount = len(h.NSTargets)

        h.HasIPv6Glue = hasIPv6Glue(records, nsTargets)

        for rtype, count := range typeCounts {
                pct := float64(count) / float64(h.TotalRecords) * 100
                h.TypeDistribution = append(h.TypeDistribution, TypeCount{
                        Type:    rtype,
                        Count:   count,
                        Percent: pct,
                })
        }
        sort.Slice(h.TypeDistribution, func(i, j int) bool {
                return h.TypeDistribution[i].Count > h.TypeDistribution[j].Count
        })

        computeTTLStats(h, allTTLs, typeTTLs)

        h.SOATimers = analyzeSOA(records)
        h.Duplicates = findDuplicates(records)
        h.ZoneProfile, h.ZoneProfileDesc = classifyZoneProfile(h)
        h.PolicySignals = buildPolicySignals(h)
        h.StructuralChecks = runStructuralChecks(h)
        h.StructuralScore, h.StructuralVerdict = computeStructuralScore(h.StructuralChecks)

        return h
}

func computeTTLStats(h *ZoneHealth, allTTLs []uint32, typeTTLs map[string][]uint32) {
        sort.Slice(allTTLs, func(i, j int) bool { return allTTLs[i] < allTTLs[j] })
        h.MinTTL = allTTLs[0]
        h.MaxTTL = allTTLs[len(allTTLs)-1]
        h.MedianTTL = allTTLs[len(allTTLs)/2]

        if h.MinTTL > 0 && h.MaxTTL > 0 {
                h.TTLSpreadHigh = h.MaxTTL/h.MinTTL > 100
        } else if h.MinTTL == 0 && h.MaxTTL > 3600 {
                h.TTLSpreadHigh = true
        }

        typeOrder := make([]string, 0, len(typeTTLs))
        for t := range typeTTLs {
                typeOrder = append(typeOrder, t)
        }
        sort.Strings(typeOrder)

        for _, rtype := range typeOrder {
                ttls := typeTTLs[rtype]
                sort.Slice(ttls, func(i, j int) bool { return ttls[i] < ttls[j] })
                uniform := ttls[0] == ttls[len(ttls)-1]
                h.TTLByType = append(h.TTLByType, TypeTTL{
                        Type:    rtype,
                        MinTTL:  ttls[0],
                        MaxTTL:  ttls[len(ttls)-1],
                        Count:   len(ttls),
                        Uniform: uniform,
                })
        }
}

func hasIPv6Glue(records []ParsedRecord, nsTargets map[string]struct{}) bool {
        for _, r := range records {
                if r.Type != "AAAA" {
                        continue
                }
                name := strings.TrimSuffix(strings.ToLower(r.Name), ".")
                if _, ok := nsTargets[name]; ok {
                        return true
                }
        }
        return false
}

func (h *ZoneHealth) classifyRecord(r ParsedRecord, apex string, nsTargets map[string]struct{}) {
        switch r.Type {
        case "SOA":
                h.HasSOA = true
        case "NS":
                if apex == "" || strings.ToLower(r.Name) == apex {
                        h.HasNS = true
                }
                nsTargets[strings.TrimSuffix(strings.ToLower(r.RData), ".")] = struct{}{}
        case "MX":
                h.HasMX = true
        case "A":
                h.HasA = true
        case "AAAA":
                h.HasAAAA = true
        case "CAA":
                h.HasCAA = true
        case "TLSA":
                h.HasTLSA = true
        case "DNSKEY":
                h.HasDNSSEC = true
                h.DNSKEYCount++
        case "RRSIG":
                h.HasDNSSEC = true
                h.RRSIGCount++
        case "DS":
                h.HasDNSSEC = true
                h.DSCount++
        case "NSEC":
                h.HasDNSSEC = true
                h.NSECCount++
        case "NSEC3":
                h.HasDNSSEC = true
                h.NSEC3Count++
        case "NSEC3PARAM":
                h.HasDNSSEC = true
                h.NSEC3ParamCount++
        case "TXT":
                h.classifyTXT(r)
        }
}

func (h *ZoneHealth) classifyTXT(r ParsedRecord) {
        rdata := strings.ToLower(r.RData)
        if strings.Contains(rdata, "v=spf1") {
                h.HasSPF = true
        }
        if strings.HasPrefix(r.Name, "_dmarc.") {
                h.HasDMARC = true
        }
        if strings.Contains(r.Name, "._domainkey.") {
                h.HasDKIM = true
        }
}

func classifyZoneProfile(h *ZoneHealth) (string, string) {
        hasDelegations := h.DSCount > 0
        hasAddresses := h.HasA || h.HasAAAA
        hasEmail := h.HasMX || h.HasSPF || h.HasDMARC || h.HasDKIM

        if hasDelegations && !hasAddresses && !hasEmail {
                return profileDelegationOnly, "This zone contains only delegation records (SOA, NS, DS). Typical of TLD/registry zones or parent zones that delegate to child zones."
        }

        if h.HasNS && !hasAddresses && !hasEmail && !hasDelegations {
                return profileDelegationOnly, "This zone contains structural records (SOA, NS) without address or email records. Typical of delegation-only zones."
        }

        if hasAddresses && hasEmail {
                return "Full-Service", "This zone serves address records and email infrastructure. Typical of a standard domain zone."
        }

        if hasAddresses && !hasEmail {
                return "Web-Only", "This zone contains address records but no email infrastructure. Email may be managed by an external provider."
        }

        if !hasAddresses && hasEmail {
                return "Email-Only", "This zone contains email records but no address records. Web hosting may use a CNAME or external service."
        }

        return profileMinimal, "This zone contains limited record types."
}

func buildPolicySignals(h *ZoneHealth) []PolicySignal {
        var signals []PolicySignal

        isDelegation := h.ZoneProfile == profileDelegationOnly
        emailIntent := h.HasMX || h.HasSPF || h.HasDMARC || h.HasDKIM
        webIntent := h.HasA || h.HasAAAA

        if h.HasMX {
                signals = append(signals, PolicySignal{
                        Label:  "MX",
                        Icon:   "mail-bulk",
                        Detail: "Mail exchange records present",
                        Status: sigDetected,
                })
        }

        if h.HasSPF {
                signals = append(signals, PolicySignal{
                        Label:  "SPF",
                        Icon:   "envelope",
                        Detail: "Sender Policy Framework record detected",
                        Status: sigDetected,
                })
        } else if !isDelegation {
                signals = append(signals, PolicySignal{
                        Label:  "SPF",
                        Icon:   "envelope",
                        Detail: "No SPF record — any server can claim to send email as this domain (RFC 7208)",
                        Status: sigMissing,
                })
        }

        if h.HasDMARC {
                signals = append(signals, PolicySignal{
                        Label:  "DMARC",
                        Icon:   "shield-alt",
                        Detail: "Domain-based Message Authentication policy detected",
                        Status: sigDetected,
                })
        } else if !isDelegation {
                signals = append(signals, PolicySignal{
                        Label:  "DMARC",
                        Icon:   "shield-alt",
                        Detail: "No DMARC policy — receiving servers have no spoofing policy to enforce (RFC 7489)",
                        Status: sigMissing,
                })
        }

        if h.HasDKIM {
                signals = append(signals, PolicySignal{
                        Label:  "DKIM",
                        Icon:   "key",
                        Detail: "DomainKeys Identified Mail selector detected",
                        Status: sigDetected,
                })
        } else if emailIntent && !isDelegation {
                signals = append(signals, PolicySignal{
                        Label:  "DKIM",
                        Icon:   "key",
                        Detail: "No DKIM selector found in zone file — may be managed by email provider",
                        Status: sevInfo,
                })
        }

        if h.HasCAA {
                signals = append(signals, PolicySignal{
                        Label:  "CAA",
                        Icon:   "certificate",
                        Detail: "Certificate Authority Authorization records present",
                        Status: sigDetected,
                })
        } else if webIntent && !isDelegation {
                signals = append(signals, PolicySignal{
                        Label:  "CAA",
                        Icon:   "certificate",
                        Detail: "Web presence detected without CAA records restricting certificate issuance",
                        Status: sevInfo,
                })
        }

        if h.HasTLSA {
                signals = append(signals, PolicySignal{
                        Label:  "TLSA/DANE",
                        Icon:   "lock",
                        Detail: "DNS-Based Authentication of Named Entities records present",
                        Status: sigDetected,
                })
        }

        return signals
}

func runStructuralChecks(h *ZoneHealth) []StructuralCheck {
        var checks []StructuralCheck

        checks = append(checks, StructuralCheck{
                Label:    "SOA record present",
                RFC:      "RFC 1035 \u00a75.2.1",
                Pass:     h.HasSOA,
                Severity: sevCritical,
                Detail:   condStr(h.HasSOA, "Zone has a Start of Authority record", "Every zone MUST have exactly one SOA record at the apex"),
        })

        checks = append(checks, StructuralCheck{
                Label:    "NS records at apex",
                RFC:      "RFC 1035 \u00a75.2.1",
                Pass:     h.HasNS,
                Severity: sevCritical,
                Detail:   condStr(h.HasNS, fmt.Sprintf("%d nameserver(s) defined", h.NSCount), "Zone MUST have at least one NS record at the apex"),
        })

        nsRedundant := h.NSCount >= 2
        checks = append(checks, StructuralCheck{
                Label:    "NS redundancy (\u22652 nameservers)",
                RFC:      "RFC 2182 \u00a74",
                Pass:     nsRedundant,
                Severity: sevWarning,
                Detail:   condStr(nsRedundant, fmt.Sprintf("%d nameservers provide redundancy", h.NSCount), "RFC 2182 recommends at least 2 nameservers for resilience"),
        })

        hasAddr := h.HasA || h.HasAAAA
        checks = append(checks, StructuralCheck{
                Label:    "Address records (A/AAAA)",
                RFC:      "RFC 1035 \u00a73.2.1",
                Pass:     hasAddr,
                Severity: sevInfo,
                Detail:   condStr(hasAddr, "Zone contains address records for resolution", "No A or AAAA records found \u2014 zone may be delegation-only"),
        })

        soaOK := h.SOATimers != nil && len(h.SOATimers.Findings) == 0
        soaDetail := "No SOA record to evaluate"
        soaSeverity := sevInfo
        if h.SOATimers != nil {
                if soaOK {
                        soaDetail = "SOA timers within recommended ranges"
                } else {
                        soaDetail = fmt.Sprintf("%d timer finding(s)", len(h.SOATimers.Findings))
                        soaSeverity = sevWarning
                }
        }
        checks = append(checks, StructuralCheck{
                Label:    "SOA timers RFC-compliant",
                RFC:      "RFC 1912 \u00a72.2",
                Pass:     soaOK,
                Severity: soaSeverity,
                Detail:   soaDetail,
        })

        ttlConsistent := !h.TTLSpreadHigh
        checks = append(checks, StructuralCheck{
                Label:    "TTL consistency",
                RFC:      "RFC 2308 \u00a74",
                Pass:     ttlConsistent,
                Severity: sevWarning,
                Detail:   condStr(ttlConsistent, fmt.Sprintf("TTL spread %ds\u2013%ds is reasonable", h.MinTTL, h.MaxTTL), fmt.Sprintf("TTL spread %ds\u2013%ds exceeds 100\u00d7 ratio \u2014 review for coherence", h.MinTTL, h.MaxTTL)),
        })

        noDups := len(h.Duplicates) == 0
        checks = append(checks, StructuralCheck{
                Label:    "No duplicate RRsets",
                RFC:      "RFC 2181 \u00a75.2",
                Pass:     noDups,
                Severity: sevWarning,
                Detail:   condStr(noDups, "No exact duplicate records detected", fmt.Sprintf("%d duplicate RRset(s) found", len(h.Duplicates))),
        })

        return checks
}

func computeStructuralScore(checks []StructuralCheck) (int, string) {
        score := 0
        total := 0
        for _, c := range checks {
                w := checkWeight(c.Severity)
                total += w
                if c.Pass {
                        score += w
                }
        }
        if total == 0 {
                return 0, profileMinimal
        }

        pct := score * 100 / total
        verdict := profileMinimal
        switch {
        case pct >= 90:
                verdict = "Well-Formed"
        case pct >= 70:
                verdict = "Adequate"
        case pct >= 50:
                verdict = "Needs Attention"
        case pct >= 30:
                verdict = "Deficient"
        }
        return pct, verdict
}

func checkWeight(severity string) int {
        switch severity {
        case sevCritical:
                return 25
        case sevWarning:
                return 15
        case sevInfo:
                return 10
        }
        return 5
}

func analyzeSOA(records []ParsedRecord) *SOATimerAnalysis {
        for _, r := range records {
                if r.Type != "SOA" {
                        continue
                }
                fields := strings.Fields(r.RData)
                if len(fields) < 7 {
                        return nil
                }

                serial, _ := strconv.ParseUint(fields[2], 10, 32)
                refresh, _ := strconv.ParseUint(fields[3], 10, 32)
                retry, _ := strconv.ParseUint(fields[4], 10, 32)
                expire, _ := strconv.ParseUint(fields[5], 10, 32)
                minimum, _ := strconv.ParseUint(fields[6], 10, 32)

                soa := &SOATimerAnalysis{
                        MName:   fields[0],
                        RName:   fields[1],
                        Serial:  uint32(serial),
                        Refresh: uint32(refresh),
                        Retry:   uint32(retry),
                        Expire:  uint32(expire),
                        Minimum: uint32(minimum),
                }

                soa.Findings = collectSOAFindings(soa)

                return soa
        }
        return nil
}

func collectSOAFindings(soa *SOATimerAnalysis) []SOAFinding {
        var findings []SOAFinding

        if soa.Refresh < 1200 {
                findings = append(findings, SOAFinding{
                        Field:    "refresh",
                        Severity: sevWarning,
                        Message:  fmt.Sprintf("Refresh %ds is below RFC 1912 recommendation of 1200–43200s", soa.Refresh),
                })
        }
        if soa.Retry < 120 {
                findings = append(findings, SOAFinding{
                        Field:    fieldRetry,
                        Severity: sevWarning,
                        Message:  fmt.Sprintf("Retry %ds is below RFC 1912 recommendation of 120–10800s", soa.Retry),
                })
        }
        if soa.Retry >= soa.Refresh {
                findings = append(findings, SOAFinding{
                        Field:    fieldRetry,
                        Severity: sevWarning,
                        Message:  "Retry should be less than Refresh (RFC 1912 §2.2)",
                })
        }
        if soa.Expire < 1209600 {
                findings = append(findings, SOAFinding{
                        Field:    fieldExpire,
                        Severity: sevInfo,
                        Message:  fmt.Sprintf("Expire %ds is below RFC 1912 recommendation of 2–4 weeks (%d–%d)", soa.Expire, 1209600, 2419200),
                })
        }
        if soa.Minimum > 86400 {
                findings = append(findings, SOAFinding{
                        Field:    "minimum",
                        Severity: sevInfo,
                        Message:  fmt.Sprintf("Negative cache TTL %ds exceeds 1 day; RFC 2308 §5 recommends 1–3 hours for most zones", soa.Minimum),
                })
        }
        if soa.Expire <= soa.Refresh {
                findings = append(findings, SOAFinding{
                        Field:    fieldExpire,
                        Severity: sevWarning,
                        Message:  "Expire must be greater than Refresh (RFC 1912 §2.2)",
                })
        }
        if soa.Serial == 0 {
                findings = append(findings, SOAFinding{
                        Field:    "serial",
                        Severity: sevInfo,
                        Message:  "Serial is 0 — consider using YYYYMMDDNN format for meaningful versioning",
                })
        }
        return findings
}

func findDuplicates(records []ParsedRecord) []DuplicateRRset {
        type rrKey struct {
                name  string
                rtype string
                rdata string
        }
        seen := make(map[rrKey]int)
        for _, r := range records {
                k := rrKey{
                        name:  strings.ToLower(r.Name),
                        rtype: r.Type,
                        rdata: strings.TrimSpace(strings.ToLower(r.RData)),
                }
                seen[k]++
        }

        var dups []DuplicateRRset
        for k, count := range seen {
                if count > 1 {
                        dups = append(dups, DuplicateRRset{
                                Name:  k.name,
                                Type:  k.rtype,
                                Count: count,
                                RData: k.rdata,
                        })
                }
        }
        sort.Slice(dups, func(i, j int) bool {
                if dups[i].Name != dups[j].Name {
                        return dups[i].Name < dups[j].Name
                }
                return dups[i].Type < dups[j].Type
        })
        return dups
}

func condStr(cond bool, ifTrue, ifFalse string) string {
        if cond {
                return ifTrue
        }
        return ifFalse
}
