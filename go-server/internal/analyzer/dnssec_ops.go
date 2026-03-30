// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "fmt"
        "net"
        "strings"
        "time"

        "codeberg.org/miekg/dns"
        "codeberg.org/miekg/dns/dnsutil"
)

const (
        mapKeyPartial    = "partial"
        mapKeyFlags      = "flags"
        mapKeyHasCDS     = "has_cds"
        mapKeyHasCDNSKEY = "has_cdnskey"
        mapKeyKeyTag     = "key_tag"
        mapKeyRaw        = "raw"
        mapKeyComplete   = "complete"

        keyRoleKSK = "KSK"
        keyRoleZSK = "ZSK"
)

type DNSSECKeyInfo struct {
        Flags     uint16 `json:"flags"`
        Protocol  uint8  `json:"protocol"`
        Algorithm uint8  `json:"algorithm"`
        KeyTag    uint16 `json:"key_tag"`
        KeyRole   string `json:"key_role"`
        AlgName   string `json:"algorithm_name"`
        KeySize   int    `json:"key_size"`
        Raw       string `json:"raw"`
}

type RRSIGInfo struct {
        TypeCovered  string        `json:"type_covered"`
        Algorithm    uint8         `json:"algorithm"`
        Labels       uint8         `json:"labels"`
        OriginalTTL  uint32        `json:"original_ttl"`
        Expiration   time.Time     `json:"expiration"`
        Inception    time.Time     `json:"inception"`
        KeyTag       uint16        `json:"key_tag"`
        SignerName   string        `json:"signer_name"`
        TimeToExpiry time.Duration `json:"time_to_expiry"`
        ExpiringSoon bool          `json:"expiring_soon"`
        Expired      bool          `json:"expired"`
        Raw          string        `json:"raw"`
}

type NSEC3Params struct {
        HashAlgorithm  uint8  `json:"hash_algorithm"`
        Flags          uint8  `json:"flags"`
        Iterations     uint16 `json:"iterations"`
        SaltLength     int    `json:"salt_length"`
        Salt           string `json:"salt"`
        HighIterations bool   `json:"high_iterations"`
}

type DenialOfExistence struct {
        Method      string       `json:"method"`
        NSEC3Params *NSEC3Params `json:"nsec3_params,omitempty"`
        Issues      []string     `json:"issues"`
}

type RolloverReadiness struct {
        MultipleKSKs    bool     `json:"multiple_ksks"`
        KSKCount        int      `json:"ksk_count"`
        ZSKCount        int      `json:"zsk_count"`
        HasCDS          bool     `json:"has_cds"`
        HasCDNSKEY      bool     `json:"has_cdnskey"`
        AutomationLevel string   `json:"automation_level"`
        ReadinessLevel  string   `json:"readiness_level"`
        Issues          []string `json:"issues"`
}

type DNSSECOpsResult struct {
        Status            string            `json:"status"`
        Message           string            `json:"message"`
        Keys              []DNSSECKeyInfo   `json:"keys"`
        Signatures        []RRSIGInfo       `json:"signatures"`
        DenialOfExistence DenialOfExistence `json:"denial_of_existence"`
        RolloverReadiness RolloverReadiness `json:"rollover_readiness"`
        Issues            []string          `json:"issues"`
}

func classifyKeyRole(flags uint16) string {
        if flags == 257 {
                return keyRoleKSK
        }
        if flags == 256 {
                return keyRoleZSK
        }
        if flags&1 != 0 {
                return "KSK-like"
        }
        return "unknown"
}

func estimateKeySize(algorithm uint8, publicKey string) int {
        keyBytes := len(publicKey) * 3 / 4
        switch algorithm {
        case 13:
                return 256
        case 14:
                return 384
        case 15:
                return 256
        case 16:
                return 456
        case 5, 7, 8, 10:
                return keyBytes * 8
        default:
                return keyBytes * 8
        }
}

func dnssecAlgorithmName(alg uint8) string {
        if name, ok := algorithmNames[int(alg)]; ok {
                return name
        }
        return fmt.Sprintf("Algorithm %d", alg)
}

func uint32ToTime(ts uint32) time.Time {
        return time.Unix(int64(ts), 0).UTC()
}

func parseDNSSECKeys(records []*dns.DNSKEY) []DNSSECKeyInfo {
        var keys []DNSSECKeyInfo
        for _, rr := range records {
                kt := rr.KeyTag()
                info := DNSSECKeyInfo{
                        Flags:     rr.Flags,
                        Protocol:  rr.Protocol,
                        Algorithm: rr.Algorithm,
                        KeyTag:    kt,
                        KeyRole:   classifyKeyRole(rr.Flags),
                        AlgName:   dnssecAlgorithmName(rr.Algorithm),
                        KeySize:   estimateKeySize(rr.Algorithm, rr.PublicKey),
                        Raw:       rr.String(),
                }
                keys = append(keys, info)
        }
        return keys
}

func parseRRSIGRecords(records []*dns.RRSIG, now time.Time) []RRSIGInfo {
        var sigs []RRSIGInfo
        for _, rr := range records {
                expTime := uint32ToTime(rr.Expiration)
                incTime := uint32ToTime(rr.Inception)
                tte := expTime.Sub(now)
                info := RRSIGInfo{
                        TypeCovered:  dns.TypeToString[rr.TypeCovered],
                        Algorithm:    rr.Algorithm,
                        Labels:       rr.Labels,
                        OriginalTTL:  rr.OrigTTL,
                        Expiration:   expTime,
                        Inception:    incTime,
                        KeyTag:       rr.KeyTag,
                        SignerName:   rr.SignerName,
                        TimeToExpiry: tte,
                        ExpiringSoon: tte > 0 && tte < 7*24*time.Hour,
                        Expired:      tte <= 0,
                        Raw:          rr.String(),
                }
                sigs = append(sigs, info)
        }
        return sigs
}

func detectDenialOfExistence(nsecRecords []*dns.NSEC, nsec3Records []*dns.NSEC3) DenialOfExistence {
        doe := DenialOfExistence{
                Method: "none",
                Issues: []string{},
        }

        if len(nsec3Records) > 0 {
                doe.Method = "NSEC3"
                rr := nsec3Records[0]
                params := &NSEC3Params{
                        HashAlgorithm:  rr.Hash,
                        Flags:          rr.Flags,
                        Iterations:     rr.Iterations,
                        SaltLength:     int(rr.SaltLength),
                        Salt:           rr.Salt,
                        HighIterations: rr.Iterations > 100,
                }
                doe.NSEC3Params = params
                if params.HighIterations {
                        doe.Issues = append(doe.Issues, fmt.Sprintf("NSEC3 iterations (%d) exceed recommended maximum of 100 (RFC 9276)", rr.Iterations))
                }
                if params.SaltLength > 0 {
                        doe.Issues = append(doe.Issues, "NSEC3 uses a non-empty salt; RFC 9276 recommends empty salt for new deployments")
                }
                return doe
        }

        if len(nsecRecords) > 0 {
                doe.Method = "NSEC"
                return doe
        }

        return doe
}

func assessRolloverReadiness(keys []DNSSECKeyInfo, hasCDS, hasCDNSKEY bool) RolloverReadiness {
        rr := RolloverReadiness{
                Issues: []string{},
        }

        kskCount, zskCount := countKeyRoles(keys)

        rr.KSKCount = kskCount
        rr.ZSKCount = zskCount
        rr.MultipleKSKs = kskCount > 1
        rr.HasCDS = hasCDS
        rr.HasCDNSKEY = hasCDNSKEY
        rr.AutomationLevel = determineAutomationLevel(hasCDS, hasCDNSKEY)
        rr.ReadinessLevel = determineReadinessLevel(kskCount, hasCDS, hasCDNSKEY, &rr.Issues)

        if zskCount == 0 && kskCount > 0 {
                rr.Issues = append(rr.Issues, "No separate ZSK found — single-key signing scheme (CSK) detected")
        }

        return rr
}

func countKeyRoles(keys []DNSSECKeyInfo) (kskCount, zskCount int) {
        for _, k := range keys {
                switch k.KeyRole {
                case keyRoleKSK:
                        kskCount++
                case keyRoleZSK:
                        zskCount++
                }
        }
        return
}

func determineAutomationLevel(hasCDS, hasCDNSKEY bool) string {
        if hasCDS && hasCDNSKEY {
                return "full"
        }
        if hasCDS || hasCDNSKEY {
                return mapKeyPartial
        }
        return "none"
}

func determineReadinessLevel(kskCount int, hasCDS, hasCDNSKEY bool, issues *[]string) string {
        hasAutomation := hasCDS || hasCDNSKEY
        if kskCount > 1 && hasAutomation {
                return "ready"
        }
        if kskCount > 1 {
                *issues = append(*issues, "Multiple KSKs present but no CDS/CDNSKEY automation for rollover signaling")
                return mapKeyPartial
        }
        if hasAutomation {
                *issues = append(*issues, "CDS/CDNSKEY automation present but only single KSK — pre-publish second KSK before rollover")
                return mapKeyPartial
        }
        *issues = append(*issues, "Single KSK with no CDS/CDNSKEY automation — manual rollover required")
        return "not_ready"
}

func collectDNSSECOpsIssues(sigs []RRSIGInfo, doe DenialOfExistence, rollover RolloverReadiness) []string {
        issues := make([]string, 0)
        for _, sig := range sigs {
                if sig.Expired {
                        issues = append(issues, fmt.Sprintf("RRSIG for %s (key tag %d) has expired", sig.TypeCovered, sig.KeyTag))
                } else if sig.ExpiringSoon {
                        issues = append(issues, fmt.Sprintf("RRSIG for %s (key tag %d) expires in less than 7 days", sig.TypeCovered, sig.KeyTag))
                }
        }
        issues = append(issues, doe.Issues...)
        issues = append(issues, rollover.Issues...)
        return issues
}

func buildDNSSECOpsStatus(keys []DNSSECKeyInfo, issues []string) (string, string) {
        if len(keys) == 0 {
                return "info", "No DNSKEY records found — DNSSEC not enabled or keys unavailable"
        }
        if len(issues) == 0 {
                return "success", "DNSSEC operations healthy — keys, signatures, and denial-of-existence all nominal"
        }
        for _, iss := range issues {
                if strings.Contains(iss, "expired") {
                        return "error", fmt.Sprintf("DNSSEC operational issues detected: %d issue(s) found", len(issues))
                }
        }
        return "warning", fmt.Sprintf("DNSSEC operational notes: %d item(s) to review", len(issues))
}

func (a *Analyzer) queryDNSKEYForOps(ctx context.Context, domain string) []*dns.DNSKEY {
        fqdn := dnsutil.Fqdn(domain)
        msg := dns.NewMsg(fqdn, dns.TypeDNSKEY)
        msg.RecursionDesired = true
        msg.UDPSize = 4096
        msg.Security = true

        resp, err := a.DNS.ExchangeContext(ctx, msg)
        if err != nil || resp == nil {
                return nil
        }

        var records []*dns.DNSKEY
        for _, rr := range resp.Answer {
                if key, ok := rr.(*dns.DNSKEY); ok {
                        records = append(records, key)
                }
        }
        return records
}

func (a *Analyzer) queryRRSIGTyped(ctx context.Context, domain string) []*dns.RRSIG {
        fqdn := dnsutil.Fqdn(domain)
        msg := dns.NewMsg(fqdn, dns.TypeRRSIG)
        msg.RecursionDesired = true
        msg.UDPSize = 4096
        msg.Security = true

        resp, err := a.DNS.ExchangeContext(ctx, msg)
        if err != nil || resp == nil {
                return nil
        }

        var records []*dns.RRSIG
        for _, rr := range resp.Answer {
                if sig, ok := rr.(*dns.RRSIG); ok {
                        records = append(records, sig)
                }
        }
        return records
}

func (a *Analyzer) queryNSECTyped(ctx context.Context, domain string) []*dns.NSEC {
        fqdn := dnsutil.Fqdn(domain)
        msg := dns.NewMsg(fqdn, dns.TypeNSEC)
        msg.RecursionDesired = true

        resolverAddr := net.JoinHostPort("1.1.1.1", "53") // S1313: Cloudflare public DNS — intentional for DNSSEC validation
        client := &dns.Client{
                Transport: &dns.Transport{
                        Dialer: &net.Dialer{
                                Timeout: 3 * time.Second,
                        },
                        ReadTimeout:  3 * time.Second,
                        WriteTimeout: 3 * time.Second,
                },
        }

        resp, _, err := client.Exchange(ctx, msg, "udp", resolverAddr)
        if err != nil || resp == nil {
                return nil
        }

        var records []*dns.NSEC
        for _, rr := range resp.Answer {
                if nsec, ok := rr.(*dns.NSEC); ok {
                        records = append(records, nsec)
                }
        }
        for _, rr := range resp.Ns {
                if nsec, ok := rr.(*dns.NSEC); ok {
                        records = append(records, nsec)
                }
        }
        return records
}

func (a *Analyzer) queryNSEC3Typed(ctx context.Context, domain string) []*dns.NSEC3 {
        randLabel := "dnssec-ops-probe-nonexistent"
        probeName := dnsutil.Fqdn(randLabel + "." + domain)
        msg := dns.NewMsg(probeName, dns.TypeA)
        msg.RecursionDesired = true
        msg.UDPSize = 4096
        msg.Security = true

        resolverAddr := net.JoinHostPort("1.1.1.1", "53") // S1313: Cloudflare public DNS — intentional for DNSSEC validation
        client := &dns.Client{
                Transport: &dns.Transport{
                        Dialer: &net.Dialer{
                                Timeout: 3 * time.Second,
                        },
                        ReadTimeout:  3 * time.Second,
                        WriteTimeout: 3 * time.Second,
                },
        }

        resp, _, err := client.Exchange(ctx, msg, "udp", resolverAddr)
        if err != nil || resp == nil {
                return nil
        }

        var records []*dns.NSEC3
        for _, rr := range resp.Ns {
                if nsec3, ok := rr.(*dns.NSEC3); ok {
                        records = append(records, nsec3)
                }
        }
        return records
}

func (a *Analyzer) AnalyzeDNSSECOps(ctx context.Context, domain string) map[string]any {
        dnskeyRecords := a.queryDNSKEYForOps(ctx, domain)
        rrsigRecords := a.queryRRSIGTyped(ctx, domain)
        nsecRecords := a.queryNSECTyped(ctx, domain)
        nsec3Records := a.queryNSEC3Typed(ctx, domain)

        cdsResult := a.AnalyzeCDSCDNSKEY(ctx, domain)
        hasCDS, _ := cdsResult[mapKeyHasCDS].(bool)
        hasCDNSKEY, _ := cdsResult[mapKeyHasCDNSKEY].(bool)

        now := time.Now().UTC()

        keys := parseDNSSECKeys(dnskeyRecords)
        sigs := parseRRSIGRecords(rrsigRecords, now)
        doe := detectDenialOfExistence(nsecRecords, nsec3Records)
        rollover := assessRolloverReadiness(keys, hasCDS, hasCDNSKEY)
        issues := collectDNSSECOpsIssues(sigs, doe, rollover)
        status, message := buildDNSSECOpsStatus(keys, issues)

        keyMaps := dnssecKeysToMaps(keys)
        sigMaps := rrsigInfosToMaps(sigs)
        doeMaps := denialToMap(doe)
        rolloverMap := rolloverToMap(rollover)

        var kskAlgs, zskAlgs []string
        for _, k := range keys {
                if k.KeyRole == keyRoleKSK {
                        kskAlgs = append(kskAlgs, k.AlgName)
                } else if k.KeyRole == keyRoleZSK {
                        zskAlgs = append(zskAlgs, k.AlgName)
                }
        }

        return map[string]any{
                "status":              status,
                "message":             message,
                "keys":                keyMaps,
                "signatures":          sigMaps,
                "denial_of_existence": doeMaps,
                "rollover_readiness":  rolloverMap,
                mapKeyIssues:          issues,
                "ksk_algorithms":      kskAlgs,
                "zsk_algorithms":      zskAlgs,
                "key_count":           len(keys),
                "signature_count":     len(sigs),
        }
}

func dnssecKeysToMaps(keys []DNSSECKeyInfo) []map[string]any {
        result := make([]map[string]any, len(keys))
        for i, k := range keys {
                result[i] = map[string]any{
                        mapKeyFlags:      k.Flags,
                        "protocol":       k.Protocol,
                        mapKeyAlgorithm:  k.Algorithm,
                        mapKeyKeyTag:     k.KeyTag,
                        "key_role":       k.KeyRole,
                        "algorithm_name": k.AlgName,
                        "key_size":       k.KeySize,
                }
        }
        return result
}

func rrsigInfosToMaps(sigs []RRSIGInfo) []map[string]any {
        result := make([]map[string]any, len(sigs))
        for i, s := range sigs {
                result[i] = map[string]any{
                        "type_covered":   s.TypeCovered,
                        mapKeyAlgorithm:  s.Algorithm,
                        "labels":         s.Labels,
                        "ttl":            s.OriginalTTL,
                        "expiration":     s.Expiration.Format(time.RFC3339),
                        "inception":      s.Inception.Format(time.RFC3339),
                        mapKeyKeyTag:     s.KeyTag,
                        "signer":         s.SignerName,
                        mapKeyExpired:    s.Expired,
                        "expiring_soon":  s.ExpiringSoon,
                        "time_to_expiry": s.TimeToExpiry.String(),
                }
        }
        return result
}

func denialToMap(d DenialOfExistence) map[string]any {
        result := map[string]any{
                "method": d.Method,
        }
        if d.NSEC3Params != nil {
                result["nsec3_hash_algorithm"] = d.NSEC3Params.HashAlgorithm
                result["nsec3_iterations"] = d.NSEC3Params.Iterations
                result["nsec3_salt_length"] = d.NSEC3Params.SaltLength
                result["nsec3_flags"] = d.NSEC3Params.Flags
                result["nsec3_high_iterations"] = d.NSEC3Params.HighIterations
        }
        if len(d.Issues) > 0 {
                result[mapKeyIssues] = d.Issues
        }
        return result
}

func rolloverToMap(r RolloverReadiness) map[string]any {
        return map[string]any{
                "multiple_ksks":  r.MultipleKSKs,
                mapKeyHasCDS:     r.HasCDS,
                mapKeyHasCDNSKEY: r.HasCDNSKEY,
                "automation":     r.AutomationLevel,
                "readiness":      r.ReadinessLevel,
        }
}
