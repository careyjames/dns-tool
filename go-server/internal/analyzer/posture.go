// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "fmt"
        "strings"
)

const (
        riskLow      = "Low Risk"
        riskMedium   = "Medium Risk"
        riskHigh     = "High Risk"
        riskCritical = "Critical Risk"

        iconShieldAlt           = "shield-alt"
        iconExclamationTriangle = "exclamation-triangle"

        protocolMTASTS = "MTA-STS"
        protocolTLSRPT = "TLS-RPT"

        mapKeyAiCrawlerGovernance = "ai_crawler_governance"
        mapKeyAiLlmsTxt           = "ai_llms_txt"
        mapKeyAnswer              = "answer"
        mapKeyBrandImpersonation  = "brand_impersonation"
        mapKeyColor               = "color"
        mapKeyDanger              = "danger"
        mapKeyDnsTampering        = "dns_tampering"
        mapKeyEmailSpoofing       = "email_spoofing"
        mapKeySecondary           = "secondary"
        mapKeyTransport           = "transport"
        strBasic                  = "Basic"
        strExposed                = "Exposed"
        strLikely                 = "Likely"
        strPartially              = "Partially"
        strPossible               = "Possible"
        strProtected              = "Protected"
        strUnlikely               = "Unlikely"
        mapKeyIcon                = "icon"
        mapKeyLabel               = "label"
        answerYes                 = "Yes"
        statusNone                = "none"
        statusInfoPosture         = "info"
)

type protocolState struct {
        spfOK               bool
        spfWarning          bool
        spfMissing          bool
        spfHardFail         bool
        spfDangerous        bool
        spfNeutral          bool
        spfLookupExceeded   bool
        spfLookupCount      int
        dmarcOK             bool
        dmarcWarning        bool
        dmarcMissing        bool
        dmarcPolicy         string
        dmarcPct            int
        dmarcHasRua         bool
        dkimOK              bool
        dkimProvider        bool
        dkimPartial         bool
        dkimWeakKeys        bool
        dkimThirdPartyOnly  bool
        caaOK               bool
        mtaStsOK            bool
        tlsrptOK            bool
        bimiOK              bool
        daneOK              bool
        daneProviderLimited bool
        dnssecOK            bool
        dnssecBroken        bool
        dnssecAlgoStrength  string
        primaryProvider     string
        isNoMailDomain      bool
        probableNoMail      bool
        isTLD               bool
}

type postureAccumulator struct {
        issues          []string
        recommendations []string
        monitoring      []string
        configured      []string
        absent          []string
        providerLimited []string
}

type gradeInput struct {
        corePresent           bool
        dmarcFullEnforcing    bool
        dmarcPartialEnforcing bool
        dmarcStrict           bool
        hasCAA                bool
        hasSPF                bool
        hasDMARC              bool
        hasDKIM               bool
        dkimInconclusive      bool
        isNoMail              bool
        monitoring            []string
        configured            []string
        absent                []string
}

func evaluateSPFState(spf map[string]any) (spfOK, spfWarning, spfMissing, spfHardFail, spfDangerous, spfNeutral, spfLookupExceeded bool, spfLookupCount int) {
        if isMissingRecord(spf) {
                spfMissing = true
                return
        }

        status, _ := spf[mapKeyStatus].(string)
        switch status {
        case mapKeySuccess:
                spfOK = true
        case mapKeyWarning:
                spfWarning = true
                spfOK = true
        default:
                spfMissing = true
        }

        mechanism, _ := spf["all_mechanism"].(string)
        mechanism = strings.TrimSpace(mechanism)
        switch mechanism {
        case "-all":
                spfHardFail = true
        case "+all":
                spfDangerous = true
        case "?all":
                spfNeutral = true
        }

        spfLookupCount = extractIntField(spf, "lookup_count")
        if spfLookupCount > 10 {
                spfLookupExceeded = true
        }
        return
}

func evaluateDMARCState(dmarc map[string]any) (dmarcOK, dmarcWarning, dmarcMissing, dmarcHasRua bool, dmarcPolicy string, dmarcPct int) {
        if isMissingRecord(dmarc) {
                dmarcMissing = true
                return
        }

        status, _ := dmarc[mapKeyStatus].(string)
        switch status {
        case mapKeySuccess:
                dmarcOK = true
        case mapKeyWarning:
                dmarcWarning = true
                dmarcOK = true
        default:
                dmarcMissing = true
        }

        dmarcPolicy, _ = dmarc["policy"].(string)
        dmarcPct = extractIntFieldDefault(dmarc, "pct", 100)
        if rua, ok := dmarc["rua"].(string); ok && rua != "" {
                dmarcHasRua = true
        }
        return
}

func evaluateDKIMState(dkim map[string]any) (dkimOK, dkimProvider, dkimPartial, dkimWeakKeys, dkimThirdPartyOnly bool, primaryProvider string) {
        if isMissingRecord(dkim) {
                return
        }

        status, _ := dkim[mapKeyStatus].(string)
        switch status {
        case mapKeySuccess:
                dkimOK = true
        case mapKeyWarning:
                dkimOK = true
        }

        if pp, ok := dkim["primary_provider"].(string); ok && pp != "" {
                primaryProvider = pp
                dkimProvider = true
        }

        dkimWeakKeys, dkimThirdPartyOnly = evaluateDKIMIssues(dkim)

        recordsFound := extractIntField(dkim, "records_found")
        if recordsFound > 0 && !dkimOK {
                dkimPartial = true
        }
        return
}

func evaluateSimpleProtocolState(analysis map[string]any, successField string) bool {
        if isMissingRecord(analysis) {
                return false
        }
        status, _ := analysis[successField].(string)
        return status == mapKeySuccess
}

func evaluateProtocolStates(results map[string]any) protocolState {
        ps := protocolState{}

        spf, _ := results["spf_analysis"].(map[string]any)
        dmarc, _ := results["dmarc_analysis"].(map[string]any)
        dkim, _ := results["dkim_analysis"].(map[string]any)
        mtaSts, _ := results["mta_sts_analysis"].(map[string]any)
        tlsrpt, _ := results["tlsrpt_analysis"].(map[string]any)
        bimi, _ := results["bimi_analysis"].(map[string]any)
        dane, _ := results["dane_analysis"].(map[string]any)
        caa, _ := results["caa_analysis"].(map[string]any)
        dnssec, _ := results["dnssec_analysis"].(map[string]any)

        if nullMX, ok := results["has_null_mx"].(bool); ok {
                ps.isNoMailDomain = nullMX
        }
        if noMail, ok := results["is_no_mail_domain"].(bool); ok && noMail {
                ps.isNoMailDomain = true
        }
        if !ps.isNoMailDomain {
                ps.probableNoMail = detectProbableNoMail(results)
        }

        ps.spfOK, ps.spfWarning, ps.spfMissing, ps.spfHardFail, ps.spfDangerous, ps.spfNeutral, ps.spfLookupExceeded, ps.spfLookupCount = evaluateSPFState(spf)
        ps.dmarcOK, ps.dmarcWarning, ps.dmarcMissing, ps.dmarcHasRua, ps.dmarcPolicy, ps.dmarcPct = evaluateDMARCState(dmarc)
        ps.dkimOK, ps.dkimProvider, ps.dkimPartial, ps.dkimWeakKeys, ps.dkimThirdPartyOnly, ps.primaryProvider = evaluateDKIMState(dkim)

        ps.caaOK = evaluateSimpleProtocolState(caa, mapKeyStatus)
        ps.mtaStsOK = evaluateSimpleProtocolState(mtaSts, mapKeyStatus)
        ps.tlsrptOK = evaluateSimpleProtocolState(tlsrpt, mapKeyStatus)
        ps.bimiOK = evaluateSimpleProtocolState(bimi, mapKeyStatus)

        evaluateDANEState(dane, &ps)
        evaluateDNSSECState(dnssec, &ps)

        return ps
}

func evaluateDANEState(dane map[string]any, ps *protocolState) {
        if isMissingRecord(dane) {
                return
        }
        if hasDane, ok := dane["has_dane"].(bool); ok && hasDane {
                ps.daneOK = true
        }
        if deployable, ok := dane["dane_deployable"].(bool); ok && !deployable {
                ps.daneProviderLimited = true
        }
}

func evaluateDNSSECState(dnssec map[string]any, ps *protocolState) {
        if isMissingRecord(dnssec) {
                return
        }
        status, _ := dnssec[mapKeyStatus].(string)
        switch status {
        case mapKeySuccess:
                ps.dnssecOK = true
        case "error":
                ps.dnssecBroken = true
        }
        if obs, ok := dnssec["algorithm_observation"].(map[string]any); ok {
                if s, ok := obs["strength"].(string); ok {
                        ps.dnssecAlgoStrength = s
                }
        }
}

func detectProbableNoMail(results map[string]any) bool {
        basic, _ := results["basic_records"].(map[string]any)
        if basic == nil {
                return false
        }
        mxRecords, _ := basic["MX"].([]string)
        if len(mxRecords) > 0 {
                return false
        }
        mxAny, _ := results["mx_records"].([]any)
        if len(mxAny) > 0 {
                return false
        }
        return true
}

func isMissingRecord(m map[string]any) bool {
        if m == nil {
                return true
        }
        status, _ := m[mapKeyStatus].(string)
        return status == "error" || status == "missing" || status == "n/a"
}

func hasNonEmptyString(m map[string]any, key string) bool {
        if m == nil {
                return false
        }
        s, ok := m[key].(string)
        return ok && s != ""
}

func extractIntField(m map[string]any, key string) int {
        if m == nil {
                return 0
        }
        v, ok := m[key]
        if !ok {
                return 0
        }
        switch n := v.(type) {
        case int:
                return n
        case int64:
                return int(n)
        case float64:
                return int(n)
        case float32:
                return int(n)
        }
        return 0
}

func extractIntFieldDefault(m map[string]any, key string, defaultVal int) int {
        if m == nil {
                return defaultVal
        }
        v, ok := m[key]
        if !ok {
                return defaultVal
        }
        switch n := v.(type) {
        case int:
                return n
        case int64:
                return int(n)
        case float64:
                return int(n)
        case float32:
                return int(n)
        }
        return defaultVal
}

func evaluateDKIMIssues(dkim map[string]any) (weakKeys, thirdPartyOnly bool) {
        if dkim == nil {
                return false, false
        }

        if wk, ok := dkim["weak_keys"].(bool); ok && wk {
                weakKeys = true
        }
        if tpo, ok := dkim["third_party_only"].(bool); ok && tpo {
                thirdPartyOnly = true
        }

        if issues, ok := dkim[mapKeyIssues].([]any); ok {
                wk, tpo := scanDKIMIssueStrings(issues)
                if wk {
                        weakKeys = true
                }
                if tpo {
                        thirdPartyOnly = true
                }
        }

        return weakKeys, thirdPartyOnly
}

func scanDKIMIssueStrings(issues []any) (weakKeys, thirdPartyOnly bool) {
        for _, issue := range issues {
                s, ok := issue.(string)
                if !ok {
                        continue
                }
                lower := strings.ToLower(s)
                if strings.Contains(lower, "weak") || strings.Contains(lower, "1024") {
                        weakKeys = true
                }
                if strings.Contains(lower, "third-party") || strings.Contains(lower, "third party") {
                        thirdPartyOnly = true
                }
        }
        return
}

func classifySPF(ps protocolState, acc *postureAccumulator) {
        if ps.spfMissing {
                acc.issues = append(acc.issues, "No SPF record published — RFC 7208 defines the SPF mechanism but does not mandate publication. Without SPF, any server can send email claiming to be this domain (CVE-2024-7208, CVE-2024-7209)")
                acc.recommendations = append(acc.recommendations, "Publish an SPF record to authorize legitimate mail senders")
                acc.absent = append(acc.absent, rtSPF)
                return
        }

        if ps.spfDangerous {
                acc.issues = append(acc.issues, "SPF record uses +all — allows any server to send mail as this domain (RFC 7208 §5.1 defines +all as passing all senders)")
                acc.recommendations = append(acc.recommendations, "Change SPF mechanism from +all to ~all or -all")
                acc.configured = append(acc.configured, rtSPF)
                return
        }

        if ps.spfLookupExceeded {
                acc.issues = append(acc.issues, fmt.Sprintf("SPF record exceeds 10-lookup limit (%d lookups)", ps.spfLookupCount))
                acc.recommendations = append(acc.recommendations, "Reduce SPF lookup count to 10 or fewer using IP-based mechanisms")
        }

        if ps.spfNeutral {
                acc.recommendations = append(acc.recommendations, "SPF uses ?all (neutral) — consider ~all or -all for stronger policy")
        }

        if ps.spfWarning && !ps.spfHardFail {
                acc.monitoring = append(acc.monitoring, "SPF configured with soft fail (~all) — industry-standard when paired with DMARC enforcement (RFC 7489)")
        }

        if ps.spfHardFail {
                acc.configured = append(acc.configured, "SPF (hard fail)")
        } else if ps.spfOK {
                acc.configured = append(acc.configured, rtSPF)
        }
}

func classifyDMARC(ps protocolState, acc *postureAccumulator) {
        if ps.dmarcMissing {
                acc.issues = append(acc.issues, "No DMARC record published — RFC 7489 is Informational (not Standards Track); DMARCbis will elevate to Standards Track. Without DMARC, receivers have no policy for handling SPF/DKIM failures — spoofed mail may be delivered (CVE-2024-49040)")
                acc.recommendations = append(acc.recommendations, "Publish a DMARC record starting with p=none and rua reporting")
                acc.absent = append(acc.absent, "DMARC")
                return
        }

        if ps.dmarcOK && !ps.dmarcWarning {
                classifyDMARCSuccess(ps, acc)
        } else if ps.dmarcWarning {
                classifyDMARCWarning(ps, acc)
        }
}

func classifyDMARCSuccess(ps protocolState, acc *postureAccumulator) {
        switch ps.dmarcPolicy {
        case mapKeyReject:
                acc.configured = append(acc.configured, "DMARC (reject)")
        case mapKeyQuarantine:
                if ps.dmarcPct >= 100 {
                        acc.configured = append(acc.configured, "DMARC (quarantine, 100%)")
                        acc.recommendations = append(acc.recommendations, "Upgrade DMARC policy from quarantine to reject (p=reject) for maximum spoofing protection")
                } else {
                        acc.configured = append(acc.configured, fmt.Sprintf("DMARC (quarantine, %d%%)", ps.dmarcPct))
                        acc.monitoring = append(acc.monitoring, fmt.Sprintf("DMARC quarantine policy only applies to %d%% of messages", ps.dmarcPct))
                        acc.recommendations = append(acc.recommendations, "Increase DMARC pct to 100 for full enforcement")
                }
        case statusNone:
                acc.configured = append(acc.configured, "DMARC (monitoring only)")
                if ps.dmarcHasRua {
                        acc.monitoring = append(acc.monitoring, "DMARC policy is 'none' (monitoring mode) — receiving aggregate reports")
                        acc.recommendations = append(acc.recommendations, "Review DMARC aggregate reports and move to quarantine or reject policy")
                } else {
                        acc.issues = append(acc.issues, "DMARC policy is 'none' with no reporting — provides no protection or visibility")
                        acc.recommendations = append(acc.recommendations, "Add rua tag to receive DMARC aggregate reports before enforcing policy")
                }
        default:
                acc.configured = append(acc.configured, "DMARC")
        }

        if !ps.dmarcHasRua && ps.dmarcPolicy != statusNone {
                acc.recommendations = append(acc.recommendations, "Add DMARC aggregate reporting (rua) for visibility into email authentication")
        }
}

func classifyDMARCWarning(ps protocolState, acc *postureAccumulator) {
        acc.configured = append(acc.configured, "DMARC (with warnings)")
        acc.monitoring = append(acc.monitoring, "DMARC record has configuration warnings — review recommended")

        if ps.dmarcPolicy == statusNone {
                acc.recommendations = append(acc.recommendations, "Move DMARC policy from 'none' to 'quarantine' or 'reject'")
        }
        if !ps.dmarcHasRua {
                acc.recommendations = append(acc.recommendations, "Enable DMARC aggregate reporting (rua) for authentication visibility")
        }
}

func classifyDKIMPosture(ds DKIMState, primaryProvider string, acc *postureAccumulator) {
        switch ds {
        case DKIMSuccess:
                acc.configured = append(acc.configured, "DKIM")
        case DKIMProviderInferred:
                acc.configured = append(acc.configured, fmt.Sprintf("DKIM (inferred via %s)", primaryProvider))
                acc.monitoring = append(acc.monitoring, "DKIM signing inferred from provider — could not directly verify selector")
        case DKIMThirdPartyOnly:
                acc.configured = append(acc.configured, "DKIM (third-party only)")
                acc.recommendations = append(acc.recommendations, "Configure DKIM signing for your primary domain selector in addition to third-party services")
        case DKIMWeakKeysOnly:
                acc.configured = append(acc.configured, "DKIM (weak keys)")
                acc.issues = append(acc.issues, "DKIM keys are weak (1024-bit or less) — RFC 6376 §3.3.3 requires minimum 1024-bit RSA; 2048-bit is the current operational standard. Keys below 1024-bit are considered cryptographically breakable")
                acc.recommendations = append(acc.recommendations, "Upgrade DKIM keys to 2048-bit RSA or Ed25519")
        case DKIMNoMailDomain:
                acc.configured = append(acc.configured, "DKIM (not applicable — no-mail domain)")
        case DKIMInconclusive:
                acc.monitoring = append(acc.monitoring, "DKIM status is inconclusive — selector could not be verified")
                acc.absent = append(acc.absent, "DKIM (inconclusive)")
        case DKIMAbsent:
                acc.absent = append(acc.absent, "DKIM")
                acc.recommendations = append(acc.recommendations, "Configure DKIM signing to cryptographically authenticate outgoing email — RFC 6376 defines the mechanism; without it, messages cannot be verified as unaltered in transit")
        }
}

func classifyPresence(ok bool, name string, acc *postureAccumulator) {
        if ok {
                acc.configured = append(acc.configured, name)
        } else {
                acc.absent = append(acc.absent, name)
        }
}

func classifyDANE(ps protocolState, acc *postureAccumulator) {
        if ps.daneOK {
                acc.configured = append(acc.configured, rtDANE)
        } else if ps.daneProviderLimited {
                acc.providerLimited = append(acc.providerLimited, rtDANE)
        } else {
                acc.absent = append(acc.absent, rtDANE)
        }
}

func classifyDNSSEC(ps protocolState, acc *postureAccumulator) {
        if ps.dnssecOK {
                acc.configured = append(acc.configured, "DNSSEC")
        } else if ps.dnssecBroken {
                acc.issues = append(acc.issues, "DNSSEC validation is failing — DNS responses cannot be trusted")
                acc.recommendations = append(acc.recommendations, "Fix DNSSEC configuration or remove broken DS records")
        } else {
                acc.absent = append(acc.absent, "DNSSEC")
        }
}

func classifySimpleProtocols(ps protocolState, isTLD bool, acc *postureAccumulator) {
        if !isTLD {
                classifyPresence(ps.mtaStsOK, protocolMTASTS, acc)
                classifyPresence(ps.tlsrptOK, protocolTLSRPT, acc)
                classifyPresence(ps.bimiOK, "BIMI", acc)
                classifyDANE(ps, acc)
        }

        classifyDNSSEC(ps, acc)

        if !isTLD {
                classifyPresence(ps.caaOK, "CAA", acc)
        }
}

func classifyDanglingDNS(results map[string]any, acc *postureAccumulator) {
        dangling, ok := results["dangling_dns"].(map[string]any)
        if !ok {
                return
        }
        count := extractIntField(dangling, "dangling_count")
        if count > 0 {
                acc.issues = append(acc.issues, fmt.Sprintf("%d dangling DNS record(s) detected — potential subdomain takeover risk", count))
                acc.recommendations = append(acc.recommendations, "Review and remove dangling DNS records pointing to deprovisioned services")
        }
}

func classifyDMARCReportAuth(results map[string]any, acc *postureAccumulator) {
        reportAuth, ok := results["dmarc_report_auth"].(map[string]any)
        if !ok {
                return
        }

        issues, _ := reportAuth[mapKeyIssues].([]string)
        for _, issue := range issues {
                acc.monitoring = append(acc.monitoring, issue)
        }

        externalDomains := extractExternalDomainMaps(reportAuth["external_domains"])
        for _, ed := range externalDomains {
                if authorized, ok := ed["authorized"].(bool); ok && !authorized {
                        domain, _ := ed["domain"].(string)
                        if domain != "" {
                                acc.recommendations = append(acc.recommendations, fmt.Sprintf("Authorize external DMARC reporting for %s or remove from rua/ruf", domain))
                        }
                }
        }
}

func extractExternalDomainMaps(raw any) []map[string]any {
        if raw == nil {
                return nil
        }
        if arr, ok := raw.([]map[string]any); ok {
                return arr
        }
        if arr, ok := raw.([]any); ok {
                result := make([]map[string]any, 0, len(arr))
                for _, item := range arr {
                        if m, ok := item.(map[string]any); ok {
                                result = append(result, m)
                        }
                }
                return result
        }
        return nil
}

var freeCAs = map[string]bool{
        "Let's Encrypt": true,
        "ZeroSSL":       true,
        "Buypass":       true,
        "Google Trust":  true,
        "E1":            true,
        "R3":            true,
        "R10":           true,
        "R11":           true,
        "ISRG Root":     true,
        "WE1":           true,
        "Amazon":        true,
        "AWS":           true,
        "Cloudflare":    true,
}

func matchesFreeCertAuthority(caName string) bool {
        if freeCAs[caName] {
                return true
        }
        lower := strings.ToLower(caName)
        for free := range freeCAs {
                if strings.Contains(lower, strings.ToLower(free)) {
                        return true
                }
        }
        return false
}

func classifyCertificateCosts(results map[string]any, acc *postureAccumulator) {
        ct, ok := results["ct_subdomains"].(map[string]any)
        if !ok {
                return
        }

        caSummaryRaw, ok := ct["ca_summary"]
        if !ok {
                return
        }

        caSummary, ok := caSummaryRaw.([]map[string]any)
        if !ok {
                return
        }

        hasWildcard := false
        if wc, ok := ct["wildcard_certs"].(map[string]any); ok {
                if present, ok := wc["present"].(bool); ok && present {
                        hasWildcard = true
                }
        }

        totalPaidCerts := 0
        paidCANames := []string{}
        hasFreeCerts := false
        for _, ca := range caSummary {
                name, _ := ca["name"].(string)
                count := extractIntField(ca, "certCount")
                if matchesFreeCertAuthority(name) {
                        hasFreeCerts = true
                } else if count > 0 {
                        totalPaidCerts += count
                        paidCANames = append(paidCANames, name)
                }
        }

        if totalPaidCerts >= 3 && !hasWildcard {
                acc.recommendations = append(acc.recommendations,
                        fmt.Sprintf("Consider a wildcard certificate (*.domain) to reduce certificate management overhead — %d individual certificates detected across %s",
                                totalPaidCerts, strings.Join(paidCANames, ", ")))
        }

        if totalPaidCerts >= 3 && !hasFreeCerts {
                acc.recommendations = append(acc.recommendations,
                        "Evaluate free certificate providers (Let's Encrypt, AWS Certificate Manager) — automated issuance and renewal can reduce costs, especially with shorter certificate lifetimes ahead")
        }
}

func evaluateDeliberateMonitoring(ps protocolState, configuredCount int) (bool, string) {
        if !ps.dmarcOK || !ps.dmarcHasRua || !ps.spfOK {
                return false, ""
        }
        if ps.dmarcPolicy == statusNone && configuredCount >= 2 {
                return true, "Domain appears to be in deliberate DMARC monitoring phase with aggregate reporting enabled"
        }
        if ps.dmarcPolicy == mapKeyQuarantine && ps.dmarcPct < 100 && configuredCount >= 2 {
                return true, "Domain appears to be in deliberate DMARC deployment phase — quarantine at partial enforcement with reporting enabled"
        }
        if ps.dmarcPolicy == mapKeyQuarantine && ps.dmarcPct >= 100 && configuredCount >= 2 {
                return true, "Domain appears to be in deliberate DMARC deployment phase — quarantine fully enforced with reporting, consider upgrading to reject"
        }
        return false, ""
}

func (a *Analyzer) CalculatePosture(results map[string]any) map[string]any {
        isTLD, _ := results["is_tld"].(bool)
        ps := evaluateProtocolStates(results)
        ds := classifyDKIMState(ps)

        acc := &postureAccumulator{
                issues:          []string{},
                recommendations: []string{},
                monitoring:      []string{},
                configured:      []string{},
                absent:          []string{},
                providerLimited: []string{},
        }

        if !isTLD {
                classifySPF(ps, acc)
                classifyDMARC(ps, acc)
                classifyDKIMPosture(ds, ps.primaryProvider, acc)
        }
        classifySimpleProtocols(ps, isTLD, acc)
        classifyDanglingDNS(results, acc)
        classifyDMARCReportAuth(results, acc)
        classifyCertificateCosts(results, acc)

        hasSPF := !ps.spfMissing
        hasDMARC := !ps.dmarcMissing
        hasDKIM := ds.IsPresent()

        if isTLD {
                hasSPF = true
                hasDMARC = true
                hasDKIM = true
                ps.isNoMailDomain = true
                ps.isTLD = true
        }

        gi := gradeInput{
                hasSPF:     hasSPF,
                hasDMARC:   hasDMARC,
                hasDKIM:    hasDKIM,
                monitoring: acc.monitoring,
                configured: acc.configured,
                absent:     acc.absent,
        }

        state, icon, color, message := determineGrade(ps, ds, gi)

        score := computeInternalScore(ps, ds)

        vi := verdictInput{ps: ps, ds: ds, hasSPF: hasSPF, hasDMARC: hasDMARC, hasDKIM: hasDKIM}
        verdicts := buildVerdicts(vi)
        buildAISurfaceVerdicts(results, verdicts)

        deliberate, deliberateNote := evaluateDeliberateMonitoring(ps, len(acc.configured))

        var criticalIssues []string
        if ps.dnssecBroken {
                criticalIssues = append(criticalIssues, "DNSSEC validation is failing")
        }
        if !isTLD && ps.spfMissing && ps.dmarcMissing {
                criticalIssues = append(criticalIssues, "No SPF and no DMARC — domain is completely unprotected against email spoofing. Both protocols are RFC-recommended (not mandatory), but their absence leaves the domain open to impersonation (CVE-2024-7208, CVE-2024-49040)")
        }

        grade := state
        label := state

        return map[string]any{
                "score":                      score,
                "grade":                      grade,
                mapKeyLabel:                  label,
                "state":                      state,
                mapKeyIcon:                   icon,
                mapKeyColor:                  color,
                "message":                    message,
                mapKeyIssues:                 acc.issues,
                "critical_issues":            criticalIssues,
                "recommendations":            acc.recommendations,
                "monitoring":                 acc.monitoring,
                "configured":                 acc.configured,
                "absent":                     acc.absent,
                "provider_limited":           acc.providerLimited,
                "deliberate_monitoring":      deliberate,
                "deliberate_monitoring_note": deliberateNote,
                "verdicts":                   verdicts,
        }
}

func determineGrade(ps protocolState, ds DKIMState, gi gradeInput) (state, icon, color, message string) {
        gi.corePresent = gi.hasSPF && gi.hasDMARC
        gi.dmarcFullEnforcing = ps.dmarcPolicy == mapKeyReject || (ps.dmarcPolicy == mapKeyQuarantine && ps.dmarcPct >= 100)
        gi.dmarcPartialEnforcing = ps.dmarcPolicy == mapKeyQuarantine && ps.dmarcPct < 100
        gi.dmarcStrict = ps.dmarcPolicy == mapKeyReject
        gi.hasCAA = ps.caaOK
        gi.dkimInconclusive = ds == DKIMInconclusive
        gi.isNoMail = ps.isNoMailDomain

        state, icon, color, message = classifyGrade(ps, gi)
        return
}

func classifyGrade(ps protocolState, gi gradeInput) (string, string, string, string) {
        if ps.dnssecBroken {
                return riskCritical, iconExclamationTriangle, mapKeyDanger, "DNSSEC validation is broken — DNS responses may be tampered with"
        }

        if ps.isTLD {
                return classifyRegistryGrade(ps, gi)
        }

        if gi.isNoMail {
                return classifyNoMailGrade(ps, gi)
        }

        return classifyMailGrade(ps, gi)
}

func classifyMailGrade(ps protocolState, gi gradeInput) (string, string, string, string) {
        if !gi.hasSPF && !gi.hasDMARC {
                return riskCritical, iconExclamationTriangle, mapKeyDanger, "No SPF or DMARC records — domain is unprotected against email spoofing"
        }

        if !gi.hasSPF || !gi.hasDMARC {
                return classifyMailPartial(gi)
        }

        return classifyMailCorePresent(ps, gi)
}

func classifyMailCorePresent(ps protocolState, gi gradeInput) (string, string, string, string) {
        if gi.dmarcFullEnforcing && gi.hasDKIM {
                state := riskLow
                msg := buildDescriptiveMessage(ps, gi.configured, gi.absent, gi.monitoring)
                return applyMonitoringSuffix(state, gi.monitoring), iconShieldAlt, mapKeySuccess, msg
        }

        if gi.dmarcFullEnforcing && !gi.hasDKIM {
                state := riskMedium
                msg := "SPF and DMARC enforcing but DKIM not confirmed"
                return applyMonitoringSuffix(state, gi.monitoring), iconShieldAlt, statusInfoPosture, msg
        }

        if gi.dmarcPartialEnforcing {
                state := riskMedium
                msg := fmt.Sprintf("DMARC quarantine at %d%% — not fully enforcing", ps.dmarcPct)
                return applyMonitoringSuffix(state, gi.monitoring), iconShieldAlt, statusInfoPosture, msg
        }

        if ps.dmarcPolicy == statusNone {
                if ps.dmarcHasRua {
                        state := riskMedium
                        msg := "DMARC is in monitoring mode (p=none) with reporting enabled"
                        return applyMonitoringSuffix(state, gi.monitoring), iconShieldAlt, statusInfoPosture, msg
                }
                return riskHigh, iconExclamationTriangle, mapKeyWarning, "DMARC policy is 'none' with no reporting — no protection or visibility"
        }

        state := riskMedium
        msg := buildDescriptiveMessage(ps, gi.configured, gi.absent, gi.monitoring)
        return applyMonitoringSuffix(state, gi.monitoring), iconShieldAlt, statusInfoPosture, msg
}

func classifyMailPartial(gi gradeInput) (string, string, string, string) {
        if gi.hasSPF && !gi.hasDMARC {
                return riskHigh, iconExclamationTriangle, mapKeyWarning, "SPF present but no DMARC — spoofed emails may still be delivered"
        }
        return riskHigh, iconExclamationTriangle, mapKeyWarning, "DMARC present but no SPF — mail authentication is incomplete"
}

func classifyNoMailGrade(ps protocolState, gi gradeInput) (string, string, string, string) {
        if gi.hasSPF && gi.hasDMARC {
                if gi.dmarcStrict || gi.dmarcFullEnforcing {
                        return riskLow, iconShieldAlt, mapKeySuccess, "No-mail domain properly configured with SPF and DMARC reject policy"
                }
                return riskMedium, iconShieldAlt, statusInfoPosture, "No-mail domain has SPF and DMARC but policy is not reject"
        }
        if gi.hasSPF || gi.hasDMARC {
                return riskHigh, iconExclamationTriangle, mapKeyWarning, "No-mail domain is missing SPF or DMARC"
        }
        return riskCritical, iconExclamationTriangle, mapKeyDanger, "No-mail domain has no email authentication records"
}

func classifyRegistryGrade(ps protocolState, _ gradeInput) (string, string, string, string) {
        if ps.dnssecOK {
                return riskLow, iconShieldAlt, mapKeySuccess, "Registry zone has DNSSEC signing active — delegation chain is cryptographically secured"
        }
        return riskHigh, iconExclamationTriangle, mapKeyWarning, "Registry zone is not DNSSEC-signed — delegation chain lacks cryptographic verification"
}

func applyMonitoringSuffix(state string, monitoring []string) string {
        if len(monitoring) > 0 {
                return state
        }
        return state
}

func buildDescriptiveMessage(ps protocolState, configured, absent, monitoring []string) string {
        parts := []string{}

        if len(configured) > 0 {
                parts = append(parts, fmt.Sprintf("%d protocols configured", len(configured)))
        }
        if len(absent) > 0 {
                parts = append(parts, fmt.Sprintf("%d not configured", len(absent)))
        }
        if len(monitoring) > 0 {
                parts = append(parts, fmt.Sprintf("%d need attention", len(monitoring)))
        }

        if len(parts) == 0 {
                return "Email security posture evaluated"
        }

        return strings.Join(parts, ", ")
}

type verdictInput struct {
        ps       protocolState
        ds       DKIMState
        hasSPF   bool
        hasDMARC bool
        hasDKIM  bool
}

func buildVerdicts(vi verdictInput) map[string]any {
        verdicts := map[string]any{}

        buildEmailVerdict(vi, verdicts)
        buildBrandVerdict(vi.ps, verdicts)
        buildDNSVerdict(vi.ps, verdicts)
        buildCAAVerdict(vi.ps, verdicts)

        verdicts["email_answer"] = buildEmailAnswer(vi.ps, vi.hasSPF, vi.hasDMARC)
        ea := buildEmailAnswerStructured(vi.ps, vi.hasSPF, vi.hasDMARC)
        verdicts["email_answer_short"] = ea[mapKeyAnswer]
        verdicts["email_answer_reason"] = ea[mapKeyReason]
        verdicts["email_answer_color"] = ea[mapKeyColor]

        buildTransportVerdict(vi.ps, verdicts)

        return verdicts
}

func buildCAAVerdict(ps protocolState, verdicts map[string]any) {
        if ps.caaOK {
                verdicts["certificate_control"] = map[string]any{
                        mapKeyLabel:  "Configured",
                        mapKeyColor:  mapKeySuccess,
                        mapKeyIcon:   iconShieldAlt,
                        mapKeyAnswer: answerYes,
                        mapKeyReason: "CAA records restrict which certificate authorities may issue certificates",
                }
        } else {
                verdicts["certificate_control"] = map[string]any{
                        mapKeyLabel:  "Not Configured",
                        mapKeyColor:  mapKeySecondary,
                        mapKeyIcon:   iconShieldAlt,
                        mapKeyAnswer: "No",
                        mapKeyReason: "No CAA records — any certificate authority may issue certificates for this domain",
                }
        }
}

type emailSpoofClass int

const (
        emailSpoofNoMail emailSpoofClass = iota
        emailSpoofUnprotected
        emailSpoofReject
        emailSpoofQuarantineFull
        emailSpoofQuarantinePartial
        emailSpoofMonitorOnly
        emailSpoofSPFOnly
        emailSpoofDMARCOnly
        emailSpoofUncertain
)

func classifyEmailSpoofability(ps protocolState, hasSPF, hasDMARC bool) emailSpoofClass {
        if ps.isNoMailDomain {
                return emailSpoofNoMail
        }
        if !hasSPF && !hasDMARC {
                return emailSpoofUnprotected
        }
        if hasSPF && hasDMARC {
                return classifyDMARCPolicy(ps)
        }
        if hasSPF {
                return emailSpoofSPFOnly
        }
        if hasDMARC {
                return emailSpoofDMARCOnly
        }
        return emailSpoofUncertain
}

func classifyDMARCPolicy(ps protocolState) emailSpoofClass {
        switch ps.dmarcPolicy {
        case mapKeyReject:
                return emailSpoofReject
        case mapKeyQuarantine:
                if ps.dmarcPct >= 100 {
                        return emailSpoofQuarantineFull
                }
                return emailSpoofQuarantinePartial
        case statusNone:
                return emailSpoofMonitorOnly
        default:
                return emailSpoofUncertain
        }
}

var emailAnswerText = map[emailSpoofClass]string{
        emailSpoofNoMail:            "No — null MX indicates no-mail domain",
        emailSpoofUnprotected:       "Yes — no SPF or DMARC protection",
        emailSpoofReject:            "No — SPF and DMARC reject policy enforced",
        emailSpoofQuarantineFull:    "Unlikely — SPF and DMARC quarantine policy enforced",
        emailSpoofQuarantinePartial: "Partially — DMARC quarantine at limited percentage",
        emailSpoofMonitorOnly:       "Yes — DMARC is monitor-only (p=none)",
        emailSpoofSPFOnly:           "Likely — SPF alone cannot prevent spoofing",
        emailSpoofDMARCOnly:         "Partially — DMARC present but no SPF",
        emailSpoofUncertain:         "Uncertain — incomplete configuration",
}

type emailAnswerDetail struct {
        answer string
        reason string
        color  string
}

var emailAnswerDetails = map[emailSpoofClass]emailAnswerDetail{
        emailSpoofNoMail:            {"No", "null MX indicates no-mail domain", mapKeySuccess},
        emailSpoofUnprotected:       {answerYes, "no SPF or DMARC protection", mapKeyDanger},
        emailSpoofReject:            {"No", "SPF and DMARC reject policy enforced", mapKeySuccess},
        emailSpoofQuarantineFull:    {strUnlikely, "SPF and DMARC quarantine policy enforced", mapKeySuccess},
        emailSpoofQuarantinePartial: {strPartially, "DMARC quarantine at limited percentage", mapKeyWarning},
        emailSpoofMonitorOnly:       {answerYes, "DMARC is monitor-only (p=none)", mapKeyDanger},
        emailSpoofSPFOnly:           {strLikely, "SPF alone cannot prevent spoofing", mapKeyDanger},
        emailSpoofDMARCOnly:         {strPartially, "DMARC present but no SPF", mapKeyWarning},
        emailSpoofUncertain:         {"Uncertain", "incomplete configuration", mapKeyWarning},
}

func buildEmailAnswer(ps protocolState, hasSPF, hasDMARC bool) string {
        cls := classifyEmailSpoofability(ps, hasSPF, hasDMARC)
        if text, ok := emailAnswerText[cls]; ok {
                return text
        }
        return emailAnswerText[emailSpoofUncertain]
}

func buildEmailAnswerStructured(ps protocolState, hasSPF, hasDMARC bool) map[string]string {
        cls := classifyEmailSpoofability(ps, hasSPF, hasDMARC)
        detail, ok := emailAnswerDetails[cls]
        if !ok {
                detail = emailAnswerDetails[emailSpoofUncertain]
        }
        return map[string]string{mapKeyAnswer: detail.answer, mapKeyReason: detail.reason, mapKeyColor: detail.color}
}

func buildEmailVerdict(vi verdictInput, verdicts map[string]any) {
        if vi.hasSPF && vi.hasDMARC && (vi.ps.dmarcPolicy == mapKeyReject || (vi.ps.dmarcPolicy == mapKeyQuarantine && vi.ps.dmarcPct >= 100)) {
                buildEnforcingEmailVerdict(vi.ps, vi.ds, verdicts)
                return
        }

        if vi.hasSPF && !vi.hasDMARC {
                verdicts[mapKeyEmailSpoofing] = map[string]any{
                        mapKeyLabel: strBasic,
                        mapKeyColor: mapKeyWarning,
                        mapKeyIcon:  iconShieldAlt,
                }
                return
        }

        if !vi.hasSPF && !vi.hasDMARC {
                verdicts[mapKeyEmailSpoofing] = map[string]any{
                        mapKeyLabel: strExposed,
                        mapKeyColor: mapKeyDanger,
                        mapKeyIcon:  iconExclamationTriangle,
                }
                return
        }

        if vi.hasSPF && vi.hasDMARC {
                verdicts[mapKeyEmailSpoofing] = map[string]any{
                        mapKeyLabel: strBasic,
                        mapKeyColor: mapKeyWarning,
                        mapKeyIcon:  iconShieldAlt,
                }
                return
        }

        verdicts[mapKeyEmailSpoofing] = map[string]any{
                mapKeyLabel: strExposed,
                mapKeyColor: mapKeyDanger,
                mapKeyIcon:  iconExclamationTriangle,
        }
}

func buildEnforcingEmailVerdict(ps protocolState, ds DKIMState, verdicts map[string]any) {
        verdicts[mapKeyEmailSpoofing] = map[string]any{
                mapKeyLabel: strProtected,
                mapKeyColor: mapKeySuccess,
                mapKeyIcon:  iconShieldAlt,
        }
}

func buildBrandVerdict(ps protocolState, verdicts map[string]any) {
        if ps.dmarcMissing {
                verdicts[mapKeyBrandImpersonation] = map[string]any{
                        mapKeyLabel:  strExposed,
                        mapKeyColor:  mapKeyDanger,
                        mapKeyIcon:   iconExclamationTriangle,
                        mapKeyAnswer: answerYes,
                        mapKeyReason: "No DMARC policy (RFC 7489) — attackers can send email appearing to be from this domain with no sender-authentication barrier",
                }
                return
        }

        switch ps.dmarcPolicy {
        case mapKeyReject:
                verdicts[mapKeyBrandImpersonation] = buildBrandRejectVerdict(ps)
        case mapKeyQuarantine:
                verdicts[mapKeyBrandImpersonation] = buildBrandQuarantineVerdict(ps)
        default:
                verdicts[mapKeyBrandImpersonation] = buildBrandWeakVerdict(ps)
        }
}

func buildBrandRejectVerdict(ps protocolState) map[string]any {
        if ps.bimiOK && ps.caaOK {
                return map[string]any{
                        mapKeyLabel:  strProtected,
                        mapKeyColor:  mapKeySuccess,
                        mapKeyIcon:   iconShieldAlt,
                        mapKeyAnswer: "No",
                        mapKeyReason: "DMARC reject policy enforced (RFC 7489 §6.3), BIMI brand verification active (BIMI Spec), and certificate issuance restricted by CAA (RFC 8659 §4) — all three brand-faking vectors addressed",
                }
        }
        if ps.bimiOK {
                reason := "DMARC reject policy blocks email spoofing (RFC 7489 §6.3) and BIMI with VMC provides verified brand identity in inboxes — email-based brand faking is effectively blocked"
                if !ps.caaOK {
                        reason += "; adding CAA records (RFC 8659) would further restrict certificate issuance for lookalike domains"
                }
                return map[string]any{
                        mapKeyLabel:  "Well Protected",
                        mapKeyColor:  mapKeySuccess,
                        mapKeyIcon:   iconShieldAlt,
                        mapKeyAnswer: strUnlikely,
                        mapKeyReason: reason,
                }
        }
        if ps.caaOK {
                return map[string]any{
                        mapKeyLabel:  "Mostly Protected",
                        mapKeyColor:  statusInfoPosture,
                        mapKeyIcon:   iconShieldAlt,
                        mapKeyAnswer: strPossible,
                        mapKeyReason: "DMARC reject policy blocks email spoofing (RFC 7489 §6.3) and CAA restricts certificate issuance (RFC 8659 §4), but no BIMI brand verification — lookalike domains display identically in inboxes without visual proof of authenticity",
                }
        }
        return map[string]any{
                mapKeyLabel:  "Partially Protected",
                mapKeyColor:  mapKeyWarning,
                mapKeyIcon:   iconExclamationTriangle,
                mapKeyAnswer: strPossible,
                mapKeyReason: "DMARC reject policy blocks email spoofing (RFC 7489 §6.3), but no BIMI brand verification and no CAA certificate restriction (RFC 8659) — visual impersonation via lookalike domains and unrestricted certificate issuance remain open vectors",
        }
}

func buildBrandQuarantineVerdict(ps protocolState) map[string]any {
        if ps.bimiOK && ps.caaOK {
                return map[string]any{
                        mapKeyLabel:  "Well Protected",
                        mapKeyColor:  mapKeySuccess,
                        mapKeyIcon:   iconShieldAlt,
                        mapKeyAnswer: strUnlikely,
                        mapKeyReason: "DMARC quarantine enforced (RFC 7489 §6.3) with BIMI brand verification (VMC-validated logo in inboxes) and CAA certificate restriction (RFC 8659 §4) — all three brand-faking vectors addressed; upgrade to p=reject to block spoofed mail outright instead of flagging",
                }
        }
        if ps.bimiOK {
                reason := "DMARC quarantine flags spoofed mail (RFC 7489 §6.3) and BIMI with VMC provides verified brand identity in inboxes; upgrade to p=reject to block spoofed mail outright"
                if !ps.caaOK {
                        reason += "; adding CAA records (RFC 8659) would further restrict certificate issuance for lookalike domains"
                }
                return map[string]any{
                        mapKeyLabel:  "Mostly Protected",
                        mapKeyColor:  statusInfoPosture,
                        mapKeyIcon:   iconShieldAlt,
                        mapKeyAnswer: strPossible,
                        mapKeyReason: reason,
                }
        }
        if ps.caaOK {
                return map[string]any{
                        mapKeyLabel:  "Partially Protected",
                        mapKeyColor:  mapKeyWarning,
                        mapKeyIcon:   iconExclamationTriangle,
                        mapKeyAnswer: strLikely,
                        mapKeyReason: "DMARC quarantine flags but does not reject spoofed mail (RFC 7489 §6.3), and no BIMI brand verification — lookalike domains display identically in inboxes; CAA restricts certificate issuance (RFC 8659 §4) but visual brand faking remains open",
                }
        }
        return map[string]any{
                mapKeyLabel:  strBasic,
                mapKeyColor:  mapKeyWarning,
                mapKeyIcon:   iconExclamationTriangle,
                mapKeyAnswer: strLikely,
                mapKeyReason: "DMARC quarantine flags but does not reject spoofed mail (RFC 7489 §6.3) — no BIMI or CAA (RFC 8659) reinforcement leaves brand impersonation largely unaddressed",
        }
}

func buildBrandWeakVerdict(ps protocolState) map[string]any {
        reason := "DMARC policy is not set to reject (RFC 7489 §6.3) — partial protection only"
        if ps.dmarcPolicy == statusNone {
                reason = "DMARC is monitor-only p=none (RFC 7489 §6.3) — spoofed mail is not blocked, brand faking is trivial"
        }
        return map[string]any{
                mapKeyLabel:  strBasic,
                mapKeyColor:  mapKeyWarning,
                mapKeyIcon:   iconExclamationTriangle,
                mapKeyAnswer: strLikely,
                mapKeyReason: reason,
        }
}

func buildDNSVerdict(ps protocolState, verdicts map[string]any) {
        if ps.dnssecOK {
                verdicts[mapKeyDnsTampering] = map[string]any{
                        mapKeyLabel:  strProtected,
                        mapKeyColor:  mapKeySuccess,
                        mapKeyIcon:   iconShieldAlt,
                        mapKeyAnswer: "No",
                        mapKeyReason: "DNSSEC signed and validated, cryptographic chain of trust verified",
                }
        } else if ps.dnssecBroken {
                verdicts[mapKeyDnsTampering] = map[string]any{
                        mapKeyLabel:  strExposed,
                        mapKeyColor:  mapKeyDanger,
                        mapKeyIcon:   iconExclamationTriangle,
                        mapKeyAnswer: answerYes,
                        mapKeyReason: "DNSSEC validation is failing, DNS responses cannot be trusted",
                }
        } else {
                verdicts[mapKeyDnsTampering] = map[string]any{
                        mapKeyLabel:  "Not Configured",
                        mapKeyColor:  mapKeySecondary,
                        mapKeyIcon:   iconShieldAlt,
                        mapKeyAnswer: strPossible,
                        mapKeyReason: "DNSSEC is not deployed, DNS responses are not cryptographically verified",
                }
        }
}

func buildTransportVerdict(ps protocolState, verdicts map[string]any) {
        if ps.mtaStsOK && ps.daneOK {
                verdicts[mapKeyTransport] = map[string]any{
                        mapKeyLabel:  "Fully Protected",
                        mapKeyColor:  mapKeySuccess,
                        mapKeyAnswer: answerYes,
                        mapKeyReason: "Both MTA-STS and DANE enforce encrypted mail delivery",
                }
        } else if ps.mtaStsOK {
                verdicts[mapKeyTransport] = map[string]any{
                        mapKeyLabel:  strProtected,
                        mapKeyColor:  mapKeySuccess,
                        mapKeyAnswer: answerYes,
                        mapKeyReason: "MTA-STS enforces TLS for all inbound mail delivery",
                }
        } else if ps.daneOK {
                verdicts[mapKeyTransport] = map[string]any{
                        mapKeyLabel:  strProtected,
                        mapKeyColor:  mapKeySuccess,
                        mapKeyAnswer: answerYes,
                        mapKeyReason: "DANE/TLSA provides cryptographic transport verification",
                }
        } else if ps.tlsrptOK {
                verdicts[mapKeyTransport] = map[string]any{
                        mapKeyLabel:  "Monitoring",
                        mapKeyColor:  statusInfoPosture,
                        mapKeyAnswer: strPartially,
                        mapKeyReason: "TLS reporting is configured but no transport enforcement policy is active",
                }
        } else {
                verdicts[mapKeyTransport] = map[string]any{
                        mapKeyLabel:  "Not Enforced",
                        mapKeyColor:  mapKeySecondary,
                        mapKeyAnswer: "No",
                        mapKeyReason: "No MTA-STS or DANE — mail transport encryption is opportunistic only",
                }
        }
}

func getNumericValue(m map[string]any, key string) float64 {
        v, ok := m[key]
        if !ok {
                return 0
        }
        switch n := v.(type) {
        case float64:
                return n
        case int:
                return float64(n)
        case int64:
                return float64(n)
        }
        return 0
}

func buildAISurfaceVerdicts(results, verdicts map[string]any) {
        aiSurface, ok := results["ai_surface"].(map[string]any)
        if !ok {
                return
        }

        llmsTxt, _ := aiSurface["llms_txt"].(map[string]any)
        robotsTxt, _ := aiSurface["robots_txt"].(map[string]any)
        poisoning, _ := aiSurface["poisoning"].(map[string]any)
        hiddenPrompts, _ := aiSurface["hidden_prompts"].(map[string]any)

        buildLlmsTxtVerdict(llmsTxt, verdicts)
        buildRobotsTxtVerdict(robotsTxt, verdicts)
        buildPoisoningVerdict(poisoning, verdicts)
        buildHiddenPromptsVerdict(hiddenPrompts, verdicts)
}

func buildLlmsTxtVerdict(llmsTxt, verdicts map[string]any) {
        if llmsTxt == nil {
                return
        }
        found, _ := llmsTxt["found"].(bool)
        fullFound, _ := llmsTxt["full_found"].(bool)
        if found && fullFound {
                verdicts[mapKeyAiLlmsTxt] = map[string]any{
                        mapKeyAnswer: answerYes,
                        mapKeyColor:  mapKeySuccess,
                        mapKeyReason: "llms.txt and llms-full.txt published — AI models receive structured context about this domain",
                }
        } else if found {
                verdicts[mapKeyAiLlmsTxt] = map[string]any{
                        mapKeyAnswer: answerYes,
                        mapKeyColor:  mapKeySuccess,
                        mapKeyReason: "llms.txt published — AI models receive structured context about this domain",
                }
        } else {
                verdicts[mapKeyAiLlmsTxt] = map[string]any{
                        mapKeyAnswer: "No",
                        mapKeyColor:  mapKeySecondary,
                        mapKeyReason: "No llms.txt file detected — AI models have no structured instructions for this domain",
                }
        }
}

func buildRobotsTxtVerdict(robotsTxt, verdicts map[string]any) {
        if robotsTxt == nil {
                return
        }
        found, _ := robotsTxt["found"].(bool)
        blocksAI, _ := robotsTxt["blocks_ai_crawlers"].(bool)
        if found && blocksAI {
                verdicts[mapKeyAiCrawlerGovernance] = map[string]any{
                        mapKeyAnswer: answerYes,
                        mapKeyColor:  mapKeySuccess,
                        mapKeyReason: "robots.txt actively blocks AI crawlers from scraping site content",
                }
        } else if found {
                verdicts[mapKeyAiCrawlerGovernance] = map[string]any{
                        mapKeyAnswer: "No",
                        mapKeyColor:  mapKeyWarning,
                        mapKeyReason: "robots.txt present but does not block AI crawlers — content may be freely scraped",
                }
        } else {
                verdicts[mapKeyAiCrawlerGovernance] = map[string]any{
                        mapKeyAnswer: "No",
                        mapKeyColor:  mapKeySecondary,
                        mapKeyReason: "No robots.txt found — AI crawlers have unrestricted access",
                }
        }
}

func buildPoisoningVerdict(poisoning, verdicts map[string]any) {
        if poisoning == nil {
                return
        }
        iocCount := getNumericValue(poisoning, "ioc_count")
        if iocCount > 0 {
                verdicts["ai_poisoning"] = map[string]any{
                        mapKeyAnswer: answerYes,
                        mapKeyColor:  mapKeyDanger,
                        mapKeyReason: fmt.Sprintf("%.0f indicator(s) of AI recommendation manipulation detected on homepage", iocCount),
                }
        } else {
                verdicts["ai_poisoning"] = map[string]any{
                        mapKeyAnswer: "No",
                        mapKeyColor:  mapKeySuccess,
                        mapKeyReason: "No indicators of AI recommendation manipulation found",
                }
        }
}

func buildHiddenPromptsVerdict(hiddenPrompts, verdicts map[string]any) {
        if hiddenPrompts == nil {
                return
        }
        artifactCount := getNumericValue(hiddenPrompts, "artifact_count")
        if artifactCount > 0 {
                verdicts["ai_hidden_prompts"] = map[string]any{
                        mapKeyAnswer: answerYes,
                        mapKeyColor:  mapKeyDanger,
                        mapKeyReason: fmt.Sprintf("%.0f hidden prompt-like artifact(s) detected in page source", artifactCount),
                }
        } else {
                verdicts["ai_hidden_prompts"] = map[string]any{
                        mapKeyAnswer: "No",
                        mapKeyColor:  mapKeySuccess,
                        mapKeyReason: "No hidden prompt artifacts found in page source",
                }
        }
}

func computeInternalScore(ps protocolState, ds DKIMState) int {
        score := 0
        score += computeSPFScore(ps)
        score += computeDMARCScore(ps)
        score += computeDKIMScore(ds)
        score += computeAuxScore(ps)
        if score > 100 {
                score = 100
        }
        return score
}

func computeSPFScore(ps protocolState) int {
        if ps.spfMissing {
                return 0
        }
        if ps.spfDangerous {
                return 5
        }
        if ps.spfHardFail {
                return 20
        }
        return 15
}

func computeDMARCScore(ps protocolState) int {
        if ps.dmarcMissing {
                return 0
        }
        switch ps.dmarcPolicy {
        case mapKeyReject:
                return 30
        case mapKeyQuarantine:
                if ps.dmarcPct >= 100 {
                        return 25
                }
                return 20
        case statusNone:
                if ps.dmarcHasRua {
                        return 10
                }
                return 5
        }
        return 10
}

func computeDKIMScore(ds DKIMState) int {
        switch ds {
        case DKIMSuccess:
                return 15
        case DKIMProviderInferred:
                return 12
        case DKIMThirdPartyOnly:
                return 8
        case DKIMWeakKeysOnly:
                return 5
        case DKIMNoMailDomain:
                return 15
        }
        return 0
}

func computeAuxScore(ps protocolState) int {
        score := 0
        if ps.dnssecOK {
                score += 10
        }
        if ps.daneOK {
                score += 5
        }
        if ps.mtaStsOK {
                score += 5
        }
        if ps.tlsrptOK {
                score += 5
        }
        if ps.caaOK {
                score += 5
        }
        if ps.bimiOK {
                score += 5
        }
        return score
}
