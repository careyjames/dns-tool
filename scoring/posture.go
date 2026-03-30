// Copyright (c) 2024-2026 IT Help San Diego Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL — See LICENSE for terms.
// This file is part of the DNS Tool Intelligence Module.
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

        postureStatus    = "status"
        postureSuccess   = "success"
        postureWarning   = "warning"
        policyReject     = "reject"
        policyQuarantine = "quarantine"
        policyNone       = "none"
        answerYes        = "Yes"
        answerNo         = "No"
        answerPartially  = "Partially"
        answerMostlyNo   = "Mostly No"
        verdictEmail       = "email"
        verdictEmailSecure = "email_secure"
        verdictEmailAnswer = "email_answer"
        verdictBrand       = "brand"
        verdictBrandSecure = "brand_secure"
        verdictBrandAnswer = "brand_answer"
        verdictDNS         = "dns"
        verdictDNSSecure   = "dns_secure"
        verdictDomainAns   = "domain_answer"
        protDNSSEC = "DNSSEC"
        protDMARC  = "DMARC"
)


type protocolState struct {
        spfOK              bool
        spfWarning         bool
        spfMissing         bool
        spfHardFail        bool
        spfDangerous       bool
        spfNeutral         bool
        spfLookupExceeded  bool
        spfLookupCount     int
        dmarcOK            bool
        dmarcWarning       bool
        dmarcMissing       bool
        dmarcPolicy        string
        dmarcPct           int
        dmarcHasRua        bool
        dkimOK             bool
        dkimProvider       bool
        dkimPartial        bool
        dkimWeakKeys       bool
        dkimThirdPartyOnly bool
        caaOK              bool
        mtaStsOK           bool
        tlsrptOK           bool
        bimiOK             bool
        daneOK             bool
        dnssecOK           bool
        dnssecBroken       bool
        primaryProvider    string
        isNoMailDomain     bool
}

type postureAccumulator struct {
        issues          []string
        recommendations []string
        monitoring      []string
        configured      []string
        absent          []string
}

func evaluateProtocolStates(results map[string]any) protocolState {
        spf := getMapResult(results, "spf_analysis")
        dmarc := getMapResult(results, "dmarc_analysis")
        dkim := getMapResult(results, "dkim_analysis")
        mtaSts := getMapResult(results, "mta_sts_analysis")
        tlsrpt := getMapResult(results, "tlsrpt_analysis")
        bimi := getMapResult(results, "bimi_analysis")
        dane := getMapResult(results, "dane_analysis")
        caa := getMapResult(results, "caa_analysis")
        dnssec := getMapResult(results, "dnssec_analysis")

        dmarcPolicy, _ := dmarc["policy"].(string)
        primaryProvider, _ := dkim["primary_provider"].(string)
        allMech, _ := spf["all_mechanism"].(string)
        spfPerm, _ := spf["permissiveness"].(string)
        dnssecChain, _ := dnssec["chain_of_trust"].(string)

        spfLookupCount := extractIntField(spf, "lookup_count")
        dkimWeakKeys, dkimThirdPartyOnly := evaluateDKIMIssues(dkim)

        spfNoMailIntent := getBool(spf, "no_mail_intent")
        isNoMailDomain := spfNoMailIntent || (allMech == "-all" && getBool(results, "has_null_mx"))

        return protocolState{
                spfOK:              spf[postureStatus] == postureSuccess,
                spfWarning:         spf[postureStatus] == postureWarning,
                spfMissing:         isMissingRecord(spf),
                spfHardFail:        allMech == "-all",
                spfDangerous:       spfPerm == "DANGEROUS",
                spfNeutral:         spfPerm == "NEUTRAL",
                spfLookupExceeded:  spfLookupCount > 10,
                spfLookupCount:     spfLookupCount,
                dmarcOK:            dmarc[postureStatus] == postureSuccess,
                dmarcWarning:       dmarc[postureStatus] == postureWarning,
                dmarcMissing:       isMissingRecord(dmarc),
                dmarcPolicy:        dmarcPolicy,
                dmarcPct:           extractIntFieldDefault(dmarc, "pct", 100),
                dmarcHasRua:        hasNonEmptyString(dmarc, "rua"),
                dkimOK:             dkim[postureStatus] == postureSuccess,
                dkimProvider:       dkim[postureStatus] == "info" && isKnownDKIMProvider(primaryProvider),
                dkimPartial:        (dkim[postureStatus] == "info" && !isKnownDKIMProvider(primaryProvider)) || dkim[postureStatus] == "partial",
                dkimWeakKeys:       dkimWeakKeys,
                dkimThirdPartyOnly: dkimThirdPartyOnly || dkim[postureStatus] == "partial",
                caaOK:              caa[postureStatus] == postureSuccess,
                mtaStsOK:           mtaSts[postureStatus] == postureSuccess,
                tlsrptOK:           tlsrpt[postureStatus] == postureSuccess,
                bimiOK:             bimi[postureStatus] == postureSuccess,
                daneOK:             dane["has_dane"] == true,
                dnssecOK:           dnssec[postureStatus] == postureSuccess,
                dnssecBroken:       dnssecChain == "broken",
                primaryProvider:    primaryProvider,
                isNoMailDomain:     isNoMailDomain,
        }
}

func isMissingRecord(m map[string]any) bool {
        if m[postureStatus] != postureWarning {
                return false
        }
        records, _ := m["valid_records"].([]string)
        return len(records) == 0
}

func hasNonEmptyString(m map[string]any, key string) bool {
        s, ok := m[key].(string)
        return ok && s != ""
}

func extractIntField(m map[string]any, key string) int {
        if v, ok := m[key].(int); ok {
                return v
        }
        if v, ok := m[key].(float64); ok {
                return int(v)
        }
        return 0
}

func extractIntFieldDefault(m map[string]any, key string, defaultVal int) int {
        if v, ok := m[key].(int); ok {
                return v
        }
        return defaultVal
}

func evaluateDKIMIssues(dkim map[string]any) (weakKeys bool, thirdPartyOnly bool) {
        switch ki := dkim["key_issues"].(type) {
        case []string:
                for _, s := range ki {
                        if strings.Contains(s, "1024") {
                                weakKeys = true
                        }
                }
        case []any:
                for _, issue := range ki {
                        if s, ok := issue.(string); ok && strings.Contains(s, "1024") {
                                weakKeys = true
                        }
                }
        }
        if tpo, ok := dkim["third_party_only"].(bool); ok {
                thirdPartyOnly = tpo
        }
        return
}

func classifySPF(ps protocolState, acc *postureAccumulator) {
        if ps.spfDangerous {
                acc.configured = append(acc.configured, "SPF (+all)")
                acc.issues = append(acc.issues, "SPF uses +all — anyone can send as this domain")
                return
        }
        if ps.spfNeutral {
                acc.configured = append(acc.configured, "SPF (?all)")
                acc.issues = append(acc.issues, "SPF uses ?all — provides no protection")
                return
        }
        if ps.spfOK {
                if ps.spfHardFail {
                        acc.configured = append(acc.configured, "SPF (-all)")
                } else {
                        acc.configured = append(acc.configured, "SPF (~all)")
                }
                return
        }
        if ps.spfWarning && !ps.spfMissing {
                acc.configured = append(acc.configured, "SPF")
                acc.issues = append(acc.issues, "SPF needs attention")
                return
        }
        acc.absent = append(acc.absent, "SPF")
        acc.issues = append(acc.issues, "No SPF record")
}

func classifyDMARC(ps protocolState, acc *postureAccumulator) {
        if ps.dmarcOK {
                classifyDMARCSuccess(ps, acc)
                return
        }
        if ps.dmarcWarning && !ps.dmarcMissing {
                classifyDMARCWarning(ps, acc)
                return
        }
        acc.absent = append(acc.absent, protDMARC)
        acc.issues = append(acc.issues, "No DMARC record")
}

func classifyDMARCSuccess(ps protocolState, acc *postureAccumulator) {
        switch ps.dmarcPolicy {
        case policyReject:
                acc.configured = append(acc.configured, "DMARC (reject)")
        case policyQuarantine:
                acc.configured = append(acc.configured, "DMARC (quarantine)")
        default:
                acc.configured = append(acc.configured, protDMARC)
        }
}

func classifyDMARCWarning(ps protocolState, acc *postureAccumulator) {
        if ps.dmarcPolicy == policyNone {
                acc.monitoring = append(acc.monitoring, "DMARC in monitoring mode (p=none)")
                return
        }
        if ps.dmarcPct < 100 {
                acc.configured = append(acc.configured, fmt.Sprintf("DMARC (%s, pct=%d%%)", ps.dmarcPolicy, ps.dmarcPct))
                acc.issues = append(acc.issues, fmt.Sprintf("DMARC enforcement partial — only %d%% of mail subject to policy", ps.dmarcPct))
                return
        }
        acc.issues = append(acc.issues, "DMARC needs strengthening")
}

func classifyDKIMPosture(ds DKIMState, primaryProvider string, acc *postureAccumulator) {
        switch ds {
        case DKIMSuccess:
                acc.configured = append(acc.configured, "DKIM")
        case DKIMProviderInferred:
                acc.configured = append(acc.configured, "DKIM (provider-verified)")
        case DKIMThirdPartyOnly:
                acc.configured = append(acc.configured, "DKIM (third-party)")
                acc.recommendations = append(acc.recommendations,
                        fmt.Sprintf("DKIM found for third-party senders only — enable DKIM for primary mail platform (%s) for full alignment", primaryProvider))
        case DKIMInconclusive:
                acc.monitoring = append(acc.monitoring, "DKIM (inconclusive)")
                acc.recommendations = append(acc.recommendations,
                        "DKIM not discoverable via common selectors — may be configured with custom or rotating selectors (RFC 6376 §3.6.2.1)")
        case DKIMNoMailDomain:
                acc.recommendations = append(acc.recommendations,
                        "DKIM not applicable for no-mail domains — DKIM signing is only relevant for domains that send email")
        case DKIMAbsent:
                acc.absent = append(acc.absent, "DKIM")
                acc.issues = append(acc.issues, "No DKIM found")
        }
}

func classifySimpleProtocols(ps protocolState, acc *postureAccumulator) {
        if ps.mtaStsOK {
                acc.configured = append(acc.configured, protocolMTASTS)
        } else {
                acc.absent = append(acc.absent, protocolMTASTS)
        }

        if ps.tlsrptOK {
                acc.configured = append(acc.configured, protocolTLSRPT)
        } else {
                acc.absent = append(acc.absent, protocolTLSRPT)
        }

        if ps.bimiOK {
                acc.configured = append(acc.configured, "BIMI")
        }
        if ps.daneOK {
                acc.configured = append(acc.configured, "DANE")
        }

        if ps.caaOK {
                acc.configured = append(acc.configured, "CAA")
        } else {
                acc.absent = append(acc.absent, "CAA")
        }

        if ps.dnssecOK {
                acc.configured = append(acc.configured, protDNSSEC)
        } else {
                acc.absent = append(acc.absent, protDNSSEC)
        }
}

func classifyDanglingDNS(results map[string]any, acc *postureAccumulator) {
        dangling := getMapResult(results, "dangling_dns")
        if dangling == nil {
                return
        }
        count := extractIntField(dangling, "dangling_count")
        if count > 0 {
                acc.issues = append(acc.issues, fmt.Sprintf("%d dangling DNS record(s) detected — potential subdomain takeover risk", count))
        }
}

func classifyDMARCReportAuth(results map[string]any, acc *postureAccumulator) {
        auth := getMapResult(results, "dmarc_report_auth")
        if auth == nil || !getBool(auth, "checked") {
                return
        }
        domains := extractExternalDomainMaps(auth["external_domains"])
        for _, ed := range domains {
                if authorized, ok := ed["authorized"].(bool); ok && !authorized {
                        domain, _ := ed["external_domain"].(string)
                        acc.recommendations = append(acc.recommendations, fmt.Sprintf("DMARC external reporting to %s is not authorized (RFC 7489 §7.1)", domain))
                }
        }
}

func extractExternalDomainMaps(raw any) []map[string]any {
        switch v := raw.(type) {
        case []map[string]any:
                return v
        case []any:
                var result []map[string]any
                for _, item := range v {
                        if ed, ok := item.(map[string]any); ok {
                                result = append(result, ed)
                        }
                }
                return result
        }
        return nil
}

func evaluateDeliberateMonitoring(ps protocolState, configuredCount int) (bool, string) {
        if ps.dmarcPolicy != "none" {
                return false, ""
        }
        if configuredCount < 3 {
                return false, ""
        }

        if ps.dmarcHasRua {
                return true, "DMARC is in monitoring mode (p=none) with aggregate reporting active — this appears to be a deliberate deployment phase before enforcement"
        }
        if ps.dnssecOK || ps.daneOK || ps.mtaStsOK {
                return true, "DMARC is in monitoring mode (p=none) with advanced security controls (DNSSEC/DANE/MTA-STS) deployed — this indicates sophisticated security management with deliberate monitoring"
        }
        return true, "DMARC is in monitoring mode (p=none) — this appears intentional while gathering data before enforcement"
}

func (a *Analyzer) CalculatePosture(results map[string]any) map[string]any {
        ps := evaluateProtocolStates(results)
        ds := classifyDKIMState(ps)

        acc := &postureAccumulator{}

        hasSPF := ps.spfOK || (ps.spfWarning && !ps.spfMissing)
        hasDMARC := ps.dmarcOK || (ps.dmarcWarning && !ps.dmarcMissing)
        hasDKIM := ds.IsPresent()

        classifySPF(ps, acc)
        classifyDMARC(ps, acc)

        if hasDMARC && !ps.dmarcHasRua {
                acc.recommendations = append(acc.recommendations, "No DMARC aggregate reporting (rua) configured — unable to monitor authentication results")
        }

        classifyDKIMPosture(ds, ps.primaryProvider, acc)
        classifySimpleProtocols(ps, acc)
        classifyDanglingDNS(results, acc)
        classifyDMARCReportAuth(results, acc)

        state, icon, color, message := determineGrade(ps, ds, hasSPF, hasDMARC, hasDKIM, acc.monitoring, acc.configured, acc.absent)

        deliberateMonitoring, deliberateMonitoringNote := evaluateDeliberateMonitoring(ps, len(acc.configured))

        score := computeInternalScore(ps, ds)
        verdicts := buildVerdicts(ps, ds, hasSPF, hasDMARC, hasDKIM)
        allIssues := append(acc.issues, acc.recommendations...)

        return map[string]any{
                "score":                      score,
                "grade":                      state,
                "label":                      message,
                "state":                      state,
                "icon":                       icon,
                "color":                      color,
                "message":                    message,
                "issues":                     allIssues,
                "critical_issues":            acc.issues,
                "recommendations":            acc.recommendations,
                "monitoring":                 acc.monitoring,
                "configured":                 acc.configured,
                "absent":                     acc.absent,
                "deliberate_monitoring":      deliberateMonitoring,
                "deliberate_monitoring_note": deliberateMonitoringNote,
                "verdicts":                   verdicts,
        }
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
}

func determineGrade(ps protocolState, ds DKIMState, hasSPF, hasDMARC, hasDKIM bool, monitoring, configured, absent []string) (state, icon, color, message string) {
        gi := gradeInput{
                corePresent:           hasSPF && hasDMARC && hasDKIM,
                dmarcFullEnforcing:    (ps.dmarcPolicy == policyReject || ps.dmarcPolicy == policyQuarantine) && ps.dmarcPct == 100,
                dmarcPartialEnforcing: (ps.dmarcPolicy == policyReject || ps.dmarcPolicy == policyQuarantine) && ps.dmarcPct < 100,
                dmarcStrict:           ps.dmarcPolicy == policyReject && ps.dmarcPct == 100,
                hasCAA:                ps.caaOK,
                hasSPF:                hasSPF,
                hasDMARC:              hasDMARC,
                hasDKIM:               hasDKIM,
                dkimInconclusive:      ds == DKIMInconclusive,
                isNoMail:              ds == DKIMNoMailDomain,
        }

        state, icon, color, message = classifyGrade(ps, gi, monitoring, configured, absent)
        state = applyMonitoringSuffix(state, monitoring)
        return
}

func classifyGrade(ps protocolState, gi gradeInput, monitoring, configured, absent []string) (string, string, string, string) {
        if gi.isNoMail {
                return classifyNoMailGrade(ps, gi, configured, absent)
        }
        return classifyMailGrade(ps, gi, monitoring, configured, absent)
}

func classifyMailGrade(ps protocolState, gi gradeInput, monitoring, configured, absent []string) (string, string, string, string) {
        if gi.corePresent {
                return classifyMailCorePresent(ps, gi, monitoring, configured, absent)
        }
        return classifyMailPartial(gi)
}

func classifyMailCorePresent(ps protocolState, gi gradeInput, monitoring, configured, absent []string) (string, string, string, string) {
        if gi.dmarcStrict && gi.hasCAA && ps.dnssecOK {
                return "Secure", iconShieldAlt, postureSuccess, buildDescriptiveMessage(ps, configured, absent, monitoring)
        }
        if (gi.dmarcStrict && gi.hasCAA) || gi.dmarcFullEnforcing {
                return riskLow, iconShieldAlt, postureSuccess, buildDescriptiveMessage(ps, configured, absent, monitoring)
        }
        if gi.dmarcPartialEnforcing {
                return riskMedium, iconExclamationTriangle, postureWarning,
                        fmt.Sprintf("Email authentication configured but DMARC enforcement is partial (pct=%d%%). Only %d%% of failing mail is subject to policy.", ps.dmarcPct, ps.dmarcPct)
        }
        if ps.dmarcPolicy == policyNone {
                return riskMedium, iconExclamationTriangle, postureWarning,
                        "Email authentication configured but DMARC is in monitoring mode (p=none). Enforcement recommended after reviewing reports."
        }
        return riskLow, iconShieldAlt, postureSuccess, buildDescriptiveMessage(ps, configured, absent, monitoring)
}

func classifyMailPartial(gi gradeInput) (string, string, string, string) {
        if gi.hasSPF && gi.hasDMARC && !gi.hasDKIM {
                if gi.dkimInconclusive {
                        return riskLow + " Monitoring", iconExclamationTriangle, postureWarning,
                                "SPF and DMARC present. DKIM not discoverable via common selectors but may be configured with custom or rotating selectors."
                }
                return riskMedium, iconExclamationTriangle, postureWarning,
                        "SPF and DMARC present but DKIM not verified. DKIM signing is required for full DMARC alignment."
        }
        if gi.hasSPF && !gi.hasDMARC {
                return riskHigh, iconExclamationTriangle, postureWarning,
                        "SPF configured but no DMARC policy. Without DMARC, SPF alone cannot prevent email spoofing."
        }
        if !gi.hasSPF && !gi.hasDMARC && !gi.hasDKIM {
                return riskCritical, "times-circle", "danger",
                        "No email authentication configured. This domain is fully vulnerable to email spoofing."
        }
        return riskHigh, iconExclamationTriangle, postureWarning,
                "Partial email authentication. Critical security controls are missing."
}

func classifyNoMailGrade(ps protocolState, gi gradeInput, configured, absent []string) (string, string, string, string) {
        hasReject := ps.dmarcPolicy == policyReject
        hasSPFDeny := ps.spfHardFail

        if hasSPFDeny && hasReject {
                return "Secure", iconShieldAlt, postureSuccess,
                        "No-mail domain properly secured. SPF -all rejects all senders, DMARC p=reject discards unauthenticated mail."
        }
        if hasSPFDeny || hasReject {
                return riskLow, iconShieldAlt, postureSuccess,
                        "No-mail domain with partial protection. SPF and/or DMARC enforcement configured but not both are at full enforcement."
        }
        if gi.hasSPF {
                return riskMedium, iconExclamationTriangle, postureWarning,
                        "Domain appears to not send mail but SPF does not use -all (hardfail). Spoofing is still possible."
        }
        return riskHigh, iconExclamationTriangle, postureWarning,
                "Domain appears to not send mail but lacks proper no-mail protections (SPF -all, DMARC p=reject)."
}

func applyMonitoringSuffix(state string, monitoring []string) string {
        if len(monitoring) > 0 && state != riskCritical && state != riskHigh {
                if !strings.Contains(state, "Monitoring") {
                        state += " Monitoring"
                }
        }
        return state
}

func buildDescriptiveMessage(ps protocolState, configured, absent, monitoring []string) string {
        var parts []string

        if ps.dmarcPolicy == policyReject {
                if ps.dkimThirdPartyOnly {
                        parts = append(parts, "Email authentication with full DMARC enforcement. DKIM verified for third-party senders; primary provider DKIM recommended")
                } else {
                        parts = append(parts, "Email authentication with full DMARC enforcement")
                }
        } else if ps.dmarcPolicy == policyQuarantine {
                parts = append(parts, "Email authentication configured with DMARC quarantine policy")
        }

        var notConfigured []string
        for _, item := range absent {
                switch item {
                case protocolMTASTS, protocolTLSRPT, protDNSSEC, "BIMI":
                        notConfigured = append(notConfigured, item)
                }
        }

        if len(notConfigured) > 0 {
                parts = append(parts, fmt.Sprintf("%s not configured", strings.Join(notConfigured, ", ")))
        }

        if len(monitoring) > 0 {
                for _, m := range monitoring {
                        if strings.Contains(m, protDMARC) {
                                parts = append(parts, "DMARC in monitoring mode")
                        }
                }
        }

        if len(parts) == 0 {
                return "Comprehensive email and DNS security configured."
        }

        return strings.Join(parts, ". ") + "."
}

func buildVerdicts(ps protocolState, ds DKIMState, hasSPF, hasDMARC, hasDKIM bool) map[string]any {
        verdicts := make(map[string]any)
        buildEmailVerdict(ps, ds, hasSPF, hasDMARC, hasDKIM, verdicts)
        buildBrandVerdict(ps, verdicts)
        buildDNSVerdict(ps, verdicts)
        return verdicts
}

func buildEmailVerdict(ps protocolState, ds DKIMState, hasSPF, hasDMARC, hasDKIM bool, verdicts map[string]any) {
        enforcing := ps.dmarcPolicy == policyReject || ps.dmarcPolicy == policyQuarantine

        if hasSPF && hasDMARC && enforcing && hasDKIM {
                buildEnforcingEmailVerdict(ps, ds, verdicts)
                return
        }
        if hasSPF && hasDMARC && ps.dmarcPolicy == policyNone {
                verdicts[verdictEmail] = "Partial email authentication configured — some spoofed messages may be delivered. DMARC is in monitoring mode (p=none)."
                verdicts[verdictEmailSecure] = false
                verdicts[verdictEmailAnswer] = answerPartially
                return
        }
        if hasSPF && !hasDMARC {
                verdicts[verdictEmail] = "SPF is configured but without DMARC, receiving servers may still accept spoofed messages."
                verdicts[verdictEmailSecure] = false
                verdicts[verdictEmailAnswer] = answerYes
                return
        }
        if !hasSPF && !hasDMARC {
                verdicts[verdictEmail] = "No email authentication — this domain can be impersonated by anyone."
                verdicts[verdictEmailSecure] = false
                verdicts[verdictEmailAnswer] = answerYes
                return
        }
        verdicts[verdictEmail] = "Partial email authentication configured — some spoofed messages may be delivered."
        verdicts[verdictEmailSecure] = false
        verdicts[verdictEmailAnswer] = answerPartially
}

func buildEnforcingEmailVerdict(ps protocolState, ds DKIMState, verdicts map[string]any) {
        action := map[string]string{policyReject: "blocked", policyQuarantine: "flagged as spam"}[ps.dmarcPolicy]
        msg := "DMARC policy is " + ps.dmarcPolicy + " — spoofed messages will be " + action + " by receiving servers."

        switch ds {
        case DKIMThirdPartyOnly:
                msg += " DKIM verified for third-party senders; primary provider (" + ps.primaryProvider + ") DKIM not observed."
        case DKIMProviderInferred:
                msg += " DKIM keys verified (provider-verified for " + ps.primaryProvider + ")."
        default:
                msg += " DKIM keys verified with strong cryptography."
        }

        verdicts[verdictEmail] = msg
        verdicts[verdictEmailSecure] = ps.dmarcPolicy == policyReject
        if ps.dmarcPolicy == policyReject {
                verdicts[verdictEmailAnswer] = answerNo
        } else {
                verdicts[verdictEmailAnswer] = answerMostlyNo
        }
}

func buildBrandVerdict(ps protocolState, verdicts map[string]any) {
        switch {
        case ps.bimiOK && ps.caaOK:
                verdicts[verdictBrand] = "Attackers cannot easily spoof your logo or obtain fraudulent TLS certificates."
                verdicts[verdictBrandSecure] = true
                verdicts[verdictBrandAnswer] = answerNo
        case ps.caaOK:
                verdicts[verdictBrand] = "Certificate issuance restricted via CAA. BIMI not configured for brand logo protection."
                verdicts[verdictBrandSecure] = false
                verdicts[verdictBrandAnswer] = answerPartially
        case ps.bimiOK:
                verdicts[verdictBrand] = "BIMI brand logo configured. CAA not configured — any CA can issue certificates."
                verdicts[verdictBrandSecure] = false
                verdicts[verdictBrandAnswer] = answerPartially
        default:
                verdicts[verdictBrand] = "No brand protection configured. Any CA can issue certificates and no brand logo verification in place."
                verdicts[verdictBrandSecure] = false
                verdicts[verdictBrandAnswer] = answerYes
        }
}

func buildDNSVerdict(ps protocolState, verdicts map[string]any) {
        if ps.dnssecOK {
                verdicts[verdictDNS] = "DNS responses are cryptographically signed and verified via DNSSEC."
                verdicts[verdictDNSSecure] = true
                verdicts[verdictDomainAns] = answerNo
        } else {
                verdicts[verdictDNS] = "DNS responses are unsigned and could be spoofed. DNSSEC provides cryptographic verification."
                verdicts[verdictDNSSecure] = false
                verdicts[verdictDomainAns] = answerYes
        }
}

func computeInternalScore(ps protocolState, ds DKIMState) int {
        score := computeSPFScore(ps) + computeDMARCScore(ps) + computeDKIMScore(ds) + computeAuxScore(ps)
        if score > 100 {
                return 100
        }
        return score
}

func computeSPFScore(ps protocolState) int {
        if ps.spfMissing {
                return 0
        }
        if ps.spfOK {
                if ps.spfHardFail {
                        return 20
                }
                return 15
        }
        if ps.spfWarning {
                return 10
        }
        return 0
}

func computeDMARCScore(ps protocolState) int {
        if ps.dmarcMissing {
                return 0
        }
        if !ps.dmarcOK {
                if ps.dmarcWarning {
                        return 10
                }
                return 0
        }
        base := 25
        switch ps.dmarcPolicy {
        case policyReject:
                return base + 5
        case policyQuarantine:
                return base + 3
        }
        return base
}

func computeDKIMScore(ds DKIMState) int {
        switch ds {
        case DKIMSuccess:
                return 20
        case DKIMProviderInferred:
                return 15
        case DKIMThirdPartyOnly:
                return 12
        case DKIMInconclusive:
                return 5
        case DKIMWeakKeysOnly:
                return 10
        default:
                return 0
        }
}

func computeAuxScore(ps protocolState) int {
        score := 0
        if ps.mtaStsOK {
                score += 8
        }
        if ps.tlsrptOK {
                score += 4
        }
        if ps.bimiOK {
                score += 3
        }
        if ps.daneOK {
                score += 5
        }
        if ps.caaOK {
                score += 8
        }
        if ps.dnssecOK {
                score += 5
        }
        return score
}


