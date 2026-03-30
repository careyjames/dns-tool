// Copyright (c) 2024-2026 IT Help San Diego Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL — See LICENSE for terms.
// This file is part of the DNS Tool Intelligence Module.
package analyzer

import (
        "fmt"
        "strings"
)

const (
        severityCritical = "Critical"
        severityHigh     = "High"
        severityMedium   = "Medium"
        severityLow      = "Low"

        colorCritical = "danger"
        colorHigh     = "warning"
        colorMedium   = "info"
        colorLow      = "secondary"

        rfcDMARCPolicy    = "RFC 7489 §6.3"
        rfcDMARCPolicyURL = "https://datatracker.ietf.org/doc/html/rfc7489#section-6.3"

        dkimRecordExampleGeneric = "selector1._domainkey.%s TXT \"v=DKIM1; k=rsa; p=<public_key>\""

        tlsrptDescDefault = "TLS-RPT (TLS Reporting) sends you reports about TLS connection failures when other servers try to deliver mail to your domain. Helps diagnose MTA-STS and STARTTLS issues."
        tlsrptDescDANE    = "Your domain has DNSSEC + DANE — the strongest email transport security available. TLS-RPT adds operational visibility by reporting when sending servers fail DANE validation or encounter STARTTLS issues delivering to your MX hosts. It does not add security — it monitors the security you already have."
        tlsrptDescMTASTS  = "Your domain has MTA-STS configured for transport encryption. TLS-RPT complements MTA-STS by reporting when sending servers fail to establish TLS or encounter policy mismatches delivering to your domain. Essential for monitoring MTA-STS enforcement."

	helpRootDomain = "@ means the root domain itself \u2014 some providers show this as the domain name or leave it blank"
	helpDMARCHost  = "Enter _dmarc as the hostname \u2014 your provider will append the domain automatically"
)

func dkimRecordExample(domain, provider string) string {
        selector := dkimSelectorForProvider(provider)
        return fmt.Sprintf("%s._domainkey.%s TXT \"v=DKIM1; k=rsa; p=<public_key>\"", selector, domain)
}

func dkimSelectorForProvider(provider string) string {
        p := strings.ToLower(provider)
        switch {
        case strings.Contains(p, "google"):
                return "google"
        case strings.Contains(p, "microsoft"), strings.Contains(p, "365"):
                return "selector1"
        case strings.Contains(p, "amazon"), strings.Contains(p, "ses"):
                return "<unique_token>.dkim.amazonses"
        case strings.Contains(p, "zoho"):
                return "zmail"
        case strings.Contains(p, "protonmail"), strings.Contains(p, "proton"):
                return "protonmail"
        case strings.Contains(p, "fastmail"):
                return "fm1"
        default:
                return "selector1"
        }
}

type fix struct {
        Title         string
        Description   string
        DNSRecord     string
        DNSHost       string
        DNSType       string
        DNSValue      string
        DNSPurpose    string
        DNSHostHelp   string
        RFC           string
        RFCURL        string
        Severity      string
        SeverityColor string
        SeverityOrder int
        Section       string
}

func (a *Analyzer) GenerateRemediation(results map[string]any) map[string]any {
        ps := evaluateProtocolStates(results)
        ds := classifyDKIMState(ps)
        domain := extractDomain(results)

        var fixes []fix

        fixes = appendSPFFixes(fixes, ps, ds, results, domain)
        fixes = appendDMARCFixes(fixes, ps, results, domain)
        fixes = appendDKIMFixes(fixes, ps, ds, results, domain)
        fixes = appendCAAFixes(fixes, ps, domain)
        fixes = appendMTASTSFixes(fixes, ps, domain)
        fixes = appendTLSRPTFixes(fixes, ps, domain)
        fixes = appendDNSSECFixes(fixes, ps)
        fixes = appendDANEFixes(fixes, ps, results, domain)
        fixes = appendBIMIFixes(fixes, ps, domain)

        sortFixes(fixes)

        topCount := 3
        if len(fixes) < topCount {
                topCount = len(fixes)
        }

        topFixes := make([]map[string]any, topCount)
        for i := 0; i < topCount; i++ {
                topFixes[i] = fixToMap(fixes[i])
        }

        allFixes := make([]map[string]any, len(fixes))
        for i := range fixes {
                allFixes[i] = fixToMap(fixes[i])
        }

        achievable := computeAchievablePosture(ps, fixes)
        perSection := buildPerSection(fixes)

        return map[string]any{
                "top_fixes":          topFixes,
                "all_fixes":          allFixes,
                "fix_count":          float64(len(fixes)),
                "posture_achievable": achievable,
                "per_section":        perSection,
        }
}

func extractDomain(results map[string]any) string {
        if d, ok := results["domain"].(string); ok {
                return d
        }
        return "yourdomain.com"
}

func fixToMap(f fix) map[string]any {
        m := map[string]any{
                "title":          f.Title,
                "fix":            f.Description,
                "dns_record":     f.DNSRecord,
                "rfc":            f.RFC,
                "rfc_url":        f.RFCURL,
                "severity_label": f.Severity,
                "severity_color": f.SeverityColor,
                "severity_order": f.SeverityOrder,
                "section":        f.Section,
        }
        if f.DNSHost != "" {
                m["dns_host"] = f.DNSHost
                m["dns_type"] = f.DNSType
                m["dns_value"] = f.DNSValue
                m["dns_purpose"] = f.DNSPurpose
                m["dns_host_help"] = f.DNSHostHelp
        }
        return m
}

func sortFixes(fixes []fix) {
        for i := 1; i < len(fixes); i++ {
                key := fixes[i]
                j := i - 1
                for j >= 0 && fixes[j].SeverityOrder > key.SeverityOrder {
                        fixes[j+1] = fixes[j]
                        j--
                }
                fixes[j+1] = key
        }
}

func buildSPFValue(includes []string, qualifier string) string {
        var parts []string
        parts = append(parts, "v=spf1")
        for _, inc := range includes {
                parts = append(parts, fmt.Sprintf("include:%s", inc))
        }
        if len(includes) == 0 {
                parts = append(parts, "include:_spf.google.com")
        }
        parts = append(parts, qualifier)
        return strings.Join(parts, " ")
}

func buildSPFRecordExample(domain string, includes []string, qualifier string) string {
        var parts []string
        parts = append(parts, "v=spf1")
        for _, inc := range includes {
                parts = append(parts, fmt.Sprintf("include:%s", inc))
        }
        if len(includes) == 0 {
                parts = append(parts, "include:_spf.google.com")
        }
        parts = append(parts, qualifier)
        return fmt.Sprintf("%s TXT \"%s\"", domain, strings.Join(parts, " "))
}

func extractSPFIncludes(results map[string]any) []string {
        spf := getMapResult(results, "spf_analysis")
        if inc, ok := spf["includes"].([]any); ok && len(inc) > 0 {
                out := make([]string, 0, len(inc))
                for _, v := range inc {
                        if s, ok := v.(string); ok && s != "" {
                                out = append(out, s)
                        }
                }
                if len(out) > 0 {
                        return out
                }
        }
        if inc, ok := spf["includes"].([]string); ok && len(inc) > 0 {
                return inc
        }
        return nil
}

func appendSPFFixes(fixes []fix, ps protocolState, ds DKIMState, results map[string]any, domain string) []fix {
        includes := extractSPFIncludes(results)

        if ps.spfDangerous {
                return append(fixes, fix{
                        Title:         "Fix dangerously permissive SPF",
                        Description:   "Your SPF record uses +all, which allows any server in the world to send email as your domain — it provides zero protection. Change to ~all (softfail) or -all (hardfail) immediately.",
                        DNSRecord:     buildSPFRecordExample(domain, includes, "~all"),
                        DNSHost:       "@",
                        DNSType:       "TXT",
                        DNSValue:      buildSPFValue(includes, "~all"),
                        DNSPurpose:    "Replaces the dangerous +all with ~all to restrict unauthorized senders",
                        DNSHostHelp:   helpRootDomain,
                        RFC:           "RFC 7208 §5.1",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7208#section-5.1",
                        Severity:      severityCritical,
                        SeverityColor: colorCritical,
                        SeverityOrder: 1,
                        Section:       "spf",
                })
        }

        if ps.spfNeutral {
                return append(fixes, fix{
                        Title:         "Strengthen SPF enforcement",
                        Description:   "Your SPF record uses ?all (neutral), which tells receivers to accept email regardless of SPF check results. Change to ~all (softfail) or -all (hardfail) to restrict unauthorized senders.",
                        DNSRecord:     buildSPFRecordExample(domain, includes, "~all"),
                        DNSHost:       "@",
                        DNSType:       "TXT",
                        DNSValue:      buildSPFValue(includes, "~all"),
                        DNSPurpose:    "Replaces ?all (neutral) with ~all to restrict unauthorized senders",
                        DNSHostHelp:   helpRootDomain,
                        RFC:           "RFC 7208 §5.2",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7208#section-5.2",
                        Severity:      severityHigh,
                        SeverityColor: colorHigh,
                        SeverityOrder: 2,
                        Section:       "spf",
                })
        }

        if ps.spfOK {
                fixes = appendSPFLookupFix(fixes, ps)
                return appendSPFUpgradeFix(fixes, ps, ds, domain, includes)
        }
        if ps.spfWarning && !ps.spfMissing {
                if ps.spfLookupExceeded {
                        fixes = append(fixes, fix{
                                Title:         "Reduce SPF DNS lookups",
                                Description:   fmt.Sprintf("Your SPF record uses %d DNS lookups (limit is 10). Exceeding 10 lookups causes SPF to permanently fail (PermError), meaning receivers treat it as if you have no SPF at all. Consolidate include mechanisms or use SPF flattening.", ps.spfLookupCount),
                                RFC:           "RFC 7208 §4.6.4",
                                RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4",
                                Severity:      severityMedium,
                                SeverityColor: colorMedium,
                                SeverityOrder: 3,
                                Section:       "spf",
                        })
                }
                return fixes
        }
        return append(fixes, fix{
                Title:         "Publish SPF record",
                Description:   "SPF (Sender Policy Framework) tells receiving mail servers which IP addresses are authorized to send email for your domain. Without SPF, any server can claim to send as your domain.",
                DNSRecord:     buildSPFRecordExample(domain, includes, "~all"),
                DNSHost:       "@",
                DNSType:       "TXT",
                DNSValue:      buildSPFValue(includes, "~all"),
                DNSPurpose:    "Defines which servers are authorized to send email for this domain",
                DNSHostHelp:   helpRootDomain,
                RFC:           "RFC 7208 §4",
                RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7208#section-4",
                Severity:      severityCritical,
                SeverityColor: colorCritical,
                SeverityOrder: 1,
                Section:       "spf",
        })
}

func appendSPFLookupFix(fixes []fix, ps protocolState) []fix {
        if !ps.spfLookupExceeded {
                return fixes
        }
        return append(fixes, fix{
                Title:         "Reduce SPF DNS lookups",
                Description:   fmt.Sprintf("Your SPF record uses %d DNS lookups (limit is 10). Exceeding 10 lookups causes SPF to permanently fail (PermError), meaning receivers treat it as if you have no SPF at all. Consolidate include mechanisms or use SPF flattening to stay within the limit.", ps.spfLookupCount),
                RFC:           "RFC 7208 §4.6.4",
                RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4",
                Severity:      severityMedium,
                SeverityColor: colorMedium,
                SeverityOrder: 3,
                Section:       "spf",
        })
}

func appendSPFUpgradeFix(fixes []fix, ps protocolState, ds DKIMState, domain string, includes []string) []fix {
        if ps.spfHardFail || ds.IsPresent() || ds == DKIMNoMailDomain {
                return fixes
        }
        return append(fixes, fix{
                Title:       "Upgrade SPF to hard fail (-all)",
                Description: "Your SPF record uses ~all (softfail) and no DKIM signing was detected. Without DKIM, SPF is your only line of defense — upgrading to -all (hardfail) instructs receivers to reject unauthorized senders outright. Verify all legitimate sending sources are included before switching. If you configure DKIM, ~all becomes the industry-standard best practice because DMARC evaluates both SPF and DKIM alignment (RFC 7489 §10.1).",
                DNSRecord:   buildSPFRecordExample(domain, includes, "-all"),
                RFC:         "RFC 7208 §5",
                RFCURL:      "https://datatracker.ietf.org/doc/html/rfc7208#section-5",
                Severity:    severityLow,
                SeverityColor: colorLow,
                SeverityOrder: 4,
                Section:     "spf",
        })
}

func appendDMARCFixes(fixes []fix, ps protocolState, results map[string]any, domain string) []fix {
        if ps.dmarcOK && ps.dmarcPolicy == "reject" {
                return fixes
        }

        if ps.dmarcMissing || (!ps.dmarcOK && !ps.dmarcWarning) {
                return append(fixes, fix{
                        Title:         "Publish DMARC policy",
                        Description:   "DMARC (Domain-based Message Authentication, Reporting & Conformance) tells receivers how to handle messages that fail SPF/DKIM checks. Without DMARC, failed authentication checks are ignored. Start with p=none and rua reporting to monitor, then escalate to p=quarantine and p=reject.",
                        DNSRecord:     fmt.Sprintf("_dmarc.%s TXT \"v=DMARC1; p=none; rua=mailto:dmarc-reports@%s\"", domain, domain),
                        DNSHost:       "_dmarc",
                        DNSType:       "TXT",
                        DNSValue:      fmt.Sprintf("v=DMARC1; p=none; rua=mailto:dmarc-reports@%s", domain),
                        DNSPurpose:    "Tells receivers how to handle messages that fail authentication checks",
                        DNSHostHelp:   helpDMARCHost,
                        RFC:           rfcDMARCPolicy,
                        RFCURL:        rfcDMARCPolicyURL,
                        Severity:      severityCritical,
                        SeverityColor: colorCritical,
                        SeverityOrder: 1,
                        Section:       "dmarc",
                })
        }

        if ps.dmarcPolicy == "none" {
                return append(fixes, fix{
                        Title:         "Escalate DMARC from monitoring to enforcement",
                        Description:   "Change your DMARC policy from p=none to p=quarantine (then p=reject). Review your DMARC aggregate reports first to ensure legitimate senders pass authentication.",
                        DNSRecord:     fmt.Sprintf("_dmarc.%s TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@%s\"", domain, domain),
                        DNSHost:       "_dmarc",
                        DNSType:       "TXT",
                        DNSValue:      fmt.Sprintf("v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@%s", domain),
                        DNSPurpose:    "Upgrades DMARC from monitoring to quarantining failed messages",
                        DNSHostHelp:   helpDMARCHost,
                        RFC:           rfcDMARCPolicy,
                        RFCURL:        rfcDMARCPolicyURL,
                        Severity:      severityHigh,
                        SeverityColor: colorHigh,
                        SeverityOrder: 2,
                        Section:       "dmarc",
                })
        }

        if ps.dmarcPolicy == "quarantine" {
                fixes = append(fixes, fix{
                        Title:         "Upgrade DMARC to reject policy",
                        Description:   "Your DMARC policy is quarantine — spoofed messages are flagged. Upgrading to p=reject blocks them entirely. Review aggregate reports to confirm legitimate senders are aligned.",
                        DNSRecord:     fmt.Sprintf("_dmarc.%s TXT \"v=DMARC1; p=reject; rua=mailto:dmarc-reports@%s\"", domain, domain),
                        DNSHost:       "_dmarc",
                        DNSType:       "TXT",
                        DNSValue:      fmt.Sprintf("v=DMARC1; p=reject; rua=mailto:dmarc-reports@%s", domain),
                        DNSPurpose:    "Blocks spoofed messages entirely by rejecting authentication failures",
                        DNSHostHelp:   helpDMARCHost,
                        RFC:           rfcDMARCPolicy,
                        RFCURL:        rfcDMARCPolicyURL,
                        Severity:      severityLow,
                        SeverityColor: colorLow,
                        SeverityOrder: 4,
                        Section:       "dmarc",
                })
        }

        if (ps.dmarcOK || ps.dmarcWarning) && !ps.dmarcMissing && !ps.dmarcHasRua {
                fixes = append(fixes, fix{
                        Title:         "Add DMARC aggregate reporting",
                        Description:   "Add a rua= tag to your DMARC record to receive aggregate reports about authentication results. Without reporting, you cannot see who is sending email as your domain or whether legitimate mail is failing authentication.",
                        DNSRecord:     fmt.Sprintf("_dmarc.%s TXT \"v=DMARC1; p=%s; rua=mailto:dmarc-reports@%s\"", domain, ps.dmarcPolicy, domain),
                        DNSHost:       "_dmarc",
                        DNSType:       "TXT",
                        DNSValue:      fmt.Sprintf("v=DMARC1; p=%s; rua=mailto:dmarc-reports@%s", ps.dmarcPolicy, domain),
                        DNSPurpose:    "Enables aggregate reports so you can see who sends email as your domain",
                        DNSHostHelp:   helpDMARCHost,
                        RFC:           "RFC 7489 §7.1",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7489#section-7.1",
                        Severity:      severityMedium,
                        SeverityColor: colorMedium,
                        SeverityOrder: 3,
                        Section:       "dmarc",
                })
        }

        return fixes
}

func appendDKIMFixes(fixes []fix, ps protocolState, ds DKIMState, results map[string]any, domain string) []fix {
        dkim := getMapResult(results, "dkim_analysis")
        provider, _ := dkim["primary_provider"].(string)

        switch ds {
        case DKIMNoMailDomain:
                return fixes

        case DKIMSuccess, DKIMProviderInferred:
                if ps.dkimWeakKeys {
                        fixes = append(fixes, weakKeysFix(domain))
                }
                return fixes

        case DKIMThirdPartyOnly:
                if provider != "" && provider != "Unknown" {
                        fixes = append(fixes, fix{
                                Title:         fmt.Sprintf("Enable DKIM for %s", provider),
                                Description:   fmt.Sprintf("DKIM is only configured for third-party services, not your primary mail platform (%s). Enable DKIM signing in %s settings to cover all outbound mail. Note: large organizations may already have DKIM configured with custom or rotating selectors not discoverable through standard checks — try re-scanning with a custom DKIM selector, or verify in your %s admin console.", provider, provider, provider),
                                DNSRecord:     dkimRecordExample(domain, provider),
                                RFC:           "RFC 6376 §3.6",
                                RFCURL:        "https://datatracker.ietf.org/doc/html/rfc6376#section-3.6",
                                Severity:      severityMedium,
                                SeverityColor: colorMedium,
                                SeverityOrder: 3,
                                Section:       "dkim",
                        })
                }
                if ps.dkimWeakKeys {
                        fixes = append(fixes, weakKeysFix(domain))
                }
                return fixes

        case DKIMInconclusive:
                return append(fixes, fix{
                        Title:         "Verify DKIM configuration",
                        Description:   "DKIM selectors were not discoverable via common selector names. This does not confirm DKIM is absent — your provider may use custom or rotating selectors that cannot be enumerated through DNS (RFC 6376 §3.6.2.1). Check your email provider's DKIM settings to confirm signing is enabled.",
                        DNSRecord:     dkimRecordExample(domain, provider),
                        RFC:           "RFC 6376 §3.6.2.1",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.2.1",
                        Severity:      severityLow,
                        SeverityColor: colorLow,
                        SeverityOrder: 4,
                        Section:       "dkim",
                })

        case DKIMAbsent:
                return append(fixes, fix{
                        Title:         "Configure DKIM signing",
                        Description:   "DKIM (DomainKeys Identified Mail) adds a cryptographic signature to outgoing emails, proving they haven't been tampered with. Enable DKIM in your email provider's settings.",
                        DNSRecord:     dkimRecordExample(domain, provider),
                        RFC:           "RFC 6376 §3.6",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc6376#section-3.6",
                        Severity:      severityHigh,
                        SeverityColor: colorHigh,
                        SeverityOrder: 2,
                        Section:       "dkim",
                })
        }

        return fixes
}

func weakKeysFix(domain string) fix {
        return fix{
                Title:         "Upgrade weak DKIM keys",
                Description:   "One or more DKIM selectors use 1024-bit RSA keys which are considered weak by modern standards. Upgrade to 2048-bit keys for stronger cryptographic protection.",
                DNSRecord:     fmt.Sprintf(dkimRecordExampleGeneric, domain),
                RFC:           "RFC 8301 §3.2",
                RFCURL:        "https://datatracker.ietf.org/doc/html/rfc8301#section-3.2",
                Severity:      severityMedium,
                SeverityColor: colorMedium,
                SeverityOrder: 3,
                Section:       "dkim",
        }
}

func appendCAAFixes(fixes []fix, ps protocolState, domain string) []fix {
        if ps.caaOK {
                return fixes
        }
        desc := "Publish CAA DNS records to restrict which Certificate Authorities can issue TLS certificates for your domain. Specify your preferred CA (e.g., letsencrypt.org, digicert.com). CAA is advisory — CAs must check it before issuing, but absence means any CA can issue."
        if ps.daneOK {
                desc = "Publish CAA DNS records to restrict which Certificate Authorities can issue TLS certificates for your web services (HTTPS). Your email transport already uses DANE, which validates mail server certificates via DNSSEC without relying on CAs — so CAA is primarily relevant to your web-facing certificates."
        }
        return append(fixes, fix{
                Title:         "Add CAA records",
                Description:   desc,
                DNSRecord:     fmt.Sprintf("%s CAA 0 issue \"letsencrypt.org\"", domain),
                DNSHost:       "@",
                DNSType:       "CAA",
                DNSValue:      `0 issue "letsencrypt.org"`,
                DNSPurpose:    "Controls which certificate authorities can issue SSL certificates for this domain",
                DNSHostHelp:   helpRootDomain,
                RFC:           "RFC 8659 §4",
                RFCURL:        "https://datatracker.ietf.org/doc/html/rfc8659#section-4",
                Severity:      severityLow,
                SeverityColor: colorLow,
                SeverityOrder: 4,
                Section:       "caa",
        })
}

func appendMTASTSFixes(fixes []fix, ps protocolState, domain string) []fix {
        if ps.mtaStsOK {
                return fixes
        }
        return append(fixes, fix{
                Title:         "Deploy MTA-STS policy",
                Description:   fmt.Sprintf("Publish an MTA-STS DNS record and host a policy file at https://mta-sts.%s/.well-known/mta-sts.txt. This tells senders to require TLS when delivering mail to your domain.", domain),
                DNSRecord:     fmt.Sprintf("_mta-sts.%s TXT \"v=STSv1; id=20240101\"", domain),
                DNSHost:       "_mta-sts",
                DNSType:       "TXT",
                DNSValue:      "v=STSv1; id=20240101",
                DNSPurpose:    "Enables strict transport security for incoming email connections",
                DNSHostHelp:   "Enter _mta-sts as the hostname — your provider will append the domain automatically",
                RFC:           "RFC 8461 §3",
                RFCURL:        "https://datatracker.ietf.org/doc/html/rfc8461#section-3",
                Severity:      severityMedium,
                SeverityColor: colorMedium,
                SeverityOrder: 3,
                Section:       "mta_sts",
        })
}

func appendTLSRPTFixes(fixes []fix, ps protocolState, domain string) []fix {
        if ps.tlsrptOK {
                return fixes
        }
        desc := tlsrptDescDefault
        if ps.daneOK && ps.dnssecOK {
                desc = tlsrptDescDANE
        } else if ps.mtaStsOK {
                desc = tlsrptDescMTASTS
        }
        return append(fixes, fix{
                Title:         "Configure TLS-RPT reporting",
                Description:   desc,
                DNSRecord:     fmt.Sprintf("_smtp._tls.%s TXT \"v=TLSRPTv1; rua=mailto:tls-reports@%s\"", domain, domain),
                DNSHost:       "_smtp._tls",
                DNSType:       "TXT",
                DNSValue:      fmt.Sprintf("v=TLSRPTv1; rua=mailto:tls-reports@%s", domain),
                DNSPurpose:    "Enables reports about TLS connection failures with your mail servers",
                DNSHostHelp:   "Enter _smtp._tls as the hostname — your provider will append the domain automatically",
                RFC:           "RFC 8460 §3",
                RFCURL:        "https://datatracker.ietf.org/doc/html/rfc8460#section-3",
                Severity:      severityLow,
                SeverityColor: colorLow,
                SeverityOrder: 4,
                Section:       "tlsrpt",
        })
}

func appendDNSSECFixes(fixes []fix, ps protocolState) []fix {
        if ps.dnssecOK {
                return fixes
        }
        if ps.dnssecBroken {
                return append(fixes, fix{
                        Title:         "Fix broken DNSSEC chain of trust",
                        Description:   "DNSSEC is partially configured — DNSKEY records exist but the DS record is missing at the parent zone (registrar). This means DNS responses are signed but receivers cannot validate the signatures, causing validation failures. Publish the correct DS record at your registrar.",
                        DNSRecord:     "",
                        RFC:           "RFC 4035 §2.4",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc4035#section-2.4",
                        Severity:      severityCritical,
                        SeverityColor: colorCritical,
                        SeverityOrder: 1,
                        Section:       "dnssec",
                })
        }
        return append(fixes, fix{
                Title:         "Enable DNSSEC",
                Description:   "DNSSEC (DNS Security Extensions) cryptographically signs DNS responses, preventing attackers from forging DNS answers. Contact your DNS hosting provider to enable DNSSEC signing.",
                DNSRecord:     "",
                RFC:           "RFC 4033 §2",
                RFCURL:        "https://datatracker.ietf.org/doc/html/rfc4033#section-2",
                Severity:      severityLow,
                SeverityColor: colorLow,
                SeverityOrder: 4,
                Section:       "dnssec",
        })
}

func appendDANEFixes(fixes []fix, ps protocolState, results map[string]any, domain string) []fix {
        if ps.daneOK && !ps.dnssecOK {
                return append(fixes, fix{
                        Title:         "Enable DNSSEC for DANE validation",
                        Description:   "DANE/TLSA records are published but DNSSEC is not enabled. DANE requires DNSSEC to work — without it, TLSA records cannot be authenticated and are ignored by validating resolvers (RFC 7672 §2.2). Enable DNSSEC first.",
                        DNSRecord:     "",
                        RFC:           "RFC 7672 §2.2",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7672#section-2.2",
                        Severity:      severityHigh,
                        SeverityColor: colorHigh,
                        SeverityOrder: 2,
                        Section:       "dane",
                })
        }
        if !ps.daneOK && ps.dnssecOK {
                if !isDANEDeployable(results) {
                        return fixes
                }
                if isHostedMXProvider(results) {
                        return fixes
                }
                return append(fixes, fix{
                        Title:         "Deploy DANE/TLSA for email transport",
                        Description:   "DNSSEC is already enabled — you can strengthen email transport security by publishing DANE TLSA records. DANE binds your mail server's TLS certificate to DNS, preventing man-in-the-middle attacks on SMTP connections.",
                        DNSRecord:     fmt.Sprintf("_25._tcp.mail.%s TLSA 3 1 1 <certificate_hash>", domain),
                        RFC:           "RFC 7672 §3",
                        RFCURL:        "https://datatracker.ietf.org/doc/html/rfc7672#section-3",
                        Severity:      severityLow,
                        SeverityColor: colorLow,
                        SeverityOrder: 4,
                        Section:       "dane",
                })
        }
        return fixes
}

var hostedMXProviders = map[string]bool{
        providerGoogleWS:        true,
        providerMicrosoft365:    true,
        providerZohoMail:        true,
        providerFastmail:        true,
        providerProtonMail:      true,
        providerCloudflareEmail: true,
}

func isHostedMXProvider(results map[string]any) bool {
        dkim := getMapResult(results, "dkim_analysis")
        provider, _ := dkim["primary_provider"].(string)
        return hostedMXProviders[provider]
}

func isDANEDeployable(results map[string]any) bool {
        dane := getMapResult(results, "dane_analysis")
        deployable, ok := dane["dane_deployable"].(bool)
        if ok {
                return deployable
        }
        return true
}

func appendBIMIFixes(fixes []fix, ps protocolState, domain string) []fix {
        if ps.bimiOK {
                return fixes
        }
        if !ps.dmarcOK || (ps.dmarcPolicy != "reject" && ps.dmarcPolicy != "quarantine") {
                return fixes
        }
        return append(fixes, fix{
                Title:         "Configure BIMI brand logo",
                Description:   "Publish a BIMI DNS record pointing to your brand logo (SVG Tiny PS format). For full support in Gmail, you will also need a Verified Mark Certificate (VMC).",
                DNSRecord:     fmt.Sprintf("default._bimi.%s TXT \"v=BIMI1; l=https://%s/logo.svg\"", domain, domain),
                RFC:           "BIMI Spec",
                RFCURL:        "https://bimigroup.org/implementation-guide/",
                Severity:      severityLow,
                SeverityColor: colorLow,
                SeverityOrder: 4,
                Section:       "bimi",
        })
}

func buildPerSection(fixes []fix) map[string]any {
        sections := []string{"spf", "dmarc", "dkim", "dnssec", "dane", "mta_sts", "tlsrpt", "bimi", "caa"}
        perSection := make(map[string]any)

        for _, s := range sections {
                perSection[s] = map[string]any{
                        "status": "ok",
                        "fixes":  []map[string]any{},
                }
        }

        grouped := make(map[string][]map[string]any)
        for _, f := range fixes {
                if f.Section != "" {
                        grouped[f.Section] = append(grouped[f.Section], fixToMap(f))
                }
        }

        for section, sectionFixes := range grouped {
                perSection[section] = map[string]any{
                        "status": "action_needed",
                        "fixes":  sectionFixes,
                }
        }

        return perSection
}

func computeAchievablePosture(ps protocolState, fixes []fix) string {
        hasCritical := false
        hasHigh := false
        for _, f := range fixes {
                if f.Severity == severityCritical {
                        hasCritical = true
                }
                if f.Severity == severityHigh {
                        hasHigh = true
                }
        }

        if !hasCritical && !hasHigh {
                if len(fixes) <= 3 {
                        return "Secure"
                }
                return riskLow
        }

        if hasCritical {
                return riskMedium
        }

        return riskLow
}

type mailFlags struct {
        hasSPF      bool
        hasDMARC    bool
        hasDKIM     bool
        hasNullMX   bool
        hasMX       bool
        spfDenyAll  bool
        dmarcReject bool
        dmarcPolicy string
}

type dnsRecord struct {
        RecordType string `json:"record_type"`
        Host       string `json:"host"`
        Value      string `json:"value"`
        Purpose    string `json:"purpose"`
        HostHelp   string `json:"host_help"`
}

type mailClassification struct {
        classification string
        label          string
        color          string
        icon           string
        summary        string
        isNoMail       bool
        recommended    []dnsRecord
}

func buildMailPosture(results map[string]any) map[string]any {
        ps := evaluateProtocolStates(results)
        mp := make(map[string]any)

        mf := extractMailFlags(results, ps)

        verdict, badge := computeMailVerdict(mf)
        mp["verdict"] = verdict
        mp["badge"] = badge

        signals, presentCount := buildNoMailSignals(mf)
        mp["signals"] = signals
        mp["present_count"] = presentCount
        mp["total_signals"] = 3
        mp["missing_steps"] = buildMissingSteps(mf)

        domain := extractDomain(results)
        cls := classifyMailPosture(mf, presentCount, domain, ps)
        mp["classification"] = cls.classification
        mp["label"] = cls.label
        mp["color"] = cls.color
        mp["icon"] = cls.icon
        mp["summary"] = cls.summary
        mp["is_no_mail"] = cls.isNoMail
        if len(cls.recommended) > 0 {
                var recMaps []map[string]any
                for _, r := range cls.recommended {
                        recMaps = append(recMaps, map[string]any{
                                "record_type": r.RecordType,
                                "host":        r.Host,
                                "value":       r.Value,
                                "purpose":     r.Purpose,
                                "host_help":   r.HostHelp,
                        })
                }
                mp["recommended_records"] = recMaps
        } else {
                mp["recommended_records"] = nil
        }

        dnsInfra := getMapResult(results, "dns_infrastructure")
        if tier, ok := dnsInfra["provider_tier"].(string); ok && tier == "enterprise" {
                mp["dns_tier"] = "enterprise"
        }

        return mp
}

func extractMailFlags(results map[string]any, ps protocolState) mailFlags {
        spf := getMapResult(results, "spf_analysis")
        spfNoMailIntent := getBool(spf, "no_mail_intent")
        spfAllMech, _ := spf["all_mechanism"].(string)

        basic := getMapResult(results, "basic_records")
        mxRecords := getSlice(basic, "MX")
        hasNullMX := getBool(results, "has_null_mx")

        return mailFlags{
                hasSPF:      ps.spfOK || (ps.spfWarning && !ps.spfMissing),
                hasDMARC:    ps.dmarcOK || (ps.dmarcWarning && !ps.dmarcMissing),
                hasDKIM:     ps.dkimOK || ps.dkimProvider,
                hasNullMX:   hasNullMX,
                hasMX:       len(mxRecords) > 0 && !hasNullMX,
                spfDenyAll:  spfNoMailIntent || spfAllMech == "-all",
                dmarcReject: ps.dmarcPolicy == "reject",
                dmarcPolicy: ps.dmarcPolicy,
        }
}

func computeMailVerdict(mf mailFlags) (string, string) {
        switch {
        case mf.hasSPF && mf.hasDMARC && mf.dmarcPolicy == "reject" && mf.hasDKIM:
                return "Protected", "success"
        case mf.hasSPF && mf.hasDMARC && mf.dmarcPolicy == "quarantine" && mf.hasDKIM:
                return "Mostly Protected", "success"
        case mf.hasSPF && mf.hasDMARC && mf.hasDKIM:
                return "Monitoring", "info"
        case mf.hasSPF || mf.hasDMARC:
                return "Partially", "warning"
        default:
                return "Vulnerable", "danger"
        }
}

type noMailSignalDef struct {
        key         string
        present     bool
        rfc         string
        label       string
        description string
        missingRisk string
}

func buildNoMailSignals(mf mailFlags) (map[string]any, int) {
        defs := []noMailSignalDef{
                {"null_mx", mf.hasNullMX, "RFC 7505", "Null MX",
                        "A null MX record (0 .) explicitly declares that a domain does not accept email.",
                        "Without a null MX record, senders may still attempt delivery to this domain."},
                {"spf_deny_all", mf.spfDenyAll, "RFC 7208", "SPF -all",
                        "An SPF record with '-all' rejects all mail, signaling the domain sends no email.",
                        "Without SPF -all, mail servers may accept forged messages from this domain."},
                {"dmarc_reject", mf.dmarcReject, "RFC 7489", "DMARC reject",
                        "A DMARC policy of p=reject instructs receivers to discard unauthenticated mail.",
                        "Without DMARC reject, spoofed messages may still be delivered."},
        }

        signals := make(map[string]any, len(defs))
        presentCount := 0
        for _, d := range defs {
                signals[d.key] = map[string]any{
                        "present": d.present, "rfc": d.rfc, "label": d.label,
                        "description": d.description, "missing_risk": d.missingRisk,
                }
                if d.present {
                        presentCount++
                }
        }
        return signals, presentCount
}

type missingStepDef struct {
        missing bool
        control string
        rfc     string
        rfcURL  string
        action  string
        risk    string
}

func buildMissingSteps(mf mailFlags) []map[string]any {
        defs := []missingStepDef{
                {!mf.hasNullMX, "Null MX", "RFC 7505",
                        "https://datatracker.ietf.org/doc/html/rfc7505",
                        "Publish a null MX record: 0 .",
                        "Without null MX, senders may still attempt delivery."},
                {!mf.spfDenyAll, "SPF -all", "RFC 7208",
                        "https://datatracker.ietf.org/doc/html/rfc7208",
                        "Publish SPF with -all to reject all senders.",
                        "Without SPF -all, mail servers may accept forged messages."},
                {!mf.dmarcReject, "DMARC reject", "RFC 7489",
                        "https://datatracker.ietf.org/doc/html/rfc7489",
                        "Publish DMARC with p=reject to discard unauthenticated mail.",
                        "Without DMARC reject, spoofed messages may still be delivered."},
        }

        var steps []map[string]any
        for _, d := range defs {
                if !d.missing {
                        continue
                }
                steps = append(steps, map[string]any{
                        "control": d.control, "rfc": d.rfc, "rfc_url": d.rfcURL,
                        "action": d.action, "risk": d.risk,
                })
        }
        return steps
}

func classifyMailPosture(mf mailFlags, presentCount int, domain string, ps protocolState) mailClassification {
        if presentCount == 3 {
                return mailClassification{
                        classification: "no_mail_verified", label: "No-Mail: Verified",
                        color: "success", icon: "shield-alt",
                        summary:  "This domain has verified no-mail controls: null MX, SPF -all, and DMARC reject are all present.",
                        isNoMail: true,
                }
        }

        if presentCount >= 1 && !mf.hasMX {
                return mailClassification{
                        classification: "no_mail_partial", label: "No-Mail: Partial",
                        color: "warning", icon: "exclamation-triangle",
                        summary:     fmt.Sprintf("This domain appears to not send mail but only %d of 3 no-mail signals are present.", presentCount),
                        isNoMail:    true,
                        recommended: buildNoMailStructuredRecords(mf, domain),
                }
        }

        enforce := ps.dmarcPolicy == "reject" || ps.dmarcPolicy == "quarantine"
        if mf.hasSPF && mf.hasDMARC && mf.hasDKIM && enforce {
                return mailClassification{
                        classification: "email_enforced", label: "Email: Enforced",
                        color: "success", icon: "shield-alt",
                        summary: "Email authentication is fully enforced with SPF, DKIM, and DMARC policy enforcement.",
                }
        }

        if mf.hasSPF && mf.hasDMARC && mf.hasDKIM && ps.dmarcPolicy == "none" {
                return mailClassification{
                        classification: "email_monitoring", label: "Email: Monitoring",
                        color: "info", icon: "info-circle",
                        summary: "Email authentication is configured with DMARC in monitoring mode (p=none). Enforcement recommended after reviewing reports.",
                }
        }

        if mf.hasSPF || mf.hasDMARC {
                return mailClassification{
                        classification: "email_enabled", label: "Email: Enabled",
                        color: "warning", icon: "check-circle",
                        summary: "Some email authentication is configured but full protection is not yet in place.",
                }
        }

        cls := mailClassification{
                classification: "email_ambiguous", label: "Email: Ambiguous",
                color: "secondary", icon: "question-circle",
                summary: "No email authentication detected. It is unclear whether this domain sends email.",
        }
        if !mf.hasMX {
                cls.recommended = buildNoMailStructuredRecords(mailFlags{}, domain)
        }
        return cls
}

func buildNoMailRecommendedRecords(mf mailFlags, domain string) []string {
        var recs []string
        if !mf.hasNullMX {
                recs = append(recs, fmt.Sprintf("%s MX 0 .", domain))
        }
        if !mf.spfDenyAll {
                recs = append(recs, fmt.Sprintf("%s TXT \"v=spf1 -all\"", domain))
        }
        if !mf.dmarcReject {
                recs = append(recs, fmt.Sprintf("_dmarc.%s TXT \"v=DMARC1; p=reject;\"", domain))
        }
        return recs
}

func buildNoMailStructuredRecords(mf mailFlags, domain string) []dnsRecord {
        var recs []dnsRecord
        if !mf.hasNullMX {
                recs = append(recs, dnsRecord{
                        RecordType: "MX",
                        Host:       "@",
                        Value:      "0 .",
                        Purpose:    "Declares this domain does not accept email (null MX)",
                        HostHelp:   helpRootDomain,
                })
        }
        if !mf.spfDenyAll {
                recs = append(recs, dnsRecord{
                        RecordType: "TXT",
                        Host:       "@",
                        Value:      "v=spf1 -all",
                        Purpose:    "Tells receiving mail servers that no one is authorized to send email from this domain",
                        HostHelp:   helpRootDomain,
                })
        }
        if !mf.dmarcReject {
                recs = append(recs, dnsRecord{
                        RecordType: "TXT",
                        Host:       "_dmarc",
                        Value:      "v=DMARC1; p=reject;",
                        Purpose:    "Instructs receiving servers to reject any email claiming to be from this domain",
                        HostHelp:   helpDMARCHost,
                })
        }
        return recs
}

func getVerdict(results map[string]any, key string) string {
        posture := getMapResult(results, "posture")
        verdicts, ok := posture["verdicts"].(map[string]any)
        if !ok {
                return ""
        }
        v, _ := verdicts[key].(string)
        return v
}

func countCoreIssues(fixes []fix) int {
        count := 0
        for _, f := range fixes {
                if f.Severity == severityCritical || f.Severity == severityHigh {
                        count++
                }
        }
        return count
}

func hasSeverity(fixes []fix, severity string) bool {
        for _, f := range fixes {
                if f.Severity == severity {
                        return true
                }
        }
        return false
}

func filterBySeverity(fixes []fix, severity string) []fix {
        var result []fix
        for _, f := range fixes {
                if f.Severity == severity {
                        result = append(result, f)
                }
        }
        return result
}

func joinFixTitles(fixes []fix) string {
        titles := make([]string, len(fixes))
        for i, f := range fixes {
                titles[i] = f.Title
        }
        return strings.Join(titles, ", ")
}
