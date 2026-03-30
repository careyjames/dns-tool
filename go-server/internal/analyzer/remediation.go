// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Remediation engine — generates actionable security fixes from scan results.
// dns-tool:scrutiny science
package analyzer

import (
        "fmt"
        "sort"
        "strings"

        "dnstool/go-server/internal/citation"
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

        dkimRecordExampleGeneric = "selector1._domainkey.%s TXT \"v=DKIM1; k=rsa; p=<public_key>\""

        tlsrptDescDefault = "TLS-RPT (TLS Reporting) sends you reports about TLS connection failures when other servers try to deliver mail to your domain."
        tlsrptDescDANE    = "Your domain has DNSSEC + DANE — the strongest email transport security available."
        tlsrptDescMTASTS  = "Your domain has MTA-STS configured for transport encryption."

        dmarcHostPrefix = "_dmarc."
        hostHelpDMARC   = "(DMARC policy record)"
        hostHelpRootDom = "(root of domain)"

        sectionDMARC     = "DMARC"
        sectionSPF       = "SPF"
        sectionDNSSEC    = "DNSSEC"
        sectionDKIM      = "DKIM"
        sectionDANE      = "DANE"
        policyReject     = "reject"
        spfHardFailValue = "v=spf1 -all"

        mapKeyRFCURL = "rfc_url"
        mapKeyRFC    = "rfc"

        dnsTypeTXT = "TXT"
)

var (
        remSPF            string
        remSPFURL         string
        remDKIMSign       string
        remDKIMSignURL    string
        remDMARCPolicy    string
        remDMARCPolicyURL string
        remDMARC7489      string
        remDMARC7489URL   string

        remSPF51Label     string
        remSPF51URL       string
        remSPF464Label    string
        remSPF464URL      string
        remDMARC71Label   string
        remDMARC71URL     string
        remDKIM8301Label  string
        remDKIM8301URL    string
        remCAA8659Label   string
        remCAA8659URL     string
        remMTASTS8461Label string
        remMTASTS8461URL  string
        remTLSRPT8460Label string
        remTLSRPT8460URL  string
        remDNSSEC4035Label string
        remDNSSEC4035URL  string
        remDNSSEC8624Label string
        remDNSSEC8624URL  string
        remDANE7672Label  string
        remDANE7672URL    string
        remDANE267221Label string
        remDANE267221URL  string
        remBIMI9495Label  string
        remBIMI9495URL    string
        remNullMX7505Label string
        remNullMX7505URL  string
)

func init() {
        reg := citation.Global()
        remSPF, remSPFURL = reg.ResolveRFC("rfc:7208")
        remDKIMSign, remDKIMSignURL = reg.ResolveRFC("rfc:6376")
        remDMARCPolicy, remDMARCPolicyURL = reg.ResolveRFC("rfc:7489§6.3")
        remDMARC7489, remDMARC7489URL = reg.ResolveRFC("rfc:7489")
        remSPF51Label, remSPF51URL = reg.ResolveRFC("rfc:7208§5.1")
        remSPF464Label, remSPF464URL = reg.ResolveRFC("rfc:7208§4.6.4")
        remDMARC71Label, remDMARC71URL = reg.ResolveRFC("rfc:7489§7.1")
        remDKIM8301Label, remDKIM8301URL = reg.ResolveRFC("rfc:8301")
        remCAA8659Label, remCAA8659URL = reg.ResolveRFC("rfc:8659")
        remMTASTS8461Label, remMTASTS8461URL = reg.ResolveRFC("rfc:8461")
        remTLSRPT8460Label, remTLSRPT8460URL = reg.ResolveRFC("rfc:8460")
        remDNSSEC4035Label, remDNSSEC4035URL = reg.ResolveRFC("rfc:4035")
        remDNSSEC8624Label, remDNSSEC8624URL = reg.ResolveRFC("rfc:8624§3.1")
        remDANE7672Label, remDANE7672URL = reg.ResolveRFC("rfc:7672")
        remDANE267221Label, remDANE267221URL = reg.ResolveRFC("rfc:7672§2.1")
        remBIMI9495Label, remBIMI9495URL = reg.ResolveRFC("rfc:9495")
        remNullMX7505Label, remNullMX7505URL = reg.ResolveRFC("rfc:7505")
}

func CitationReg() *citation.Registry {
        return citation.Global()
}

type severityLevel struct {
        Name  string
        Color string
        Order int
}

var (
        sevCritical = severityLevel{severityCritical, colorCritical, 1}
        sevHigh     = severityLevel{severityHigh, colorHigh, 2}
        sevMedium   = severityLevel{severityMedium, colorMedium, 3}
        sevLow      = severityLevel{severityLow, colorLow, 4}
)

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
        SeverityLevel severityLevel
        Section       string
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

type noMailSignalDef struct {
        key         string
        present     bool
        rfc         string
        rfcURL      string
        label       string
        description string
        missingRisk string
}

type missingStepDef struct {
        missing bool
        control string
        rfc     string
        rfcURL  string
        action  string
        risk    string
}

func providerSupportsDANE(provider string) bool {
        if provider == "" {
                return true
        }
        return !isHostedEmailProvider(provider)
}

func providerSupportsBIMI(provider string) bool {
        if provider == "" {
                return true
        }
        return isBIMICapableProvider(provider)
}

func (a *Analyzer) GenerateRemediation(results map[string]any) map[string]any {
        isTLD, _ := results["is_tld"].(bool)
        ps := evaluateProtocolStates(results)
        ds := classifyDKIMState(ps)
        domain := extractDomain(results)

        var fixes []fix

        if isTLD {
                fixes = appendDNSSECFixes(fixes, ps)
        } else if ps.isNoMailDomain {
                fixes = appendNoMailHardeningFixes(fixes, ps, domain)
                fixes = appendDNSSECFixes(fixes, ps)
                fixes = appendDANEFixes(fixes, ps, results, domain)
                fixes = appendCAAFixes(fixes, ps, domain)
        } else if ps.probableNoMail {
                fixes = appendProbableNoMailFixes(fixes, ps, domain)
                fixes = appendDNSSECFixes(fixes, ps)
                fixes = appendDANEFixes(fixes, ps, results, domain)
                fixes = appendCAAFixes(fixes, ps, domain)
        } else {
                fixes = appendSPFFixes(fixes, ps, ds, results, domain)
                fixes = appendDMARCFixes(fixes, ps, results, domain)
                fixes = appendDKIMFixes(fixes, ps, ds, results, domain)
                fixes = appendMTASTSFixes(fixes, ps, domain)
                fixes = appendTLSRPTFixes(fixes, ps, domain)
                fixes = appendBIMIFixes(fixes, ps, domain)
                fixes = appendDNSSECFixes(fixes, ps)
                fixes = appendDANEFixes(fixes, ps, results, domain)
                fixes = appendCAAFixes(fixes, ps, domain)
        }

        sortFixes(fixes)

        allFixMaps := make([]map[string]any, 0, len(fixes))
        for _, f := range fixes {
                allFixMaps = append(allFixMaps, fixToMap(f))
        }

        topCount := 3
        if len(allFixMaps) < topCount {
                topCount = len(allFixMaps)
        }
        topFixMaps := allFixMaps[:topCount]

        return map[string]any{
                "top_fixes":          topFixMaps,
                "all_fixes":          allFixMaps,
                "fix_count":          float64(len(allFixMaps)),
                "posture_achievable": computeAchievablePosture(ps, fixes),
                "per_section":        buildPerSection(fixes),
        }
}

func dkimRecordExample(domain, provider string) string {
        selector := dkimSelectorForProvider(provider)
        return fmt.Sprintf(dkimRecordExampleGeneric, selector+"._domainkey."+domain)
}

func dkimSelectorForProvider(provider string) string {
        lower := strings.ToLower(provider)
        if strings.Contains(lower, "google") {
                return "google"
        }
        if strings.Contains(lower, "microsoft") || strings.Contains(lower, "office") {
                return "selector1"
        }
        return "selector1"
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
                "severity_label": f.SeverityLevel.Name,
                "severity_color": f.SeverityLevel.Color,
                mapKeyRFC:        f.RFC,
                mapKeyRFCURL:     f.RFCURL,
                "rfc_title":      f.RFC,
                "rfc_obsolete":   false,
                "section":        f.Section,
        }
        if f.DNSHost != "" {
                m["dns_host"] = f.DNSHost
                m["dns_type"] = f.DNSType
                m["dns_value"] = f.DNSValue
                m["dns_purpose"] = f.DNSPurpose
                m["dns_host_help"] = f.DNSHostHelp
        }
        if f.DNSRecord != "" {
                m["dns_record"] = f.DNSRecord
        }
        return m
}

func sortFixes(fixes []fix) {
        sort.SliceStable(fixes, func(i, j int) bool {
                if fixes[i].SeverityLevel.Order != fixes[j].SeverityLevel.Order {
                        return fixes[i].SeverityLevel.Order < fixes[j].SeverityLevel.Order
                }
                return fixes[i].Title < fixes[j].Title
        })
}

func buildSPFValue(includes []string, qualifier string) string {
        parts := []string{"v=spf1"}
        for _, inc := range includes {
                parts = append(parts, "include:"+inc)
        }
        parts = append(parts, qualifier)
        return strings.Join(parts, " ")
}

func buildSPFRecordExample(domain string, includes []string, qualifier string) string {
        value := buildSPFValue(includes, qualifier)
        return fmt.Sprintf("%s TXT \"%s\"", domain, value)
}

func extractSPFIncludes(results map[string]any) []string {
        spf, _ := results["spf_analysis"].(map[string]any)
        if spf == nil {
                return nil
        }
        if includes, ok := spf["includes"].([]string); ok {
                return includes
        }
        if includes, ok := spf["includes"].([]any); ok {
                var result []string
                for _, inc := range includes {
                        if s, ok := inc.(string); ok {
                                result = append(result, s)
                        }
                }
                return result
        }
        return nil
}

func appendSPFFixes(fixes []fix, ps protocolState, ds DKIMState, results map[string]any, domain string) []fix {
        if ps.spfMissing {
                includes := extractSPFIncludes(results)
                value := "v=spf1 ~all"
                if len(includes) > 0 {
                        value = buildSPFValue(includes, "~all")
                }
                fixes = append(fixes, fix{
                        Title:         "Publish SPF Record",
                        Description:   "Add an SPF record to authorize mail servers for this domain.",
                        DNSHost:       domain,
                        DNSType:       dnsTypeTXT,
                        DNSValue:      value,
                        DNSPurpose:    "SPF tells receiving servers which IPs may send mail for your domain.",
                        DNSHostHelp:   hostHelpRootDom,
                        RFC:           remSPF,
                        RFCURL:        remSPFURL,
                        SeverityLevel: sevCritical,
                        Section:       sectionSPF,
                })
                return fixes
        }
        if ps.spfDangerous {
                fixes = append(fixes, fix{
                        Title:         "Remove Dangerous SPF +all",
                        Description:   "Your SPF record uses +all which allows anyone to send mail as your domain. Change to ~all immediately.",
                        DNSHost:       domain,
                        DNSType:       dnsTypeTXT,
                        DNSValue:      "v=spf1 [your includes] ~all",
                        DNSPurpose:    "The +all qualifier is dangerous — it authorizes the entire internet to send as your domain.",
                        DNSHostHelp:   hostHelpRootDom,
                        RFC:           remSPF51Label,
                        RFCURL:        remSPF51URL,
                        SeverityLevel: sevCritical,
                        Section:       sectionSPF,
                })
        }
        if ps.spfNeutral {
                fixes = append(fixes, fix{
                        Title:         "Upgrade SPF from ?all",
                        Description:   "Your SPF record uses ?all (neutral) which provides no protection. Upgrade to ~all (soft fail) for proper SPF enforcement.",
                        RFC:           remSPF51Label,
                        RFCURL:        remSPF51URL,
                        SeverityLevel: sevHigh,
                        Section:       sectionSPF,
                })
        }
        fixes = appendSPFLookupFix(fixes, ps)
        fixes = appendSPFUpgradeFix(fixes, ps, ds, domain, extractSPFIncludes(results))
        return fixes
}

func appendSPFLookupFix(fixes []fix, ps protocolState) []fix {
        if ps.spfLookupExceeded {
                fixes = append(fixes, fix{
                        Title:         "Reduce SPF Lookup Count",
                        Description:   fmt.Sprintf("Your SPF record uses %d DNS lookups, exceeding the RFC limit of 10. Some receivers may ignore your SPF policy.", ps.spfLookupCount),
                        RFC:           remSPF464Label,
                        RFCURL:        remSPF464URL,
                        SeverityLevel: sevMedium,
                        Section:       sectionSPF,
                })
        }
        return fixes
}

func appendSPFUpgradeFix(fixes []fix, ps protocolState, ds DKIMState, domain string, includes []string) []fix {
        return fixes
}

func appendDMARCFixes(fixes []fix, ps protocolState, results map[string]any, domain string) []fix {
        if ps.dmarcMissing {
                fixes = append(fixes, fix{
                        Title:         "Publish DMARC Record",
                        Description:   "Add a DMARC record to protect your domain against email spoofing and receive authentication reports.",
                        DNSHost:       dmarcHostPrefix + domain,
                        DNSType:       dnsTypeTXT,
                        DNSValue:      "v=DMARC1; p=none; rua=mailto:dmarc-reports@" + domain,
                        DNSPurpose:    "DMARC tells receivers how to handle mail that fails SPF/DKIM checks.",
                        DNSHostHelp:   hostHelpDMARC,
                        RFC:           remDMARCPolicy,
                        RFCURL:        remDMARCPolicyURL,
                        SeverityLevel: sevCritical,
                        Section:       sectionDMARC,
                })
                return fixes
        }
        if ps.dmarcPolicy == "none" {
                fixes = append(fixes, fix{
                        Title:         "Upgrade DMARC from p=none",
                        Description:   "Your DMARC policy is monitor-only (p=none). Upgrade to p=quarantine or p=reject after reviewing reports to actively prevent spoofing.",
                        DNSHost:       dmarcHostPrefix + domain,
                        DNSType:       dnsTypeTXT,
                        DNSValue:      "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@" + domain,
                        DNSPurpose:    "A quarantine or reject policy instructs receivers to take action on failing mail.",
                        DNSHostHelp:   hostHelpDMARC,
                        RFC:           remDMARCPolicy,
                        RFCURL:        remDMARCPolicyURL,
                        SeverityLevel: sevHigh,
                        Section:       sectionDMARC,
                })
        }
        if ps.dmarcPolicy == "quarantine" && ps.dmarcPct >= 100 {
                fixes = append(fixes, fix{
                        Title:         "Upgrade DMARC to Reject",
                        Description:   "Your DMARC policy is set to quarantine. Upgrade to p=reject for maximum protection — reject instructs receivers to discard spoofed mail entirely rather than quarantining it.",
                        DNSHost:       dmarcHostPrefix + domain,
                        DNSType:       dnsTypeTXT,
                        DNSValue:      "v=DMARC1; p=reject; rua=mailto:dmarc-reports@" + domain,
                        DNSPurpose:    "A reject policy provides the strongest protection against domain spoofing.",
                        DNSHostHelp:   "(update existing DMARC record)",
                        RFC:           remDMARCPolicy,
                        RFCURL:        remDMARCPolicyURL,
                        SeverityLevel: sevMedium,
                        Section:       sectionDMARC,
                })
        }
        if ps.dmarcPolicy == "quarantine" && ps.dmarcPct < 100 && ps.dmarcPct > 0 {
                fixes = append(fixes, fix{
                        Title:         "Increase DMARC Coverage",
                        Description:   fmt.Sprintf("Your DMARC policy only applies to %d%% of mail. Increase pct to 100 for full protection.", ps.dmarcPct),
                        RFC:           remDMARCPolicy,
                        RFCURL:        remDMARCPolicyURL,
                        SeverityLevel: sevMedium,
                        Section:       sectionDMARC,
                })
        }
        if !ps.dmarcHasRua {
                fixes = append(fixes, fix{
                        Title:         "Add DMARC Aggregate Reporting",
                        Description:   "Add a rua= tag to receive aggregate DMARC reports. Without reporting, you cannot monitor authentication failures.",
                        DNSHost:       dmarcHostPrefix + domain,
                        DNSType:       dnsTypeTXT,
                        DNSValue:      "rua=mailto:dmarc-reports@" + domain,
                        DNSPurpose:    "Aggregate reports show who is sending mail as your domain and whether it passes authentication.",
                        DNSHostHelp:   "(add to existing DMARC record)",
                        RFC:           remDMARC71Label,
                        RFCURL:        remDMARC71URL,
                        SeverityLevel: sevMedium,
                        Section:       sectionDMARC,
                })
        }
        return fixes
}

func appendDKIMFixes(fixes []fix, ps protocolState, ds DKIMState, results map[string]any, domain string) []fix {
        if ds == DKIMWeakKeysOnly {
                fixes = append(fixes, weakKeysFix(domain))
        }
        if ds == DKIMAbsent || ds == DKIMInconclusive {
                selector := dkimSelectorForProvider(ps.primaryProvider)
                fixes = append(fixes, fix{
                        Title:         "Configure DKIM Signing",
                        Description:   "No DKIM records were discovered for common selectors. Configure DKIM signing with your mail provider to authenticate outbound messages.",
                        DNSHost:       selector + "._domainkey." + domain,
                        DNSType:       "TXT (or CNAME)",
                        DNSValue:      "v=DKIM1; k=rsa; p=<public_key>",
                        DNSPurpose:    "DKIM lets receivers verify that messages were authorized by the domain owner and not altered in transit.",
                        DNSHostHelp:   "(DKIM selector record — your provider supplies the exact value)",
                        RFC:           remDKIMSign,
                        RFCURL:        remDKIMSignURL,
                        SeverityLevel: sevHigh,
                        Section:       sectionDKIM,
                })
        }
        if ds == DKIMThirdPartyOnly {
                fixes = append(fixes, fix{
                        Title:         "Add Primary Domain DKIM",
                        Description:   "DKIM records were found for third-party services but not for your primary mail platform. Configure DKIM for your main sending domain.",
                        RFC:           remDKIMSign,
                        RFCURL:        remDKIMSignURL,
                        SeverityLevel: sevMedium,
                        Section:       sectionDKIM,
                })
        }
        return fixes
}

func weakKeysFix(domain string) fix {
        return fix{
                Title:         "Upgrade DKIM Key Strength",
                Description:   "One or more DKIM keys use 1024-bit RSA which is considered weak. Upgrade to 2048-bit RSA keys.",
                RFC:           remDKIM8301Label,
                RFCURL:        remDKIM8301URL,
                SeverityLevel: sevMedium,
                Section:       sectionDKIM,
        }
}

func appendCAAFixes(fixes []fix, ps protocolState, domain string) []fix {
        if !ps.caaOK {
                fixes = append(fixes, fix{
                        Title:         "Add CAA Records",
                        Description:   "CAA records specify which Certificate Authorities may issue certificates for your domain, reducing the risk of unauthorized certificate issuance.",
                        DNSHost:       domain,
                        DNSType:       "CAA",
                        DNSValue:      "0 issue \"letsencrypt.org\"",
                        DNSPurpose:    "CAA constrains which CAs can issue certificates for this domain.",
                        DNSHostHelp:   "(root of domain — adjust CA to match your provider)",
                        RFC:           remCAA8659Label,
                        RFCURL:        remCAA8659URL,
                        SeverityLevel: sevLow,
                        Section:       "CAA",
                })
        }
        return fixes
}

func appendMTASTSFixes(fixes []fix, ps protocolState, domain string) []fix {
        if !ps.mtaStsOK && !ps.isNoMailDomain {
                fixes = append(fixes, fix{
                        Title:         "Deploy MTA-STS",
                        Description:   "MTA-STS enforces TLS encryption for inbound mail delivery, preventing downgrade attacks on your mail transport.",
                        DNSHost:       "_mta-sts." + domain,
                        DNSType:       dnsTypeTXT,
                        DNSValue:      "v=STSv1; id=" + domain,
                        DNSPurpose:    "MTA-STS tells sending servers to require TLS when delivering mail to your domain.",
                        DNSHostHelp:   "(MTA-STS policy record)",
                        RFC:           remMTASTS8461Label,
                        RFCURL:        remMTASTS8461URL,
                        SeverityLevel: sevLow,
                        Section:       "MTA-STS",
                })
        }
        return fixes
}

func appendTLSRPTFixes(fixes []fix, ps protocolState, domain string) []fix {
        if !ps.tlsrptOK && !ps.isNoMailDomain {
                desc := tlsrptDescDefault
                if ps.daneOK {
                        desc = tlsrptDescDANE + " " + tlsrptDescDefault
                } else if ps.mtaStsOK {
                        desc = tlsrptDescMTASTS + " " + tlsrptDescDefault
                }
                fixes = append(fixes, fix{
                        Title:         "Add TLS-RPT Reporting",
                        Description:   desc,
                        DNSHost:       "_smtp._tls." + domain,
                        DNSType:       dnsTypeTXT,
                        DNSValue:      "v=TLSRPTv1; rua=mailto:tls-reports@" + domain,
                        DNSPurpose:    "TLS-RPT sends you reports about TLS connection failures to your mail servers.",
                        DNSHostHelp:   "(SMTP TLS reporting record)",
                        RFC:           remTLSRPT8460Label,
                        RFCURL:        remTLSRPT8460URL,
                        SeverityLevel: sevLow,
                        Section:       "TLS-RPT",
                })
        }
        return fixes
}

func appendDNSSECFixes(fixes []fix, ps protocolState) []fix {
        if ps.dnssecBroken {
                fixes = append(fixes, fix{
                        Title:         "Fix Broken DNSSEC",
                        Description:   "DNSSEC validation is failing for this domain. This can cause resolvers to reject all DNS responses, making your domain unreachable.",
                        RFC:           remDNSSEC4035Label,
                        RFCURL:        remDNSSEC4035URL,
                        SeverityLevel: sevCritical,
                        Section:       sectionDNSSEC,
                })
        }
        if !ps.dnssecOK && !ps.dnssecBroken {
                fixes = append(fixes, fix{
                        Title:         "Enable DNSSEC",
                        Description:   "DNSSEC is not enabled for this domain. DNSSEC provides cryptographic authentication of DNS responses, preventing cache poisoning and DNS spoofing attacks.",
                        RFC:           remDNSSEC4035Label,
                        RFCURL:        remDNSSEC4035URL,
                        SeverityLevel: sevMedium,
                        Section:       sectionDNSSEC,
                })
        }
        if ps.dnssecOK && ps.dnssecAlgoStrength == "deprecated" {
                fixes = append(fixes, fix{
                        Title:         "Migrate From Deprecated DNSSEC Algorithm",
                        Description:   "This domain uses a DNSSEC signing algorithm classified as MUST NOT use per RFC 8624. Deprecated algorithms (RSAMD5, DSA, ECC-GOST) have known cryptographic weaknesses. Re-sign the zone with ECDSAP256SHA256 (algorithm 13) or Ed25519 (algorithm 15).",
                        RFC:           remDNSSEC8624Label,
                        RFCURL:        remDNSSEC8624URL,
                        SeverityLevel: sevHigh,
                        Section:       sectionDNSSEC,
                })
        }
        if ps.dnssecOK && ps.dnssecAlgoStrength == "legacy" {
                fixes = append(fixes, fix{
                        Title:         "Upgrade From Legacy DNSSEC Algorithm",
                        Description:   "This domain uses RSA/SHA-1 (algorithm 5 or 7) which is NOT RECOMMENDED per RFC 8624. While still operational, plan migration to ECDSAP256SHA256 (algorithm 13) or Ed25519 (algorithm 15) for improved security and smaller signatures.",
                        RFC:           remDNSSEC8624Label,
                        RFCURL:        remDNSSEC8624URL,
                        SeverityLevel: sevMedium,
                        Section:       sectionDNSSEC,
                })
        }
        return fixes
}

func appendDANEFixes(fixes []fix, ps protocolState, results map[string]any, domain string) []fix {
        if ps.daneOK && !ps.dnssecOK {
                fixes = append(fixes, fix{
                        Title:         "DANE Requires DNSSEC",
                        Description:   "DANE/TLSA records are present but DNSSEC is not enabled. DANE cannot function without DNSSEC validation.",
                        RFC:           remDANE267221Label,
                        RFCURL:        remDANE267221URL,
                        SeverityLevel: sevHigh,
                        Section:       sectionDANE,
                })
        }
        if !ps.daneOK && ps.dnssecOK && !ps.isNoMailDomain && providerSupportsDANE(ps.primaryProvider) {
                mxHost := extractFirstMXHost(results)
                tlsaHost := "_25._tcp." + mxHost
                fixes = append(fixes, fix{
                        Title:         "Add DANE/TLSA Records",
                        Description:   "DNSSEC is active — adding TLSA records enables DANE, which cryptographically binds your mail server certificates to DNS and prevents certificate-based MITM attacks.",
                        DNSHost:       tlsaHost,
                        DNSType:       "TLSA",
                        DNSValue:      "3 1 1 <certificate-sha256-hash>",
                        DNSPurpose:    "TLSA pins your mail server's TLS certificate in DNS, verified via DNSSEC.",
                        DNSHostHelp:   "(TLSA record for primary MX — generate hash from your server certificate)",
                        RFC:           remDANE7672Label,
                        RFCURL:        remDANE7672URL,
                        SeverityLevel: sevLow,
                        Section:       sectionDANE,
                })
        }
        return fixes
}

func extractFirstMXHost(results map[string]any) string {
        if host := extractMXHostFromRecords(results); host != "" {
                return host
        }
        if host := extractMXHostFromAnalysis(results); host != "" {
                return host
        }
        return "mail.yourdomain.com"
}

func extractMXHostFromRecords(results map[string]any) string {
        mx, _ := results["mx_records"].([]any)
        if len(mx) == 0 {
                return ""
        }
        rec, ok := mx[0].(map[string]any)
        if !ok {
                return ""
        }
        if host, ok := rec["host"].(string); ok && host != "" {
                return strings.TrimSuffix(host, ".")
        }
        if host, ok := rec["exchange"].(string); ok && host != "" {
                return strings.TrimSuffix(host, ".")
        }
        return ""
}

func extractMXHostFromAnalysis(results map[string]any) string {
        mxAnalysis, _ := results["mx_analysis"].(map[string]any)
        if mxAnalysis == nil {
                return ""
        }
        hosts, ok := mxAnalysis["mx_hosts"].([]any)
        if !ok || len(hosts) == 0 {
                return ""
        }
        if h, ok := hosts[0].(string); ok {
                return strings.TrimSuffix(h, ".")
        }
        return ""
}

func appendNoMailHardeningFixes(fixes []fix, ps protocolState, domain string) []fix {
        if !ps.spfHardFail {
                fixes = append(fixes, fix{
                        Title:         "Harden SPF for Null MX Domain",
                        Description:   "This domain publishes a Null MX record (RFC 7505) declaring it does not accept email. Complete the no-mail hardening by adding a strict SPF record that explicitly denies all senders.",
                        SeverityLevel: sevHigh,
                        DNSHost:       domain,
                        DNSType:       dnsTypeTXT,
                        DNSValue:      spfHardFailValue,
                        DNSPurpose:    "Explicitly declares no servers are authorized to send email from this null MX domain.",
                        RFC:           remSPF,
                        RFCURL:        remSPFURL,
                        Section:       sectionSPF,
                })
        }
        if ps.dmarcMissing || (ps.dmarcPolicy != policyReject) {
                fixes = append(fixes, fix{
                        Title:         "Add DMARC Reject for Null MX Domain",
                        Description:   "This domain publishes a Null MX record (RFC 7505) but lacks a DMARC reject policy. Without it, attackers can still spoof email from this domain. Complete the no-mail hardening with a strict DMARC reject policy.",
                        SeverityLevel: sevHigh,
                        DNSHost:       dmarcHostPrefix + domain,
                        DNSType:       dnsTypeTXT,
                        DNSValue:      "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;",
                        DNSPurpose:    "Instructs receiving servers to reject all email from this null MX domain — no legitimate mail is expected.",
                        RFC:           remDMARC7489,
                        RFCURL:        remDMARC7489URL,
                        Section:       sectionDMARC,
                })
        }
        return fixes
}

func appendProbableNoMailFixes(fixes []fix, ps protocolState, domain string) []fix {
        if !ps.spfHardFail {
                fixes = append(fixes, fix{
                        Title:         "Lock Down SPF for No-Mail Domain",
                        Description:   "This domain has no MX records and appears to be a website-only domain. Publishing a strict SPF record explicitly declares that no servers are authorized to send email, preventing attackers from spoofing your domain.",
                        SeverityLevel: sevHigh,
                        DNSHost:       domain,
                        DNSType:       dnsTypeTXT,
                        DNSValue:      spfHardFailValue,
                        DNSPurpose:    "Explicitly declares no servers are authorized to send email from this domain.",
                        RFC:           remSPF,
                        RFCURL:        remSPFURL,
                        Section:       sectionSPF,
                })
        }
        if ps.dmarcMissing || (ps.dmarcPolicy != policyReject) {
                fixes = append(fixes, fix{
                        Title:         "Add DMARC Reject for No-Mail Domain",
                        Description:   "This domain has no MX records and appears to be a website-only domain. A DMARC reject policy tells receiving mail servers to reject any email claiming to be from your domain.",
                        SeverityLevel: sevHigh,
                        DNSHost:       dmarcHostPrefix + domain,
                        DNSType:       dnsTypeTXT,
                        DNSValue:      "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;",
                        DNSPurpose:    "Instructs receiving servers to reject all email from this domain — no legitimate mail is expected.",
                        RFC:           remDMARC7489,
                        RFCURL:        remDMARC7489URL,
                        Section:       sectionDMARC,
                })
        }
        return fixes
}

func appendBIMIFixes(fixes []fix, ps protocolState, domain string) []fix {
        if !ps.bimiOK && ps.dmarcPolicy == policyReject {
                fixes = append(fixes, fix{
                        Title:         "Add BIMI Record",
                        Description:   "Your domain has DMARC reject — you qualify for BIMI, which displays your brand logo in receiving email clients that support it (Gmail, Apple Mail, Yahoo).",
                        DNSHost:       "default._bimi." + domain,
                        DNSType:       dnsTypeTXT,
                        DNSValue:      "v=BIMI1; l=https://" + domain + "/brand/logo.svg",
                        DNSPurpose:    "BIMI displays your verified brand logo next to your emails in supporting mail clients.",
                        DNSHostHelp:   "(BIMI default record)",
                        RFC:           remBIMI9495Label,
                        RFCURL:        remBIMI9495URL,
                        SeverityLevel: sevLow,
                        Section:       "BIMI",
                })
        }
        return fixes
}

func isDANEDeployable(results map[string]any) bool {
        dnssec, _ := results["dnssec_analysis"].(map[string]any)
        if dnssec == nil {
                return false
        }
        status, _ := dnssec["status"].(string)
        return status == "secure"
}

func buildPerSection(fixes []fix) map[string]any {
        sections := map[string][]map[string]any{}
        for _, f := range fixes {
                if f.Section != "" {
                        sections[f.Section] = append(sections[f.Section], fixToMap(f))
                }
        }
        result := map[string]any{}
        for k, v := range sections {
                result[k] = v
        }
        return result
}

func computeAchievablePosture(ps protocolState, fixes []fix) string {
        coreIssues := countCoreIssues(fixes)
        if coreIssues == 0 {
                return "Secure"
        }
        if !hasSeverity(fixes, severityCritical) {
                return "Low Risk"
        }
        if len(fixes) <= 3 {
                return "Low Risk"
        }
        return "Moderate Risk"
}

func buildMailPosture(results map[string]any) map[string]any {
        ps := evaluateProtocolStates(results)
        mf := extractMailFlags(results, ps)
        signals, presentCount := buildNoMailSignals(mf)
        missingSteps := buildMissingSteps(mf)
        mc := classifyMailPosture(mf, presentCount, extractDomain(results), ps)
        verdict, badge := computeMailVerdict(mf)

        mp := map[string]any{
                "verdict":        verdict,
                "badge":          badge,
                "classification": mc.classification,
                "label":          mc.label,
                "color":          mc.color,
                "icon":           mc.icon,
                "summary":        mc.summary,
                "is_no_mail":     mc.isNoMail,
                "signals":        signals,
                "present_count":  presentCount,
                "total_signals":  3,
                "missing_steps":  missingSteps,
        }

        if mc.isNoMail {
                domain := extractDomain(results)
                mp["recommended_records"] = buildNoMailRecommendedRecords(mf, domain)
                mp["structured_records"] = buildNoMailStructuredRecords(mf, domain)
        }

        return mp
}

func extractMailFlags(results map[string]any, ps protocolState) mailFlags {
        mf := mailFlags{}
        mf.hasSPF = ps.spfOK
        mf.hasDMARC = ps.dmarcOK || ps.dmarcWarning
        mf.hasDKIM = ps.dkimOK || ps.dkimProvider
        mf.hasNullMX = ps.isNoMailDomain
        mf.spfDenyAll = ps.spfHardFail
        mf.dmarcReject = ps.dmarcPolicy == policyReject
        mf.dmarcPolicy = ps.dmarcPolicy

        basic, _ := results["basic_records"].(map[string]any)
        if basic != nil {
                if mx, ok := basic["MX"].([]string); ok && len(mx) > 0 {
                        mf.hasMX = true
                }
        }
        return mf
}

func computeMailVerdict(mf mailFlags) (string, string) {
        if mf.hasNullMX {
                return "no_mail", "No Mail Observed"
        }
        if mf.hasSPF && mf.hasDMARC && mf.hasDKIM {
                if mf.dmarcReject {
                        return "protected", "Strongly Protected"
                }
                return "partial", "Moderately Protected"
        }
        if mf.hasSPF || mf.hasDMARC {
                return "minimal", "Limited Protection"
        }
        return "unprotected", "Unprotected"
}

func buildNoMailSignals(mf mailFlags) (map[string]any, int) {
        signals := map[string]any{}
        count := 0
        defs := []noMailSignalDef{
                {key: "null_mx", present: mf.hasNullMX, rfc: remNullMX7505Label, rfcURL: remNullMX7505URL, label: "Null MX", description: "Null MX record published", missingRisk: "Domain may receive unwanted mail"},
                {key: "spf_deny", present: mf.spfDenyAll, rfc: remSPF, rfcURL: remSPFURL, label: "SPF -all", description: "SPF hard fail configured", missingRisk: "Unauthorized senders not explicitly rejected"},
                {key: "dmarc_reject", present: mf.dmarcReject, rfc: remDMARC7489, rfcURL: remDMARC7489URL, label: "DMARC reject", description: "DMARC reject policy active", missingRisk: "Spoofed mail may be delivered"},
        }
        for _, d := range defs {
                signals[d.key] = map[string]any{
                        "present":      d.present,
                        mapKeyRFC:      d.rfc,
                        mapKeyRFCURL:   d.rfcURL,
                        "label":        d.label,
                        "description":  d.description,
                        "missing_risk": d.missingRisk,
                }
                if d.present {
                        count++
                }
        }
        return signals, count
}

func buildMissingSteps(mf mailFlags) []map[string]any {
        var steps []map[string]any
        defs := []missingStepDef{
                {missing: !mf.hasSPF, control: "SPF Record", rfc: remSPF, rfcURL: remSPFURL, action: "Publish an SPF record", risk: "No sender authorization"},
                {missing: !mf.hasDMARC, control: "DMARC Policy", rfc: remDMARC7489, rfcURL: remDMARC7489URL, action: "Publish a DMARC record", risk: "No spoofing protection policy"},
                {missing: !mf.hasDKIM, control: "DKIM Signing", rfc: remDKIMSign, rfcURL: remDKIMSignURL, action: "Configure DKIM signing", risk: "Messages cannot be cryptographically verified"},
        }
        for _, d := range defs {
                if d.missing {
                        steps = append(steps, map[string]any{
                                "control":    d.control,
                                mapKeyRFC:    d.rfc,
                                mapKeyRFCURL: d.rfcURL,
                                "action":     d.action,
                                "risk":       d.risk,
                        })
                }
        }
        return steps
}

func classifyMailPosture(mf mailFlags, presentCount int, domain string, ps protocolState) mailClassification {
        if mf.hasNullMX {
                if mf.spfDenyAll && mf.dmarcReject {
                        return mailClassification{
                                classification: "no_mail_verified",
                                label:          "No-Mail Domain — Fully Hardened",
                                color:          "success",
                                icon:           "shield-alt",
                                summary:        "This domain declares it does not send or receive email and has all three RFC-recommended controls in place: Null MX (RFC 7505), SPF -all (RFC 7208), and DMARC reject (RFC 7489).",
                                isNoMail:       true,
                        }
                }
                return mailClassification{
                        classification: "no_mail_partial",
                        label:          "No-Mail Domain — Incomplete Hardening",
                        color:          colorHigh,
                        icon:           "exclamation-triangle",
                        summary:        "This domain publishes a Null MX record (RFC 7505) declaring it does not accept email, but is missing additional hardening controls needed to fully prevent spoofing.",
                        isNoMail:       true,
                }
        }
        if !mf.hasMX && mf.spfDenyAll {
                return mailClassification{
                        classification: "no_mail_intent",
                        label:          "Probable No-Mail Domain — Needs Formal Declaration",
                        color:          "info",
                        icon:           "info-circle",
                        summary:        "This domain has no MX records and an SPF -all policy, which suggests it is intended to be a no-mail domain. However, it is missing the formal Null MX record (RFC 7505) that explicitly declares this intent. Adding the standard no-mail DNS records would make this intention unambiguous to all mail servers.",
                        isNoMail:       true,
                }
        }
        if mf.hasSPF && mf.hasDMARC && mf.hasDKIM && mf.dmarcReject {
                return mailClassification{
                        classification: "protected",
                        label:          "Strongly Protected",
                        color:          "success",
                        icon:           "shield-alt",
                        summary:        "SPF, DKIM, and DMARC reject policy observed — strong anti-spoofing controls detected.",
                }
        }
        if mf.hasSPF && mf.hasDMARC && mf.hasDKIM {
                return mailClassification{
                        classification: "partial",
                        label:          "Moderately Protected",
                        color:          colorHigh,
                        icon:           "exclamation-triangle",
                        summary:        "Core email authentication controls observed but DMARC enforcement could be strengthened.",
                }
        }
        if mf.hasSPF || mf.hasDMARC {
                return mailClassification{
                        classification: "minimal",
                        label:          "Limited Protection",
                        color:          colorHigh,
                        icon:           "exclamation-circle",
                        summary:        "Some email authentication controls observed but critical components are missing.",
                }
        }
        return mailClassification{
                classification: "unprotected",
                label:          "Unprotected",
                color:          "danger",
                icon:           "times-circle",
                summary:        "No email authentication controls observed — this domain appears vulnerable to spoofing.",
        }
}

func buildNoMailRecommendedRecords(mf mailFlags, domain string) []string {
        var records []string
        if !mf.hasNullMX {
                records = append(records, domain+" MX 0 .")
        }
        if !mf.spfDenyAll {
                records = append(records, domain+" TXT \"v=spf1 -all\"")
        }
        if !mf.dmarcReject {
                records = append(records, dmarcHostPrefix+domain+" TXT \"v=DMARC1; p=reject;\"")
        }
        return records
}

func buildNoMailStructuredRecords(mf mailFlags, domain string) []dnsRecord {
        var records []dnsRecord
        if !mf.hasNullMX {
                records = append(records, dnsRecord{RecordType: "MX", Host: domain, Value: "0 .", Purpose: "Null MX declares this domain does not accept mail", HostHelp: hostHelpRootDom})
        }
        if !mf.spfDenyAll {
                records = append(records, dnsRecord{RecordType: dnsTypeTXT, Host: domain, Value: spfHardFailValue, Purpose: "Hard-fail SPF blocks all mail from this domain", HostHelp: hostHelpRootDom})
        }
        if !mf.dmarcReject {
                records = append(records, dnsRecord{RecordType: dnsTypeTXT, Host: dmarcHostPrefix + domain, Value: "v=DMARC1; p=reject;", Purpose: "DMARC reject policy for no-mail domain", HostHelp: hostHelpDMARC})
        }
        return records
}

func getVerdict(results map[string]any, key string) string {
        if analysis, ok := results[key].(map[string]any); ok {
                if status, ok := analysis["status"].(string); ok {
                        return status
                }
        }
        return ""
}

func countCoreIssues(fixes []fix) int {
        count := 0
        for _, f := range fixes {
                if f.SeverityLevel.Name == severityCritical || f.SeverityLevel.Name == severityHigh {
                        count++
                }
        }
        return count
}

func hasSeverity(fixes []fix, severity string) bool {
        for _, f := range fixes {
                if f.SeverityLevel.Name == severity {
                        return true
                }
        }
        return false
}

func filterBySeverity(fixes []fix, severity string) []fix {
        var result []fix
        for _, f := range fixes {
                if f.SeverityLevel.Name == severity {
                        result = append(result, f)
                }
        }
        return result
}

func joinFixTitles(fixes []fix) string {
        var titles []string
        for _, f := range fixes {
                titles = append(titles, f.Title)
        }
        return strings.Join(titles, ", ")
}
