//go:build !intel

// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Stub implementations. See the corresponding _intel.go file (requires -tags intel build).
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "strings"

        "dnstool/go-server/internal/providers"
)

const (
        nameGoogleWorkspace = "Google Workspace"
        nameMicrosoft365    = "Microsoft 365"
        nameCloudflare      = "Cloudflare"
        nameCSCGlobalDNS    = "CSC Global DNS"
        nameDigitalOcean    = "DigitalOcean"
        nameGoDaddy         = "GoDaddy"
        nameLinode          = "Linode"
        nameNamecheap       = "Namecheap"
        nameAmazonRoute53   = "Amazon Route 53"

        mapKeyLevel  = "level"
        mapKeyMethod = "method"
)

var enterpriseProviders = map[string]providerInfo{}
var legacyProviderBlocklist = map[string]bool{}
var selfHostedEnterprise = map[string]providerInfo{}
var governmentDomains = map[string]providerInfo{}
var managedProviders = map[string]providerInfo{}
var hostingProviders = map[string]string{}
var hostingPTRProviders = map[string]string{}
var dnsHostingProviders = map[string]string{}
var emailHostingProviders = map[string]string{}
var hostedMXProviders = map[string]bool{}
var mxProviderPatterns = map[string]string{}
var nsProviderPatterns = map[string]string{}
var webHostingPatterns = map[string]string{}
var ptrHostingPatterns = map[string]string{}

func (a *Analyzer) AnalyzeDNSInfrastructure(domain string, results map[string]any) map[string]any {
        return map[string]any{
                "provider_tier":      "standard",
                "provider_features":  []string{},
                "is_government":      false,
                "alt_security_items": []string{},
                "assessment":         "Standard DNS",
        }
}

func (a *Analyzer) GetHostingInfo(ctx context.Context, domain string, results map[string]any) map[string]any {
        basic, _ := results["basic_records"].(map[string]any)
        nsRecords := toStringSlice(basic, "NS")
        mxRecords := toStringSlice(basic, "MX")
        cnameRecords := toStringSlice(basic, "CNAME")

        webHosting := identifyWebHostingOSS(cnameRecords)
        dnsHosting := identifyDNSProviderOSS(nsRecords)
        emailHosting := identifyEmailProviderOSS(mxRecords)

        hostConf := map[string]any{}
        if webHosting != strUnknown {
                hostConf = map[string]any{mapKeyLevel: "observed", mapKeyLabel: "Observed", mapKeyMethod: "CNAME record analysis"}
        }
        dnsConf := map[string]any{}
        if dnsHosting != strUnknown {
                dnsConf = map[string]any{mapKeyLevel: "observed", mapKeyLabel: "Observed", mapKeyMethod: "NS record analysis"}
        }
        emailConf := map[string]any{}
        if emailHosting != strUnknown {
                emailConf = map[string]any{mapKeyLevel: "inferred", mapKeyLabel: "Inferred", mapKeyMethod: "MX record analysis"}
        }

        return map[string]any{
                "hosting":            webHosting,
                "dns_hosting":        dnsHosting,
                "email_hosting":      emailHosting,
                "domain":             domain,
                "hosting_confidence": hostConf,
                "dns_confidence":     dnsConf,
                "email_confidence":   emailConf,
                "dns_from_parent":    false,
        }
}

func toStringSlice(m map[string]any, key string) []string {
        if m == nil {
                return nil
        }
        sl, _ := m[key].([]string)
        return sl
}

func identifyWebHostingOSS(cnameRecords []string) string {
        for _, cname := range cnameRecords {
                lower := strings.ToLower(strings.TrimRight(cname, "."))
                for suffix, info := range providers.CNAMEProviderMap {
                        if strings.HasSuffix(lower, suffix) || strings.Contains(lower, suffix) {
                                return info.Name
                        }
                }
        }
        return strUnknown
}

func identifyDNSProviderOSS(nsRecords []string) string {
        for _, ns := range nsRecords {
                provider := classifyNSProvider(ns)
                if provider != "" {
                        return provider
                }
        }
        return strUnknown
}

func identifyEmailProviderOSS(mxRecords []string) string {
        for _, mx := range mxRecords {
                lower := strings.ToLower(strings.TrimRight(mx, "."))
                for _, cap := range providers.DANEMXCapability {
                        for _, pattern := range cap.Patterns {
                                if strings.Contains(lower, pattern) {
                                        return cap.Name
                                }
                        }
                }
        }
        return strUnknown
}

func (a *Analyzer) DetectEmailSecurityManagement(spf, dmarc, tlsrpt, mtasts map[string]any, domain string, dkim map[string]any) map[string]any {
        return map[string]any{
                "actively_managed": false,
                "providers":        []map[string]any{},
                "spf_flattening":   nil,
                "provider_count":   0,
                "confidence":       ConfidenceInferredMap(MethodDMARCRua),
        }
}

func enrichHostingFromEdgeCDN(results map[string]any) {
        // OSS stub: CDN edge detection in _intel.go counterpart
}

func matchEnterpriseProvider(nsList []string) *infraMatch { return nil }

func matchSelfHostedProvider(nsStr string) *infraMatch { return nil }

func matchManagedProvider(nsStr string) *infraMatch { return nil }

func matchGovernmentDomain(domain string) (*infraMatch, bool) { return nil, false }

func collectAltSecurityItems(results map[string]any) []string { return nil }

func assessTier(tier string) string { return "Standard DNS" }

func (a *Analyzer) resolveNSRecords(domain string, nsRecords []string) ([]string, bool) {
        return nsRecords, false
}

func matchAllProviders(nsList []string, nsStr string) *infraMatch { return nil }

func buildInfraResult(im *infraMatch, isGovernment, nsFromParent bool, results map[string]any) map[string]any {
        return map[string]any{}
}

func (a *Analyzer) detectHostingFromPTR(ctx context.Context, aRecords []string) (string, bool) {
        return "", false
}

func (a *Analyzer) resolveDNSHosting(domain string, nsRecords []string) (string, bool) {
        return "", false
}

func resolveEmailHosting(results map[string]any, mxRecords []string) (string, bool) {
        return "", false
}

func hostingConfidence(hosting string, fromPTR bool) map[string]any { return map[string]any{} }

func dnsConfidence(dnsFromParent bool) map[string]any { return map[string]any{} }

func emailConfidence(emailFromSPF, isNoMail bool) map[string]any { return map[string]any{} }

func detectEmailProviderFromSPF(results map[string]any) string { return "" }

func detectProvider(records []string, providers map[string]string) string { return "" }

func matchMonitoringProvider(domain string) *managementProviderInfo { return nil }

func detectDMARCReportProviders(providers map[string]map[string]any, dmarc map[string]any) {
        // OSS stub: DMARC report provider detection in _intel.go counterpart
}

func detectTLSRPTReportProviders(providers map[string]map[string]any, tlsrpt map[string]any) {
        // OSS stub: TLS-RPT report provider detection in _intel.go counterpart
}

func detectSPFFlatteningProvider(providers map[string]map[string]any, spf map[string]any) map[string]any {
        return nil
}

func detectMTASTSManagement(providers map[string]map[string]any, mtasts map[string]any) {
        // OSS stub: MTA-STS management detection in _intel.go counterpart
}

func (a *Analyzer) detectHostedDKIMProviders(providers map[string]map[string]any, domain string, dkim map[string]any) {
        // OSS stub: hosted DKIM provider detection in _intel.go counterpart
}

func matchDynamicServiceNS(nsLower string) (dynamicServiceInfo, bool) {
        return dynamicServiceInfo{}, false
}

func addDSDetection(detections map[string]*dsDetection, dsInfo dynamicServiceInfo, cap string) {
        // OSS stub: dynamic service detection accumulator in _intel.go counterpart
}

func (a *Analyzer) scanDynamicServiceZones(ctx context.Context, zones map[string]string) map[string]*dsDetection {
        return make(map[string]*dsDetection)
}

func (a *Analyzer) detectDynamicServices(providers map[string]map[string]any, domain string) {
        // OSS stub: dynamic service detection in _intel.go counterpart
}

func identifyEmailProvider(mxRecords []string) string { return "" }

func identifyDNSProvider(nsRecords []string) string { return "" }

func identifyWebHosting(basic map[string]any) string { return "" }

func identifyHostingFromPTR(aRecords []string) string { return "" }
