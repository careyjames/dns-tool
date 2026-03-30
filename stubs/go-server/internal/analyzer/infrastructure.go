//go:build !intel

// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Stub implementations. See the corresponding _intel.go file (requires -tags intel build).
package analyzer

import "context"

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
        return map[string]any{
                "hosting":            "Unknown",
                "dns_hosting":        "Unknown",
                "email_hosting":      "Unknown",
                "domain":             domain,
                "hosting_confidence": map[string]any{},
                "dns_confidence":     map[string]any{},
                "email_confidence":   map[string]any{},
                "dns_from_parent":    false,
        }
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
        // intentionally empty — OSS stub
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
        // intentionally empty — OSS stub
}

func detectTLSRPTReportProviders(providers map[string]map[string]any, tlsrpt map[string]any) {
        // intentionally empty — OSS stub
}

func detectSPFFlatteningProvider(providers map[string]map[string]any, spf map[string]any) map[string]any {
        return nil
}

func detectMTASTSManagement(providers map[string]map[string]any, mtasts map[string]any) {
        // intentionally empty — OSS stub
}

func (a *Analyzer) detectHostedDKIMProviders(providers map[string]map[string]any, domain string, dkim map[string]any) {
        // intentionally empty — OSS stub
}

func matchDynamicServiceNS(nsLower string) (dynamicServiceInfo, bool) {
        return dynamicServiceInfo{}, false
}

func addDSDetection(detections map[string]*dsDetection, dsInfo dynamicServiceInfo, cap string) {
        // intentionally empty — OSS stub
}

func (a *Analyzer) scanDynamicServiceZones(ctx context.Context, zones map[string]string) map[string]*dsDetection {
        return make(map[string]*dsDetection)
}

func (a *Analyzer) detectDynamicServices(providers map[string]map[string]any, domain string) {
        // intentionally empty — OSS stub
}

func identifyEmailProvider(mxRecords []string) string { return "" }

func identifyDNSProvider(nsRecords []string) string { return "" }

func identifyWebHosting(basic map[string]any) string { return "" }

func identifyHostingFromPTR(aRecords []string) string { return "" }
