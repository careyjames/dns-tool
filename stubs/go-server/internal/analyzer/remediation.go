// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// This file contains stub implementations. See the corresponding _intel.go file (requires -tags intel build).
package analyzer

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

        tlsrptDescDefault = "TLS-RPT (TLS Reporting) sends you reports about TLS connection failures when other servers try to deliver mail to your domain."
        tlsrptDescDANE    = "Your domain has DNSSEC + DANE — the strongest email transport security available."
        tlsrptDescMTASTS  = "Your domain has MTA-STS configured for transport encryption."
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
        Severity      string
        SeverityColor string
        SeverityOrder int
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

func (a *Analyzer) GenerateRemediation(results map[string]any) map[string]any {
        return map[string]any{
                "top_fixes":          []map[string]any{},
                "all_fixes":          []map[string]any{},
                "fix_count":          float64(0),
                "posture_achievable": "",
                "per_section":        map[string]any{},
        }
}

func dkimRecordExample(domain, provider string) string {
        return ""
}

func dkimSelectorForProvider(provider string) string {
        return "selector1"
}

func extractDomain(results map[string]any) string {
        if d, ok := results["domain"].(string); ok {
                return d
        }
        return "yourdomain.com"
}

func fixToMap(f fix) map[string]any {
        return map[string]any{}
}

func sortFixes(fixes []fix) {
        // intentionally empty — OSS stub
}

func buildSPFValue(includes []string, qualifier string) string {
        return ""
}

func buildSPFRecordExample(domain string, includes []string, qualifier string) string {
        return ""
}

func extractSPFIncludes(results map[string]any) []string {
        return nil
}

func appendSPFFixes(fixes []fix, ps protocolState, ds DKIMState, results map[string]any, domain string) []fix {
        return fixes
}

func appendSPFLookupFix(fixes []fix, ps protocolState) []fix {
        return fixes
}

func appendSPFUpgradeFix(fixes []fix, ps protocolState, ds DKIMState, domain string, includes []string) []fix {
        return fixes
}

func appendDMARCFixes(fixes []fix, ps protocolState, results map[string]any, domain string) []fix {
        return fixes
}

func appendDKIMFixes(fixes []fix, ps protocolState, ds DKIMState, results map[string]any, domain string) []fix {
        return fixes
}

func weakKeysFix(domain string) fix {
        return fix{}
}

func appendCAAFixes(fixes []fix, ps protocolState, domain string) []fix {
        return fixes
}

func appendMTASTSFixes(fixes []fix, ps protocolState, domain string) []fix {
        return fixes
}

func appendTLSRPTFixes(fixes []fix, ps protocolState, domain string) []fix {
        return fixes
}

func appendDNSSECFixes(fixes []fix, ps protocolState) []fix {
        return fixes
}

func appendDANEFixes(fixes []fix, ps protocolState, results map[string]any, domain string) []fix {
        return fixes
}

func appendBIMIFixes(fixes []fix, ps protocolState, domain string) []fix {
        return fixes
}

func isHostedMXProvider(results map[string]any) bool {
        return false
}

func isDANEDeployable(results map[string]any) bool {
        return false
}

func buildPerSection(fixes []fix) map[string]any {
        return map[string]any{}
}

func computeAchievablePosture(ps protocolState, fixes []fix) string {
        return ""
}

func buildMailPosture(results map[string]any) map[string]any {
        return map[string]any{
                "verdict":        "",
                "badge":          "",
                "classification": "",
                "label":          "",
                "color":          "",
                "icon":           "",
                "summary":        "",
                "is_no_mail":     false,
                "signals":        map[string]any{},
                "present_count":  0,
                "total_signals":  3,
                "missing_steps":  []map[string]any{},
        }
}

func extractMailFlags(results map[string]any, ps protocolState) mailFlags {
        return mailFlags{}
}

func computeMailVerdict(mf mailFlags) (string, string) {
        return "", ""
}

func buildNoMailSignals(mf mailFlags) (map[string]any, int) {
        return map[string]any{}, 0
}

func buildMissingSteps(mf mailFlags) []map[string]any {
        return nil
}

func classifyMailPosture(mf mailFlags, presentCount int, domain string, ps protocolState) mailClassification {
        return mailClassification{}
}

func buildNoMailRecommendedRecords(mf mailFlags, domain string) []string {
        return nil
}

func buildNoMailStructuredRecords(mf mailFlags, domain string) []dnsRecord {
        return nil
}

func getVerdict(results map[string]any, key string) string {
        return ""
}

func countCoreIssues(fixes []fix) int {
        return 0
}

func hasSeverity(fixes []fix, severity string) bool {
        return false
}

func filterBySeverity(fixes []fix, severity string) []fix {
        return nil
}

func joinFixTitles(fixes []fix) string {
        return ""
}
