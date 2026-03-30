// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// This file contains stub implementations. See the corresponding _intel.go file (requires -tags intel build).
package analyzer

const (
        riskLow      = "Low Risk"
        riskMedium   = "Medium Risk"
        riskHigh     = "High Risk"
        riskCritical = "Critical Risk"

        iconShieldAlt           = "shield-alt"
        iconExclamationTriangle = "exclamation-triangle"

        protocolMTASTS = "MTA-STS"
        protocolTLSRPT = "TLS-RPT"
)

var knownDKIMProviders = map[string]bool{}

func isKnownDKIMProvider(provider interface{}) bool {
        return false
}

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

func evaluateProtocolStates(results map[string]any) protocolState {
        return protocolState{}
}

func isMissingRecord(m map[string]any) bool {
        return false
}

func hasNonEmptyString(m map[string]any, key string) bool {
        return false
}

func extractIntField(m map[string]any, key string) int {
        return 0
}

func extractIntFieldDefault(m map[string]any, key string, defaultVal int) int {
        return defaultVal
}

func evaluateDKIMIssues(dkim map[string]any) (weakKeys bool, thirdPartyOnly bool) {
        return false, false
}

func classifySPF(ps protocolState, acc *postureAccumulator) {
        // intentionally empty — OSS stub
}

func classifyDMARC(ps protocolState, acc *postureAccumulator) {
        // intentionally empty — OSS stub
}

func classifyDMARCSuccess(ps protocolState, acc *postureAccumulator) {
        // intentionally empty — OSS stub
}

func classifyDMARCWarning(ps protocolState, acc *postureAccumulator) {
        // intentionally empty — OSS stub
}

func classifyDKIMPosture(ds DKIMState, primaryProvider string, acc *postureAccumulator) {
        // intentionally empty — OSS stub
}

func classifySimpleProtocols(ps protocolState, acc *postureAccumulator) {
        // intentionally empty — OSS stub
}

func classifyDanglingDNS(results map[string]any, acc *postureAccumulator) {
        // intentionally empty — OSS stub
}

func classifyDMARCReportAuth(results map[string]any, acc *postureAccumulator) {
        // intentionally empty — OSS stub
}

func extractExternalDomainMaps(raw any) []map[string]any {
        return nil
}

func evaluateDeliberateMonitoring(ps protocolState, configuredCount int) (bool, string) {
        return false, ""
}

func (a *Analyzer) CalculatePosture(results map[string]any) map[string]any {
        return map[string]any{
                "score":                      0,
                "grade":                      "",
                "label":                      "",
                "state":                      "",
                "icon":                       "",
                "color":                      "",
                "message":                    "",
                "issues":                     []string{},
                "critical_issues":            []string{},
                "recommendations":            []string{},
                "monitoring":                 []string{},
                "configured":                 []string{},
                "absent":                     []string{},
                "deliberate_monitoring":      false,
                "deliberate_monitoring_note": "",
                "verdicts":                   map[string]any{},
        }
}

func determineGrade(ps protocolState, ds DKIMState, hasSPF, hasDMARC, hasDKIM bool, monitoring, configured, absent []string) (state, icon, color, message string) {
        return "", "", "", ""
}

func classifyGrade(ps protocolState, gi gradeInput, monitoring, configured, absent []string) (string, string, string, string) {
        return "", "", "", ""
}

func classifyMailGrade(ps protocolState, gi gradeInput, monitoring, configured, absent []string) (string, string, string, string) {
        return "", "", "", ""
}

func classifyMailCorePresent(ps protocolState, gi gradeInput, monitoring, configured, absent []string) (string, string, string, string) {
        return "", "", "", ""
}

func classifyMailPartial(gi gradeInput) (string, string, string, string) {
        return "", "", "", ""
}

func classifyNoMailGrade(ps protocolState, gi gradeInput, configured, absent []string) (string, string, string, string) {
        return "", "", "", ""
}

func applyMonitoringSuffix(state string, monitoring []string) string {
        return state
}

func buildDescriptiveMessage(ps protocolState, configured, absent, monitoring []string) string {
        return ""
}

func buildVerdicts(ps protocolState, ds DKIMState, hasSPF, hasDMARC, hasDKIM bool) map[string]any {
        return map[string]any{}
}

func buildEmailVerdict(ps protocolState, ds DKIMState, hasSPF, hasDMARC, hasDKIM bool, verdicts map[string]any) {
        // intentionally empty — OSS stub
}

func buildEnforcingEmailVerdict(ps protocolState, ds DKIMState, verdicts map[string]any) {
        // intentionally empty — OSS stub
}

func buildBrandVerdict(ps protocolState, verdicts map[string]any) {
        // intentionally empty — OSS stub
}

func buildDNSVerdict(ps protocolState, verdicts map[string]any) {
        // intentionally empty — OSS stub
}

func computeInternalScore(ps protocolState, ds DKIMState) int {
        return 0
}

func computeSPFScore(ps protocolState) int {
        return 0
}

func computeDMARCScore(ps protocolState) int {
        return 0
}

func computeDKIMScore(ds DKIMState) int {
        return 0
}

func computeAuxScore(ps protocolState) int {
        return 0
}
