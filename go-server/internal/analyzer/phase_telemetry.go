package analyzer
// dns-tool:scrutiny science

import (
        "encoding/hex"
        "encoding/json"
        "sort"

        "golang.org/x/crypto/sha3"
)

type PhaseTiming struct {
        PhaseGroup   string `json:"phase_group"`
        PhaseTask    string `json:"phase_task"`
        StartedAtMs  int    `json:"started_at_ms"`
        DurationMs   int    `json:"duration_ms"`
        RecordCount  int    `json:"record_count"`
        Error        string `json:"error,omitempty"`
}

type ScanTelemetry struct {
        AnalysisID      int32          `json:"analysis_id"`
        Timings         []PhaseTiming  `json:"timings"`
        TotalDurationMs int            `json:"total_duration_ms"`
        SHA3Hash        string         `json:"sha3_512"`
}

var phaseGroupMap = map[string]string{
        "basic":                    "dns_records",
        "auth":                     "dns_records",
        "resolver_consensus":       "dns_records",
        "spf":                      "email_auth",
        "dmarc":                    "email_auth",
        "dkim":                     "email_auth",
        "dnssec":                   "dnssec_dane",
        "cds_cdnskey":              "dnssec_dane",
        "dnssec_ops":               "dnssec_dane",
        "dane":                     "dnssec_dane",
        "ct_subdomains":            "ct_subdomains",
        "security_txt":             "ct_subdomains",
        "ai_surface":               "ct_subdomains",
        "secret_exposure":          "ct_subdomains",
        "smtp_transport":           "smtp_transport",
        "nmap_dns":                 "smtp_transport",
        "smimea_openpgpkey":        "smtp_transport",
        "mta_sts":                  "policy_records",
        "tlsrpt":                   "policy_records",
        "bimi":                     "policy_records",
        "caa":                      "policy_records",
        "registrar":                "registrar_infra",
        "ns_delegation":            "registrar_infra",
        "ns_fleet":                 "registrar_infra",
        "delegation_consistency":   "registrar_infra",
        "https_svcb":               "registrar_infra",
        "posture":                  "analysis_engine",
        "remediation":              "analysis_engine",
        "currency":                 "analysis_engine",
        "icuae":                    "analysis_engine",
        "hosting":                  "analysis_engine",
        "web_exposure":             "analysis_engine",
        "asn":                      "analysis_engine",
        "dangling_dns":             "analysis_engine",
        "edge_cdn":                 "analysis_engine",
        "saas_txt":                 "analysis_engine",
        "web3_analysis":            "web3_analysis",
}

var PhaseGroupLabels = map[string]string{
        "dns_records":     "DNS Records",
        "email_auth":      "Email Authentication",
        "dnssec_dane":     "DNSSEC & DANE",
        "ct_subdomains":   "Certificate Transparency",
        "smtp_transport":  "SMTP Transport",
        "policy_records":  "Policy Records",
        "registrar_infra": "Registrar & Infrastructure",
        "analysis_engine": "Analysis Engine",
        "web3_analysis":   "Web3 Analysis",
}

var PhaseGroupOrder = []string{
        "dns_records",
        "email_auth",
        "dnssec_dane",
        "ct_subdomains",
        "smtp_transport",
        "policy_records",
        "registrar_infra",
        "web3_analysis",
        "analysis_engine",
}

func PhaseGroupTaskCounts() map[string]int {
        counts := make(map[string]int, len(PhaseGroupOrder))
        for _, group := range PhaseGroupOrder {
                counts[group] = 0
        }
        for _, group := range phaseGroupMap {
                counts[group]++
        }
        return counts
}

func PhaseGroupCallbackCounts() map[string]int {
        counts := PhaseGroupTaskCounts()
        counts["analysis_engine"] = 1
        return counts
}

func LookupPhaseGroup(taskKey string) string {
        if group, ok := phaseGroupMap[taskKey]; ok {
                return group
        }
        return "analysis_engine"
}

func ComputeTelemetryHash(timings []PhaseTiming) string {
        sorted := make([]PhaseTiming, len(timings))
        copy(sorted, timings)
        sort.Slice(sorted, func(i, j int) bool {
                if sorted[i].StartedAtMs != sorted[j].StartedAtMs {
                        return sorted[i].StartedAtMs < sorted[j].StartedAtMs
                }
                return sorted[i].PhaseTask < sorted[j].PhaseTask
        })

        canonical, _ := json.Marshal(sorted)
        hash := sha3.Sum512(canonical)
        return hex.EncodeToString(hash[:])
}

func NewScanTelemetry(timings []PhaseTiming, totalMs int) ScanTelemetry {
        return ScanTelemetry{
                Timings:         timings,
                TotalDurationMs: totalMs,
                SHA3Hash:        ComputeTelemetryHash(timings),
        }
}
