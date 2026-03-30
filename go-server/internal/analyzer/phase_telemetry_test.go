package analyzer

import (
        "testing"
)

func TestLookupPhaseGroup(t *testing.T) {
        tests := []struct {
                task     string
                expected string
        }{
                {"basic", "dns_records"},
                {"auth", "dns_records"},
                {"resolver_consensus", "dns_records"},
                {"spf", "email_auth"},
                {"dmarc", "email_auth"},
                {"dkim", "email_auth"},
                {"dnssec", "dnssec_dane"},
                {"cds_cdnskey", "dnssec_dane"},
                {"dnssec_ops", "dnssec_dane"},
                {"dane", "dnssec_dane"},
                {"ct_subdomains", "ct_subdomains"},
                {"security_txt", "ct_subdomains"},
                {"ai_surface", "ct_subdomains"},
                {"secret_exposure", "ct_subdomains"},
                {"smtp_transport", "smtp_transport"},
                {"nmap_dns", "smtp_transport"},
                {"smimea_openpgpkey", "smtp_transport"},
                {"mta_sts", "policy_records"},
                {"tlsrpt", "policy_records"},
                {"bimi", "policy_records"},
                {"caa", "policy_records"},
                {"registrar", "registrar_infra"},
                {"ns_delegation", "registrar_infra"},
                {"ns_fleet", "registrar_infra"},
                {"delegation_consistency", "registrar_infra"},
                {"https_svcb", "registrar_infra"},
                {"posture", "analysis_engine"},
                {"hosting", "analysis_engine"},
                {"unknown_task", "analysis_engine"},
        }

        for _, tt := range tests {
                t.Run(tt.task, func(t *testing.T) {
                        got := LookupPhaseGroup(tt.task)
                        if got != tt.expected {
                                t.Errorf("LookupPhaseGroup(%q) = %q, want %q", tt.task, got, tt.expected)
                        }
                })
        }
}

func TestComputeTelemetryHash(t *testing.T) {
        timings := []PhaseTiming{
                {PhaseGroup: "dns_records", PhaseTask: "basic", StartedAtMs: 0, DurationMs: 500},
                {PhaseGroup: "email_auth", PhaseTask: "spf", StartedAtMs: 0, DurationMs: 800},
        }

        hash1 := ComputeTelemetryHash(timings)
        if len(hash1) != 128 {
                t.Errorf("expected 128-char hex hash, got %d chars", len(hash1))
        }

        hash2 := ComputeTelemetryHash(timings)
        if hash1 != hash2 {
                t.Error("identical inputs must produce identical hashes")
        }

        reversed := []PhaseTiming{timings[1], timings[0]}
        hash3 := ComputeTelemetryHash(reversed)
        if hash1 != hash3 {
                t.Error("hash must be order-independent (canonical sorting)")
        }

        different := []PhaseTiming{
                {PhaseGroup: "dns_records", PhaseTask: "basic", StartedAtMs: 0, DurationMs: 999},
                {PhaseGroup: "email_auth", PhaseTask: "spf", StartedAtMs: 0, DurationMs: 800},
        }
        hash4 := ComputeTelemetryHash(different)
        if hash1 == hash4 {
                t.Error("different inputs must produce different hashes")
        }
}

func TestExtractResultMeta(t *testing.T) {
        tests := []struct {
                name        string
                result      any
                wantCount   int
                wantErr     string
        }{
                {"nil_result", nil, 0, ""},
                {"non_map_result", "string_result", 0, ""},
                {"empty_map", map[string]any{}, 0, ""},
                {"map_with_error", map[string]any{"error": "lookup failed"}, 0, "lookup failed"},
                {"map_with_records", map[string]any{"records": []any{"a", "b", "c"}}, 3, ""},
                {"map_with_string_records", map[string]any{"records": []string{"a.example.com", "b.example.com"}}, 2, ""},
                {"map_with_map_records", map[string]any{"records": []map[string]any{{"type": "A"}, {"type": "AAAA"}}}, 2, ""},
                {"map_with_count", map[string]any{"count": 5}, 5, ""},
                {"map_with_int32_count", map[string]any{"count": int32(7)}, 7, ""},
                {"map_with_int64_count", map[string]any{"count": int64(12)}, 12, ""},
                {"map_with_float64_count", map[string]any{"count": float64(3)}, 3, ""},
                {"records_takes_precedence_over_count", map[string]any{"records": []any{"x"}, "count": 10}, 1, ""},
                {"error_and_records", map[string]any{"error": "partial", "records": []any{"a", "b"}}, 2, "partial"},
                {"empty_error_string", map[string]any{"error": ""}, 0, ""},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        gotCount, gotErr := extractResultMeta(tc.result)
                        if gotCount != tc.wantCount {
                                t.Errorf("recordCount = %d, want %d", gotCount, tc.wantCount)
                        }
                        if gotErr != tc.wantErr {
                                t.Errorf("errMsg = %q, want %q", gotErr, tc.wantErr)
                        }
                })
        }
}

func TestNewScanTelemetry(t *testing.T) {
        timings := []PhaseTiming{
                {PhaseGroup: "dns_records", PhaseTask: "basic", StartedAtMs: 0, DurationMs: 500},
        }
        tel := NewScanTelemetry(timings, 500)
        if tel.TotalDurationMs != 500 {
                t.Errorf("TotalDurationMs = %d, want 500", tel.TotalDurationMs)
        }
        if tel.SHA3Hash == "" {
                t.Error("SHA3Hash must not be empty")
        }
        if len(tel.Timings) != 1 {
                t.Errorf("expected 1 timing, got %d", len(tel.Timings))
        }
}
