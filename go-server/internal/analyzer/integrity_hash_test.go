package analyzer

import (
        "strings"
        "testing"
)

func TestCanonicalizeValue(t *testing.T) {
        tests := []struct {
                name  string
                input any
                want  string
        }{
                {"nil", nil, "null"},
                {"string", "hello", "hello"},
                {"bool true", true, "true"},
                {"bool false", false, "false"},
                {"float64", float64(3.14), "3.14"},
                {"int", int(42), "42"},
                {"int32", int32(10), "10"},
                {"int64", int64(100), "100"},
                {"empty slice", []any{}, "[]"},
                {"string slice sorted", []string{"b", "a", "c"}, "[a,b,c]"},
                {"any slice", []any{"x", "y"}, "[x,y]"},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := canonicalizeValue(tt.input)
                        if got != tt.want {
                                t.Errorf("canonicalizeValue(%v) = %q, want %q", tt.input, got, tt.want)
                        }
                })
        }
}

func TestCanonicalizeMap(t *testing.T) {
        tests := []struct {
                name  string
                input map[string]any
                want  string
        }{
                {"empty map", map[string]any{}, ""},
                {"single key", map[string]any{"a": "1"}, "a=1"},
                {"sorted keys", map[string]any{"b": "2", "a": "1"}, "a=1;b=2"},
                {"skips underscore keys", map[string]any{"_internal": "x", "visible": "y"}, "visible=y"},
                {"nested map", map[string]any{"outer": map[string]any{"inner": "val"}}, "outer={inner=val}"},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := canonicalizeMap(tt.input)
                        if got != tt.want {
                                t.Errorf("canonicalizeMap() = %q, want %q", got, tt.want)
                        }
                })
        }
}

func TestCountVerifiedStandards(t *testing.T) {
        tests := []struct {
                name    string
                results map[string]any
                want    int
        }{
                {"empty results", map[string]any{}, 0},
                {"spf present", map[string]any{"spf_analysis": map[string]any{"status": "pass"}}, 1},
                {"dnssec has 3 RFCs", map[string]any{"dnssec_analysis": map[string]any{"status": "secure"}}, 3},
                {"dane has 2 RFCs", map[string]any{"dane_analysis": map[string]any{"status": "present"}}, 2},
                {"multiple sections", map[string]any{
                        "spf_analysis":   map[string]any{"status": "pass"},
                        "dmarc_analysis": map[string]any{"status": "pass"},
                        "dkim_analysis":  map[string]any{"status": "pass"},
                }, 3},
                {"section with empty status excluded", map[string]any{"spf_analysis": map[string]any{"status": ""}}, 0},
                {"non-map section ignored", map[string]any{"spf_analysis": "not a map"}, 0},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := CountVerifiedStandards(tt.results)
                        if got != tt.want {
                                t.Errorf("CountVerifiedStandards() = %d, want %d", got, tt.want)
                        }
                })
        }
}

func TestReportIntegrityHash(t *testing.T) {
        hash := ReportIntegrityHash("Example.COM", 1, "2024-01-01T00:00:00Z", "1.0.0", map[string]any{"key": "val"})
        if hash == "" {
                t.Fatal("expected non-empty hash")
        }
        if len(hash) != 128 {
                t.Errorf("expected SHA3-512 hex hash length 128, got %d", len(hash))
        }

        hash2 := ReportIntegrityHash("Example.COM", 1, "2024-01-01T00:00:00Z", "1.0.0", map[string]any{"key": "val"})
        if hash != hash2 {
                t.Error("same inputs should produce same hash")
        }

        hash3 := ReportIntegrityHash("other.com", 1, "2024-01-01T00:00:00Z", "1.0.0", map[string]any{"key": "val"})
        if hash == hash3 {
                t.Error("different domain should produce different hash")
        }
}

func TestReportIntegrityHash_Lowercase(t *testing.T) {
        hash1 := ReportIntegrityHash("EXAMPLE.COM", 1, "2024-01-01T00:00:00Z", "1.0.0", map[string]any{})
        hash2 := ReportIntegrityHash("example.com", 1, "2024-01-01T00:00:00Z", "1.0.0", map[string]any{})
        if hash1 != hash2 {
                t.Error("domain should be lowercased, so hashes should match")
        }
}

func TestCanonicalizeValue_MapOfMaps(t *testing.T) {
        input := []map[string]any{{"a": "1"}, {"b": "2"}}
        got := canonicalizeValue(input)
        if !strings.HasPrefix(got, "[{") || !strings.HasSuffix(got, "}]") {
                t.Errorf("expected map slice format, got %q", got)
        }
}
