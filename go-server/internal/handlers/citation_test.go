package handlers

import (
        "testing"

        "dnstool/go-server/internal/citation"
)

func TestRfcLabelToSectionID(t *testing.T) {
        tests := []struct {
                name  string
                label string
                want  string
        }{
                {"empty string", "", ""},
                {"not an RFC", "some random text", ""},
                {"simple RFC number", "RFC 7489", "rfc:7489"},
                {"RFC with leading/trailing spaces", "  RFC 7489  ", "rfc:7489"},
                {"RFC with section separator in number", "RFC 7489§3.1", "rfc:7489§3.1"},
                {"RFC with section separator after space", "RFC 7489 §3.1", "rfc:7489§3.1"},
                {"RFC without section", "RFC 5321", "rfc:5321"},
                {"RFC with extra text after number", "RFC 5321 something else", "rfc:5321"},
                {"not starting with RFC", "rfc 1234", ""},
                {"RFC prefix only no number", "RFC ", ""},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := rfcLabelToSectionID(tt.label)
                        if got != tt.want {
                                t.Errorf("rfcLabelToSectionID(%q) = %q, want %q", tt.label, got, tt.want)
                        }
                })
        }
}

func TestExtractFixCitations(t *testing.T) {
        tests := []struct {
                name      string
                fixes     []any
                wantCount int
        }{
                {
                        name:      "nil fixes",
                        fixes:     nil,
                        wantCount: 0,
                },
                {
                        name:      "empty fixes",
                        fixes:     []any{},
                        wantCount: 0,
                },
                {
                        name:      "non-map entry skipped",
                        fixes:     []any{"not a map", 42},
                        wantCount: 0,
                },
                {
                        name:      "fix without rfc key",
                        fixes:     []any{map[string]any{"desc": "something"}},
                        wantCount: 0,
                },
                {
                        name:      "fix with empty rfc",
                        fixes:     []any{map[string]any{"rfc": ""}},
                        wantCount: 0,
                },
                {
                        name:      "fix with non-string rfc",
                        fixes:     []any{map[string]any{"rfc": 123}},
                        wantCount: 0,
                },
                {
                        name:      "fix with valid rfc",
                        fixes:     []any{map[string]any{"rfc": "RFC 7489"}},
                        wantCount: 1,
                },
                {
                        name: "multiple fixes some valid",
                        fixes: []any{
                                map[string]any{"rfc": "RFC 7489"},
                                map[string]any{"desc": "no rfc"},
                                map[string]any{"rfc": "RFC 5321"},
                                "not a map",
                        },
                        wantCount: 2,
                },
                {
                        name:      "fix with non-RFC label skipped",
                        fixes:     []any{map[string]any{"rfc": "not an RFC"}},
                        wantCount: 0,
                },
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        m := citation.NewManifest()
                        extractFixCitations(tt.fixes, m)
                        reg := citation.Global()
                        entries := m.Entries(reg)
                        if len(entries) != tt.wantCount {
                                t.Errorf("got %d citation entries, want %d", len(entries), tt.wantCount)
                        }
                })
        }
}

func TestExtractRemCitations(t *testing.T) {
        tests := []struct {
                name      string
                rem       map[string]any
                wantCount int
        }{
                {
                        name:      "nil rem",
                        rem:       nil,
                        wantCount: 0,
                },
                {
                        name:      "empty rem",
                        rem:       map[string]any{},
                        wantCount: 0,
                },
                {
                        name:      "no per_section key",
                        rem:       map[string]any{"other": "data"},
                        wantCount: 0,
                },
                {
                        name:      "per_section not a map",
                        rem:       map[string]any{"per_section": "string"},
                        wantCount: 0,
                },
                {
                        name: "per_section with non-slice value",
                        rem: map[string]any{
                                "per_section": map[string]any{
                                        "dmarc": "not a slice",
                                },
                        },
                        wantCount: 0,
                },
                {
                        name: "per_section with valid fixes",
                        rem: map[string]any{
                                "per_section": map[string]any{
                                        "dmarc": []any{
                                                map[string]any{"rfc": "RFC 7489"},
                                        },
                                },
                        },
                        wantCount: 1,
                },
                {
                        name: "per_section with multiple sections",
                        rem: map[string]any{
                                "per_section": map[string]any{
                                        "dmarc": []any{
                                                map[string]any{"rfc": "RFC 7489"},
                                        },
                                        "spf": []any{
                                                map[string]any{"rfc": "RFC 7208"},
                                        },
                                },
                        },
                        wantCount: 2,
                },
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        m := citation.NewManifest()
                        extractRemCitations(tt.rem, m)
                        reg := citation.Global()
                        entries := m.Entries(reg)
                        if len(entries) != tt.wantCount {
                                t.Errorf("got %d citation entries, want %d", len(entries), tt.wantCount)
                        }
                })
        }
}

func TestSectionSeparatorConstant(t *testing.T) {
        if sectionSeparator != "\u00a7" {
                t.Errorf("sectionSeparator = %q, want §", sectionSeparator)
        }
}
