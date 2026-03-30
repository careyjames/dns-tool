package handlers

import (
        "testing"
)

func TestCsvEscape_CB11(t *testing.T) {
        tests := []struct {
                input string
                want  string
        }{
                {"hello", "hello"},
                {"hello,world", "\"hello,world\""},
                {"say \"hi\"", "\"say \"\"hi\"\"\""},
                {"line\nbreak", "\"line\nbreak\""},
                {"", ""},
        }
        for _, tc := range tests {
                got := csvEscape(tc.input)
                if got != tc.want {
                        t.Errorf("csvEscape(%q) = %q, want %q", tc.input, got, tc.want)
                }
        }
}

func TestExtractAnalysisError_CB11(t *testing.T) {
        t.Run("no error", func(t *testing.T) {
                ok, errStr := extractAnalysisError(map[string]any{"domain": "example.com"})
                if !ok {
                        t.Fatal("expected ok=true")
                }
                if errStr != nil {
                        t.Fatal("expected nil error string")
                }
        })
        t.Run("with error", func(t *testing.T) {
                ok, errStr := extractAnalysisError(map[string]any{mapKeyError: "DNS lookup failed"})
                if ok {
                        t.Fatal("expected ok=false")
                }
                if errStr == nil || *errStr != "DNS lookup failed" {
                        t.Fatal("expected error string")
                }
        })
        t.Run("empty error", func(t *testing.T) {
                ok, _ := extractAnalysisError(map[string]any{mapKeyError: ""})
                if !ok {
                        t.Fatal("expected ok=true for empty error string")
                }
        })
}

func TestOptionalStrings_CB11(t *testing.T) {
        a, b := optionalStrings("hello", "")
        if a == nil || *a != "hello" {
                t.Fatal("expected a=hello")
        }
        if b != nil {
                t.Fatal("expected b=nil")
        }

        a2, b2 := optionalStrings("", "world")
        if a2 != nil {
                t.Fatal("expected a2=nil")
        }
        if b2 == nil || *b2 != "world" {
                t.Fatal("expected b2=world")
        }
}

func TestExtractRootDomain_CB11(t *testing.T) {
        tests := []struct {
                domain string
                isSub  bool
                root   string
        }{
                {"example.com", false, ""},
                {"sub.example.com", true, "example.com"},
                {"deep.sub.example.com", true, "example.com"},
                {"com", false, ""},
        }
        for _, tc := range tests {
                isSub, root := extractRootDomain(tc.domain)
                if isSub != tc.isSub {
                        t.Errorf("extractRootDomain(%q) isSub=%v, want %v", tc.domain, isSub, tc.isSub)
                }
                if root != tc.root {
                        t.Errorf("extractRootDomain(%q) root=%q, want %q", tc.domain, root, tc.root)
                }
        }
}

func TestMaskURL_CB11(t *testing.T) {
        short := "https://example.com"
        if maskURL(short) != short {
                t.Fatalf("expected short URL unchanged, got %q", maskURL(short))
        }

        long := "https://hooks.example.com/webhook/very-long-path-id-1234567890"
        masked := maskURL(long)
        if len(masked) > 40 {
                t.Fatalf("expected masked URL shorter, got %q", masked)
        }
}

func TestCadenceToNextRun_CB11(t *testing.T) {
        cases := []string{"hourly", "daily", "weekly", "unknown"}
        for _, c := range cases {
                result := cadenceToNextRun(c)
                if !result.Valid {
                        t.Errorf("cadenceToNextRun(%q) returned invalid timestamp", c)
                }
        }
}

func TestHasMigrationRecord_CB11(t *testing.T) {
        records := []TTLRecordResult{
                {RecordType: "A", Status: "ok"},
                {RecordType: "MX", Status: "ok"},
        }
        if !hasMigrationRecord(records) {
                t.Fatal("expected true when A record present")
        }

        records2 := []TTLRecordResult{
                {RecordType: "MX", Status: "ok"},
        }
        if hasMigrationRecord(records2) {
                t.Fatal("expected false when no A/AAAA records")
        }
}

func TestCleanDomainInput_CB11(t *testing.T) {
        tests := []struct {
                input string
                want  string
        }{
                {"https://example.com", "example.com"},
                {"http://example.com/path", "example.com"},
                {"example.com/", "example.com"},
                {"example.com", "example.com"},
        }
        for _, tc := range tests {
                got := cleanDomainInput(tc.input)
                if got != tc.want {
                        t.Errorf("cleanDomainInput(%q) = %q, want %q", tc.input, got, tc.want)
                }
        }
}

func TestFormatTotalReduction_CB11(t *testing.T) {
        result := formatTotalReduction(100, 50)
        if result == "" {
                t.Fatal("expected non-empty reduction string")
        }

        _ = formatTotalReduction(0, 0)
}

func TestTtlForProfile_CB11(t *testing.T) {
        v := ttlForProfile("A", "default")
        if v == 0 {
                t.Fatal("expected non-zero TTL for A record")
        }

        v2 := ttlForProfile("MX", "default")
        if v2 == 0 {
                t.Fatal("expected non-zero TTL for MX record")
        }
}
