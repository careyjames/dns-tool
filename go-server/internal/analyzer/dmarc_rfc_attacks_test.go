package analyzer

import (
        "strings"
        "testing"
)

func TestDMARCRFCAttack_DuplicateTags(t *testing.T) {
        record := "v=dmarc1; p=reject; p=none"
        tags := parseDMARCTags(record)
        if tags.policy == nil {
                t.Fatal("expected policy to be parsed even with duplicate tags")
        }
}

func TestDMARCRFCAttack_UnknownTags(t *testing.T) {
        record := "v=dmarc1; p=reject; xyz=hello; foo=bar"
        tags := parseDMARCTags(record)
        if len(tags.unknownTags) < 2 {
                t.Fatalf("expected at least 2 unknown tags, got %d: %v", len(tags.unknownTags), tags.unknownTags)
        }
}

func TestDMARCRFCAttack_EmptyTagValues(t *testing.T) {
        tests := []struct {
                name   string
                record string
        }{
                {"empty p value", "v=dmarc1; p="},
                {"empty rua value", "v=dmarc1; p=reject; rua="},
                {"empty sp value", "v=dmarc1; p=reject; sp="},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        tags := parseDMARCTags(tt.record)
                        if tags.policy == nil && tt.name != "empty p value" {
                                t.Error("expected non-nil policy for records with p=reject")
                        }
                        if tt.name == "empty p value" && tags.policy != nil && *tags.policy != "" {
                                t.Error("expected empty or nil policy for empty p= value")
                        }
                })
        }
}

func TestDMARCRFCAttack_MissingPTag(t *testing.T) {
        record := "v=dmarc1; rua=mailto:dmarc@example.com"
        tags := parseDMARCTags(record)
        if tags.policy != nil {
                t.Fatal("expected nil policy when p= tag is missing")
        }

        status, _, _ := evaluateDMARCPolicy(tags)
        if status != "info" {
                t.Fatalf("expected status=info for missing p= tag, got %s", status)
        }
}

func TestDMARCRFCAttack_InvalidPolicyValues(t *testing.T) {
        tests := []struct {
                name       string
                record     string
                wantStatus string
        }{
                {"p=invalid", "v=dmarc1; p=invalid", "info"},
                {"p=REJECT uppercase", "v=dmarc1; p=REJECT", "success"},
                {"p=None mixed case", "v=dmarc1; p=None; rua=mailto:d@example.com", "warning"},
                {"p=xyz", "v=dmarc1; p=xyz", "info"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        tags := parseDMARCTags(tt.record)
                        status, _, _ := evaluateDMARCPolicy(tags)
                        if status != tt.wantStatus {
                                t.Fatalf("expected status=%s, got %s", tt.wantStatus, status)
                        }
                })
        }
}

func TestDMARCRFCAttack_MultipleRecords(t *testing.T) {
        records := []string{
                "v=dmarc1; p=reject",
                "v=dmarc1; p=none",
        }
        status, msg, issues, _ := evaluateDMARCRecordSet(records)
        if status != "error" {
                t.Fatalf("expected error for multiple DMARC records per RFC 7489 §6.6.3, got %s", status)
        }
        if !strings.Contains(msg, "Multiple") {
                t.Fatalf("expected message about multiple records, got %s", msg)
        }
        if len(issues) == 0 {
                t.Fatal("expected issues for multiple DMARC records")
        }
}

func TestDMARCRFCAttack_NoRecords(t *testing.T) {
        status, _, _, _ := evaluateDMARCRecordSet(nil)
        if status != "error" {
                t.Fatalf("expected error for no records, got %s", status)
        }

        status2, _, _, _ := evaluateDMARCRecordSet([]string{})
        if status2 != "error" {
                t.Fatalf("expected error for empty slice, got %s", status2)
        }
}

func TestDMARCRFCAttack_MisplacedDMARC(t *testing.T) {
        tests := []struct {
                name     string
                records  []string
                detected bool
        }{
                {"dmarc at root", []string{"v=dmarc1; p=reject"}, true},
                {"dmarc at root bare", []string{"v=dmarc1"}, true},
                {"dmarc at root with space", []string{"v=dmarc1 p=reject"}, true},
                {"no dmarc at root", []string{"v=spf1 include:example.com ~all"}, false},
                {"empty records", []string{}, false},
                {"dmarc-like but not valid", []string{"this mentions dmarc but is not a record"}, false},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        result := DetectMisplacedDMARC(tt.records)
                        if result["detected"].(bool) != tt.detected {
                                t.Fatalf("expected detected=%v, got %v", tt.detected, result["detected"])
                        }
                })
        }
}

func TestDMARCRFCAttack_PctZero(t *testing.T) {
        record := "v=dmarc1; p=reject; pct=0"
        tags := parseDMARCTags(record)
        if tags.pct != 0 {
                t.Fatalf("expected pct=0, got %d", tags.pct)
        }

        status, msg, _ := classifyDMARCPolicyVerdict("reject", 0)
        if status != "warning" {
                t.Fatalf("expected warning for pct=0, got %s", status)
        }
        if !strings.Contains(msg, "0%") {
                t.Fatalf("expected message mentioning 0%%, got %s", msg)
        }
}

func TestDMARCRFCAttack_SubdomainPolicyInheritance(t *testing.T) {
        reject := "reject"
        quarantine := "quarantine"

        tests := []struct {
                name       string
                tags       dmarcTags
                wantIssues bool
        }{
                {
                        "sp absent inherits p=reject, missing np",
                        dmarcTags{policy: &reject, pct: 100, aspf: "relaxed", adkim: "relaxed"},
                        true,
                },
                {
                        "sp=none with p=reject",
                        dmarcTags{policy: &reject, subdomainPolicy: strPtr("none"), pct: 100, aspf: "relaxed", adkim: "relaxed"},
                        true,
                },
                {
                        "sp=reject with p=reject, has np",
                        dmarcTags{policy: &reject, subdomainPolicy: &reject, npPolicy: &reject, pct: 100, aspf: "relaxed", adkim: "relaxed"},
                        false,
                },
                {
                        "sp=quarantine with p=quarantine, np=reject",
                        dmarcTags{policy: &quarantine, subdomainPolicy: &quarantine, npPolicy: &reject, pct: 100, aspf: "relaxed", adkim: "relaxed"},
                        false,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        issues := checkDMARCSubdomainIssues(tt.tags)
                        if tt.wantIssues && len(issues) == 0 {
                                t.Fatal("expected subdomain issues")
                        }
                        if !tt.wantIssues && len(issues) != 0 {
                                t.Fatalf("expected no subdomain issues, got %v", issues)
                        }
                })
        }
}

func TestDMARCRFCAttack_RuaRufURIValidation(t *testing.T) {
        tests := []struct {
                name        string
                rua         string
                wantDomains []string
        }{
                {"valid mailto", "mailto:dmarc@example.com", []string{"example.com"}},
                {"multiple mailto", "mailto:a@example.com,mailto:b@other.org", []string{"example.com", "other.org"}},
                {"no mailto prefix", "dmarc@example.com", nil},
                {"empty string", "", nil},
                {"mailto with trailing dot", "mailto:dmarc@example.com.", []string{"example.com"}},
                {"mailto mixed case", "Mailto:dmarc@EXAMPLE.COM", []string{"example.com"}},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := ExtractMailtoDomains(tt.rua)
                        if len(got) != len(tt.wantDomains) {
                                t.Fatalf("expected %d domains, got %d: %v", len(tt.wantDomains), len(got), got)
                        }
                        for i := range tt.wantDomains {
                                if got[i] != tt.wantDomains[i] {
                                        t.Fatalf("expected domain %s, got %s", tt.wantDomains[i], got[i])
                                }
                        }
                })
        }
}

func TestDMARCRFCAttack_DMARCbisNpTag(t *testing.T) {
        tests := []struct {
                name   string
                record string
                wantNp string
                hasNp  bool
        }{
                {"np=reject", "v=dmarc1; p=reject; np=reject", "reject", true},
                {"np=none", "v=dmarc1; p=reject; np=none", "none", true},
                {"np=quarantine", "v=dmarc1; p=reject; np=quarantine", "quarantine", true},
                {"no np tag", "v=dmarc1; p=reject", "", false},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        tags := parseDMARCTags(tt.record)
                        if tt.hasNp {
                                if tags.npPolicy == nil {
                                        t.Fatal("expected np to be set")
                                }
                                if *tags.npPolicy != tt.wantNp {
                                        t.Fatalf("expected np=%s, got %s", tt.wantNp, *tags.npPolicy)
                                }
                        } else {
                                if tags.npPolicy != nil {
                                        t.Fatalf("expected np to be nil, got %s", *tags.npPolicy)
                                }
                        }

                        dmarcbisTags := buildDMARCbisTags(tags)
                        if tt.hasNp {
                                if dmarcbisTags["np"] != tt.wantNp {
                                        t.Fatalf("expected dmarcbis np=%s, got %s", tt.wantNp, dmarcbisTags["np"])
                                }
                        } else {
                                if _, ok := dmarcbisTags["np"]; ok {
                                        t.Fatal("expected no np in dmarcbis tags")
                                }
                        }
                })
        }
}

func TestDMARCRFCAttack_CaseSensitivity(t *testing.T) {
        tests := []struct {
                name       string
                record     string
                wantPolicy string
        }{
                {"lowercase", "v=dmarc1; p=reject", "reject"},
                {"uppercase", "V=DMARC1; P=REJECT", "reject"},
                {"mixed case", "v=DMARC1; P=Reject", "reject"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        tags := parseDMARCTags(tt.record)
                        if tags.policy == nil {
                                t.Fatal("expected policy to be parsed")
                        }
                        if *tags.policy != tt.wantPolicy {
                                t.Fatalf("expected policy=%s, got %s", tt.wantPolicy, *tags.policy)
                        }
                })
        }
}

func TestDMARCRFCAttack_ClassifyDMARCRecords(t *testing.T) {
        tests := []struct {
                name      string
                records   []string
                wantValid int
                wantLike  int
        }{
                {"two valid records", []string{"v=dmarc1; p=reject", "v=dmarc1; p=none"}, 2, 0},
                {"valid and dmarc-like", []string{"v=dmarc1; p=reject", "dmarc is configured"}, 1, 1},
                {"only dmarc-like", []string{"we have dmarc", "dmarc policy active"}, 0, 2},
                {"mixed with non-dmarc", []string{"v=dmarc1; p=reject", "v=spf1 ~all", "dmarc note"}, 1, 1},
                {"case insensitive valid", []string{"V=DMARC1; P=REJECT"}, 1, 0},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        valid, like := classifyDMARCRecords(tt.records)
                        if len(valid) != tt.wantValid {
                                t.Fatalf("expected %d valid, got %d", tt.wantValid, len(valid))
                        }
                        if len(like) != tt.wantLike {
                                t.Fatalf("expected %d like, got %d", tt.wantLike, len(like))
                        }
                })
        }
}

func TestDMARCRFCAttack_UnknownTagsIssues(t *testing.T) {
        record := "v=dmarc1; p=reject; bogus=value; rua=mailto:d@example.com"
        tags := parseDMARCTags(record)
        issues := checkDMARCUnknownTags(tags)
        if len(issues) == 0 {
                t.Fatal("expected issues for unknown tag 'bogus'")
        }
        found := false
        for _, issue := range issues {
                if strings.Contains(issue, "bogus") {
                        found = true
                }
        }
        if !found {
                t.Fatalf("expected issue mentioning 'bogus', got %v", issues)
        }
}

func TestDMARCRFCAttack_EvaluateRecordSetSingleValid(t *testing.T) {
        tests := []struct {
                name       string
                record     string
                wantStatus string
        }{
                {"reject with rua", "v=dmarc1; p=reject; rua=mailto:d@example.com", "success"},
                {"none policy", "v=dmarc1; p=none; rua=mailto:d@example.com", "warning"},
                {"quarantine full", "v=dmarc1; p=quarantine; pct=100; rua=mailto:d@example.com", "success"},
                {"quarantine partial", "v=dmarc1; p=quarantine; pct=25; rua=mailto:d@example.com", "warning"},
                {"no p tag", "v=dmarc1; rua=mailto:d@example.com", "info"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        status, _, _, _ := evaluateDMARCRecordSet([]string{tt.record})
                        if status != tt.wantStatus {
                                t.Fatalf("expected status=%s, got %s", tt.wantStatus, status)
                        }
                })
        }
}

func TestDMARCRFCAttack_ReportingIssues(t *testing.T) {
        tests := []struct {
                name       string
                tags       dmarcTags
                wantIssues bool
        }{
                {"no rua", dmarcTags{pct: 100, aspf: "relaxed", adkim: "relaxed"}, true},
                {"with rua", dmarcTags{rua: strPtr("mailto:d@example.com"), pct: 100, aspf: "relaxed", adkim: "relaxed"}, false},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        issues := checkDMARCReportingIssues(tt.tags)
                        if tt.wantIssues && len(issues) == 0 {
                                t.Fatal("expected reporting issues")
                        }
                        if !tt.wantIssues && len(issues) != 0 {
                                t.Fatalf("expected no reporting issues, got %v", issues)
                        }
                })
        }
}

func TestDMARCRFCAttack_RufNote(t *testing.T) {
        tests := []struct {
                name       string
                ruf        *string
                wantStatus string
        }{
                {"ruf present", strPtr("mailto:forensic@example.com"), "present"},
                {"ruf absent", nil, "absent"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        result := buildRUFNote(dmarcTags{ruf: tt.ruf})
                        if result["status"] != tt.wantStatus {
                                t.Fatalf("expected status=%s, got %v", tt.wantStatus, result["status"])
                        }
                })
        }
}

func TestDMARCRFCAttack_MisplacedDMARCPolicyExtraction(t *testing.T) {
        result := DetectMisplacedDMARC([]string{"v=dmarc1; p=quarantine; pct=50"})
        if !result["detected"].(bool) {
                t.Fatal("expected detected=true")
        }
        if result["policy_hint"] != "quarantine" {
                t.Fatalf("expected policy_hint=quarantine, got %v", result["policy_hint"])
        }
        if !strings.Contains(result["message"].(string), "_dmarc") {
                t.Fatal("expected message to mention _dmarc subdomain")
        }
}

func TestDMARCRFCAttack_FullEndToEnd(t *testing.T) {
        tests := []struct {
                name       string
                records    []string
                wantStatus string
        }{
                {
                        "perfect DMARC",
                        []string{"v=dmarc1; p=reject; pct=100; rua=mailto:d@example.com; aspf=s; adkim=s"},
                        "success",
                },
                {
                        "monitoring only",
                        []string{"v=dmarc1; p=none; rua=mailto:d@example.com"},
                        "warning",
                },
                {
                        "multiple records PermError",
                        []string{"v=dmarc1; p=reject", "v=dmarc1; p=quarantine"},
                        "error",
                },
                {
                        "no valid records",
                        []string{},
                        "error",
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        status, _, _, _ := evaluateDMARCRecordSet(tt.records)
                        if status != tt.wantStatus {
                                t.Fatalf("expected status=%s, got %s", tt.wantStatus, status)
                        }
                })
        }
}

