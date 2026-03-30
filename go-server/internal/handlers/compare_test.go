package handlers

import (
	"encoding/json"
	"testing"
	"time"

	"dnstool/go-server/internal/dbq"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestBuildCompareAnalysis(t *testing.T) {
	t.Run("full data", func(t *testing.T) {
		dur := 1.234
		ts := pgtype.Timestamp{
			Time:  time.Date(2026, 2, 15, 14, 30, 0, 0, time.UTC),
			Valid: true,
		}
		fullResults, _ := json.Marshal(map[string]interface{}{
			"_tool_version": "26.20.88",
		})
		a := dbq.DomainAnalysis{
			CreatedAt:        ts,
			AnalysisDuration: &dur,
			FullResults:      fullResults,
		}

		ca := buildCompareAnalysis(a)
		if ca.CreatedAt != "2026-02-15 14:30:00 UTC" {
			t.Errorf("unexpected CreatedAt: %q", ca.CreatedAt)
		}
		if ca.ToolVersion != "26.20.88" {
			t.Errorf("unexpected ToolVersion: %q", ca.ToolVersion)
		}
		if !ca.HasToolVersion {
			t.Error("expected HasToolVersion=true")
		}
		if ca.AnalysisDuration != "1.2s" {
			t.Errorf("unexpected AnalysisDuration: %q", ca.AnalysisDuration)
		}
		if !ca.HasDuration {
			t.Error("expected HasDuration=true")
		}
	})

	t.Run("empty data", func(t *testing.T) {
		a := dbq.DomainAnalysis{}
		ca := buildCompareAnalysis(a)
		if ca.CreatedAt != "" {
			t.Errorf("expected empty CreatedAt, got %q", ca.CreatedAt)
		}
		if ca.HasToolVersion {
			t.Error("expected HasToolVersion=false")
		}
		if ca.HasDuration {
			t.Error("expected HasDuration=false")
		}
	})

	t.Run("no tool version in results", func(t *testing.T) {
		fullResults, _ := json.Marshal(map[string]interface{}{
			"some_key": "some_value",
		})
		a := dbq.DomainAnalysis{FullResults: fullResults}
		ca := buildCompareAnalysis(a)
		if ca.HasToolVersion {
			t.Error("expected HasToolVersion=false when no _tool_version")
		}
	})

	t.Run("invalid JSON results", func(t *testing.T) {
		a := dbq.DomainAnalysis{FullResults: []byte("not json")}
		ca := buildCompareAnalysis(a)
		if ca.HasToolVersion {
			t.Error("expected HasToolVersion=false for invalid JSON")
		}
	})
}

func TestBuildSelectAnalysisItem(t *testing.T) {
	spf := "success"
	dmarc := "warning"
	dkim := "unknown"
	dur := 2.5
	ts := pgtype.Timestamp{
		Time:  time.Date(2026, 1, 10, 8, 0, 0, 0, time.UTC),
		Valid: true,
	}
	fullResults, _ := json.Marshal(map[string]interface{}{
		"_tool_version": "26.14.0",
	})

	a := dbq.DomainAnalysis{
		ID:               42,
		Domain:           "example.com",
		AsciiDomain:      "example.com",
		SpfStatus:        &spf,
		DmarcStatus:      &dmarc,
		DkimStatus:       &dkim,
		AnalysisDuration: &dur,
		CreatedAt:        ts,
		FullResults:      fullResults,
	}

	item := buildSelectAnalysisItem(a)

	if item.ID != 42 {
		t.Errorf("expected ID=42, got %d", item.ID)
	}
	if item.Domain != "example.com" {
		t.Errorf("expected Domain=example.com, got %q", item.Domain)
	}
	if item.SpfStatus != "success" {
		t.Errorf("expected SpfStatus=success, got %q", item.SpfStatus)
	}
	if item.DmarcStatus != "warning" {
		t.Errorf("expected DmarcStatus=warning, got %q", item.DmarcStatus)
	}
	if item.DkimStatus != "unknown" {
		t.Errorf("expected DkimStatus=unknown, got %q", item.DkimStatus)
	}
	if item.AnalysisDuration != 2.5 {
		t.Errorf("expected AnalysisDuration=2.5, got %f", item.AnalysisDuration)
	}
	if item.CreatedAt != "2026-01-10 08:00:00 UTC" {
		t.Errorf("unexpected CreatedAt: %q", item.CreatedAt)
	}
	if item.ToolVersion != "26.14.0" {
		t.Errorf("expected ToolVersion=26.14.0, got %q", item.ToolVersion)
	}
}

func TestBuildSelectAnalysisItemNilFields(t *testing.T) {
	a := dbq.DomainAnalysis{
		ID:     1,
		Domain: "test.com",
	}

	item := buildSelectAnalysisItem(a)

	if item.SpfStatus != "" {
		t.Errorf("expected empty SpfStatus, got %q", item.SpfStatus)
	}
	if item.DmarcStatus != "" {
		t.Errorf("expected empty DmarcStatus, got %q", item.DmarcStatus)
	}
	if item.DkimStatus != "" {
		t.Errorf("expected empty DkimStatus, got %q", item.DkimStatus)
	}
	if item.AnalysisDuration != 0.0 {
		t.Errorf("expected AnalysisDuration=0, got %f", item.AnalysisDuration)
	}
	if item.CreatedAt != "" {
		t.Errorf("expected empty CreatedAt, got %q", item.CreatedAt)
	}
	if item.ToolVersion != "" {
		t.Errorf("expected empty ToolVersion, got %q", item.ToolVersion)
	}
}

func TestCompareConstants(t *testing.T) {
	if templateCompare != "compare.html" {
		t.Errorf("unexpected templateCompare: %q", templateCompare)
	}
	if templateCompareSelect != "compare_select.html" {
		t.Errorf("unexpected templateCompareSelect: %q", templateCompareSelect)
	}
}

func TestNewCompareHandler(t *testing.T) {
	h := NewCompareHandler(nil, nil)
	if h == nil {
		t.Fatal("expected non-nil CompareHandler")
	}
}

func TestCompareGetStatus(t *testing.T) {
	tests := []struct {
		name     string
		section  map[string]interface{}
		expected string
	}{
		{"with status", map[string]interface{}{"status": "success"}, "success"},
		{"with state", map[string]interface{}{"state": "Secure"}, "Secure"},
		{"status takes priority", map[string]interface{}{"status": "warning", "state": "Secure"}, "warning"},
		{"empty section", map[string]interface{}{}, "unknown"},
		{"non-string status", map[string]interface{}{"status": 42}, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getStatus(tt.section)
			if got != tt.expected {
				t.Errorf("getStatus() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestCompareGetSection(t *testing.T) {
	results := map[string]interface{}{
		"spf_analysis": map[string]interface{}{"status": "success"},
		"bad_key":      "not a map",
	}

	t.Run("existing section", func(t *testing.T) {
		s := getSection(results, "spf_analysis")
		if s == nil {
			t.Fatal("expected non-nil section")
		}
		if s["status"] != "success" {
			t.Errorf("unexpected status: %v", s["status"])
		}
	})

	t.Run("missing section", func(t *testing.T) {
		s := getSection(results, "missing_key")
		if len(s) != 0 {
			t.Errorf("expected empty map, got %v", s)
		}
	})

	t.Run("non-map section", func(t *testing.T) {
		s := getSection(results, "bad_key")
		if len(s) != 0 {
			t.Errorf("expected empty map for non-map value, got %v", s)
		}
	})
}

func TestCompareSectionDiff(t *testing.T) {
	t.Run("identical sections", func(t *testing.T) {
		secA := map[string]interface{}{"records": "v=spf1 -all"}
		secB := map[string]interface{}{"records": "v=spf1 -all"}
		diff := ComputeSectionDiff(secA, secB, "spf", "SPF", "fa-envelope")
		if diff.Changed {
			t.Error("expected Changed=false for identical sections")
		}
		if len(diff.DetailChanges) != 0 {
			t.Errorf("expected 0 detail changes, got %d", len(diff.DetailChanges))
		}
	})

	t.Run("different status", func(t *testing.T) {
		secA := map[string]interface{}{"status": "success"}
		secB := map[string]interface{}{"status": "warning"}
		diff := ComputeSectionDiff(secA, secB, "spf", "SPF", "fa-envelope")
		if !diff.Changed {
			t.Error("expected Changed=true for different statuses")
		}
		if diff.StatusA != "success" || diff.StatusB != "warning" {
			t.Errorf("unexpected statuses: A=%q, B=%q", diff.StatusA, diff.StatusB)
		}
	})

	t.Run("different detail values", func(t *testing.T) {
		secA := map[string]interface{}{"status": "success", "policy": "reject"}
		secB := map[string]interface{}{"status": "success", "policy": "none"}
		diff := ComputeSectionDiff(secA, secB, "dmarc", "DMARC", "fa-shield")
		if !diff.Changed {
			t.Error("expected Changed=true for different detail values")
		}
		if len(diff.DetailChanges) != 1 {
			t.Fatalf("expected 1 detail change, got %d", len(diff.DetailChanges))
		}
		if diff.DetailChanges[0].Old != "reject" || diff.DetailChanges[0].New != "none" {
			t.Errorf("unexpected detail change: old=%v, new=%v", diff.DetailChanges[0].Old, diff.DetailChanges[0].New)
		}
	})

	t.Run("skips status and state keys", func(t *testing.T) {
		secA := map[string]interface{}{"status": "success", "_schema_version": "1", "_tool_version": "v1", "data": "a"}
		secB := map[string]interface{}{"status": "success", "_schema_version": "2", "_tool_version": "v2", "data": "a"}
		diff := ComputeSectionDiff(secA, secB, "test", "Test", "fa-test")
		if diff.Changed {
			t.Error("expected Changed=false when only skip keys differ")
		}
	})

	t.Run("key only in one section", func(t *testing.T) {
		secA := map[string]interface{}{"status": "success", "extra_field": "value"}
		secB := map[string]interface{}{"status": "success"}
		diff := ComputeSectionDiff(secA, secB, "test", "Test", "fa-test")
		if !diff.Changed {
			t.Error("expected Changed=true when key exists in only one section")
		}
	})

	t.Run("preserves key label icon", func(t *testing.T) {
		secA := map[string]interface{}{}
		secB := map[string]interface{}{}
		diff := ComputeSectionDiff(secA, secB, "mykey", "My Label", "fa-star")
		if diff.Key != "mykey" || diff.Label != "My Label" || diff.Icon != "fa-star" {
			t.Errorf("unexpected key/label/icon: %q/%q/%q", diff.Key, diff.Label, diff.Icon)
		}
	})
}

func TestCompareAllDiffs(t *testing.T) {
	resultsA := map[string]interface{}{
		"spf_analysis":   map[string]interface{}{"status": "success"},
		"dmarc_analysis": map[string]interface{}{"status": "success"},
	}
	resultsB := map[string]interface{}{
		"spf_analysis":   map[string]interface{}{"status": "warning"},
		"dmarc_analysis": map[string]interface{}{"status": "success"},
	}

	diffs := ComputeAllDiffs(resultsA, resultsB)
	if len(diffs) != len(CompareSections) {
		t.Errorf("expected %d diffs, got %d", len(CompareSections), len(diffs))
	}

	spfDiff := diffs[0]
	if spfDiff.Label != "SPF" {
		t.Errorf("expected first diff to be SPF, got %q", spfDiff.Label)
	}
	if !spfDiff.Changed {
		t.Error("expected SPF diff to be changed")
	}
}

func TestCompareNormalizeResults(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		got := NormalizeResults(nil)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		got := NormalizeResults(json.RawMessage{})
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		got := NormalizeResults(json.RawMessage("not json"))
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("fills defaults", func(t *testing.T) {
		input, _ := json.Marshal(map[string]interface{}{"domain": "example.com"})
		got := NormalizeResults(input)
		if got == nil {
			t.Fatal("expected non-nil result")
		}
		if _, ok := got["spf_analysis"]; !ok {
			t.Error("expected spf_analysis default to be set")
		}
		if _, ok := got["dmarc_analysis"]; !ok {
			t.Error("expected dmarc_analysis default to be set")
		}
		if _, ok := got["posture"]; !ok {
			t.Error("expected posture default to be set")
		}
	})

	t.Run("preserves existing keys", func(t *testing.T) {
		input, _ := json.Marshal(map[string]interface{}{
			"spf_analysis": map[string]interface{}{"status": "success", "records": []string{"v=spf1 -all"}},
		})
		got := NormalizeResults(input)
		spf, ok := got["spf_analysis"].(map[string]interface{})
		if !ok {
			t.Fatal("expected spf_analysis to be a map")
		}
		if spf["status"] != "success" {
			t.Errorf("expected spf status 'success', got %v", spf["status"])
		}
	})

	t.Run("normalizes legacy posture states", func(t *testing.T) {
		input, _ := json.Marshal(map[string]interface{}{
			"posture": map[string]interface{}{"state": "STRONG", "color": "secondary"},
		})
		got := NormalizeResults(input)
		posture, ok := got["posture"].(map[string]interface{})
		if !ok {
			t.Fatal("expected posture to be a map")
		}
		if posture["state"] != "Secure" {
			t.Errorf("expected state 'Secure', got %v", posture["state"])
		}
		if posture["color"] != "success" {
			t.Errorf("expected color 'success' for Secure state, got %v", posture["color"])
		}
	})
}

func TestCompareNormalizeEmailAnswer(t *testing.T) {
	t.Run("already has short answer", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"email_answer":       "No — Good protection",
			"email_answer_short": "Already Set",
		}
		normalizeEmailAnswer(verdicts)
		if verdicts["email_answer_short"] != "Already Set" {
			t.Errorf("should not override existing email_answer_short")
		}
	})

	t.Run("splits No answer", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"email_answer": "No — DMARC reject policy enforced",
		}
		normalizeEmailAnswer(verdicts)
		if verdicts["email_answer_short"] != "No" {
			t.Errorf("expected short='No', got %v", verdicts["email_answer_short"])
		}
		if verdicts["email_answer_reason"] != "DMARC reject policy enforced" {
			t.Errorf("unexpected reason: %v", verdicts["email_answer_reason"])
		}
		if verdicts["email_answer_color"] != "success" {
			t.Errorf("expected color='success', got %v", verdicts["email_answer_color"])
		}
	})

	t.Run("splits Yes answer", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"email_answer": "Yes — No DMARC policy",
		}
		normalizeEmailAnswer(verdicts)
		if verdicts["email_answer_short"] != "Yes" {
			t.Errorf("expected short='Yes', got %v", verdicts["email_answer_short"])
		}
		if verdicts["email_answer_color"] != "danger" {
			t.Errorf("expected color='danger', got %v", verdicts["email_answer_color"])
		}
	})

	t.Run("splits Unlikely answer", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"email_answer": "Unlikely — Strong protections",
		}
		normalizeEmailAnswer(verdicts)
		if verdicts["email_answer_color"] != "success" {
			t.Errorf("expected color='success', got %v", verdicts["email_answer_color"])
		}
	})

	t.Run("splits Partially answer", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"email_answer": "Partially — Some protections",
		}
		normalizeEmailAnswer(verdicts)
		if verdicts["email_answer_color"] != "warning" {
			t.Errorf("expected color='warning', got %v", verdicts["email_answer_color"])
		}
	})

	t.Run("no separator", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"email_answer": "No DMARC",
		}
		normalizeEmailAnswer(verdicts)
		if _, exists := verdicts["email_answer_short"]; exists {
			t.Error("should not set email_answer_short when no separator")
		}
	})

	t.Run("empty email_answer", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"email_answer": "",
		}
		normalizeEmailAnswer(verdicts)
		if _, exists := verdicts["email_answer_short"]; exists {
			t.Error("should not set email_answer_short for empty input")
		}
	})
}

func TestNormalizeLLMsTxtVerdict(t *testing.T) {
	tests := []struct {
		name       string
		llmsTxt    map[string]interface{}
		wantAnswer string
	}{
		{"both found", map[string]interface{}{"found": true, "full_found": true}, "Yes"},
		{"only found", map[string]interface{}{"found": true, "full_found": false}, "Yes"},
		{"not found", map[string]interface{}{"found": false, "full_found": false}, "No"},
		{"empty map", map[string]interface{}{}, "No"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeLLMsTxtVerdict(tt.llmsTxt)
			if result["answer"] != tt.wantAnswer {
				t.Errorf("got answer=%v, want %q", result["answer"], tt.wantAnswer)
			}
		})
	}
}

func TestCompareNormalizeRobotsTxtVerdict(t *testing.T) {
	tests := []struct {
		name       string
		robotsTxt  map[string]interface{}
		wantAnswer string
		wantColor  string
	}{
		{"found and blocks", map[string]interface{}{"found": true, "blocks_ai_crawlers": true}, "Yes", "success"},
		{"found no block", map[string]interface{}{"found": true, "blocks_ai_crawlers": false}, "No", "warning"},
		{"not found", map[string]interface{}{"found": false}, "No", "secondary"},
		{"empty", map[string]interface{}{}, "No", "secondary"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeRobotsTxtVerdict(tt.robotsTxt)
			if result["answer"] != tt.wantAnswer {
				t.Errorf("got answer=%v, want %q", result["answer"], tt.wantAnswer)
			}
			if result["color"] != tt.wantColor {
				t.Errorf("got color=%v, want %q", result["color"], tt.wantColor)
			}
		})
	}
}

func TestCompareNormalizeCountVerdict(t *testing.T) {
	t.Run("count > 0", func(t *testing.T) {
		section := map[string]interface{}{"ioc_count": float64(3)}
		result := normalizeCountVerdict(section, "ioc_count", "IOCs detected", "No IOCs")
		if result["answer"] != "Yes" {
			t.Errorf("expected answer=Yes, got %v", result["answer"])
		}
		if result["color"] != "danger" {
			t.Errorf("expected color=danger, got %v", result["color"])
		}
	})

	t.Run("count = 0", func(t *testing.T) {
		section := map[string]interface{}{"ioc_count": float64(0)}
		result := normalizeCountVerdict(section, "ioc_count", "IOCs detected", "No IOCs")
		if result["answer"] != "No" {
			t.Errorf("expected answer=No, got %v", result["answer"])
		}
		if result["color"] != "success" {
			t.Errorf("expected color=success, got %v", result["color"])
		}
	})

	t.Run("missing key", func(t *testing.T) {
		section := map[string]interface{}{}
		result := normalizeCountVerdict(section, "ioc_count", "IOCs detected", "No IOCs")
		if result["answer"] != "No" {
			t.Errorf("expected answer=No, got %v", result["answer"])
		}
	})
}

func TestCompareGetNumValue(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]interface{}
		key  string
		want float64
	}{
		{"float64", map[string]interface{}{"count": float64(5)}, "count", 5},
		{"int", map[string]interface{}{"count": int(3)}, "count", 3},
		{"int64", map[string]interface{}{"count": int64(7)}, "count", 7},
		{"missing", map[string]interface{}{}, "count", 0},
		{"string", map[string]interface{}{"count": "5"}, "count", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getNumValue(tt.m, tt.key)
			if got != tt.want {
				t.Errorf("got %f, want %f", got, tt.want)
			}
		})
	}
}

func TestComparePagination(t *testing.T) {
	t.Run("normal case", func(t *testing.T) {
		p := NewPagination(2, 10, 25)
		if p.Page != 2 {
			t.Errorf("expected Page=2, got %d", p.Page)
		}
		if p.PerPage != 10 {
			t.Errorf("expected PerPage=10, got %d", p.PerPage)
		}
		if p.Total != 25 {
			t.Errorf("expected Total=25, got %d", p.Total)
		}
		if p.TotalPages != 3 {
			t.Errorf("expected TotalPages=3, got %d", p.TotalPages)
		}
		if !p.HasPrev {
			t.Error("expected HasPrev=true")
		}
		if !p.HasNext {
			t.Error("expected HasNext=true")
		}
	})

	t.Run("first page", func(t *testing.T) {
		p := NewPagination(1, 10, 25)
		if p.HasPrev {
			t.Error("expected HasPrev=false on first page")
		}
	})

	t.Run("last page", func(t *testing.T) {
		p := NewPagination(3, 10, 25)
		if p.HasNext {
			t.Error("expected HasNext=false on last page")
		}
	})

	t.Run("zero page defaults to 1", func(t *testing.T) {
		p := NewPagination(0, 10, 25)
		if p.Page != 1 {
			t.Errorf("expected Page=1, got %d", p.Page)
		}
	})

	t.Run("negative page defaults to 1", func(t *testing.T) {
		p := NewPagination(-5, 10, 25)
		if p.Page != 1 {
			t.Errorf("expected Page=1, got %d", p.Page)
		}
	})

	t.Run("zero total", func(t *testing.T) {
		p := NewPagination(1, 10, 0)
		if p.TotalPages != 1 {
			t.Errorf("expected TotalPages=1, got %d", p.TotalPages)
		}
	})
}

func TestComparePaginationOffset(t *testing.T) {
	p := NewPagination(3, 10, 50)
	if p.Offset() != 20 {
		t.Errorf("expected Offset=20, got %d", p.Offset())
	}
}

func TestComparePaginationLimit(t *testing.T) {
	p := NewPagination(1, 25, 100)
	if p.Limit() != 25 {
		t.Errorf("expected Limit=25, got %d", p.Limit())
	}
}

func TestComparePaginationPages(t *testing.T) {
	p := NewPagination(1, 10, 35)
	pages := p.Pages()
	if len(pages) != 4 {
		t.Fatalf("expected 4 pages, got %d", len(pages))
	}
	for i, pg := range pages {
		if pg != i+1 {
			t.Errorf("expected page %d, got %d", i+1, pg)
		}
	}
}

func TestCompareExtractRootDomain(t *testing.T) {
	tests := []struct {
		name      string
		domain    string
		wantIsSub bool
		wantRoot  string
	}{
		{"subdomain", "www.example.com", true, "example.com"},
		{"root domain", "example.com", false, ""},
		{"deep subdomain", "a.b.c.example.com", true, "example.com"},
		{"trailing dot", "www.example.com.", true, "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isSub, root := extractRootDomain(tt.domain)
			if isSub != tt.wantIsSub {
				t.Errorf("isSub = %v, want %v", isSub, tt.wantIsSub)
			}
			if root != tt.wantRoot {
				t.Errorf("root = %q, want %q", root, tt.wantRoot)
			}
		})
	}
}

func TestCompareSectionsNotEmpty(t *testing.T) {
	if len(CompareSections) == 0 {
		t.Fatal("CompareSections should not be empty")
	}
	for i, s := range CompareSections {
		if s.Key == "" {
			t.Errorf("CompareSections[%d] has empty Key", i)
		}
		if s.Label == "" {
			t.Errorf("CompareSections[%d] has empty Label", i)
		}
		if s.Icon == "" {
			t.Errorf("CompareSections[%d] has empty Icon", i)
		}
	}
}
