package handlers

import (
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"dnstool/go-server/internal/dbq"
	"dnstool/go-server/internal/scanner"
)

func TestValidateParsedURL_CB12(t *testing.T) {
	tests := []struct {
		name    string
		scheme  string
		host    string
		wantErr bool
	}{
		{"https valid", "https", "example.com", false},
		{"http rejected", "http", "example.com", true},
		{"empty host", "https", "", true},
		{"ftp rejected", "ftp", "example.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &url.URL{Scheme: tt.scheme, Host: tt.host, Path: "/logo.svg"}
			err := validateParsedURL(u)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateParsedURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBuildSafeURL_CB12(t *testing.T) {
	u := &url.URL{
		Scheme:   "https",
		Host:     "example.com",
		Path:     "/logo.svg",
		RawQuery: "v=1",
		Fragment: "top",
	}
	got := buildSafeURL(u)
	if got != "https://example.com/logo.svg?v=1#top" {
		t.Errorf("buildSafeURL() = %q", got)
	}

	u2 := &url.URL{Scheme: "https", Host: "cdn.example.com", Path: "/img.png"}
	got2 := buildSafeURL(u2)
	if got2 != "https://cdn.example.com/img.png" {
		t.Errorf("buildSafeURL() = %q", got2)
	}
}

func TestBimiFetchError_CB12(t *testing.T) {
	e := &bimiFetchError{status: 502, msg: "Failed to fetch"}
	if e.Error() != "Failed to fetch" {
		t.Errorf("bimiFetchError.Error() = %q", e.Error())
	}
}

func TestValidationError_CB12(t *testing.T) {
	e := &validationError{msg: "Only HTTPS URLs allowed"}
	if e.Error() != "Only HTTPS URLs allowed" {
		t.Errorf("validationError.Error() = %q", e.Error())
	}
}

func TestDetermineSPFScope_CB12(t *testing.T) {
	scope, note := determineSPFScope(true)
	if scope != "local" {
		t.Errorf("determineSPFScope(true) scope = %q, want local", scope)
	}
	if note == "" {
		t.Error("determineSPFScope(true) note is empty")
	}

	scope2, note2 := determineSPFScope(false)
	if scope2 != "none" {
		t.Errorf("determineSPFScope(false) scope = %q, want none", scope2)
	}
	if note2 == "" {
		t.Error("determineSPFScope(false) note is empty")
	}
}

func TestDetermineDMARCScope_CB12(t *testing.T) {
	tests := []struct {
		name        string
		subHasDMARC bool
		orgHasDMARC bool
		orgPolicy   string
		rootDom     string
		wantScope   string
	}{
		{"sub has DMARC", true, true, "reject", "example.com", "local"},
		{"inherited with policy", false, true, "reject", "example.com", "inherited"},
		{"inherited no policy", false, true, "", "example.com", "inherited"},
		{"no DMARC anywhere", false, false, "", "example.com", "none"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope, note := determineDMARCScope(tt.subHasDMARC, tt.orgHasDMARC, tt.orgPolicy, tt.rootDom)
			if scope != tt.wantScope {
				t.Errorf("determineDMARCScope() scope = %q, want %q", scope, tt.wantScope)
			}
			if note == "" {
				t.Error("determineDMARCScope() note is empty")
			}
		})
	}
}

func TestExtractScanFields_CB12(t *testing.T) {
	t.Run("is scan", func(t *testing.T) {
		sc := scanner.Classification{IsScan: true, Source: "bot-scanner", IP: "1.2.3.4"}
		src, ip := extractScanFields(sc)
		if src == nil || *src != "bot-scanner" {
			t.Errorf("extractScanFields() src = %v", src)
		}
		if ip == nil || *ip != "1.2.3.4" {
			t.Errorf("extractScanFields() ip = %v", ip)
		}
	})

	t.Run("not scan", func(t *testing.T) {
		sc := scanner.Classification{IsScan: false, Source: "", IP: ""}
		src, ip := extractScanFields(sc)
		if src != nil {
			t.Errorf("extractScanFields() src should be nil")
		}
		if ip != nil {
			t.Errorf("extractScanFields() ip should be nil")
		}
	})
}

func TestReportModeTemplate_CB12(t *testing.T) {
	tests := []struct {
		mode string
		want string
	}{
		{"C", "results_covert.html"},
		{"CZ", "results_covert.html"},
		{"B", "results_executive.html"},
		{"E", "results.html"},
		{"Z", "results.html"},
		{"", "results.html"},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			got := reportModeTemplate(tt.mode)
			if got != tt.want {
				t.Errorf("reportModeTemplate(%q) = %q, want %q", tt.mode, got, tt.want)
			}
		})
	}
}

func TestIsCovertMode_CB12(t *testing.T) {
	if !isCovertMode("C") {
		t.Error("C should be covert")
	}
	if !isCovertMode("CZ") {
		t.Error("CZ should be covert")
	}
	if !isCovertMode("EC") {
		t.Error("EC should be covert")
	}
	if isCovertMode("E") {
		t.Error("E should not be covert")
	}
	if isCovertMode("B") {
		t.Error("B should not be covert")
	}
}

func TestDerefString_CB12(t *testing.T) {
	s := "hello"
	if derefString(&s) != "hello" {
		t.Error("derefString non-nil failed")
	}
	if derefString(nil) != "" {
		t.Error("derefString nil should be empty")
	}
}

func TestExtractToolVersion_CB12(t *testing.T) {
	results := map[string]any{"_tool_version": "1.2.3"}
	if extractToolVersion(results) != "1.2.3" {
		t.Error("extractToolVersion failed with key present")
	}
	if extractToolVersion(map[string]any{}) != "" {
		t.Error("extractToolVersion should return empty for missing key")
	}
}

func TestResultsDomainExists_CB12(t *testing.T) {
	if !resultsDomainExists(map[string]any{"domain_exists": true}) {
		t.Error("should exist when domain_exists is true")
	}
	if resultsDomainExists(map[string]any{"domain_exists": false}) {
		t.Error("should not exist when domain_exists is false")
	}
	if !resultsDomainExists(map[string]any{}) {
		t.Error("should default to true when key missing")
	}
}

func TestHasLocalMXRecords_CB12(t *testing.T) {
	tests := []struct {
		name    string
		results map[string]any
		want    bool
	}{
		{"with string MX", map[string]any{"basic_records": map[string]any{"MX": []string{"10 mail.example.com"}}}, true},
		{"with any MX", map[string]any{"basic_records": map[string]any{"MX": []any{"10 mail.example.com"}}}, true},
		{"no MX", map[string]any{"basic_records": map[string]any{"MX": []string{}}}, false},
		{"no basic_records", map[string]any{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasLocalMXRecords(tt.results)
			if got != tt.want {
				t.Errorf("hasLocalMXRecords() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsActiveStatus_CB12(t *testing.T) {
	if !isActiveStatus("success") {
		t.Error("success should be active")
	}
	if !isActiveStatus("warning") {
		t.Error("warning should be active")
	}
	if isActiveStatus("danger") {
		t.Error("danger should not be active")
	}
	if isActiveStatus("") {
		t.Error("empty should not be active")
	}
}

func TestParseOrgDMARC_CB12(t *testing.T) {
	tests := []struct {
		name       string
		records    []string
		wantHas    bool
		wantPolicy string
	}{
		{"valid dmarc reject", []string{"v=DMARC1; p=reject; rua=mailto:d@example.com"}, true, "reject"},
		{"valid dmarc none", []string{"v=DMARC1; p=none"}, true, "none"},
		{"no dmarc", []string{"v=spf1 include:example.com ~all"}, false, ""},
		{"empty", []string{}, false, ""},
		{"dmarc no policy", []string{"v=DMARC1"}, true, ""},
		{"dmarc policy at end", []string{"v=DMARC1; p=quarantine"}, true, "quarantine"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			has, policy := parseOrgDMARC(tt.records)
			if has != tt.wantHas {
				t.Errorf("parseOrgDMARC() has = %v, want %v", has, tt.wantHas)
			}
			if policy != tt.wantPolicy {
				t.Errorf("parseOrgDMARC() policy = %q, want %q", policy, tt.wantPolicy)
			}
		})
	}
}

func TestLogEphemeralReason_CB12(t *testing.T) {
	logEphemeralReason("example.com", true, true)
	logEphemeralReason("example.com", false, false)
	logEphemeralReason("example.com", false, true)
}

func TestGetStringFromResults_CB12(t *testing.T) {
	results := map[string]any{
		"spf_analysis": map[string]any{
			"status": "pass",
			"record": "v=spf1 ~all",
		},
		"top_level": "value",
	}

	got := getStringFromResults(results, "spf_analysis", "status")
	if got == nil || *got != "pass" {
		t.Error("getStringFromResults nested key failed")
	}

	got2 := getStringFromResults(results, "top_level", "")
	if got2 == nil || *got2 != "value" {
		t.Error("getStringFromResults top-level key failed")
	}

	got3 := getStringFromResults(results, "missing", "key")
	if got3 != nil {
		t.Error("getStringFromResults missing section should return nil")
	}

	got4 := getStringFromResults(results, "spf_analysis", "missing")
	if got4 != nil {
		t.Error("getStringFromResults missing key should return nil")
	}
}

func TestProtocolRawConfidence_CB12(t *testing.T) {
	tests := []struct {
		status string
		want   float64
	}{
		{"secure", 1.0},
		{"pass", 1.0},
		{"valid", 1.0},
		{"good", 1.0},
		{"warning", 0.7},
		{"info", 0.7},
		{"partial", 0.7},
		{"fail", 0.3},
		{"danger", 0.3},
		{"critical", 0.3},
		{"error", 0.0},
		{"n/a", 0.0},
		{"", 0.0},
		{"unknown", 0.5},
	}
	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			results := map[string]any{
				"test_section": map[string]any{"status": tt.status},
			}
			got := protocolRawConfidence(results, "test_section")
			if got != tt.want {
				t.Errorf("protocolRawConfidence(%q) = %f, want %f", tt.status, got, tt.want)
			}
		})
	}

	got := protocolRawConfidence(map[string]any{}, "missing")
	if got != 0.0 {
		t.Error("missing section should return 0.0")
	}
}

func TestAggregateResolverAgreement_CB12(t *testing.T) {
	results := map[string]any{
		"resolver_consensus": map[string]any{
			"per_record_consensus": map[string]any{
				"A": map[string]any{
					"resolver_count": 4,
					"consensus":      true,
				},
				"MX": map[string]any{
					"resolver_count": 3,
					"consensus":      false,
				},
			},
		},
	}
	agree, total := aggregateResolverAgreement(results)
	if total != 7 {
		t.Errorf("total = %d, want 7", total)
	}
	if agree != 6 {
		t.Errorf("agree = %d, want 6", agree)
	}

	agree2, total2 := aggregateResolverAgreement(map[string]any{})
	if agree2 != 0 || total2 != 0 {
		t.Error("empty results should return 0,0")
	}
}

func TestTimeAgo_CB12(t *testing.T) {
	tests := []struct {
		name   string
		offset time.Duration
		want   string
	}{
		{"just now", 10 * time.Second, "just now"},
		{"1 minute ago", 90 * time.Second, "1 minute ago"},
		{"5 minutes ago", 5 * time.Minute, "5 minutes ago"},
		{"1 hour ago", 90 * time.Minute, "1 hour ago"},
		{"3 hours ago", 3 * time.Hour, "3 hours ago"},
		{"1 day ago", 25 * time.Hour, "1 day ago"},
		{"5 days ago", 5 * 24 * time.Hour, "5 days ago"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := timeAgo(time.Now().Add(-tt.offset))
			if got != tt.want {
				t.Errorf("timeAgo() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMatchErrorCategory_CB12(t *testing.T) {
	label, icon, ok := matchErrorCategory("dns timeout exceeded")
	if !ok {
		t.Error("should match timeout category")
	}
	if label == "" || icon == "" {
		t.Error("label and icon should not be empty")
	}

	_, _, ok2 := matchErrorCategory("completely unknown error xyz123")
	if ok2 {
		t.Error("should not match unknown error")
	}
}

func TestSanitizeErrorMessage_CB12(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		label, icon := sanitizeErrorMessage(nil)
		if label != "Unknown Error" {
			t.Errorf("label = %q, want Unknown Error", label)
		}
		if icon == "" {
			t.Error("icon should not be empty")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		s := ""
		label, _ := sanitizeErrorMessage(&s)
		if label != "Unknown Error" {
			t.Errorf("label = %q, want Unknown Error", label)
		}
	})

	t.Run("known category", func(t *testing.T) {
		s := "DNS resolution timeout"
		label, icon := sanitizeErrorMessage(&s)
		if label == "Unknown Error" {
			t.Error("should match a known category")
		}
		if icon == "" {
			t.Error("icon should not be empty")
		}
	})

	t.Run("unknown error with IP", func(t *testing.T) {
		s := "connection refused 192.168.1.1:443"
		label, _ := sanitizeErrorMessage(&s)
		if label == "" {
			t.Error("should produce a label")
		}
	})
}

func TestFormatDiffValue_CB12(t *testing.T) {
	if formatDiffValue(nil) != "" {
		t.Error("nil should return empty string")
	}
	if formatDiffValue("hello") != "hello" {
		t.Error("string should return as-is")
	}
	got := formatDiffValue(map[string]any{"key": "val"})
	if got == "" {
		t.Error("map should marshal to JSON")
	}
	var m map[string]any
	if json.Unmarshal([]byte(got), &m) != nil {
		t.Error("output should be valid JSON")
	}
}

func TestBuildCompareAnalysis_CB12(t *testing.T) {
	dur := 1.5
	fullResults, _ := json.Marshal(map[string]any{"_tool_version": "26.27.12"})
	a := dbq.DomainAnalysis{
		AnalysisDuration: &dur,
		FullResults:      fullResults,
	}
	ca := buildCompareAnalysis(a)
	if ca.ToolVersion != "26.27.12" {
		t.Errorf("ToolVersion = %q, want 26.27.12", ca.ToolVersion)
	}
	if !ca.HasToolVersion {
		t.Error("HasToolVersion should be true")
	}
	if !ca.HasDuration {
		t.Error("HasDuration should be true")
	}

	ca2 := buildCompareAnalysis(dbq.DomainAnalysis{})
	if ca2.HasToolVersion {
		t.Error("HasToolVersion should be false for empty")
	}
	if ca2.HasDuration {
		t.Error("HasDuration should be false for empty")
	}
}
