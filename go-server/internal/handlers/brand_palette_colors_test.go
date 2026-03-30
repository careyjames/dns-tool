// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
	"testing"

	"dnstool/go-server/internal/config"
)

func TestGetBrandPalette_CB2(t *testing.T) {
	palette := getBrandPalette()
	if len(palette) == 0 {
		t.Fatal("getBrandPalette returned empty slice")
	}
	for _, c := range palette {
		if c.Name == "" {
			t.Error("BrandColor has empty Name")
		}
		if c.Token == "" {
			t.Error("BrandColor has empty Token")
		}
		if c.Value == "" {
			t.Error("BrandColor has empty Value")
		}
	}
}

func TestGetStatusColors_CB2(t *testing.T) {
	colors := getStatusColors()
	if len(colors) != 5 {
		t.Errorf("expected 5 status colors, got %d", len(colors))
	}
	names := map[string]bool{}
	for _, c := range colors {
		names[c.Name] = true
	}
	for _, expected := range []string{"Success", "Warning", "Danger", "Info", "Neutral"} {
		if !names[expected] {
			t.Errorf("missing status color: %s", expected)
		}
	}
}

func TestGetSurfaceColors_CB2(t *testing.T) {
	colors := getSurfaceColors()
	if len(colors) != 4 {
		t.Errorf("expected 4 surface colors, got %d", len(colors))
	}
}

func TestGetTLPColors_CB2(t *testing.T) {
	colors := getTLPColors()
	if len(colors) < 5 {
		t.Errorf("expected at least 5 TLP colors, got %d", len(colors))
	}
	for _, c := range colors {
		if c.Source == "" {
			t.Errorf("TLP color %s missing Source", c.Name)
		}
		if c.SourceURL == "" {
			t.Errorf("TLP color %s missing SourceURL", c.Name)
		}
	}
}

func TestGetCVSSColors_CB2(t *testing.T) {
	colors := getCVSSColors()
	if len(colors) != 5 {
		t.Errorf("expected 5 CVSS colors, got %d", len(colors))
	}
	for _, c := range colors {
		if c.SourceURL == "" {
			t.Errorf("CVSS color %s missing SourceURL", c.Name)
		}
	}
}

func TestNewBrandColorsHandler_CB2(t *testing.T) {
	cfg := &config.Config{AppVersion: "test"}
	h := NewBrandColorsHandler(cfg)
	if h == nil {
		t.Fatal("NewBrandColorsHandler returned nil")
	}
	if h.Config != cfg {
		t.Error("Config not set correctly")
	}
}

func TestGetChangelog_CB2(t *testing.T) {
	entries := GetChangelog()
	if len(entries) == 0 {
		t.Fatal("GetChangelog returned empty")
	}
	for i, e := range entries {
		if e.Version == "" {
			t.Errorf("entry %d has empty version", i)
		}
		if e.Date == "" {
			t.Errorf("entry %d has empty date", i)
		}
		if e.Title == "" {
			t.Errorf("entry %d has empty title", i)
		}
		if e.Category == "" {
			t.Errorf("entry %d has empty category", i)
		}
	}
}

func TestGetRecentChangelog_CB2(t *testing.T) {
	recent := GetRecentChangelog(3)
	if len(recent) > 3 {
		t.Errorf("GetRecentChangelog(3) returned %d entries", len(recent))
	}
	all := GetChangelog()
	big := GetRecentChangelog(len(all) + 10)
	if len(big) != len(all) {
		t.Errorf("GetRecentChangelog(n > total) should return all, got %d vs %d", len(big), len(all))
	}
	zero := GetRecentChangelog(0)
	if len(zero) != 0 {
		t.Errorf("GetRecentChangelog(0) should return empty, got %d", len(zero))
	}
}

func TestGetLegacyChangelog_CB2(t *testing.T) {
	legacy := GetLegacyChangelog()
	if len(legacy) == 0 {
		t.Fatal("GetLegacyChangelog returned empty")
	}
	for _, e := range legacy {
		if !e.IsLegacy {
			t.Errorf("legacy entry %q should have IsLegacy=true", e.Title)
		}
	}
}

func TestBuildPaginationData(t *testing.T) {
	pd := BuildPagination(1, 5, 100)
	if pd.CurrentPage != 1 {
		t.Errorf("expected CurrentPage 1, got %d", pd.CurrentPage)
	}
	if pd.TotalPages != 5 {
		t.Errorf("expected TotalPages 5, got %d", pd.TotalPages)
	}
	if pd.HasPrev {
		t.Error("page 1 should not have prev")
	}
	if !pd.HasNext {
		t.Error("page 1 of 5 should have next")
	}
	if pd.NextPage != 2 {
		t.Errorf("expected NextPage 2, got %d", pd.NextPage)
	}
	if pd.Total != 100 {
		t.Errorf("expected Total 100, got %d", pd.Total)
	}
	if len(pd.Pages) == 0 {
		t.Error("expected non-empty Pages")
	}
}

func TestBuildPaginationLastPage_CB2(t *testing.T) {
	pd := BuildPagination(5, 5, 50)
	if !pd.HasPrev {
		t.Error("page 5 should have prev")
	}
	if pd.HasNext {
		t.Error("page 5 of 5 should not have next")
	}
	if pd.PrevPage != 4 {
		t.Errorf("expected PrevPage 4, got %d", pd.PrevPage)
	}
}

func TestBuildPaginationSinglePage_CB2(t *testing.T) {
	pd := BuildPagination(1, 1, 5)
	if pd.HasPrev || pd.HasNext {
		t.Error("single page should have neither prev nor next")
	}
}

func TestIterPagesGap(t *testing.T) {
	pages := iterPages(10, 20)
	hasGap := false
	for _, p := range pages {
		if p.IsGap {
			hasGap = true
			break
		}
	}
	if !hasGap {
		t.Error("expected gap for 20-page pagination at page 10")
	}

	hasActive := false
	for _, p := range pages {
		if p.IsActive && p.Number == 10 {
			hasActive = true
		}
	}
	if !hasActive {
		t.Error("expected page 10 to be active")
	}
}

func TestIterPagesSmall_CB2(t *testing.T) {
	pages := iterPages(1, 3)
	if len(pages) != 3 {
		t.Errorf("expected 3 pages for totalPages=3, got %d", len(pages))
	}
	for _, p := range pages {
		if p.IsGap {
			t.Error("no gaps expected for 3-page pagination")
		}
	}
}

func TestTopN_CB2(t *testing.T) {
	m := map[string]int{"google": 10, "bing": 5, "yahoo": 3, "duckduckgo": 1}
	result := topN(m, 2)
	if len(result) != 2 {
		t.Errorf("expected 2 entries, got %d", len(result))
	}
	if result[0].Count < result[1].Count {
		t.Error("entries should be sorted descending by count")
	}
}

func TestTopNEmpty(t *testing.T) {
	result := topN(nil, 5)
	if len(result) != 0 {
		t.Errorf("expected 0 entries for nil map, got %d", len(result))
	}
}

func TestTopNMoreThanAvailable(t *testing.T) {
	m := map[string]int{"a": 1}
	result := topN(m, 10)
	if len(result) != 1 {
		t.Errorf("expected 1 entry, got %d", len(result))
	}
}

func TestTopNPages_CB2(t *testing.T) {
	m := map[string]int{"/": 100, "/about": 50, "/scan": 25}
	result := topNPages(m, 2)
	if len(result) != 2 {
		t.Errorf("expected 2 entries, got %d", len(result))
	}
	if result[0].Count < result[1].Count {
		t.Error("entries should be sorted descending by count")
	}
}

func TestTopNPagesEmpty(t *testing.T) {
	result := topNPages(nil, 5)
	if len(result) != 0 {
		t.Errorf("expected 0 entries for nil map, got %d", len(result))
	}
}

func TestNewAnalyticsHandler_CB2(t *testing.T) {
	cfg := &config.Config{AppVersion: "test"}
	h := NewAnalyticsHandler(nil, cfg)
	if h == nil {
		t.Fatal("NewAnalyticsHandler returned nil")
	}
	if h.Config != cfg {
		t.Error("Config not set correctly")
	}
}

func TestNewStatsHandler_CB2(t *testing.T) {
	cfg := &config.Config{AppVersion: "test"}
	h := NewStatsHandler(nil, cfg)
	if h == nil {
		t.Fatal("NewStatsHandler returned nil")
	}
}

func TestNewFailuresHandler_CB2(t *testing.T) {
	cfg := &config.Config{AppVersion: "test"}
	h := NewFailuresHandler(nil, cfg)
	if h == nil {
		t.Fatal("NewFailuresHandler returned nil")
	}
}

func TestNewToolkitHandler_CB2(t *testing.T) {
	cfg := &config.Config{AppVersion: "test"}
	h := NewToolkitHandler(cfg)
	if h == nil {
		t.Fatal("NewToolkitHandler returned nil")
	}
}

func TestDetectPlatformCB2(t *testing.T) {
	tests := []struct {
		ua       string
		expected string
	}{
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 16_0)", "ios"},
		{"Mozilla/5.0 (iPad; CPU OS 16_0)", "ios"},
		{"Mozilla/5.0 (iPod touch; CPU iPhone OS 16_0)", "ios"},
		{"Mozilla/5.0 (Linux; Android 13)", "android"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0)", "macos"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "windows"},
		{"Mozilla/5.0 (X11; Linux x86_64)", "linux"},
		{"curl/7.88.1", "unknown"},
		{"", "unknown"},
	}
	for _, tt := range tests {
		got := detectPlatform(tt.ua)
		if got != tt.expected {
			t.Errorf("detectPlatform(%q) = %q, want %q", tt.ua, got, tt.expected)
		}
	}
}

func TestResolveProbeConfigNoProbes(t *testing.T) {
	cfg := &config.Config{ProbeAPIURL: ""}
	h := &ToolkitHandler{Config: cfg}
	_, ok := h.resolveProbeConfig("any")
	if ok {
		t.Error("expected false when no probes configured")
	}
}

func TestResolveProbeConfigFallback(t *testing.T) {
	cfg := &config.Config{
		ProbeAPIURL: "https://probe.example.com",
		ProbeAPIKey: "key123",
	}
	h := &ToolkitHandler{Config: cfg}
	pc, ok := h.resolveProbeConfig("")
	if !ok {
		t.Fatal("expected true for fallback probe")
	}
	if pc.url != "https://probe.example.com" {
		t.Errorf("expected fallback URL, got %q", pc.url)
	}
	if pc.label != "Default" {
		t.Errorf("expected label Default, got %q", pc.label)
	}
}

func TestResolveProbeConfigWithProbes(t *testing.T) {
	cfg := &config.Config{
		Probes: []config.ProbeEndpoint{
			{ID: "probe-01", Label: "US-East", URL: "https://p1.example.com", Key: "k1"},
			{ID: "probe-02", Label: "US-West", URL: "https://p2.example.com", Key: "k2"},
		},
	}
	h := &ToolkitHandler{Config: cfg}

	pc, ok := h.resolveProbeConfig("probe-02")
	if !ok {
		t.Fatal("expected true")
	}
	if pc.url != "https://p2.example.com" {
		t.Errorf("expected probe-02 URL, got %q", pc.url)
	}
	if pc.label != "US-West" {
		t.Errorf("expected US-West label, got %q", pc.label)
	}

	pc2, ok2 := h.resolveProbeConfig("nonexistent")
	if !ok2 {
		t.Fatal("expected true (falls back to first probe)")
	}
	if pc2.url != "https://p1.example.com" {
		t.Errorf("expected first probe URL for unknown ID, got %q", pc2.url)
	}
}

func TestFlashMessageStruct_CB2(t *testing.T) {
	fm := FlashMessage{Category: "success", Message: "Saved!"}
	if fm.Category != "success" {
		t.Errorf("expected success, got %s", fm.Category)
	}
	if fm.Message != "Saved!" {
		t.Errorf("expected Saved!, got %s", fm.Message)
	}
}

func TestAnalysisItemStruct_CB2(t *testing.T) {
	item := AnalysisItem{
		ID:              1,
		Domain:          "example.com",
		AsciiDomain:     "example.com",
		SpfStatus:       "pass",
		DmarcStatus:     "pass",
		DkimStatus:      "pass",
		AnalysisSuccess: true,
	}
	if item.ID != 1 {
		t.Error("ID not set")
	}
	if !item.AnalysisSuccess {
		t.Error("AnalysisSuccess should be true")
	}
}

func TestCountryStatStruct_CB2(t *testing.T) {
	cs := CountryStat{Code: "US", Name: "United States", Count: 100, Flag: "🇺🇸"}
	if cs.Code != "US" {
		t.Error("Code not set")
	}
}

func TestDiffItemStruct_CB2(t *testing.T) {
	di := DiffItem{
		Label:   "SPF",
		Icon:    "envelope",
		Changed: true,
		StatusA: "pass",
		StatusB: "fail",
	}
	if !di.Changed {
		t.Error("Changed should be true")
	}
}

func TestCompareAnalysisStruct_CB2(t *testing.T) {
	ca := CompareAnalysis{
		CreatedAt:      "2026-01-01",
		ToolVersion:    "26.27.10",
		HasToolVersion: true,
	}
	if !ca.HasToolVersion {
		t.Error("HasToolVersion should be true")
	}
}

func TestPopularDomainStruct_CB2(t *testing.T) {
	pd := PopularDomain{Domain: "google.com", Count: 500}
	if pd.Domain != "google.com" {
		t.Error("Domain not set")
	}
}

func TestDailyStatStruct_CB2(t *testing.T) {
	ds := DailyStat{
		Date:               "2026-01-01",
		TotalAnalyses:      100,
		SuccessfulAnalyses: 95,
		FailedAnalyses:     5,
		UniqueDomains:      42,
		AvgAnalysisTime:    2.5,
		HasAvgTime:         true,
	}
	if !ds.HasAvgTime {
		t.Error("HasAvgTime should be true")
	}
	if ds.TotalAnalyses != 100 {
		t.Error("TotalAnalyses should be 100")
	}
}

func TestAnalyticsDayStruct_CB2(t *testing.T) {
	ad := AnalyticsDay{
		Date:            "2026-01-01",
		Pageviews:       1000,
		ReferrerSources: map[string]int{"google": 500},
		TopPages:        map[string]int{"/": 800},
	}
	if ad.Pageviews != 1000 {
		t.Error("Pageviews not set")
	}
}

func TestAnalyticsSummaryStruct_CB2(t *testing.T) {
	as := AnalyticsSummary{
		TotalPageviews:      10000,
		TotalUniqueVisitors: 5000,
		DaysTracked:         30,
	}
	if as.DaysTracked != 30 {
		t.Error("DaysTracked not set")
	}
}

func TestExtractRootDomainCB2(t *testing.T) {
	tests := []struct {
		domain string
		isSub  bool
		root   string
	}{
		{"example.com", false, ""},
		{"sub.example.com", true, "example.com"},
		{"deep.sub.example.com", true, "example.com"},
		{"example.co.uk", false, ""},
		{"sub.example.co.uk", true, "example.co.uk"},
		{"com", false, ""},
	}
	for _, tt := range tests {
		isSub, root := extractRootDomain(tt.domain)
		if isSub != tt.isSub {
			t.Errorf("extractRootDomain(%q) isSub=%v, want %v", tt.domain, isSub, tt.isSub)
		}
		if root != tt.root {
			t.Errorf("extractRootDomain(%q) root=%q, want %q", tt.domain, root, tt.root)
		}
	}
}

func TestIsPublicSuffixDomainCB2(t *testing.T) {
	if !isPublicSuffixDomain("com") {
		t.Error("com should be public suffix")
	}
	if !isPublicSuffixDomain("co.uk") {
		t.Error("co.uk should be public suffix")
	}
	if isPublicSuffixDomain("example.com") {
		t.Error("example.com should not be public suffix")
	}
}

func TestIsTwoPartSuffix_CB2(t *testing.T) {
	if !isTwoPartSuffix("co.uk") {
		t.Error("co.uk should be two-part suffix")
	}
	if !isTwoPartSuffix("com.au") {
		t.Error("com.au should be two-part suffix")
	}
	if isTwoPartSuffix("com") {
		t.Error("com should not be two-part suffix")
	}
	if isTwoPartSuffix("example.com") {
		t.Error("example.com should not be two-part suffix")
	}
}

func TestIsActiveStatusCB2(t *testing.T) {
	if !isActiveStatus("success") {
		t.Error("success should be active")
	}
	if !isActiveStatus("warning") {
		t.Error("warning should be active")
	}
	if isActiveStatus("") {
		t.Error("empty should not be active")
	}
	if isActiveStatus("fail") {
		t.Error("fail should not be active")
	}
}

func TestGetNumValue_CB2(t *testing.T) {
	m := map[string]interface{}{
		"float": 3.14,
		"int":   float64(42),
		"str":   "hello",
	}
	if v := getNumValue(m, "float"); v != 3.14 {
		t.Errorf("expected 3.14, got %f", v)
	}
	if v := getNumValue(m, "int"); v != 42 {
		t.Errorf("expected 42, got %f", v)
	}
	if v := getNumValue(m, "str"); v != 0 {
		t.Errorf("expected 0 for string, got %f", v)
	}
	if v := getNumValue(m, "missing"); v != 0 {
		t.Errorf("expected 0 for missing, got %f", v)
	}
	if v := getNumValue(nil, "any"); v != 0 {
		t.Errorf("expected 0 for nil map, got %f", v)
	}
}

func TestGetStatus_CB2(t *testing.T) {
	m := map[string]interface{}{"status": "pass"}
	if s := getStatus(m); s != "pass" {
		t.Errorf("expected pass, got %s", s)
	}
	if s := getStatus(map[string]interface{}{}); s != "unknown" {
		t.Errorf("expected unknown, got %s", s)
	}
	if s := getStatus(map[string]interface{}{"state": "active"}); s != "active" {
		t.Errorf("expected active from state fallback, got %s", s)
	}
}

func TestGetSection_CB2(t *testing.T) {
	results := map[string]interface{}{
		"spf": map[string]interface{}{"status": "pass"},
	}
	sec := getSection(results, "spf")
	if sec == nil {
		t.Fatal("expected non-nil section")
	}
	if sec["status"] != "pass" {
		t.Error("expected status pass")
	}
	sec2 := getSection(results, "missing")
	if sec2 == nil {
		t.Error("getSection should return empty map for missing key, not nil")
	}
	if len(sec2) != 0 {
		t.Errorf("expected empty map for missing section, got %v", sec2)
	}
}

func TestNormalizeForCompareCB2(t *testing.T) {
	if v := normalizeForCompare(nil); v != nil {
		t.Error("nil should normalize to nil")
	}
	if v := normalizeForCompare("hello"); v != "hello" {
		t.Errorf("string should pass through, got %v", v)
	}
	if v := normalizeForCompare(42.0); v != 42.0 {
		t.Errorf("float should pass through, got %v", v)
	}
}

func TestParseSortedElement_CB2(t *testing.T) {
	if v := parseSortedElement("hello", true); v != "hello" {
		t.Errorf("expected string, got %v", v)
	}
	if v := parseSortedElement("42", false); v != float64(42) {
		t.Errorf("expected 42, got %v", v)
	}
	if v := parseSortedElement("notanumber", false); v != "notanumber" {
		t.Errorf("expected fallback string, got %v", v)
	}
}

func TestChangelogEntryStruct(t *testing.T) {
	e := ChangelogEntry{
		Version:     "26.27.10",
		Date:        "Feb 27, 2026",
		Category:    "Core",
		Title:       "Test Entry",
		Description: "Description",
		Icon:        "fas fa-code",
		IsIncident:  false,
		IsLegacy:    false,
	}
	if e.Version != "26.27.10" {
		t.Error("Version not set")
	}
	if e.IsIncident {
		t.Error("should not be incident")
	}
}

func TestNormalizeCountVerdict_CB2(t *testing.T) {
	section := map[string]interface{}{
		"count": float64(5),
	}
	result := normalizeCountVerdict(section, "count", "items found", "none found")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result["answer"] != "Yes" {
		t.Errorf("expected answer 'Yes' for count>0, got %v", result["answer"])
	}
	if result["reason"] == nil {
		t.Error("expected reason to be set")
	}
}

func TestNormalizeCountVerdictZero_CB2(t *testing.T) {
	section := map[string]interface{}{
		"count": float64(0),
	}
	result := normalizeCountVerdict(section, "count", "items found", "none found")
	if result["answer"] != "No" {
		t.Errorf("expected answer 'No' for count=0, got %v", result["answer"])
	}
	if result["reason"] != "none found" {
		t.Errorf("expected reason 'none found', got %v", result["reason"])
	}
}

func TestNormalizeLLMsTxtVerdict_CB2(t *testing.T) {
	section := map[string]interface{}{
		"found": true,
	}
	result := normalizeLLMsTxtVerdict(section)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestNormalizeLLMsTxtVerdictNotFound(t *testing.T) {
	section := map[string]interface{}{
		"found": false,
	}
	result := normalizeLLMsTxtVerdict(section)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestNormalizeRobotsTxtVerdict(t *testing.T) {
	section := map[string]interface{}{
		"found": true,
	}
	result := normalizeRobotsTxtVerdict(section)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestNormalizeRobotsTxtVerdictNotFound(t *testing.T) {
	section := map[string]interface{}{
		"found": false,
	}
	result := normalizeRobotsTxtVerdict(section)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestNormalizeEmailAnswer_CB2(t *testing.T) {
	verdicts := map[string]interface{}{
		"email_answer": "Yes — spoofable via missing SPF",
	}
	normalizeEmailAnswer(verdicts)
	if verdicts["email_answer_short"] != "Yes" {
		t.Errorf("expected short answer 'Yes', got %v", verdicts["email_answer_short"])
	}
	if verdicts["email_answer_reason"] != "spoofable via missing SPF" {
		t.Errorf("expected reason, got %v", verdicts["email_answer_reason"])
	}
	if verdicts["email_answer_color"] != "danger" {
		t.Errorf("expected danger color for Yes, got %v", verdicts["email_answer_color"])
	}
}

func TestNormalizeEmailAnswerNo(t *testing.T) {
	verdicts := map[string]interface{}{
		"email_answer": "No — properly configured",
	}
	normalizeEmailAnswer(verdicts)
	if verdicts["email_answer_short"] != "No" {
		t.Errorf("expected short answer 'No', got %v", verdicts["email_answer_short"])
	}
	if verdicts["email_answer_color"] != "success" {
		t.Errorf("expected success color for No, got %v", verdicts["email_answer_color"])
	}
}

func TestNormalizeEmailAnswerMissing(t *testing.T) {
	verdicts := map[string]interface{}{}
	normalizeEmailAnswer(verdicts)
}

func TestNormalizeVerdictAnswers_CB2(t *testing.T) {
	verdicts := map[string]interface{}{
		"dns_tampering": map[string]interface{}{
			"label": "Protected",
		},
		"brand_impersonation": map[string]interface{}{
			"label": "Exposed",
		},
		"certificate_control": map[string]interface{}{
			"label": "Configured",
		},
		"transport": map[string]interface{}{
			"label": "Fully Protected",
		},
	}
	normalizeVerdictAnswers(verdicts)
	dns := verdicts["dns_tampering"].(map[string]interface{})
	if dns["answer"] != "No" {
		t.Errorf("expected 'No' for Protected dns_tampering, got %v", dns["answer"])
	}
	brand := verdicts["brand_impersonation"].(map[string]interface{})
	if brand["answer"] != "Yes" {
		t.Errorf("expected 'Yes' for Exposed brand_impersonation, got %v", brand["answer"])
	}
	cert := verdicts["certificate_control"].(map[string]interface{})
	if cert["answer"] != "Yes" {
		t.Errorf("expected 'Yes' for Configured certificate_control, got %v", cert["answer"])
	}
	trans := verdicts["transport"].(map[string]interface{})
	if trans["answer"] != "Yes" {
		t.Errorf("expected 'Yes' for Fully Protected transport, got %v", trans["answer"])
	}
}

func TestNormalizeVerdictEntry_CB2(t *testing.T) {
	verdicts := map[string]interface{}{
		"testkey": map[string]interface{}{
			"label": "Good",
		},
	}
	labelMap := map[string]string{"Good": "Everything looks great"}
	normalizeVerdictEntry(verdicts, "testkey", labelMap)
	entry := verdicts["testkey"].(map[string]interface{})
	if entry["answer"] != "Everything looks great" {
		t.Errorf("expected mapped answer, got %v", entry["answer"])
	}
}

func TestNormalizeVerdictEntryUnknownLabel_CB2(t *testing.T) {
	verdicts := map[string]interface{}{
		"testkey": map[string]interface{}{
			"label": "Unknown-Label-12345",
		},
	}
	normalizeVerdictEntry(verdicts, "testkey", map[string]string{"Other": "x"})
	entry := verdicts["testkey"].(map[string]interface{})
	if _, ok := entry["answer"]; ok {
		t.Error("should not have answer for unmapped label")
	}
}

func TestNormalizeVerdictEntryAlreadyHasAnswer(t *testing.T) {
	verdicts := map[string]interface{}{
		"testkey": map[string]interface{}{
			"label":  "Good",
			"answer": "Already set",
		},
	}
	normalizeVerdictEntry(verdicts, "testkey", map[string]string{"Good": "New value"})
	entry := verdicts["testkey"].(map[string]interface{})
	if entry["answer"] != "Already set" {
		t.Error("should not overwrite existing answer")
	}
}

func TestNormalizeVerdictEntryReasonPrefix(t *testing.T) {
	verdicts := map[string]interface{}{
		"testkey": map[string]interface{}{
			"label":  "Good",
			"reason": "No — this is the reason",
		},
	}
	normalizeVerdictEntry(verdicts, "testkey", map[string]string{"Good": "Yes"})
	entry := verdicts["testkey"].(map[string]interface{})
	if entry["reason"] != "this is the reason" {
		t.Errorf("expected prefix-stripped reason, got %v", entry["reason"])
	}
}

func TestNormalizeAIVerdicts_CB2(t *testing.T) {
	results := map[string]interface{}{
		"ai_surface": map[string]interface{}{
			"llms_txt":   map[string]interface{}{"found": true},
			"robots_txt": map[string]interface{}{"found": true},
		},
	}
	verdicts := map[string]interface{}{}
	normalizeAIVerdicts(results, verdicts)
	if verdicts["ai_llms_txt"] == nil {
		t.Error("expected ai_llms_txt in verdicts")
	}
	if verdicts["ai_crawler_governance"] == nil {
		t.Error("expected ai_crawler_governance in verdicts")
	}
}

func TestNormalizeAIVerdictsAlreadyPresent(t *testing.T) {
	results := map[string]interface{}{
		"ai_surface": map[string]interface{}{
			"llms_txt": map[string]interface{}{"found": true},
		},
	}
	verdicts := map[string]interface{}{
		"ai_llms_txt": map[string]interface{}{"answer": "existing"},
	}
	normalizeAIVerdicts(results, verdicts)
	entry := verdicts["ai_llms_txt"].(map[string]interface{})
	if entry["answer"] != "existing" {
		t.Error("should not overwrite existing ai_llms_txt verdict")
	}
}

func TestComputeSectionDiffSame(t *testing.T) {
	secA := map[string]interface{}{"status": "pass", "records": []interface{}{"v=spf1 ~all"}}
	secB := map[string]interface{}{"status": "pass", "records": []interface{}{"v=spf1 ~all"}}
	diff := ComputeSectionDiff(secA, secB, "spf", "SPF", "envelope")
	if diff.Changed {
		t.Error("identical sections should not show as changed")
	}
}

func TestComputeSectionDiffDifferent(t *testing.T) {
	secA := map[string]interface{}{"status": "pass"}
	secB := map[string]interface{}{"status": "fail"}
	diff := ComputeSectionDiff(secA, secB, "spf", "SPF", "envelope")
	if !diff.Changed {
		t.Error("different sections should show as changed")
	}
}

func TestComputeAllDiffs_CB2(t *testing.T) {
	resultsA := map[string]interface{}{
		"spf":   map[string]interface{}{"status": "pass"},
		"dmarc": map[string]interface{}{"status": "pass"},
	}
	resultsB := map[string]interface{}{
		"spf":   map[string]interface{}{"status": "fail"},
		"dmarc": map[string]interface{}{"status": "pass"},
	}
	diffs := ComputeAllDiffs(resultsA, resultsB)
	if len(diffs) == 0 {
		t.Error("expected non-empty diffs")
	}
}

func TestNormalizeResultsEmpty(t *testing.T) {
	result := NormalizeResults(nil)
	if result != nil {
		t.Error("nil input should return nil")
	}
}

func TestNormalizeResultsInvalidJSON(t *testing.T) {
	result := NormalizeResults([]byte("not json"))
	if result != nil {
		t.Error("invalid JSON should return nil")
	}
}

func TestNormalizeResultsValid(t *testing.T) {
	result := NormalizeResults([]byte(`{"spf":{"status":"pass"}}`))
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result["spf"] == nil {
		t.Error("expected spf in results")
	}
}
