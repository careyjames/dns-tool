package handlers

import (
	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/dbq"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestNewAboutHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0"}
	h := NewAboutHandler(cfg)
	if h == nil {
		t.Fatal("expected non-nil")
	}
	if h.Config.AppVersion != "1.0" {
		t.Errorf("AppVersion = %q", h.Config.AppVersion)
	}
}

func TestNewApproachHandler(t *testing.T) {
	cfg := &config.Config{}
	h := NewApproachHandler(cfg)
	if h == nil {
		t.Fatal("expected non-nil")
	}
	if h.Config != cfg {
		t.Error("Config mismatch")
	}
}

func TestNewArchitectureHandler(t *testing.T) {
	cfg := &config.Config{}
	h := NewArchitectureHandler(cfg)
	if h == nil {
		t.Fatal("expected non-nil")
	}
}

func TestNewFAQHandler(t *testing.T) {
	h := NewFAQHandler(&config.Config{})
	if h == nil {
		t.Fatal("expected non-nil")
	}
}

func TestNewROEHandler(t *testing.T) {
	h := NewROEHandler(&config.Config{})
	if h == nil {
		t.Fatal("expected non-nil")
	}
}

func TestNewSecurityPolicyHandler(t *testing.T) {
	h := NewSecurityPolicyHandler(&config.Config{})
	if h == nil {
		t.Fatal("expected non-nil")
	}
}

func TestNewColorScienceHandler(t *testing.T) {
	h := NewColorScienceHandler(&config.Config{})
	if h == nil {
		t.Fatal("expected non-nil")
	}
}

func TestNewConfidenceHandler(t *testing.T) {
	h := NewConfidenceHandler(&config.Config{}, nil)
	if h == nil {
		t.Fatal("expected non-nil")
	}
	if h.DB != nil {
		t.Error("expected nil DB")
	}
}

func TestNewSnapshotHandler(t *testing.T) {
	h := NewSnapshotHandler(nil, &config.Config{})
	if h == nil {
		t.Fatal("expected non-nil")
	}
	if h.DB != nil {
		t.Error("expected nil DB")
	}
}

func TestNewInvestigateHandler(t *testing.T) {
	h := NewInvestigateHandler(&config.Config{}, nil)
	if h == nil {
		t.Fatal("expected non-nil")
	}
}

func TestNewToolkitHandler(t *testing.T) {
	h := NewToolkitHandler(&config.Config{})
	if h == nil {
		t.Fatal("expected non-nil")
	}
}

func TestNewFailuresHandler(t *testing.T) {
	h := NewFailuresHandler(nil, &config.Config{})
	if h == nil {
		t.Fatal("expected non-nil")
	}
}

func TestNewDossierHandler(t *testing.T) {
	h := NewDossierHandler(nil, &config.Config{})
	if h == nil {
		t.Fatal("expected non-nil")
	}
}

func TestNewAdminHandler(t *testing.T) {
	bpFunc := func() int64 { return 42 }
	h := NewAdminHandler(nil, &config.Config{}, bpFunc)
	if h == nil {
		t.Fatal("expected non-nil")
	}
	if h.BackpressureCountFunc() != 42 {
		t.Errorf("expected 42, got %d", h.BackpressureCountFunc())
	}
}

func TestMatchErrorCategory(t *testing.T) {
	tests := []struct {
		name      string
		msg       string
		wantLabel string
		wantOK    bool
	}{
		{"timeout", "dns resolution timeout occurred", "DNS Resolution Timeout", true},
		{"nxdomain", "no such host found", "Domain Not Found (NXDOMAIN)", true},
		{"connection refused", "connection refused by server", "Connection Refused", true},
		{"servfail", "servfail response", "DNS Server Failure (SERVFAIL)", true},
		{"network", "network unreachable", "Network Unreachable", true},
		{"tls", "tls handshake failed", "TLS/Certificate Error", true},
		{"x509", "x509 certificate error", "TLS/Certificate Error", true},
		{"refused", "query refused", "Query Refused", true},
		{"rate limit", "rate limit exceeded", "Rate Limited", true},
		{"invalid", "invalid input provided", "Invalid Input", true},
		{"unknown", "something completely new", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			label, _, ok := matchErrorCategory(tt.msg)
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && label != tt.wantLabel {
				t.Errorf("label = %q, want %q", label, tt.wantLabel)
			}
		})
	}
}

func TestPaginationInfoOffset(t *testing.T) {
	p := NewPagination(3, 10, 100)
	if p.Offset() != 20 {
		t.Errorf("Offset = %d, want 20", p.Offset())
	}
}

func TestPaginationInfoLimit(t *testing.T) {
	p := NewPagination(1, 25, 100)
	if p.Limit() != 25 {
		t.Errorf("Limit = %d, want 25", p.Limit())
	}
}

func TestPaginationInfoPages(t *testing.T) {
	p := NewPagination(1, 10, 50)
	pages := p.Pages()
	if len(pages) != 5 {
		t.Errorf("expected 5 pages, got %d", len(pages))
	}
	for i, pg := range pages {
		if pg != i+1 {
			t.Errorf("page[%d] = %d, want %d", i, pg, i+1)
		}
	}
}

func TestBuildDailyStatAllNil(t *testing.T) {
	s := dbq.AnalysisStat{
		ID: 1,
	}
	result := buildDailyStat(s)
	if result.Date != "" {
		t.Errorf("Date = %q, want empty", result.Date)
	}
	if result.TotalAnalyses != 0 {
		t.Errorf("TotalAnalyses = %d", result.TotalAnalyses)
	}
	if result.HasAvgTime {
		t.Error("HasAvgTime should be false")
	}
}

func TestBuildDailyStatAllPopulated(t *testing.T) {
	total := int32(100)
	successful := int32(90)
	failed := int32(10)
	unique := int32(50)
	avg := 1.5
	s := dbq.AnalysisStat{
		ID:                 1,
		Date:               pgtype.Date{Time: time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC), Valid: true},
		TotalAnalyses:      &total,
		SuccessfulAnalyses: &successful,
		FailedAnalyses:     &failed,
		UniqueDomains:      &unique,
		AvgAnalysisTime:    &avg,
	}
	result := buildDailyStat(s)
	if result.Date != "02/15" {
		t.Errorf("Date = %q", result.Date)
	}
	if result.TotalAnalyses != 100 {
		t.Errorf("TotalAnalyses = %d", result.TotalAnalyses)
	}
	if result.SuccessfulAnalyses != 90 {
		t.Errorf("SuccessfulAnalyses = %d", result.SuccessfulAnalyses)
	}
	if result.FailedAnalyses != 10 {
		t.Errorf("FailedAnalyses = %d", result.FailedAnalyses)
	}
	if result.UniqueDomains != 50 {
		t.Errorf("UniqueDomains = %d", result.UniqueDomains)
	}
	if !result.HasAvgTime {
		t.Error("HasAvgTime should be true")
	}
	if result.AvgAnalysisTime != 1.5 {
		t.Errorf("AvgAnalysisTime = %f", result.AvgAnalysisTime)
	}
}

func TestBuildCountryStatWithCode(t *testing.T) {
	code := "US"
	name := "United States"
	cs := dbq.ListCountryDistributionRow{
		CountryCode: &code,
		CountryName: &name,
		Count:       42,
	}
	result := buildCountryStat(cs)
	if result.Code != "US" {
		t.Errorf("Code = %q", result.Code)
	}
	if result.Name != "United States" {
		t.Errorf("Name = %q", result.Name)
	}
	if result.Count != 42 {
		t.Errorf("Count = %d", result.Count)
	}
	if result.Flag == "" {
		t.Error("expected non-empty flag")
	}
}

func TestBuildCountryStatNilFields(t *testing.T) {
	cs := dbq.ListCountryDistributionRow{Count: 10}
	result := buildCountryStat(cs)
	if result.Code != "" {
		t.Errorf("Code = %q", result.Code)
	}
	if result.Flag != "" {
		t.Errorf("Flag = %q, expected empty for nil code", result.Flag)
	}
}

func TestBuildCountryStatSingleCharCode(t *testing.T) {
	code := "X"
	cs := dbq.ListCountryDistributionRow{CountryCode: &code, Count: 5}
	result := buildCountryStat(cs)
	if result.Flag != "" {
		t.Errorf("Flag = %q, expected empty for 1-char code", result.Flag)
	}
}

func TestBrandColorStruct(t *testing.T) {
	c := BrandColor{
		Name:      "Test Color",
		Token:     "--test",
		Value:     "#000",
		Category:  "test",
		Notes:     "notes",
		Source:    "source",
		SourceURL: "https://example.com",
	}
	if c.Name != "Test Color" {
		t.Errorf("Name = %q", c.Name)
	}
}

func TestFailureEntryStruct(t *testing.T) {
	entry := FailureEntry{
		Domain:    "example.com",
		Category:  "Timeout",
		Icon:      "fas fa-clock",
		Timestamp: "2026-02-15",
		TimeAgo:   "5 minutes ago",
	}
	if entry.Domain != "example.com" {
		t.Error("unexpected Domain")
	}
}

func TestWatchlistConstants(t *testing.T) {
	if templateWatchlist != "watchlist.html" {
		t.Errorf("templateWatchlist = %q", templateWatchlist)
	}
	if maxWatchlistEntries != 25 {
		t.Errorf("maxWatchlistEntries = %d", maxWatchlistEntries)
	}
	if pathWatchlist != "/watchlist" {
		t.Errorf("pathWatchlist = %q", pathWatchlist)
	}
}

func TestAnalysisConstants(t *testing.T) {
	if templateIndex != "index.html" {
		t.Errorf("templateIndex = %q", templateIndex)
	}
	if headerContentDisposition != "Content-Disposition" {
		t.Errorf("headerContentDisposition = %q", headerContentDisposition)
	}
}

func TestSnapshotConstants(t *testing.T) {
	if snapshotSeparator == "" {
		t.Error("expected non-empty separator")
	}
	if snapshotNoneDiscovered == "" {
		t.Error("expected non-empty none discovered")
	}
}

func TestProxyConstants(t *testing.T) {
	if bimiMaxRedirects != 5 {
		t.Errorf("bimiMaxRedirects = %d", bimiMaxRedirects)
	}
	if bimiMaxResponseBytes != 512*1024 {
		t.Errorf("bimiMaxResponseBytes = %d", bimiMaxResponseBytes)
	}
}

func TestAuditLogPageSize(t *testing.T) {
	if auditLogPageSize != 50 {
		t.Errorf("auditLogPageSize = %d", auditLogPageSize)
	}
}

func TestErrorCategories(t *testing.T) {
	if len(errorCategories) == 0 {
		t.Fatal("expected non-empty errorCategories")
	}
	for _, cat := range errorCategories {
		if cat.label == "" {
			t.Error("error category has empty label")
		}
		if cat.icon == "" {
			t.Error("error category has empty icon")
		}
		if len(cat.keywords) == 0 {
			t.Errorf("error category %q has no keywords", cat.label)
		}
	}
}
