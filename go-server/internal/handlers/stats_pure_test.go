package handlers

import (
	"testing"
	"time"

	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/dbq"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestBuildDailyStat(t *testing.T) {
	t.Run("all fields populated", func(t *testing.T) {
		total := int32(100)
		successful := int32(90)
		failed := int32(10)
		unique := int32(50)
		avg := 2.5
		now := time.Date(2024, 3, 15, 0, 0, 0, 0, time.UTC)
		s := dbq.AnalysisStat{
			Date:               pgtype.Date{Time: now, Valid: true},
			TotalAnalyses:      &total,
			SuccessfulAnalyses: &successful,
			FailedAnalyses:     &failed,
			UniqueDomains:      &unique,
			AvgAnalysisTime:    &avg,
		}
		result := buildDailyStat(s)
		if result.Date != "03/15" {
			t.Errorf("Date = %q, want 03/15", result.Date)
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
		if result.AvgAnalysisTime != 2.5 {
			t.Errorf("AvgAnalysisTime = %f", result.AvgAnalysisTime)
		}
		if !result.HasAvgTime {
			t.Error("expected HasAvgTime=true")
		}
	})

	t.Run("all nil fields", func(t *testing.T) {
		s := dbq.AnalysisStat{
			Date: pgtype.Date{Valid: false},
		}
		result := buildDailyStat(s)
		if result.Date != "" {
			t.Errorf("Date = %q, want empty", result.Date)
		}
		if result.TotalAnalyses != 0 {
			t.Errorf("TotalAnalyses = %d", result.TotalAnalyses)
		}
		if result.SuccessfulAnalyses != 0 {
			t.Errorf("SuccessfulAnalyses = %d", result.SuccessfulAnalyses)
		}
		if result.FailedAnalyses != 0 {
			t.Errorf("FailedAnalyses = %d", result.FailedAnalyses)
		}
		if result.UniqueDomains != 0 {
			t.Errorf("UniqueDomains = %d", result.UniqueDomains)
		}
		if result.HasAvgTime {
			t.Error("expected HasAvgTime=false")
		}
	})

	t.Run("partial nil fields", func(t *testing.T) {
		total := int32(50)
		s := dbq.AnalysisStat{
			Date:          pgtype.Date{Time: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), Valid: true},
			TotalAnalyses: &total,
		}
		result := buildDailyStat(s)
		if result.Date != "01/01" {
			t.Errorf("Date = %q, want 01/01", result.Date)
		}
		if result.TotalAnalyses != 50 {
			t.Errorf("TotalAnalyses = %d", result.TotalAnalyses)
		}
		if result.SuccessfulAnalyses != 0 {
			t.Errorf("SuccessfulAnalyses = %d, want 0", result.SuccessfulAnalyses)
		}
	})
}

func TestBuildCountryStat(t *testing.T) {
	t.Run("full country data", func(t *testing.T) {
		code := "US"
		name := "United States"
		row := dbq.ListCountryDistributionRow{
			CountryCode: &code,
			CountryName: &name,
			Count:       42,
		}
		result := buildCountryStat(row)
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
			t.Error("expected non-empty flag emoji")
		}
	})

	t.Run("nil country data", func(t *testing.T) {
		row := dbq.ListCountryDistributionRow{
			CountryCode: nil,
			CountryName: nil,
			Count:       10,
		}
		result := buildCountryStat(row)
		if result.Code != "" {
			t.Errorf("Code = %q, want empty", result.Code)
		}
		if result.Name != "" {
			t.Errorf("Name = %q, want empty", result.Name)
		}
		if result.Flag != "" {
			t.Errorf("Flag = %q, want empty for nil code", result.Flag)
		}
	})

	t.Run("lowercase country code", func(t *testing.T) {
		code := "gb"
		name := "United Kingdom"
		row := dbq.ListCountryDistributionRow{
			CountryCode: &code,
			CountryName: &name,
			Count:       5,
		}
		result := buildCountryStat(row)
		if result.Flag == "" {
			t.Error("expected flag emoji for 'gb'")
		}
	})

	t.Run("single char code no flag", func(t *testing.T) {
		code := "X"
		row := dbq.ListCountryDistributionRow{
			CountryCode: &code,
			Count:       1,
		}
		result := buildCountryStat(row)
		if result.Flag != "" {
			t.Errorf("Flag = %q, want empty for single-char code", result.Flag)
		}
	})
}

func TestNewStatsHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "test"}
	h := NewStatsHandler(nil, cfg)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
	if h.Config != cfg {
		t.Error("Config not set")
	}
	if h.DB != nil {
		t.Error("expected nil DB")
	}
}
