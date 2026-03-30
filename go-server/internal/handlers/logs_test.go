package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestParseTimeFilter_Empty(t *testing.T) {
	result := parseTimeFilter("")
	if result.Valid {
		t.Error("expected invalid timestamp for empty input")
	}
}

func TestParseTimeFilter_DateTimeMinutes(t *testing.T) {
	result := parseTimeFilter("2026-03-15T14:30")
	if !result.Valid {
		t.Fatal("expected valid timestamp")
	}
	if result.Time.Hour() != 14 || result.Time.Minute() != 30 {
		t.Errorf("time = %v", result.Time)
	}
}

func TestParseTimeFilter_DateTimeSeconds(t *testing.T) {
	result := parseTimeFilter("2026-03-15T14:30:45")
	if !result.Valid {
		t.Fatal("expected valid timestamp")
	}
	if result.Time.Second() != 45 {
		t.Errorf("seconds = %d, want 45", result.Time.Second())
	}
}

func TestParseTimeFilter_DateOnly(t *testing.T) {
	result := parseTimeFilter("2026-03-15")
	if !result.Valid {
		t.Fatal("expected valid timestamp")
	}
	if result.Time.Day() != 15 {
		t.Errorf("day = %d, want 15", result.Time.Day())
	}
}

func TestParseTimeFilter_InvalidFormat(t *testing.T) {
	result := parseTimeFilter("not-a-date")
	if result.Valid {
		t.Error("expected invalid timestamp for malformed input")
	}
}

func TestBuildLogParams_NoFilters(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/logs", nil)

	params := buildLogParams(c, 100)
	if params.MaxRows != 100 {
		t.Errorf("MaxRows = %d, want 100", params.MaxRows)
	}
	if params.Level != nil {
		t.Error("Level should be nil without filter")
	}
	if params.Category != nil {
		t.Error("Category should be nil without filter")
	}
}

func TestBuildLogParams_AllFilters(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/logs?level=ERROR&category=scan&domain=example.com&trace_id=abc123&after=2026-03-01&before=2026-03-15", nil)

	params := buildLogParams(c, 200)
	if params.Level == nil || *params.Level != "ERROR" {
		t.Error("expected Level = ERROR")
	}
	if params.Category == nil || *params.Category != "scan" {
		t.Error("expected Category = scan")
	}
	if params.DomainFilter == nil || *params.DomainFilter != "example.com" {
		t.Error("expected DomainFilter = example.com")
	}
	if params.TraceIDFilter == nil || *params.TraceIDFilter != "abc123" {
		t.Error("expected TraceIDFilter = abc123")
	}
	if !params.AfterTs.Valid {
		t.Error("expected valid AfterTs")
	}
	if !params.BeforeTs.Valid {
		t.Error("expected valid BeforeTs")
	}
}

func TestBuildLogParams_InvalidTimeIgnored(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/logs?after=invalid&before=alsobad", nil)

	params := buildLogParams(c, 50)
	if params.AfterTs.Valid {
		t.Error("expected invalid AfterTs for bad input")
	}
	if params.BeforeTs.Valid {
		t.Error("expected invalid BeforeTs for bad input")
	}
}

func TestParseTimeFilter_BoundaryFormats(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"2026-01-01T00:00", true},
		{"2026-12-31T23:59:59", true},
		{"2026-06-15", true},
		{"2026", false},
		{"", false},
		{"2026-13-01", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseTimeFilter(tt.input)
			if result.Valid != tt.valid {
				t.Errorf("parseTimeFilter(%q).Valid = %v, want %v", tt.input, result.Valid, tt.valid)
			}
		})
	}
}

func TestFormatTimestamp_PGTypeBoundary(t *testing.T) {
	ts := pgtype.Timestamp{Valid: false}
	if formatTimestamp(ts) != "" {
		t.Error("invalid timestamp should return empty string")
	}
}
