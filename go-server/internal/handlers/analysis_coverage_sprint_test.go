package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"dnstool/go-server/internal/dbq"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestSprint_resolveReportMode_Params(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		wantMode string
	}{
		{"C", "C", "C"},
		{"CZ", "CZ", "CZ"},
		{"Z", "Z", "Z"},
		{"EC", "EC", "EC"},
		{"B", "B", "B"},
		{"lowercase c", "c", "C"},
		{"unknown param", "X", "E"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			c.Params = gin.Params{{Key: "mode", Value: tt.mode}}
			got := resolveReportMode(c)
			if got != tt.wantMode {
				t.Errorf("resolveReportMode(param=%q) = %q, want %q", tt.mode, got, tt.wantMode)
			}
		})
	}
}

func TestSprint_resolveReportMode_NoParam(t *testing.T) {
	c := mockGinContext()
	got := resolveReportMode(c)
	if got != "E" {
		t.Errorf("resolveReportMode(no param) = %q, want %q", got, "E")
	}
}

func TestSprint_resolveReportMode_CovertQuery(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/?covert=1", nil)
	got := resolveReportMode(c)
	if got != "C" {
		t.Errorf("resolveReportMode(covert=1) = %q, want %q", got, "C")
	}
}

func TestSprint_reportModeTemplate(t *testing.T) {
	tests := []struct {
		mode string
		want string
	}{
		{"C", "results_covert.html"},
		{"CZ", "results_covert.html"},
		{"B", "results_executive.html"},
		{"E", "results.html"},
		{"Z", "results.html"},
		{"EC", "results.html"},
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

func TestSprint_isCovertMode(t *testing.T) {
	tests := []struct {
		mode string
		want bool
	}{
		{"C", true},
		{"CZ", true},
		{"EC", true},
		{"E", false},
		{"B", false},
		{"Z", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			got := isCovertMode(tt.mode)
			if got != tt.want {
				t.Errorf("isCovertMode(%q) = %v, want %v", tt.mode, got, tt.want)
			}
		})
	}
}

func TestSprint_extractDomainInput_PostForm(t *testing.T) {
	form := url.Values{}
	form.Set("domain", "  example.com  ")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	got := extractDomainInput(c)
	if got != "example.com" {
		t.Errorf("extractDomainInput(POST) = %q, want %q", got, "example.com")
	}
}

func TestSprint_extractDomainInput_QueryParam(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/?domain=query.example.com", nil)
	got := extractDomainInput(c)
	if got != "query.example.com" {
		t.Errorf("extractDomainInput(query) = %q, want %q", got, "query.example.com")
	}
}

func TestSprint_extractDomainInput_Empty(t *testing.T) {
	c := mockGinContext()
	got := extractDomainInput(c)
	if got != "" {
		t.Errorf("extractDomainInput(empty) = %q, want empty", got)
	}
}

func TestSprint_applyDevNullHeaders_True(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	applyDevNullHeaders(c, true)
	if w.Header().Get("X-Hacker") == "" {
		t.Error("expected X-Hacker header when devNull=true")
	}
	if w.Header().Get("X-Persistence") != "/dev/null" {
		t.Errorf("expected X-Persistence=/dev/null, got %q", w.Header().Get("X-Persistence"))
	}
}

func TestSprint_applyDevNullHeaders_False(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	applyDevNullHeaders(c, false)
	if w.Header().Get("X-Hacker") != "" {
		t.Error("expected no X-Hacker header when devNull=false")
	}
	if w.Header().Get("X-Persistence") != "" {
		t.Error("expected no X-Persistence header when devNull=false")
	}
}

func TestSprint_resolveCovertMode(t *testing.T) {
	tests := []struct {
		name        string
		covertForm  string
		covertQuery string
		domain      string
		want        string
	}{
		{"covert+TLD", "1", "", "com", "CZ"},
		{"covert only", "1", "", "example.com", "C"},
		{"TLD only", "", "", "com", "Z"},
		{"neither", "", "", "example.com", "E"},
		{"covert via query", "", "1", "example.com", "C"},
		{"covert query+TLD", "", "1", "org", "CZ"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			form := url.Values{}
			if tt.covertForm != "" {
				form.Set("covert", tt.covertForm)
			}
			queryURL := "/"
			if tt.covertQuery != "" {
				queryURL = "/?covert=" + tt.covertQuery
			}
			c.Request = httptest.NewRequest(http.MethodPost, queryURL, strings.NewReader(form.Encode()))
			c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			got := resolveCovertMode(c, tt.domain)
			if got != tt.want {
				t.Errorf("resolveCovertMode(covertForm=%q, covertQuery=%q, domain=%q) = %q, want %q",
					tt.covertForm, tt.covertQuery, tt.domain, got, tt.want)
			}
		})
	}
}

func TestSprint_analysisTimestamp_CreatedAt(t *testing.T) {
	analysis := dbq.DomainAnalysis{
		CreatedAt: pgtype.Timestamp{
			Time:  time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC),
			Valid: true,
		},
	}
	got := analysisTimestamp(analysis)
	if got == "" {
		t.Error("expected non-empty timestamp from CreatedAt")
	}
	if !strings.Contains(got, "2025") {
		t.Errorf("timestamp should contain year 2025, got %q", got)
	}
}

func TestSprint_analysisTimestamp_UpdatedAt(t *testing.T) {
	analysis := dbq.DomainAnalysis{
		CreatedAt: pgtype.Timestamp{
			Time:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			Valid: true,
		},
		UpdatedAt: pgtype.Timestamp{
			Time:  time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
			Valid: true,
		},
	}
	got := analysisTimestamp(analysis)
	if !strings.Contains(got, "15") {
		t.Errorf("timestamp should use UpdatedAt (day 15), got %q", got)
	}
}

func TestSprint_analysisTimestamp_Invalid(t *testing.T) {
	analysis := dbq.DomainAnalysis{}
	got := analysisTimestamp(analysis)
	if got != "" {
		t.Errorf("expected empty timestamp for invalid CreatedAt, got %q", got)
	}
}

func TestSprint_analysisDuration_NonNil(t *testing.T) {
	dur := 3.14
	analysis := dbq.DomainAnalysis{AnalysisDuration: &dur}
	got := analysisDuration(analysis)
	if got != 3.14 {
		t.Errorf("analysisDuration = %f, want 3.14", got)
	}
}

func TestSprint_analysisDuration_Nil(t *testing.T) {
	analysis := dbq.DomainAnalysis{}
	got := analysisDuration(analysis)
	if got != 0.0 {
		t.Errorf("analysisDuration(nil) = %f, want 0.0", got)
	}
}

func TestSprint_derefString_NonNil(t *testing.T) {
	s := "hello"
	got := derefString(&s)
	if got != "hello" {
		t.Errorf("derefString(%q) = %q, want %q", s, got, "hello")
	}
}

func TestSprint_derefString_Nil(t *testing.T) {
	got := derefString(nil)
	if got != "" {
		t.Errorf("derefString(nil) = %q, want empty", got)
	}
}

func TestSprint_logEphemeralReason_DevNull(t *testing.T) {
	logEphemeralReason("example.com", true, true)
}

func TestSprint_logEphemeralReason_DomainNotExists(t *testing.T) {
	logEphemeralReason("nonexistent.example", false, false)
}

func TestSprint_logEphemeralReason_Default(t *testing.T) {
	logEphemeralReason("custom.example", false, true)
}

func TestSprint_extractAuthInfo_NotAuthenticated(t *testing.T) {
	c := mockGinContext()
	isAuth, userID := extractAuthInfo(c)
	if isAuth {
		t.Error("expected isAuthenticated=false when not set")
	}
	if userID != 0 {
		t.Errorf("expected userID=0, got %d", userID)
	}
}

func TestSprint_extractAuthInfo_AuthenticatedWithUserID(t *testing.T) {
	c := mockGinContext()
	c.Set("authenticated", true)
	c.Set("user_id", int32(42))
	isAuth, userID := extractAuthInfo(c)
	if !isAuth {
		t.Error("expected isAuthenticated=true")
	}
	if userID != 42 {
		t.Errorf("expected userID=42, got %d", userID)
	}
}

func TestSprint_extractAuthInfo_AuthenticatedNoUserID(t *testing.T) {
	c := mockGinContext()
	c.Set("authenticated", true)
	isAuth, userID := extractAuthInfo(c)
	if !isAuth {
		t.Error("expected isAuthenticated=true")
	}
	if userID != 0 {
		t.Errorf("expected userID=0 when user_id not set, got %d", userID)
	}
}

func TestSprint_extractAuthInfo_AuthenticatedWrongType(t *testing.T) {
	c := mockGinContext()
	c.Set("authenticated", true)
	c.Set("user_id", "not-an-int32")
	isAuth, userID := extractAuthInfo(c)
	if !isAuth {
		t.Error("expected isAuthenticated=true")
	}
	if userID != 0 {
		t.Errorf("expected userID=0 for wrong type, got %d", userID)
	}
}

func TestSprint_recordAnalyticsCollector_NoCollector(t *testing.T) {
	c := mockGinContext()
	recordAnalyticsCollector(c, "example.com")
}

type sprintMockCollector struct {
	recorded string
}

func (m *sprintMockCollector) RecordAnalysis(domain string) {
	m.recorded = domain
}

func TestSprint_recordAnalyticsCollector_WithCollector(t *testing.T) {
	c := mockGinContext()
	mc := &sprintMockCollector{}
	c.Set("analytics_collector", mc)
	recordAnalyticsCollector(c, "test.example.com")
	if mc.recorded != "test.example.com" {
		t.Errorf("expected recorded domain=%q, got %q", "test.example.com", mc.recorded)
	}
}

func TestSprint_recordAnalyticsCollector_WrongType(t *testing.T) {
	c := mockGinContext()
	c.Set("analytics_collector", "not-a-collector")
	recordAnalyticsCollector(c, "example.com")
}
