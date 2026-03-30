package handlers

import (
	"dnstool/go-server/internal/config"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNewRemediationHandler(t *testing.T) {
	h := NewRemediationHandler(nil, &config.Config{})
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestRemediationHandler_Store_NilDBAndStore(t *testing.T) {
	h := &RemediationHandler{Config: &config.Config{}}
	if h.store() != nil {
		t.Error("store() should return nil when both DB and lookupStore are nil")
	}
}

func TestBuildCopyableRecord_WithValue(t *testing.T) {
	result := buildCopyableRecord("TXT", "example.com", "v=spf1 -all")
	if result != "example.com  TXT  v=spf1 -all" {
		t.Errorf("result = %q", result)
	}
}

func TestBuildCopyableRecord_EmptyValue(t *testing.T) {
	result := buildCopyableRecord("TXT", "example.com", "")
	if result != "" {
		t.Error("expected empty result for empty value")
	}
}

func TestGetStr_Present(t *testing.T) {
	m := map[string]any{"key": "value"}
	if got := getStr(m, "key"); got != "value" {
		t.Errorf("getStr = %q, want 'value'", got)
	}
}

func TestGetStr_Missing(t *testing.T) {
	m := map[string]any{}
	if got := getStr(m, "key"); got != "" {
		t.Errorf("getStr = %q, want empty", got)
	}
}

func TestGetStr_NonString(t *testing.T) {
	m := map[string]any{"key": 42}
	result := getStr(m, "key")
	if result != fmt.Sprintf("%v", 42) {
		t.Errorf("getStr = %q, want '42'", result)
	}
}

func TestBuildRemediationItems_WithDNS(t *testing.T) {
	fixes := []any{
		map[string]any{
			"title":     "Add SPF Record",
			"fix":       "Configure SPF",
			"section":   "spf",
			"dns_host":  "example.com",
			"dns_type":  "TXT",
			"dns_value": "v=spf1 -all",
		},
	}
	items := buildRemediationItems(fixes)
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if !items[0].HasDNS {
		t.Error("expected HasDNS = true")
	}
	if items[0].DNSType != "TXT" {
		t.Errorf("DNSType = %q", items[0].DNSType)
	}
}

func TestBuildRemediationItems_WithDNSRecord(t *testing.T) {
	fixes := []any{
		map[string]any{
			"title":      "Add Record",
			"dns_record": "example.com TXT v=spf1 -all",
		},
	}
	items := buildRemediationItems(fixes)
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if !items[0].HasDNS {
		t.Error("expected HasDNS = true")
	}
	if items[0].CopyableRecord != "example.com TXT v=spf1 -all" {
		t.Errorf("CopyableRecord = %q", items[0].CopyableRecord)
	}
}

func TestBuildRemediationItems_InvalidType(t *testing.T) {
	fixes := []any{42}
	items := buildRemediationItems(fixes)
	if len(items) != 0 {
		t.Errorf("expected 0 items for non-map input, got %d", len(items))
	}
}

func TestRemediationSubmit_WithAnalysisID(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewRemediationHandler(nil, cfg)

	w := httptest.NewRecorder()
	router := gin.New()
	router.POST("/remediation", h.RemediationSubmit)

	form := url.Values{}
	form.Set("analysis_id", "42")
	req := httptest.NewRequest(http.MethodPost, "/remediation", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "analysis_id=42") {
		t.Errorf("redirect location = %q, expected analysis_id=42", loc)
	}
}

func TestRemediationSubmit_WithDomain(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewRemediationHandler(nil, cfg)

	w := httptest.NewRecorder()
	router := gin.New()
	router.POST("/remediation", h.RemediationSubmit)

	form := url.Values{}
	form.Set("domain", "EXAMPLE.COM")
	req := httptest.NewRequest(http.MethodPost, "/remediation", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "domain=example.com") {
		t.Errorf("redirect location = %q, expected lowercase domain", loc)
	}
}

func TestRemediationSubmit_Empty(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewRemediationHandler(nil, cfg)

	w := httptest.NewRecorder()
	router := gin.New()
	router.POST("/remediation", h.RemediationSubmit)

	req := httptest.NewRequest(http.MethodPost, "/remediation", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
}

func TestRemediationTemplate_Constant(t *testing.T) {
	if remediationTemplate != "remediation.html" {
		t.Errorf("remediationTemplate = %q", remediationTemplate)
	}
}
