// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

func setupAgentRouter() (*gin.Engine, *AgentHandler) {
        gin.SetMode(gin.TestMode)
        r := gin.New()
        cfg := &config.Config{
                AppVersion: "26.38.39",
                BaseURL:    "https://dnstool.it-help.tech",
        }
        h := NewAgentHandler(cfg, nil)
        return r, h
}

func TestOpenSearchXML(t *testing.T) {
        r, h := setupAgentRouter()
        r.GET("/agent/opensearch.xml", h.OpenSearchXML)

        req := httptest.NewRequest(http.MethodGet, "/agent/opensearch.xml", nil)
        w := httptest.NewRecorder()
        r.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
        ct := w.Header().Get("Content-Type")
        if !strings.Contains(ct, "opensearchdescription+xml") {
                t.Fatalf("expected opensearch content type, got %s", ct)
        }
        body := w.Body.String()
        if !strings.Contains(body, "DNS Tool") {
                t.Fatal("missing DNS Tool in OpenSearch XML")
        }
        if !strings.Contains(body, "{searchTerms}") {
                t.Fatal("missing {searchTerms} placeholder")
        }
        if !strings.Contains(body, "dnstool.it-help.tech") {
                t.Fatal("missing base URL in OpenSearch XML")
        }
}

func TestAgentSearchMissingQuery(t *testing.T) {
        r, h := setupAgentRouter()
        r.GET("/agent/search", h.AgentSearch)

        req := httptest.NewRequest(http.MethodGet, "/agent/search", nil)
        w := httptest.NewRecorder()
        r.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200 help page, got %d", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "Agent Search") {
                t.Fatal("expected help page with Agent Search heading")
        }
        if !strings.Contains(body, "/agent/search?q=") {
                t.Fatal("expected example links on help page")
        }
}

func TestCleanAgentQuery(t *testing.T) {
        tests := []struct {
                input, expect string
        }{
                {`_"it-help.tech"_`, "it-help.tech"},
                {`_"apple.com"_`, "apple.com"},
                {`_Test_`, "test"},
                {"example.com", "example.com"},
                {"  EXAMPLE.COM  ", "example.com"},
                {`"example.com"`, "example.com"},
                {`'example.com'`, "example.com"},
                {"__example.com__", "example.com"},
                {`_"_test_"_`, "test"},
        }
        for _, tt := range tests {
                got := cleanAgentQuery(tt.input)
                if got != tt.expect {
                        t.Errorf("cleanAgentQuery(%q) = %q, want %q", tt.input, got, tt.expect)
                }
        }
}

func TestAgentSearchInvalidDomain(t *testing.T) {
        r, h := setupAgentRouter()
        r.GET("/agent/search", h.AgentSearch)

        req := httptest.NewRequest(http.MethodGet, "/agent/search?q=not-a-valid-domain!!!", nil)
        w := httptest.NewRecorder()
        r.ServeHTTP(w, req)

        if w.Code != http.StatusBadRequest {
                t.Fatalf("expected 400, got %d", w.Code)
        }
        if !strings.Contains(w.Body.String(), "Invalid domain") {
                t.Fatal("expected invalid domain error message")
        }
}

func TestAgentAPIMissingQuery(t *testing.T) {
        r, h := setupAgentRouter()
        r.GET("/agent/api", h.AgentAPI)

        req := httptest.NewRequest(http.MethodGet, "/agent/api", nil)
        w := httptest.NewRecorder()
        r.ServeHTTP(w, req)

        if w.Code != http.StatusBadRequest {
                t.Fatalf("expected 400, got %d", w.Code)
        }
        if !strings.Contains(w.Body.String(), "Missing query parameter") {
                t.Fatal("expected missing query error message")
        }
}

func TestAgentAPIInvalidDomain(t *testing.T) {
        r, h := setupAgentRouter()
        r.GET("/agent/api", h.AgentAPI)

        req := httptest.NewRequest(http.MethodGet, "/agent/api?q=not-a-valid-domain!!!", nil)
        w := httptest.NewRecorder()
        r.ServeHTTP(w, req)

        if w.Code != http.StatusBadRequest {
                t.Fatalf("expected 400, got %d", w.Code)
        }
        if !strings.Contains(w.Body.String(), "Invalid domain") {
                t.Fatal("expected invalid domain error message")
        }
}

func TestBoolToPresence(t *testing.T) {
        if boolToPresence(true) != "present" {
                t.Fatal("expected 'present' for true")
        }
        if boolToPresence(false) != "not found" {
                t.Fatal("expected 'not found' for false")
        }
}

func TestExtractNestedStatus(t *testing.T) {
        parent := gin.H{
                "spf": gin.H{"status": "pass"},
                "bad": "not a map",
        }
        if extractNestedStatus(parent, "spf") != "pass" {
                t.Fatal("expected 'pass'")
        }
        if extractNestedStatus(parent, "bad") != "unknown" {
                t.Fatal("expected 'unknown' for non-map")
        }
        if extractNestedStatus(parent, "missing") != "unknown" {
                t.Fatal("expected 'unknown' for missing key")
        }
}

func TestAgentSearchXSSEscaping(t *testing.T) {
        r, h := setupAgentRouter()
        r.GET("/agent/search", h.AgentSearch)

        req := httptest.NewRequest(http.MethodGet, `/agent/search?q=%3Cscript%3Ealert(1)%3C/script%3E`, nil)
        w := httptest.NewRecorder()
        r.ServeHTTP(w, req)

        body := w.Body.String()
        if strings.Contains(body, "<script>") {
                t.Fatal("XSS: raw <script> tag found in HTML response")
        }
        if !strings.Contains(body, "&lt;script&gt;") {
                t.Fatal("expected HTML-escaped script tag in response")
        }
}

func TestEscHelper(t *testing.T) {
        if esc("<b>test</b>") != "&lt;b&gt;test&lt;/b&gt;" {
                t.Fatal("esc did not escape HTML")
        }
        if esc(`"quoted"`) != "&#34;quoted&#34;" {
                t.Fatal("esc did not escape quotes")
        }
        if esc("normal") != "normal" {
                t.Fatal("esc should not change safe strings")
        }
}

func TestSafeFloat64(t *testing.T) {
        m := map[string]any{
                "f64":   float64(3.14),
                "int":   42,
                "int64": int64(99),
                "str":   "nope",
        }
        if safeFloat64(m, "f64") != 3.14 {
                t.Fatal("safeFloat64 failed for float64")
        }
        if safeFloat64(m, "int") != 42.0 {
                t.Fatal("safeFloat64 failed for int")
        }
        if safeFloat64(m, "int64") != 99.0 {
                t.Fatal("safeFloat64 failed for int64")
        }
        if safeFloat64(m, "str") != 0 {
                t.Fatal("safeFloat64 should return 0 for non-numeric")
        }
        if safeFloat64(m, "missing") != 0 {
                t.Fatal("safeFloat64 missing should return 0")
        }
}

func TestBuildAgentJSONEnrichedLinks(t *testing.T) {
        _, h := setupAgentRouter()
        results := map[string]any{
                "domain_exists": true,
                "risk_level":    "low",
                "posture":       map[string]any{"score": float64(85), "grade": "B+", "label": "Good"},
        }
        j := h.buildAgentJSON("example.com", results)

        links, ok := j["links"].(gin.H)
        if !ok {
                t.Fatal("missing links section")
        }
        checks := map[string]string{
                "report":          "https://dnstool.it-help.tech/analyze?domain=example.com",
                "snapshot":        "https://dnstool.it-help.tech/snapshot/example.com",
                "topology":       "https://dnstool.it-help.tech/topology?domain=example.com",
                "wayback_archive": "https://dnstool.it-help.tech/agent/wayback?domain=example.com",
                "wayback_page":    "https://dnstool.it-help.tech/agent/wayback?domain=example.com",
                "report_page":     "https://dnstool.it-help.tech/analyze?domain=example.com&src=agent",
                "api_json":        "https://dnstool.it-help.tech/agent/api?q=example.com",
        }
        for key, want := range checks {
                got, ok := links[key].(string)
                if !ok || got != want {
                        t.Errorf("links[%q] = %q, want %q", key, got, want)
                }
        }

        badges, ok := j["badges"].(gin.H)
        if !ok {
                t.Fatal("missing badges section")
        }
        badgeChecks := map[string]string{
                "detailed_svg": "https://dnstool.it-help.tech/badge?domain=example.com&style=detailed",
                "covert_svg":   "https://dnstool.it-help.tech/badge?domain=example.com&style=covert",
                "flat_svg":     "https://dnstool.it-help.tech/badge?domain=example.com",
        }
        for key, want := range badgeChecks {
                got, ok := badges[key].(string)
                if !ok || got != want {
                        t.Errorf("badges[%q] = %q, want %q", key, got, want)
                }
        }

        summary, ok := j["summary"].(gin.H)
        if !ok {
                t.Fatal("missing summary")
        }
        if summary["posture_score"] != 85 {
                t.Errorf("posture_score = %v, want 85", summary["posture_score"])
        }
        if summary["posture_grade"] != "B+" {
                t.Errorf("posture_grade = %v, want B+", summary["posture_grade"])
        }
}

func TestBuildAgentHTMLZoteroMetadata(t *testing.T) {
        _, h := setupAgentRouter()
        results := map[string]any{
                "domain_exists": true,
                "risk_level":    "low",
                "posture":       map[string]any{"score": float64(72), "grade": "C+", "label": "Fair"},
                "spf_analysis":  map[string]any{"status": "success"},
                "dmarc_analysis": map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":  map[string]any{"status": "success"},
        }
        html := h.buildAgentHTML("example.com", results, 0)

        zoteroChecks := []string{
                `name="DC.title"`,
                `name="DC.creator"`,
                `name="DC.publisher"`,
                `name="DC.date"`,
                `name="DC.type" content="Dataset"`,
                `name="citation_title"`,
                `name="citation_author"`,
                `name="citation_doi" content="10.5281/zenodo.18854899"`,
                `class="Z3988"`,
                `ctx_ver=Z39.88-2004`,
                `property="og:title"`,
                `property="og:image"`,
        }
        for _, check := range zoteroChecks {
                if !strings.Contains(html, check) {
                        t.Errorf("missing Zotero/citation metadata: %q", check)
                }
        }

        assetChecks := []string{
                "/snapshot/example.com",
                "/topology?domain=example.com",
                "/analyze?domain=example.com",
                "style=detailed",
                "style=covert",
                "Observed Records Snapshot",
                "DNS Topology",
                "/agent/badge-view?domain=example.com",
                "/agent/api?q=example.com",
                "Full Intelligence Data (JSON)",
                "/export/subdomains?domain=example.com",
                "Discovered Domains",
                "/sources",
                "Sources &amp; Methodology",
                "Engineer's DNS Intelligence Report",
                "https://doi.org/10.5281/zenodo.18854899",
                "Zenodo",
                "Covert Security Badge",
                "Detailed Security Badge",
                "Covert Recon Report",
                "Executive Intelligence Brief",
                "SHA-3 Integrity Checksum",
                "Security Remediation Plan",
        }
        for _, check := range assetChecks {
                if !strings.Contains(html, check) {
                        t.Errorf("missing enrichment in HTML: %q", check)
                }
        }
}

func TestBuildAgentHTMLWithAnalysisID(t *testing.T) {
        _, h := setupAgentRouter()
        results := map[string]any{
                "domain_exists": true,
                "risk_level":    "high",
                "posture":       map[string]any{"score": float64(35), "grade": "F", "label": "Poor"},
                "spf_analysis":  map[string]any{"status": "fail"},
                "dmarc_analysis": map[string]any{"status": "fail", "policy": "none"},
                "dkim_analysis":  map[string]any{"status": "fail"},
        }
        html := h.buildAgentHTML("example.com", results, 42)

        idChecks := []string{
                "/analysis/42/view/C",
                "Covert Recon Report",
                "/analysis/42/executive",
                "Executive Intelligence Brief",
                "/api/analysis/42/checksum",
                "SHA-3 Integrity Checksum",
                "/remediation?analysis_id=42",
                "Security Remediation Plan",
        }
        for _, check := range idChecks {
                if !strings.Contains(html, check) {
                        t.Errorf("missing analysis-ID-dependent link: %q", check)
                }
        }
}

func TestBuildAgentHTMLAlways15Results(t *testing.T) {
        _, h := setupAgentRouter()
        results := map[string]any{
                "domain_exists":  true,
                "risk_level":     "low",
                "posture":        map[string]any{"score": float64(72), "grade": "C+", "label": "Fair"},
                "spf_analysis":   map[string]any{"status": "success"},
                "dmarc_analysis": map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":  map[string]any{"status": "success"},
        }
        for _, id := range []int32{0, 42} {
                html := h.buildAgentHTML("example.com", results, id)
                count := strings.Count(html, "<li>")
                if count != 15 {
                        t.Errorf("analysisID=%d: expected 15 <li> items, got %d", id, count)
                }
                if !strings.Contains(html, "<ol>") {
                        t.Errorf("analysisID=%d: expected ordered list <ol>", id)
                }
                if !strings.Contains(html, "Internet Archive") {
                        t.Errorf("analysisID=%d: missing Internet Archive (Wayback Machine) result", id)
                }
                if !strings.Contains(html, "Confidence Page") {
                        t.Errorf("analysisID=%d: missing Confidence Page result", id)
                }
        }
}

func TestBuildAgentHTMLFallbackURLs(t *testing.T) {
        _, h := setupAgentRouter()
        results := map[string]any{
                "domain_exists":  true,
                "risk_level":     "low",
                "posture":        map[string]any{"score": float64(72), "grade": "C+", "label": "Fair"},
                "spf_analysis":   map[string]any{"status": "success"},
                "dmarc_analysis": map[string]any{"status": "success", "policy": "reject"},
                "dkim_analysis":  map[string]any{"status": "success"},
        }
        html := h.buildAgentHTML("example.com", results, 0)
        fallbacks := []string{
                "/remediation?domain=example.com",
                "/analyze?domain=example.com",
        }
        for _, fb := range fallbacks {
                if !strings.Contains(html, fb) {
                        t.Errorf("missing fallback URL: %q", fb)
                }
        }
}

func TestSafeHelpers(t *testing.T) {
        m := map[string]any{
                "str":     "hello",
                "int":     42,
                "int64":   int64(99),
                "float":   3.14,
                "bool":    true,
                "nested":  map[string]any{"key": "val"},
                "invalid": []string{"a"},
        }
        if safeString(m, "str") != "hello" {
                t.Fatal("safeString failed")
        }
        if safeString(m, "missing") != "" {
                t.Fatal("safeString missing should return empty")
        }
        if safeInt(m, "int") != 42 {
                t.Fatal("safeInt failed for int")
        }
        if safeInt(m, "int64") != 99 {
                t.Fatal("safeInt failed for int64")
        }
        if safeInt(m, "float") != 3 {
                t.Fatal("safeInt failed for float64")
        }
        if safeInt(m, "missing") != 0 {
                t.Fatal("safeInt missing should return 0")
        }
        if !safeBool(m, "bool") {
                t.Fatal("safeBool failed")
        }
        if safeBool(m, "missing") {
                t.Fatal("safeBool missing should return false")
        }
        nested := safeMap(m, "nested")
        if nested == nil || nested["key"] != "val" {
                t.Fatal("safeMap failed")
        }
        if safeMap(m, "invalid") != nil {
                t.Fatal("safeMap should return nil for non-map")
        }
}

func TestBadgeViewHandler(t *testing.T) {
        router, h := setupAgentRouter()
        router.GET("/agent/badge-view", h.BadgeView)

        tests := []struct {
                name   string
                url    string
                status int
                checks []string
        }{
                {"missing domain", "/agent/badge-view", http.StatusBadRequest, nil},
                {"invalid domain", "/agent/badge-view?domain=not_valid!", http.StatusBadRequest, nil},
                {"detailed default", "/agent/badge-view?domain=example.com", http.StatusOK, []string{
                        "<title>DNS Security Badge (detailed)",
                        "example.com",
                        "/badge?domain=example.com&amp;style=detailed",
                        "/analyze?domain=example.com",
                }},
                {"covert style", "/agent/badge-view?domain=example.com&style=covert", http.StatusOK, []string{
                        "<title>DNS Security Badge (covert)",
                        "/badge?domain=example.com&amp;style=covert",
                }},
                {"flat style", "/agent/badge-view?domain=example.com&style=flat", http.StatusOK, []string{
                        "<title>DNS Security Badge (flat)",
                        "/badge?domain=example.com",
                }},
                {"q param", "/agent/badge-view?q=example.com", http.StatusOK, []string{
                        "example.com",
                }},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        w := httptest.NewRecorder()
                        req := httptest.NewRequest(http.MethodGet, tt.url, nil)
                        router.ServeHTTP(w, req)
                        if w.Code != tt.status {
                                t.Fatalf("status = %d, want %d; body: %s", w.Code, tt.status, w.Body.String())
                        }
                        body := w.Body.String()
                        for _, check := range tt.checks {
                                if !strings.Contains(body, check) {
                                        t.Errorf("response missing %q", check)
                                }
                        }
                })
        }
}

func TestBuildAgentJSONBadgePages(t *testing.T) {
        _, h := setupAgentRouter()
        results := map[string]any{
                "domain_exists": true,
                "risk_level":    "low",
                "posture":       map[string]any{"score": float64(85), "grade": "B+", "label": "Good"},
        }
        j := h.buildAgentJSON("example.com", results)

        badges, ok := j["badges"].(gin.H)
        if !ok {
                t.Fatal("missing badges section")
        }
        pageChecks := map[string]string{
                "detailed_page": "https://dnstool.it-help.tech/agent/badge-view?domain=example.com&style=detailed",
                "covert_page":   "https://dnstool.it-help.tech/agent/badge-view?domain=example.com&style=covert",
                "flat_page":     "https://dnstool.it-help.tech/agent/badge-view?domain=example.com&style=flat",
        }
        for key, want := range pageChecks {
                got, ok := badges[key].(string)
                if !ok || got != want {
                        t.Errorf("badges[%q] = %q, want %q", key, got, want)
                }
        }
}

func TestBuildAgentJSON_EmailAuthStatusMapping(t *testing.T) {
        _, h := setupAgentRouter()

        tests := []struct {
                name     string
                results  map[string]any
                wantSPF  string
                wantDMARC string
                wantDKIM string
                wantPolicy string
        }{
                {
                        name: "analyzer status fields present",
                        results: map[string]any{
                                "domain_exists":  true,
                                "risk_level":     "low",
                                "posture":        map[string]any{"score": float64(90), "grade": "A", "label": "Low Risk"},
                                "spf_analysis":   map[string]any{"status": "success"},
                                "dmarc_analysis": map[string]any{"status": "success", "policy": "reject"},
                                "dkim_analysis":  map[string]any{"status": "warning"},
                        },
                        wantSPF:    "success",
                        wantDMARC:  "success",
                        wantDKIM:   "warning",
                        wantPolicy: "reject",
                },
                {
                        name: "analyzer status missing means missing",
                        results: map[string]any{
                                "domain_exists":  true,
                                "risk_level":     "high",
                                "posture":        map[string]any{"score": float64(30), "grade": "F", "label": "Critical"},
                                "spf_analysis":   map[string]any{"status": "missing"},
                                "dmarc_analysis": map[string]any{"status": "missing"},
                                "dkim_analysis":  map[string]any{"status": "missing"},
                        },
                        wantSPF:    "missing",
                        wantDMARC:  "missing",
                        wantDKIM:   "missing",
                        wantPolicy: "none",
                },
                {
                        name: "no analysis sections",
                        results: map[string]any{
                                "domain_exists": true,
                                "risk_level":    "unknown",
                                "posture":       map[string]any{"score": float64(0), "grade": "?", "label": "Unknown"},
                        },
                        wantSPF:    "not found",
                        wantDMARC:  "not found",
                        wantDKIM:   "not found",
                        wantPolicy: "none",
                },
                {
                        name: "backward compat with verdict key",
                        results: map[string]any{
                                "domain_exists":  true,
                                "risk_level":     "low",
                                "posture":        map[string]any{"score": float64(80), "grade": "B", "label": "Good"},
                                "spf_analysis":   map[string]any{"verdict": "pass"},
                                "dmarc_analysis": map[string]any{"verdict": "present", "policy": "quarantine"},
                                "dkim_analysis":  map[string]any{"verdict": "present"},
                        },
                        wantSPF:    "pass",
                        wantDMARC:  "present",
                        wantDKIM:   "present",
                        wantPolicy: "quarantine",
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        j := h.buildAgentJSON("example.com", tt.results)
                        ea, ok := j["email_authentication"].(gin.H)
                        if !ok {
                                t.Fatal("missing email_authentication")
                        }
                        spf, _ := ea["spf"].(gin.H)
                        dmarc, _ := ea["dmarc"].(gin.H)
                        dkim, _ := ea["dkim"].(gin.H)

                        if got := spf["status"]; got != tt.wantSPF {
                                t.Errorf("SPF status = %v, want %v", got, tt.wantSPF)
                        }
                        if got := dmarc["status"]; got != tt.wantDMARC {
                                t.Errorf("DMARC status = %v, want %v", got, tt.wantDMARC)
                        }
                        if got := dkim["status"]; got != tt.wantDKIM {
                                t.Errorf("DKIM status = %v, want %v", got, tt.wantDKIM)
                        }
                        if got := dmarc["policy"]; got != tt.wantPolicy {
                                t.Errorf("DMARC policy = %v, want %v", got, tt.wantPolicy)
                        }
                })
        }
}

func TestReportViewHandler(t *testing.T) {
        router, h := setupAgentRouter()
        router.GET("/agent/report", h.ReportView)

        tests := []struct {
                name     string
                url      string
                status   int
                location string
        }{
                {"missing domain", "/agent/report", http.StatusBadRequest, ""},
                {"invalid domain", "/agent/report?domain=not_valid!", http.StatusBadRequest, ""},
                {"valid domain redirects", "/agent/report?domain=example.com", http.StatusMovedPermanently, "/analyze?domain=example.com"},
                {"q param redirects", "/agent/report?q=example.com", http.StatusMovedPermanently, "/analyze?domain=example.com"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        w := httptest.NewRecorder()
                        req := httptest.NewRequest(http.MethodGet, tt.url, nil)
                        router.ServeHTTP(w, req)
                        if w.Code != tt.status {
                                t.Fatalf("status = %d, want %d; body: %s", w.Code, tt.status, w.Body.String())
                        }
                        if tt.location != "" {
                                got := w.Header().Get("Location")
                                if got != tt.location {
                                        t.Errorf("Location = %q, want %q", got, tt.location)
                                }
                        }
                })
        }
}

func TestWaybackViewHandler(t *testing.T) {
        router, h := setupAgentRouter()
        router.GET("/agent/wayback", h.WaybackView)

        tests := []struct {
                name   string
                url    string
                status int
                checks []string
        }{
                {"missing domain", "/agent/wayback", http.StatusBadRequest, nil},
                {"invalid domain", "/agent/wayback?domain=not_valid!", http.StatusBadRequest, nil},
                {"valid domain", "/agent/wayback?domain=example.com", http.StatusFound, []string{
                        "/analyze?domain=example.com",
                }},
                {"q param", "/agent/wayback?q=example.com", http.StatusFound, []string{
                        "/analyze?domain=example.com",
                }},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        w := httptest.NewRecorder()
                        req := httptest.NewRequest(http.MethodGet, tt.url, nil)
                        router.ServeHTTP(w, req)
                        if w.Code != tt.status {
                                t.Fatalf("status = %d, want %d; body: %s", w.Code, tt.status, w.Body.String())
                        }
                        body := w.Body.String()
                        for _, check := range tt.checks {
                                if !strings.Contains(body, check) {
                                        t.Errorf("response missing %q", check)
                                }
                        }
                })
        }
}
