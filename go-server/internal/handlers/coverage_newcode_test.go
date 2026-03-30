package handlers

import (
        "html/template"
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"
        "time"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/icae"
        "dnstool/go-server/internal/icuae"

        "github.com/gin-gonic/gin"
)

func TestGetContextValue_Present(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Set("csp_nonce", "abc123")
        got := getContextValue(c, "csp_nonce")
        if got != "abc123" {
                t.Errorf("expected abc123, got %v", got)
        }
}

func TestGetContextValue_Missing(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        got := getContextValue(c, "missing_key")
        if got != "" {
                t.Errorf("expected empty string, got %v", got)
        }
}

func TestIsAgentCacheEligible(t *testing.T) {
        tests := []struct {
                name            string
                method          string
                src             string
                customSelectors []string
                exposureChecks  bool
                want            bool
        }{
                {"GET+agent, no custom, no exposure", http.MethodGet, "agent", nil, false, true},
                {"POST not eligible", http.MethodPost, "agent", nil, false, false},
                {"GET but wrong src", http.MethodGet, "browser", nil, false, false},
                {"GET+agent but custom selectors", http.MethodGet, "agent", []string{"sel1"}, false, false},
                {"GET+agent but exposure checks", http.MethodGet, "agent", nil, true, false},
                {"GET no src", http.MethodGet, "", nil, false, false},
                {"GET+agent, custom+exposure", http.MethodGet, "agent", []string{"s"}, true, false},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        gin.SetMode(gin.TestMode)
                        w := httptest.NewRecorder()
                        c, _ := gin.CreateTestContext(w)
                        req := httptest.NewRequest(tc.method, "/?src="+tc.src, nil)
                        c.Request = req
                        got := isAgentCacheEligible(c, tc.customSelectors, tc.exposureChecks)
                        if got != tc.want {
                                t.Errorf("isAgentCacheEligible() = %v, want %v", got, tc.want)
                        }
                })
        }
}

func TestExtractAnalyzeInput_EmptyDomain(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(""))
        c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        _, ok := extractAnalyzeInput(c)
        if ok {
                t.Error("expected false for empty domain")
        }
}

func TestExtractAnalyzeInput_InvalidDomain(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader("domain=!!!invalid!!!"))
        c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        _, ok := extractAnalyzeInput(c)
        if ok {
                t.Error("expected false for invalid domain")
        }
}

func TestExtractAnalyzeInput_ValidDomain(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader("domain=example.com"))
        c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        inp, ok := extractAnalyzeInput(c)
        if !ok {
                t.Fatal("expected true for valid domain")
        }
        if inp.domain != "example.com" {
                t.Errorf("expected example.com, got %s", inp.domain)
        }
        if inp.asciiDomain == "" {
                t.Error("asciiDomain should not be empty")
        }
}

func TestExtractAnalyzeInput_WithExposureAndDevNull(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        body := "domain=example.com&exposure_checks=1&devnull=1"
        c.Request = httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(body))
        c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        inp, ok := extractAnalyzeInput(c)
        if !ok {
                t.Fatal("expected true")
        }
        if !inp.exposureChecks {
                t.Error("expected exposureChecks=true")
        }
        if !inp.devNull {
                t.Error("expected devNull=true")
        }
        if !inp.ephemeral {
                t.Error("expected ephemeral=true when devNull=true")
        }
}

func TestExtractAnalyzeInput_IDNDomain(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader("domain=münchen.de"))
        c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        inp, ok := extractAnalyzeInput(c)
        if !ok {
                t.Fatal("expected true for IDN domain")
        }
        if inp.asciiDomain == inp.domain {
                t.Log("asciiDomain may differ from domain for IDN input")
        }
}

func TestTryServeFromCache_NotEligible(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodPost, "/analyze", nil)
        h := &AnalysisHandler{}
        inp := analyzeInput{domain: "example.com", asciiDomain: "example.com"}
        got := h.tryServeFromCache(c, inp, "nonce", "csrf")
        if got {
                t.Error("POST should not be cache eligible")
        }
}

func TestTryServeFromCache_EligibleButNoStore(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com&src=agent", nil)
        h := &AnalysisHandler{}
        inp := analyzeInput{domain: "example.com", asciiDomain: "example.com"}
        got := h.tryServeFromCache(c, inp, "nonce", "csrf")
        if got {
                t.Error("no store configured, should return false")
        }
}

func TestFindPEMHeader(t *testing.T) {
        tests := []struct {
                name    string
                tokens  []string
                wantHdr string
                wantIdx int
                wantOk  bool
        }{
                {
                        "standard RSA header",
                        []string{"-----BEGIN", "RSA", "PRIVATE", "KEY-----", "base64data"},
                        "-----BEGIN RSA PRIVATE KEY-----",
                        4, true,
                },
                {
                        "generic cert header",
                        []string{"-----BEGIN", "CERTIFICATE-----", "data"},
                        "-----BEGIN CERTIFICATE-----",
                        2, true,
                },
                {
                        "no header dashes",
                        []string{"not", "a", "pem", "at", "all"},
                        "", 0, false,
                },
                {
                        "empty tokens",
                        []string{},
                        "", 0, false,
                },
                {
                        "single token is header",
                        []string{"-----BEGIN-----"},
                        "-----BEGIN-----",
                        1, true,
                },
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        hdr, idx, ok := findPEMHeader(tc.tokens)
                        if ok != tc.wantOk {
                                t.Errorf("ok = %v, want %v", ok, tc.wantOk)
                        }
                        if hdr != tc.wantHdr {
                                t.Errorf("header = %q, want %q", hdr, tc.wantHdr)
                        }
                        if idx != tc.wantIdx {
                                t.Errorf("nextIdx = %d, want %d", idx, tc.wantIdx)
                        }
                })
        }
}

func TestFindPEMFooter(t *testing.T) {
        tests := []struct {
                name       string
                tokens     []string
                start      int
                wantFooter string
                wantBody   []string
        }{
                {
                        "standard footer",
                        []string{"header", "body1", "body2", "-----END", "CERTIFICATE-----"},
                        1,
                        "-----END CERTIFICATE-----",
                        []string{"body1", "body2"},
                },
                {
                        "no footer dashes treats all as footer",
                        []string{"header", "body1", "body2"},
                        1,
                        "body1 body2",
                        nil,
                },
                {
                        "footer starts immediately",
                        []string{"header", "-----END", "KEY-----"},
                        1,
                        "-----END KEY-----",
                        nil,
                },
                {
                        "single body token before footer",
                        []string{"header", "base64data", "-----END", "RSA", "KEY-----"},
                        1,
                        "-----END RSA KEY-----",
                        []string{"base64data"},
                },
                {
                        "multi token footer span",
                        []string{"hdr", "body", "-----END", "PRIVATE", "KEY-----"},
                        1,
                        "-----END PRIVATE KEY-----",
                        []string{"body"},
                },
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        footer, body := findPEMFooter(tc.tokens, tc.start)
                        if footer != tc.wantFooter {
                                t.Errorf("footer = %q, want %q", footer, tc.wantFooter)
                        }
                        if len(body) != len(tc.wantBody) {
                                t.Errorf("body len = %d, want %d; body = %v", len(body), len(tc.wantBody), body)
                        } else {
                                for i, b := range body {
                                        if b != tc.wantBody[i] {
                                                t.Errorf("body[%d] = %q, want %q", i, b, tc.wantBody[i])
                                        }
                                }
                        }
                })
        }
}

func TestExtractDNSSECStatus(t *testing.T) {
        tests := []struct {
                name    string
                results map[string]any
                want    string
        }{
                {"nil dnssec", map[string]any{}, "unknown"},
                {"signed", map[string]any{"dnssec_analysis": map[string]any{"signed": true}}, "signed"},
                {"unsigned", map[string]any{"dnssec_analysis": map[string]any{"signed": false}}, "unsigned"},
                {"missing key", map[string]any{"other": "data"}, "unknown"},
                {"wrong type", map[string]any{"dnssec_analysis": "not-a-map"}, "unknown"},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        got := extractDNSSECStatus(tc.results)
                        if got != tc.want {
                                t.Errorf("got %q, want %q", got, tc.want)
                        }
                })
        }
}

func TestExtractPosture(t *testing.T) {
        tests := []struct {
                name       string
                results    map[string]any
                wantScore  int
                wantGrade  string
                wantLabel  string
        }{
                {"nil posture", map[string]any{}, 0, "N/A", ""},
                {"missing key", map[string]any{"other": true}, 0, "N/A", ""},
                {"wrong type", map[string]any{"posture": "string"}, 0, "N/A", ""},
                {
                        "full posture",
                        map[string]any{"posture": map[string]any{
                                "score": float64(85),
                                "grade": "A",
                                "label": "Low Risk",
                        }},
                        85, "A", "Low Risk",
                },
                {
                        "zero score",
                        map[string]any{"posture": map[string]any{
                                "score": float64(0),
                                "grade": "F",
                                "label": "Critical",
                        }},
                        0, "F", "Critical",
                },
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        score, grade, label := extractPosture(tc.results)
                        if score != tc.wantScore {
                                t.Errorf("score = %d, want %d", score, tc.wantScore)
                        }
                        if grade != tc.wantGrade {
                                t.Errorf("grade = %q, want %q", grade, tc.wantGrade)
                        }
                        if label != tc.wantLabel {
                                t.Errorf("label = %q, want %q", label, tc.wantLabel)
                        }
                })
        }
}

func TestSafeInternalURL(t *testing.T) {
        tests := []struct {
                name   string
                base   string
                path   string
                params map[string]string
                want   string
        }{
                {
                        "basic URL",
                        "https://example.com",
                        "/analyze",
                        map[string]string{"domain": "test.com"},
                        "https://example.com/analyze?domain=test.com",
                },
                {
                        "invalid base falls back",
                        "://broken",
                        "/search",
                        nil,
                        "/search",
                },
                {
                        "multiple params",
                        "https://dnstool.it-help.tech",
                        "/agent/search",
                        map[string]string{"q": "example.com", "src": "agent"},
                        "",
                },
                {
                        "empty params",
                        "https://example.com",
                        "/",
                        nil,
                        "https://example.com/",
                },
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        got := safeInternalURL(tc.base, tc.path, tc.params)
                        if tc.want != "" && got != tc.want {
                                t.Errorf("got %q, want %q", got, tc.want)
                        }
                        if tc.want == "" {
                                if !strings.Contains(got, tc.path) {
                                        t.Errorf("result %q should contain path %q", got, tc.path)
                                }
                                for k, v := range tc.params {
                                        if !strings.Contains(got, k+"="+v) {
                                                t.Errorf("result %q should contain %s=%s", got, k, v)
                                        }
                                }
                        }
                })
        }
}

func TestExtractPostureRisk_NewCode(t *testing.T) {
        tests := []struct {
                name      string
                results   map[string]any
                wantLabel string
                wantColor string
        }{
                {"nil results", nil, "Unknown", ""},
                {"empty results", map[string]any{}, "Unknown", ""},
                {"no posture key", map[string]any{"other": "x"}, "Unknown", ""},
                {"posture wrong type", map[string]any{"posture": "string"}, "Unknown", ""},
                {
                        "posture with label and color",
                        map[string]any{"posture": map[string]any{
                                "label": "Low Risk",
                                "color": "success",
                        }},
                        "Low Risk", "success",
                },
                {
                        "posture with grade fallback",
                        map[string]any{"posture": map[string]any{
                                "grade": "A+",
                        }},
                        "A+", "",
                },
                {
                        "posture with empty label uses grade",
                        map[string]any{"posture": map[string]any{
                                "label": "",
                                "grade": "B",
                        }},
                        "B", "",
                },
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        label, color := extractPostureRisk(tc.results)
                        if label != tc.wantLabel {
                                t.Errorf("label = %q, want %q", label, tc.wantLabel)
                        }
                        if color != tc.wantColor {
                                t.Errorf("color = %q, want %q", color, tc.wantColor)
                        }
                })
        }
}

func TestExtractPostureScore_NewCode(t *testing.T) {
        tests := []struct {
                name string
                results map[string]any
                want int
        }{
                {"no posture", map[string]any{}, -1},
                {"posture wrong type", map[string]any{"posture": "x"}, -1},
                {"score missing", map[string]any{"posture": map[string]any{}}, -1},
                {"score 85", map[string]any{"posture": map[string]any{"score": float64(85)}}, 85},
                {"score 0", map[string]any{"posture": map[string]any{"score": float64(0)}}, 0},
                {"score negative clamped", map[string]any{"posture": map[string]any{"score": float64(-5)}}, 0},
                {"score over 100 clamped", map[string]any{"posture": map[string]any{"score": float64(150)}}, 100},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        got := extractPostureScore(tc.results)
                        if got != tc.want {
                                t.Errorf("got %d, want %d", got, tc.want)
                        }
                })
        }
}

func TestCovertSummaryLines(t *testing.T) {
        base := covertSummaryParams{
                locked:    "#3fb950",
                dimLocked: "#30363d",
                sRed:      "#f85149",
                alt:       "#9f9f9f",
        }
        tests := []struct {
                name         string
                vulnerable   int
                findingCount int
                tagline      string
                wantContains string
                wantLen      int
        }{
                {"all hardened", 0, 0, "Nice work", "hardened", 2},
                {"hardened but secrets leaking", 0, 3, "", "secrets are leaking", 2},
                {"1 vuln, 0 findings", 1, 0, "Watch out", "attack vector", 2},
                {"1 vuln, 1 finding", 1, 1, "", "attack vector", 2},
                {"5 vulns, 0 findings", 5, 0, "Bad posture", "attack vectors available", 2},
                {"5 vulns, 3 findings", 5, 3, "", "attack vectors available", 2},
                {"3 vulns, 0 findings with tagline", 3, 0, "Needs work", "attack vectors available", 2},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        p := base
                        p.vulnerable = tc.vulnerable
                        p.findingCount = tc.findingCount
                        p.tagline = tc.tagline
                        lines := covertSummaryLines(p)
                        if len(lines) != tc.wantLen {
                                t.Errorf("got %d lines, want %d", len(lines), tc.wantLen)
                        }
                        found := false
                        for _, l := range lines {
                                if strings.Contains(l.text, tc.wantContains) {
                                        found = true
                                        break
                                }
                        }
                        if !found {
                                var texts []string
                                for _, l := range lines {
                                        texts = append(texts, l.text)
                                }
                                t.Errorf("no line contains %q; got %v", tc.wantContains, texts)
                        }
                })
        }
}

func TestBadgeSVGCovert_Produces_SVG(t *testing.T) {
        results := map[string]any{
                "posture": map[string]any{
                        "score": float64(72),
                        "grade": "C",
                        "label": "Medium Risk",
                        "color": "warning",
                },
                "risk_level": "warning",
        }
        svg := badgeSVGCovert("example.com", results, time.Now(), 1, "abc123", "https://dnstool.it-help.tech")
        if len(svg) == 0 {
                t.Fatal("expected non-empty SVG output")
        }
        s := string(svg)
        if !strings.Contains(s, "<svg") {
                t.Error("output should contain <svg tag")
        }
        if !strings.Contains(s, "example.com") {
                t.Error("output should contain domain name")
        }
}

func TestBadgeSVGCovert_NilResults(t *testing.T) {
        svg := badgeSVGCovert("test.com", map[string]any{}, time.Now(), 0, "", "https://example.com")
        if len(svg) == 0 {
                t.Fatal("expected non-empty SVG even for empty results")
        }
        if !strings.Contains(string(svg), "<svg") {
                t.Error("output should contain <svg tag")
        }
}

func TestBadgeSVGCovert_LongDomain(t *testing.T) {
        longDomain := "a-very-long-subdomain-name-that-exceeds-thirty-five-chars.example.com"
        results := map[string]any{
                "posture": map[string]any{
                        "score": float64(50),
                        "grade": "D",
                        "label": "High Risk",
                        "color": "danger",
                },
        }
        svg := badgeSVGCovert(longDomain, results, time.Now(), 42, "hash", "https://dnstool.it-help.tech")
        if len(svg) == 0 {
                t.Fatal("expected non-empty SVG")
        }
        s := string(svg)
        if !strings.Contains(s, "...") {
                t.Error("long domain should be truncated with ellipsis")
        }
        truncated := longDomain[:32] + "..."
        if !strings.Contains(s, truncated) {
                t.Errorf("expected truncated domain %q in SVG", truncated)
        }
}

func TestExtractAnalyzeInput_QueryStringFallback(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.org&src=agent", nil)
        inp, ok := extractAnalyzeInput(c)
        if !ok {
                t.Fatal("expected true for GET with query param")
        }
        if inp.domain != "example.org" {
                t.Errorf("expected example.org, got %s", inp.domain)
        }
}

func TestExtractAnalyzeInput_IDNConversion(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader("domain=münchen.de"))
        c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        inp, ok := extractAnalyzeInput(c)
        if !ok {
                t.Fatal("expected true for IDN domain")
        }
        if !strings.HasPrefix(inp.asciiDomain, "xn--") {
                t.Errorf("expected punycode asciiDomain starting with xn--, got %q", inp.asciiDomain)
        }
}

func TestTryServeFromCache_CustomSelectorsNotEligible(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com&src=agent", nil)
        h := &AnalysisHandler{}
        inp := analyzeInput{
                domain:      "example.com",
                asciiDomain: "example.com",
                customSelectors: []string{"custom1"},
        }
        got := h.tryServeFromCache(c, inp, "nonce", "csrf")
        if got {
                t.Error("custom selectors should prevent cache eligibility")
        }
}

func TestTryServeFromCache_ExposureChecksNotEligible(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com&src=agent", nil)
        h := &AnalysisHandler{}
        inp := analyzeInput{
                domain:         "example.com",
                asciiDomain:    "example.com",
                exposureChecks: true,
        }
        got := h.tryServeFromCache(c, inp, "nonce", "csrf")
        if got {
                t.Error("exposure checks should prevent cache eligibility")
        }
}

func TestCovertSummaryLines_SingleVector_NoTagline(t *testing.T) {
        p := covertSummaryParams{
                vulnerable:   1,
                findingCount: 0,
                tagline:      "",
                locked:       "#3fb950",
                dimLocked:    "#30363d",
                sRed:         "#f85149",
                alt:          "#9f9f9f",
        }
        lines := covertSummaryLines(p)
        if len(lines) != 1 {
                t.Errorf("expected 1 line for single vector without tagline, got %d", len(lines))
        }
        if len(lines) > 0 && !strings.Contains(lines[0].text, "attack vector") {
                t.Errorf("expected attack vector text, got %q", lines[0].text)
        }
}

func setupTestRouter(h *AnalysisHandler) *gin.Engine {
        gin.SetMode(gin.TestMode)
        r := gin.New()
        tmpl := template.Must(template.New("index.html").Parse(`{{range .FlashMessages}}{{.Message}}{{end}}`))
        tmpl = template.Must(tmpl.New("analyze.html").Parse(`{{.Domain}}`))
        tmpl = template.Must(tmpl.New("analyze_covert.html").Parse(`{{.Domain}}`))
        r.SetHTMLTemplate(tmpl)
        r.POST("/analyze", h.Analyze)
        r.GET("/analyze", h.Analyze)
        return r
}

func TestAnalyze_EmptyDomain(t *testing.T) {
        cfg := &config.Config{
                AppVersion: "26.40.19",
                BaseURL:    "https://dnstool.it-help.tech",
        }
        h := &AnalysisHandler{Config: cfg}
        r := setupTestRouter(h)

        req := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain="))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        w := httptest.NewRecorder()
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("status = %d, want 200", w.Code)
        }
        if !strings.Contains(w.Body.String(), "Please enter a domain name") {
                t.Error("expected 'Please enter a domain name' flash message")
        }
}

func newTestAnalysisHandler() *AnalysisHandler {
        cfg := &config.Config{
                AppVersion: "26.40.19",
                BaseURL:    "https://dnstool.it-help.tech",
        }
        a := analyzer.New(analyzer.WithMaxConcurrent(1), analyzer.WithInitialIANAFetch(false))
        return &AnalysisHandler{
                Config:        cfg,
                Analyzer:      a,
                Calibration:   icae.NewCalibrationEngine(),
                DimCharts:     icuae.NewDimensionCharts(),
                ProgressStore: NewProgressStore(),
        }
}

func TestAnalyze_WantsJSON(t *testing.T) {
        h := newTestAnalysisHandler()
        defer h.ProgressStore.Close()

        r := setupTestRouter(h)

        req := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain=example.com"))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req.Header.Set("Accept", "application/json")
        w := httptest.NewRecorder()
        r.ServeHTTP(w, req)
        if w.Code != http.StatusAccepted {
                t.Errorf("status = %d, want 202", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "token") {
                t.Error("expected token in JSON response")
        }
        if !strings.Contains(body, "example.com") {
                t.Error("expected domain in JSON response")
        }
        time.Sleep(50 * time.Millisecond)
}

func TestAnalyze_FailedAnalysis(t *testing.T) {
        h := newTestAnalysisHandler()
        defer h.ProgressStore.Close()

        r := setupTestRouter(h)

        req := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain=test.invalid"))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        w := httptest.NewRecorder()
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("status = %d, want 200", w.Code)
        }
}


func TestAnalyze_InvalidDomain(t *testing.T) {
        cfg := &config.Config{
                AppVersion: "26.40.19",
                BaseURL:    "https://dnstool.it-help.tech",
        }
        h := &AnalysisHandler{Config: cfg}
        r := setupTestRouter(h)

        req := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain=not+a+valid+domain!!!"))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        w := httptest.NewRecorder()
        r.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("status = %d, want 200", w.Code)
        }
        if !strings.Contains(w.Body.String(), "Invalid domain name") {
                t.Error("expected 'Invalid domain name' flash message")
        }
}

func TestNormalizePEM_NoPEMHeader(t *testing.T) {
        got := normalizePEM("this is just some random text without pem markers")
        if got != "this is just some random text without pem markers" {
                t.Errorf("expected passthrough, got %q", got)
        }
}

func TestFindPEMFooter_NoFooterTokens(t *testing.T) {
        tokens := []string{"bodydata"}
        footer, body := findPEMFooter(tokens, 0)
        if footer != "bodydata" {
                t.Errorf("footer = %q", footer)
        }
        _ = body
}

func TestFindPEMFooter_EmptyBody(t *testing.T) {
        footer, body := findPEMFooter([]string{}, 0)
        if footer != "" {
                t.Errorf("expected empty footer, got %q", footer)
        }
        if len(body) != 0 {
                t.Errorf("expected empty body, got %v", body)
        }
}

func TestSafeInternalURL_ParamEscaping(t *testing.T) {
        got := safeInternalURL("https://example.com", "/search", map[string]string{
                "q": "hello world&foo=bar",
        })
        if strings.Contains(got, " ") {
                t.Error("URL should not contain spaces")
        }
        if !strings.Contains(got, "hello+world") && !strings.Contains(got, "hello%20world") {
                t.Error("spaces should be URL-encoded")
        }
}
