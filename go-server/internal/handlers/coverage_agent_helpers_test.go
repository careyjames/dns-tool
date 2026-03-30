package handlers

import (
        "strings"
        "testing"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

func TestExtractVerdict(t *testing.T) {
        tests := []struct {
                name     string
                m        map[string]any
                fallback string
                want     string
        }{
                {"nil map", nil, "missing", agentErrNotFound},
                {"status present", map[string]any{"status": "pass"}, "missing", "pass"},
                {"verdict fallback", map[string]any{"verdict": "fail"}, "missing", "fail"},
                {"status preferred over verdict", map[string]any{"status": "pass", "verdict": "fail"}, "missing", "pass"},
                {"empty both uses fallback", map[string]any{"other": "x"}, "missing", "missing"},
                {"empty status uses verdict", map[string]any{"status": "", "verdict": "warn"}, "missing", "warn"},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        got := extractVerdict(tc.m, tc.fallback)
                        if got != tc.want {
                                t.Errorf("got %q, want %q", got, tc.want)
                        }
                })
        }
}

func TestExtractSummaryData(t *testing.T) {
        t.Run("no summary key", func(t *testing.T) {
                d := agentHTMLData{}
                extractSummaryData(&d, gin.H{})
                if d.riskLevel != "" {
                        t.Error("expected empty riskLevel for no summary")
                }
        })

        t.Run("wrong type", func(t *testing.T) {
                d := agentHTMLData{}
                extractSummaryData(&d, gin.H{"summary": "not-a-map"})
                if d.riskLevel != "" {
                        t.Error("expected empty riskLevel for wrong type")
                }
        })

        t.Run("full summary", func(t *testing.T) {
                d := agentHTMLData{}
                extractSummaryData(&d, gin.H{
                        "summary": gin.H{
                                "risk_level":    "warning",
                                "posture_score": 75,
                                "posture_grade": "B",
                                "posture_label": "Medium Risk",
                        },
                })
                if d.riskLevel != "warning" {
                        t.Errorf("riskLevel = %q, want warning", d.riskLevel)
                }
                if d.postureScore != 75 {
                        t.Errorf("postureScore = %d, want 75", d.postureScore)
                }
                if d.postureGrade != "B" {
                        t.Errorf("postureGrade = %q, want B", d.postureGrade)
                }
                if d.postureLabel != "Medium Risk" {
                        t.Errorf("postureLabel = %q, want Medium Risk", d.postureLabel)
                }
        })

        t.Run("empty risk_level preserves default", func(t *testing.T) {
                d := agentHTMLData{riskLevel: "existing"}
                extractSummaryData(&d, gin.H{"summary": gin.H{"risk_level": ""}})
                if d.riskLevel != "existing" {
                        t.Errorf("riskLevel = %q, want existing", d.riskLevel)
                }
        })
}

func TestExtractEmailAuthData(t *testing.T) {
        t.Run("no email_authentication key", func(t *testing.T) {
                d := agentHTMLData{}
                extractEmailAuthData(&d, gin.H{})
                if d.spfStatus != "" {
                        t.Error("expected empty spfStatus")
                }
        })

        t.Run("wrong type", func(t *testing.T) {
                d := agentHTMLData{}
                extractEmailAuthData(&d, gin.H{"email_authentication": "bad"})
                if d.spfStatus != "" {
                        t.Error("expected empty spfStatus")
                }
        })

        t.Run("full email auth", func(t *testing.T) {
                d := agentHTMLData{}
                extractEmailAuthData(&d, gin.H{
                        "email_authentication": gin.H{
                                "spf":   gin.H{"status": "pass"},
                                "dkim":  gin.H{"status": "not detected"},
                                "dmarc": gin.H{"status": "pass", "policy": "reject"},
                                "bimi":  gin.H{"present": true},
                        },
                })
                if d.spfStatus != "pass" {
                        t.Errorf("spfStatus = %q, want pass", d.spfStatus)
                }
                if d.dkimStatus != "not detected" {
                        t.Errorf("dkimStatus = %q, want not detected", d.dkimStatus)
                }
                if d.dmarcStatus != "pass" {
                        t.Errorf("dmarcStatus = %q, want pass", d.dmarcStatus)
                }
                if d.dmarcPolicy != "reject" {
                        t.Errorf("dmarcPolicy = %q, want reject", d.dmarcPolicy)
                }
                if !d.bimiPresent {
                        t.Error("expected bimiPresent=true")
                }
        })

        t.Run("dmarc without policy", func(t *testing.T) {
                d := agentHTMLData{dmarcPolicy: "none"}
                extractEmailAuthData(&d, gin.H{
                        "email_authentication": gin.H{
                                "dmarc": gin.H{"status": "pass"},
                        },
                })
                if d.dmarcPolicy != "none" {
                        t.Errorf("dmarcPolicy should remain none, got %q", d.dmarcPolicy)
                }
        })
}

func TestExtractTransportData(t *testing.T) {
        t.Run("no transport_security key", func(t *testing.T) {
                d := agentHTMLData{}
                extractTransportData(&d, gin.H{})
                if d.dnssecStatus != "" {
                        t.Error("expected empty dnssecStatus")
                }
        })

        t.Run("wrong type", func(t *testing.T) {
                d := agentHTMLData{}
                extractTransportData(&d, gin.H{"transport_security": 42})
                if d.dnssecStatus != "" {
                        t.Error("expected empty dnssecStatus")
                }
        })

        t.Run("full transport", func(t *testing.T) {
                d := agentHTMLData{}
                extractTransportData(&d, gin.H{
                        "transport_security": gin.H{
                                "dnssec":  gin.H{"status": "signed"},
                                "mta_sts": gin.H{"mode": "enforce"},
                                "caa":     gin.H{"present": true},
                        },
                })
                if d.dnssecStatus != "signed" {
                        t.Errorf("dnssecStatus = %q, want signed", d.dnssecStatus)
                }
                if d.mtaSTSMode != "enforce" {
                        t.Errorf("mtaSTSMode = %q, want enforce", d.mtaSTSMode)
                }
                if !d.caaPresent {
                        t.Error("expected caaPresent=true")
                }
        })

        t.Run("mta_sts without mode", func(t *testing.T) {
                d := agentHTMLData{mtaSTSMode: "none"}
                extractTransportData(&d, gin.H{
                        "transport_security": gin.H{
                                "mta_sts": gin.H{"mode": ""},
                        },
                })
                if d.mtaSTSMode != "none" {
                        t.Errorf("mtaSTSMode should remain none, got %q", d.mtaSTSMode)
                }
        })
}

func TestExtractHTMLData(t *testing.T) {
        t.Run("empty json", func(t *testing.T) {
                d := extractHTMLData(gin.H{})
                if d.riskLevel != "Unknown" {
                        t.Errorf("default riskLevel = %q, want Unknown", d.riskLevel)
                }
                if d.postureGrade != "N/A" {
                        t.Errorf("default postureGrade = %q, want N/A", d.postureGrade)
                }
                if d.dmarcPolicy != "none" {
                        t.Errorf("default dmarcPolicy = %q, want none", d.dmarcPolicy)
                }
                if d.mtaSTSMode != "none" {
                        t.Errorf("default mtaSTSMode = %q, want none", d.mtaSTSMode)
                }
        })

        t.Run("with subdomain discovery", func(t *testing.T) {
                d := extractHTMLData(gin.H{
                        "subdomain_discovery": gin.H{
                                "subdomains_found": 10,
                                "certificates":     5,
                                "cnames":           3,
                        },
                })
                if d.subCount != 10 {
                        t.Errorf("subCount = %d, want 10", d.subCount)
                }
                if d.certCountVal != 5 {
                        t.Errorf("certCountVal = %d, want 5", d.certCountVal)
                }
                if d.cnameCountVal != 3 {
                        t.Errorf("cnameCountVal = %d, want 3", d.cnameCountVal)
                }
        })

        t.Run("full data flow", func(t *testing.T) {
                d := extractHTMLData(gin.H{
                        "summary": gin.H{
                                "risk_level":    "danger",
                                "posture_score": 30,
                                "posture_grade": "F",
                                "posture_label": "High Risk",
                        },
                        "email_authentication": gin.H{
                                "spf":  gin.H{"status": "pass"},
                                "dkim": gin.H{"status": "pass"},
                                "dmarc": gin.H{
                                        "status": "pass",
                                        "policy": "quarantine",
                                },
                        },
                        "transport_security": gin.H{
                                "dnssec":  gin.H{"status": "unsigned"},
                                "mta_sts": gin.H{"mode": "testing"},
                        },
                })
                if d.riskLevel != "danger" {
                        t.Errorf("riskLevel = %q", d.riskLevel)
                }
                if d.postureScore != 30 {
                        t.Errorf("postureScore = %d", d.postureScore)
                }
                if d.spfStatus != "pass" {
                        t.Errorf("spfStatus = %q", d.spfStatus)
                }
                if d.dmarcPolicy != "quarantine" {
                        t.Errorf("dmarcPolicy = %q", d.dmarcPolicy)
                }
                if d.dnssecStatus != "unsigned" {
                        t.Errorf("dnssecStatus = %q", d.dnssecStatus)
                }
                if d.mtaSTSMode != "testing" {
                        t.Errorf("mtaSTSMode = %q", d.mtaSTSMode)
                }
        })
}

func TestExtractNestedStatus_Branches(t *testing.T) {
        tests := []struct {
                name   string
                parent gin.H
                key    string
                want   string
        }{
                {"missing key", gin.H{}, "spf", "unknown"},
                {"wrong type", gin.H{"spf": "string"}, "spf", "unknown"},
                {"has status", gin.H{"spf": gin.H{"status": "pass"}}, "spf", "pass"},
                {"empty status", gin.H{"spf": gin.H{}}, "spf", "unknown"},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        got := extractNestedStatus(tc.parent, tc.key)
                        if got != tc.want {
                                t.Errorf("got %q, want %q", got, tc.want)
                        }
                })
        }
}

func TestBoolToPresence_Coverage(t *testing.T) {
        if got := boolToPresence(true); got != "present" {
                t.Errorf("boolToPresence(true) = %q, want present", got)
        }
        if got := boolToPresence(false); got != agentErrNotFound {
                t.Errorf("boolToPresence(false) = %q, want %q", got, agentErrNotFound)
        }
}

func TestBuildAgentHTML_Produces_HTML(t *testing.T) {
        gin.SetMode(gin.TestMode)
        cfg := &config.Config{
                AppVersion: "26.40.19",
                BaseURL:    "https://dnstool.it-help.tech",
        }
        h := NewAgentHandler(cfg, nil)

        results := map[string]any{
                "risk_level":    "warning",
                "domain_exists": true,
                "spf_analysis":  map[string]any{"status": "pass"},
                "dmarc_analysis": map[string]any{
                        "status": "pass",
                        "policy": "reject",
                },
                "dkim_analysis": map[string]any{"status": "pass"},
                "dnssec_analysis": map[string]any{"signed": true},
                "posture": map[string]any{
                        "score": float64(85),
                        "grade": "A",
                        "label": "Low Risk",
                },
                "subdomain_discovery": map[string]any{
                        "unique_subdomains": 10,
                        "unique_certs":      5,
                        "cname_count":       2,
                },
        }

        html := h.buildAgentHTML("example.com", results, 42)
        if !strings.Contains(html, "<!DOCTYPE html>") {
                t.Error("expected HTML doctype")
        }
        if !strings.Contains(html, "example.com") {
                t.Error("expected domain in HTML")
        }
        if !strings.Contains(html, "dnstool.it-help.tech") {
                t.Error("expected base URL in HTML")
        }
}

func TestBuildAgentHTML_NoAnalysisID(t *testing.T) {
        gin.SetMode(gin.TestMode)
        cfg := &config.Config{
                AppVersion: "26.40.19",
                BaseURL:    "https://dnstool.it-help.tech",
        }
        h := NewAgentHandler(cfg, nil)

        results := map[string]any{
                "risk_level":    "success",
                "domain_exists": true,
        }

        html := h.buildAgentHTML("test.org", results, 0)
        if !strings.Contains(html, "<!DOCTYPE html>") {
                t.Error("expected HTML doctype")
        }
        if !strings.Contains(html, "test.org") {
                t.Error("expected domain in HTML")
        }
}

func TestBuildAgentJSON_Complete(t *testing.T) {
        gin.SetMode(gin.TestMode)
        cfg := &config.Config{
                AppVersion: "26.40.19",
                BaseURL:    "https://dnstool.it-help.tech",
        }
        h := NewAgentHandler(cfg, nil)

        results := map[string]any{
                "risk_level":    "warning",
                "domain_exists": true,
                "spf_analysis":  map[string]any{"status": "pass"},
                "dmarc_analysis": map[string]any{
                        "status": "pass",
                        "policy": "reject",
                },
                "dkim_analysis": map[string]any{"status": "pass"},
                "dnssec_analysis": map[string]any{"signed": false},
                "mta_sts_analysis": map[string]any{"mode": "enforce"},
                "posture": map[string]any{
                        "score": float64(72),
                        "grade": "C",
                        "label": "Medium Risk",
                },
                "subdomain_discovery": map[string]any{
                        "unique_subdomains": 5,
                        "unique_certs":      3,
                        "cname_count":       1,
                },
        }

        j := h.buildAgentJSON("example.com", results)

        summary, ok := j["summary"].(gin.H)
        if !ok {
                t.Fatal("expected summary in JSON")
        }
        if summary["risk_level"] != "warning" {
                t.Errorf("risk_level = %v", summary["risk_level"])
        }

        emailAuth, ok := j["email_authentication"].(gin.H)
        if !ok {
                t.Fatal("expected email_authentication in JSON")
        }
        spf, ok := emailAuth["spf"].(gin.H)
        if !ok {
                t.Fatal("expected spf in email_authentication")
        }
        if spf["status"] != "pass" {
                t.Errorf("spf status = %v", spf["status"])
        }

        transport, ok := j["transport_security"].(gin.H)
        if !ok {
                t.Fatal("expected transport_security in JSON")
        }
        dnssecMap, ok := transport["dnssec"].(gin.H)
        if !ok {
                t.Fatal("expected dnssec in transport_security")
        }
        if dnssecMap["status"] != "unsigned" {
                t.Errorf("dnssec status = %v", dnssecMap["status"])
        }
}

func TestBuildAgentJSON_NilSubsections(t *testing.T) {
        gin.SetMode(gin.TestMode)
        cfg := &config.Config{
                AppVersion: "26.40.19",
                BaseURL:    "https://dnstool.it-help.tech",
        }
        h := NewAgentHandler(cfg, nil)

        results := map[string]any{
                "risk_level":    "success",
                "domain_exists": true,
        }

        j := h.buildAgentJSON("test.org", results)
        if j == nil {
                t.Fatal("expected non-nil JSON response")
        }
        if _, ok := j["summary"]; !ok {
                t.Error("expected summary key in JSON")
        }
}

func TestBuildAgentJSON_BimiCaaPresent(t *testing.T) {
        gin.SetMode(gin.TestMode)
        cfg := &config.Config{
                AppVersion: "26.40.19",
                BaseURL:    "https://dnstool.it-help.tech",
        }
        h := NewAgentHandler(cfg, nil)

        results := map[string]any{
                "risk_level":    "success",
                "domain_exists": true,
                "spf_analysis":  map[string]any{"status": "pass"},
                "dmarc_analysis": map[string]any{
                        "status": "pass",
                        "policy": "reject",
                },
                "dkim_analysis":    map[string]any{"verdict": "pass"},
                "dnssec_analysis":  map[string]any{"signed": true},
                "mta_sts_analysis": map[string]any{"mode": "enforce"},
                "bimi_analysis":    map[string]any{"has_bimi": true},
                "caa_analysis":     map[string]any{"has_caa": true},
                "posture": map[string]any{
                        "score": float64(95),
                        "grade": "A+",
                        "label": "Low Risk",
                },
                "subdomain_discovery": map[string]any{
                        "unique_subdomains": 20,
                        "unique_certs":      10,
                        "cname_count":       3,
                },
        }

        j := h.buildAgentJSON("secure.example.com", results)

        emailAuth := j["email_authentication"].(gin.H)
        bimi := emailAuth["bimi"].(gin.H)
        if bimi["present"] != true {
                t.Error("expected bimi present=true")
        }

        transport := j["transport_security"].(gin.H)
        mtaSTS := transport["mta_sts"].(gin.H)
        if mtaSTS["mode"] != "enforce" {
                t.Errorf("mta_sts mode = %v, want enforce", mtaSTS["mode"])
        }
        caa := transport["caa"].(gin.H)
        if caa["present"] != true {
                t.Error("expected caa present=true")
        }

        subdomain := j["subdomain_discovery"].(gin.H)
        if subdomain["subdomains_found"] != 20 {
                t.Errorf("subdomains_found = %v, want 20", subdomain["subdomains_found"])
        }
}

func TestBuildAgentJSON_DmarcPolicyEmpty(t *testing.T) {
        gin.SetMode(gin.TestMode)
        cfg := &config.Config{
                AppVersion: "26.40.19",
                BaseURL:    "https://dnstool.it-help.tech",
        }
        h := NewAgentHandler(cfg, nil)

        results := map[string]any{
                "dmarc_analysis": map[string]any{"status": "pass", "policy": ""},
        }

        j := h.buildAgentJSON("test.com", results)
        emailAuth := j["email_authentication"].(gin.H)
        dmarc := emailAuth["dmarc"].(gin.H)
        if dmarc["policy"] != "none" {
                t.Errorf("empty policy should default to none, got %v", dmarc["policy"])
        }
}

func TestBuildAgentHTML_WithBimiAndCAA(t *testing.T) {
        gin.SetMode(gin.TestMode)
        cfg := &config.Config{
                AppVersion: "26.40.19",
                BaseURL:    "https://dnstool.it-help.tech",
        }
        h := NewAgentHandler(cfg, nil)

        results := map[string]any{
                "risk_level":       "success",
                "domain_exists":    true,
                "spf_analysis":     map[string]any{"status": "pass"},
                "dmarc_analysis":   map[string]any{"status": "pass", "policy": "reject"},
                "dkim_analysis":    map[string]any{"status": "pass"},
                "dnssec_analysis":  map[string]any{"signed": true},
                "mta_sts_analysis": map[string]any{"mode": "enforce"},
                "bimi_analysis":    map[string]any{"has_bimi": true},
                "caa_analysis":     map[string]any{"has_caa": true},
                "posture": map[string]any{
                        "score": float64(98),
                        "grade": "A+",
                        "label": "Low Risk",
                },
                "subdomain_discovery": map[string]any{
                        "unique_subdomains": 15,
                        "unique_certs":      8,
                        "cname_count":       4,
                },
        }

        html := h.buildAgentHTML("secure.example.com", results, 100)
        if !strings.Contains(html, "present") {
                t.Error("expected bimi/caa presence in HTML")
        }
        if !strings.Contains(html, "enforce") {
                t.Error("expected MTA-STS enforce mode in HTML")
        }
        if !strings.Contains(html, "secure.example.com") {
                t.Error("expected domain in HTML")
        }
        if !strings.Contains(html, "/api/analysis/100/checksum") {
                t.Error("expected checksum URL with analysis ID")
        }
}

func TestExecer_NilFields(t *testing.T) {
        h := &AnalysisHandler{}
        if h.execer() != nil {
                t.Error("expected nil from execer with no DB and no statsExec")
        }
}

func TestEsc(t *testing.T) {
        tests := []struct {
                in, want string
        }{
                {"hello", "hello"},
                {"<script>", "&lt;script&gt;"},
                {"a&b", "a&amp;b"},
                {`"quoted"`, "&#34;quoted&#34;"},
        }
        for _, tc := range tests {
                got := esc(tc.in)
                if got != tc.want {
                        t.Errorf("esc(%q) = %q, want %q", tc.in, got, tc.want)
                }
        }
}
