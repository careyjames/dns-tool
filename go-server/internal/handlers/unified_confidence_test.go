package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/unified"

	"github.com/gin-gonic/gin"
)

func TestRestoreUnifiedConfidence_CB13(t *testing.T) {
	m := map[string]any{
		"level":            "High",
		"score":            0.85,
		"accuracy_factor":  0.9,
		"currency_factor":  0.8,
		"maturity_ceiling": 0.95,
		"maturity_level":   "Operational",
		"weakest_link":     "DKIM",
		"weakest_detail":   "No DKIM record found",
		"explanation":      "Overall confidence is high",
		"protocol_count":   float64(9),
	}
	uc := restoreUnifiedConfidence(m)
	if uc.Level != "High" {
		t.Errorf("Level = %q, want High", uc.Level)
	}
	if uc.Score != 0.85 {
		t.Errorf("Score = %f, want 0.85", uc.Score)
	}
	if uc.AccuracyFactor != 0.9 {
		t.Errorf("AccuracyFactor = %f, want 0.9", uc.AccuracyFactor)
	}
	if uc.CurrencyFactor != 0.8 {
		t.Errorf("CurrencyFactor = %f, want 0.8", uc.CurrencyFactor)
	}
	if uc.MaturityCeiling != 0.95 {
		t.Errorf("MaturityCeiling = %f, want 0.95", uc.MaturityCeiling)
	}
	if uc.MaturityLevel != "Operational" {
		t.Errorf("MaturityLevel = %q, want Operational", uc.MaturityLevel)
	}
	if uc.WeakestLink != "DKIM" {
		t.Errorf("WeakestLink = %q, want DKIM", uc.WeakestLink)
	}
	if uc.WeakestDetail != "No DKIM record found" {
		t.Errorf("WeakestDetail = %q", uc.WeakestDetail)
	}
	if uc.Explanation != "Overall confidence is high" {
		t.Errorf("Explanation = %q", uc.Explanation)
	}
	if uc.ProtocolCount != 9 {
		t.Errorf("ProtocolCount = %d, want 9", uc.ProtocolCount)
	}
}

func TestRestoreUnifiedConfidenceEmpty_CB13(t *testing.T) {
	uc := restoreUnifiedConfidence(map[string]any{})
	if uc.Level != "" {
		t.Error("empty map should yield empty Level")
	}
	if uc.Score != 0 {
		t.Error("empty map should yield zero Score")
	}
	if uc.ProtocolCount != 0 {
		t.Error("empty map should yield zero ProtocolCount")
	}
}

func TestRestoreUnifiedConfidencePartial_CB13(t *testing.T) {
	m := map[string]any{
		"level": "Medium",
		"score": 0.5,
	}
	uc := restoreUnifiedConfidence(m)
	if uc.Level != "Medium" {
		t.Errorf("Level = %q, want Medium", uc.Level)
	}
	if uc.WeakestLink != "" {
		t.Error("missing fields should yield empty string")
	}
}

func TestMissionCriticalDomainsFromBaseURL_CB13(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		wantLen  int
		contains string
	}{
		{"full URL", "https://dns-tool.example.com", 2, "example.com"},
		{"with port", "https://dns-tool.example.com:8080", 2, "example.com"},
		{"root domain", "https://example.com", 1, "example.com"},
		{"with trailing slash", "https://dns-tool.example.com/", 2, "example.com"},
		{"bare host", "dns-tool.example.com", 2, "example.com"},
		{"single label", "https://localhost", 1, "localhost"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domains := missionCriticalDomainsFromBaseURL(tt.baseURL)
			if len(domains) != tt.wantLen {
				t.Errorf("len = %d, want %d, domains = %v", len(domains), tt.wantLen, domains)
			}
			found := false
			for _, d := range domains {
				if d == tt.contains {
					found = true
				}
			}
			if !found {
				t.Errorf("expected domains to contain %q, got %v", tt.contains, domains)
			}
		})
	}
}

func TestMergeAuthData_CB13(t *testing.T) {
	t.Run("unauthenticated", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

		cfg := &config.Config{GoogleClientID: "test-client"}
		data := gin.H{}
		mergeAuthData(c, cfg, data)

		if _, ok := data["Authenticated"]; ok {
			t.Error("unauthenticated should not have Authenticated key")
		}
		if data["GoogleAuthEnabled"] != true {
			t.Error("expected GoogleAuthEnabled=true when client ID set")
		}
	})

	t.Run("authenticated", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Set("authenticated", true)
		c.Set("user_email", "test@example.com")
		c.Set("user_name", "Test User")
		c.Set("user_role", "admin")

		cfg := &config.Config{GoogleClientID: "test-client"}
		data := gin.H{}
		mergeAuthData(c, cfg, data)

		if data["Authenticated"] != true {
			t.Error("expected Authenticated=true")
		}
		if data["UserEmail"] != "test@example.com" {
			t.Errorf("UserEmail = %v", data["UserEmail"])
		}
		if data["UserName"] != "Test User" {
			t.Errorf("UserName = %v", data["UserName"])
		}
		if data["UserRole"] != "admin" {
			t.Errorf("UserRole = %v", data["UserRole"])
		}
	})

	t.Run("no google auth", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

		cfg := &config.Config{GoogleClientID: ""}
		data := gin.H{}
		mergeAuthData(c, cfg, data)

		if _, ok := data["GoogleAuthEnabled"]; ok {
			t.Error("expected no GoogleAuthEnabled when client ID empty")
		}
	})
}

func TestLookupCountryLocalhost_CB13(t *testing.T) {
	code, name := lookupCountry("")
	if code != "" || name != "" {
		t.Error("empty IP should return empty")
	}
	code2, name2 := lookupCountry("127.0.0.1")
	if code2 != "" || name2 != "" {
		t.Error("localhost should return empty")
	}
	code3, name3 := lookupCountry("::1")
	if code3 != "" || name3 != "" {
		t.Error("::1 should return empty")
	}
}

func TestGetJSONFromResults_CB13(t *testing.T) {
	results := map[string]any{
		"basic_records": map[string]any{
			"A":  []string{"1.2.3.4"},
			"MX": []string{"10 mail.example.com"},
		},
		"top_level_key": "simple_value",
	}

	t.Run("nested key", func(t *testing.T) {
		raw := getJSONFromResults(results, "basic_records", "A")
		if raw == nil {
			t.Fatal("expected non-nil JSON for nested key")
		}
		var arr []string
		if json.Unmarshal(raw, &arr) != nil {
			t.Error("expected valid JSON array")
		}
		if len(arr) != 1 || arr[0] != "1.2.3.4" {
			t.Errorf("unexpected value: %v", arr)
		}
	})

	t.Run("whole section", func(t *testing.T) {
		raw := getJSONFromResults(results, "basic_records", "")
		if raw == nil {
			t.Fatal("expected non-nil JSON for section")
		}
	})

	t.Run("missing section", func(t *testing.T) {
		raw := getJSONFromResults(results, "nonexistent", "key")
		if raw != nil {
			t.Error("expected nil for missing section")
		}
	})

	t.Run("missing key in section", func(t *testing.T) {
		raw := getJSONFromResults(results, "basic_records", "AAAA")
		if raw != nil {
			t.Error("expected nil for missing key")
		}
	})

	t.Run("nil data", func(t *testing.T) {
		raw := getJSONFromResults(map[string]any{"section": map[string]any{"key": nil}}, "section", "key")
		if raw != nil {
			t.Error("expected nil for nil data value")
		}
	})
}

func TestNormalizeResults_CB13(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		if NormalizeResults(nil) != nil {
			t.Error("nil input should return nil")
		}
		if NormalizeResults(json.RawMessage{}) != nil {
			t.Error("empty input should return nil")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		if NormalizeResults(json.RawMessage("not json")) != nil {
			t.Error("invalid JSON should return nil")
		}
	})

	t.Run("minimal valid input", func(t *testing.T) {
		input, _ := json.Marshal(map[string]any{"domain": "example.com"})
		results := NormalizeResults(input)
		if results == nil {
			t.Fatal("expected non-nil results")
		}
		if results["domain"] != "example.com" {
			t.Error("domain should be preserved")
		}
		if _, ok := results["basic_records"]; !ok {
			t.Error("basic_records should be added as default")
		}
		if _, ok := results["spf_analysis"]; !ok {
			t.Error("spf_analysis should be added as default")
		}
	})

	t.Run("posture normalization", func(t *testing.T) {
		input, _ := json.Marshal(map[string]any{
			"posture": map[string]any{
				"state": "STRONG",
				"color": "secondary",
			},
		})
		results := NormalizeResults(input)
		posture := results["posture"].(map[string]any)
		if posture["state"] != "Secure" {
			t.Errorf("STRONG should normalize to Secure, got %v", posture["state"])
		}
		if posture["color"] != "success" {
			t.Errorf("Secure posture should have success color, got %v", posture["color"])
		}
	})

	t.Run("legacy posture states", func(t *testing.T) {
		for legacy, normalized := range legacyPostureStates {
			input, _ := json.Marshal(map[string]any{
				"posture": map[string]any{"state": legacy},
			})
			results := NormalizeResults(input)
			posture := results["posture"].(map[string]any)
			if posture["state"] != normalized {
				t.Errorf("state %q should normalize to %q, got %v", legacy, normalized, posture["state"])
			}
		}
	})
}

func TestNormalizeEmailAnswer_CB13(t *testing.T) {
	t.Run("already has short answer", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"email_answer_short": "Yes",
		}
		normalizeEmailAnswer(verdicts)
		if verdicts["email_answer_short"] != "Yes" {
			t.Error("should not modify existing short answer")
		}
	})

	t.Run("splits answer with reason", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"email_answer": "Yes — Domain is vulnerable to email spoofing",
		}
		normalizeEmailAnswer(verdicts)
		if verdicts["email_answer_short"] != "Yes" {
			t.Errorf("short = %v", verdicts["email_answer_short"])
		}
		if verdicts["email_answer_color"] != "danger" {
			t.Errorf("color = %v, want danger", verdicts["email_answer_color"])
		}
	})

	t.Run("No answer", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"email_answer": "No — Domain is protected",
		}
		normalizeEmailAnswer(verdicts)
		if verdicts["email_answer_color"] != "success" {
			t.Errorf("color = %v, want success", verdicts["email_answer_color"])
		}
	})

	t.Run("Unlikely answer", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"email_answer": "Unlikely — DMARC reject policy",
		}
		normalizeEmailAnswer(verdicts)
		if verdicts["email_answer_color"] != "success" {
			t.Errorf("color = %v, want success", verdicts["email_answer_color"])
		}
	})

	t.Run("Partially answer", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"email_answer": "Partially — Some protections in place",
		}
		normalizeEmailAnswer(verdicts)
		if verdicts["email_answer_color"] != "warning" {
			t.Errorf("color = %v, want warning", verdicts["email_answer_color"])
		}
	})

	t.Run("Likely answer", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"email_answer": "Likely — Weak DMARC policy",
		}
		normalizeEmailAnswer(verdicts)
		if verdicts["email_answer_color"] != "danger" {
			t.Errorf("color = %v, want danger", verdicts["email_answer_color"])
		}
	})

	t.Run("no separator", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"email_answer": "SomethingWithoutSeparator",
		}
		normalizeEmailAnswer(verdicts)
		if _, ok := verdicts["email_answer_short"]; ok {
			t.Error("no separator should not set short answer")
		}
	})
}

func TestNormalizeAIVerdicts_CB13(t *testing.T) {
	t.Run("already has ai_llms_txt", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"ai_llms_txt": map[string]interface{}{"answer": "Yes"},
		}
		normalizeAIVerdicts(map[string]interface{}{}, verdicts)
		if verdicts["ai_llms_txt"].(map[string]interface{})["answer"] != "Yes" {
			t.Error("should preserve existing verdict")
		}
	})

	t.Run("no ai_surface section", func(t *testing.T) {
		verdicts := map[string]interface{}{}
		normalizeAIVerdicts(map[string]interface{}{}, verdicts)
		if _, ok := verdicts["ai_llms_txt"]; ok {
			t.Error("should not create verdict without ai_surface")
		}
	})

	t.Run("with ai_surface data", func(t *testing.T) {
		results := map[string]interface{}{
			"ai_surface": map[string]interface{}{
				"llms_txt": map[string]interface{}{
					"found":      true,
					"full_found": true,
				},
				"robots_txt": map[string]interface{}{
					"found":              true,
					"blocks_ai_crawlers": true,
				},
				"poisoning": map[string]interface{}{
					"ioc_count": float64(2),
				},
				"hidden_prompts": map[string]interface{}{
					"artifact_count": float64(0),
				},
			},
		}
		verdicts := map[string]interface{}{}
		normalizeAIVerdicts(results, verdicts)

		if verdicts["ai_llms_txt"] == nil {
			t.Error("should set ai_llms_txt verdict")
		}
		if verdicts["ai_crawler_governance"] == nil {
			t.Error("should set ai_crawler_governance verdict")
		}
		if verdicts["ai_poisoning"] == nil {
			t.Error("should set ai_poisoning verdict")
		}
		if verdicts["ai_hidden_prompts"] == nil {
			t.Error("should set ai_hidden_prompts verdict")
		}

		poisoning := verdicts["ai_poisoning"].(map[string]interface{})
		if poisoning["answer"] != "Yes" {
			t.Errorf("poisoning answer = %v, want Yes (count=2)", poisoning["answer"])
		}
		hiddenPrompts := verdicts["ai_hidden_prompts"].(map[string]interface{})
		if hiddenPrompts["answer"] != "No" {
			t.Errorf("hidden_prompts answer = %v, want No (count=0)", hiddenPrompts["answer"])
		}
	})
}

func TestComputeAllDiffs_CB13(t *testing.T) {
	resultsA := map[string]interface{}{
		"spf_analysis":   map[string]interface{}{"status": "pass"},
		"dmarc_analysis": map[string]interface{}{"status": "pass"},
	}
	resultsB := map[string]interface{}{
		"spf_analysis":   map[string]interface{}{"status": "warning"},
		"dmarc_analysis": map[string]interface{}{"status": "pass"},
	}
	diffs := ComputeAllDiffs(resultsA, resultsB)
	if len(diffs) != len(CompareSections) {
		t.Errorf("expected %d diffs, got %d", len(CompareSections), len(diffs))
	}
	spfDiff := diffs[0]
	if !spfDiff.Changed {
		t.Error("SPF should show as changed")
	}
	dmarcDiff := diffs[1]
	if dmarcDiff.Changed {
		t.Error("DMARC should show as unchanged")
	}
}

func TestComputeSectionDiff_CB13(t *testing.T) {
	t.Run("both empty", func(t *testing.T) {
		diff := ComputeSectionDiff(map[string]interface{}{}, map[string]interface{}{}, "test", "Test", "icon")
		if diff.Changed {
			t.Error("empty sections should not be changed")
		}
		if diff.StatusA != "unknown" || diff.StatusB != "unknown" {
			t.Error("empty sections should have unknown status")
		}
	})

	t.Run("status changed", func(t *testing.T) {
		a := map[string]interface{}{"status": "pass"}
		b := map[string]interface{}{"status": "fail"}
		diff := ComputeSectionDiff(a, b, "test", "Test", "icon")
		if !diff.Changed {
			t.Error("different statuses should show changed")
		}
	})

	t.Run("detail changes", func(t *testing.T) {
		a := map[string]interface{}{"status": "pass", "record": "v=spf1 -all"}
		b := map[string]interface{}{"status": "pass", "record": "v=spf1 ~all"}
		diff := ComputeSectionDiff(a, b, "test", "Test", "icon")
		if !diff.Changed {
			t.Error("different details should show changed")
		}
		if len(diff.DetailChanges) != 1 {
			t.Errorf("expected 1 detail change, got %d", len(diff.DetailChanges))
		}
	})
}

func TestExtractAuthInfo_CB13(t *testing.T) {
	t.Run("not authenticated", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		auth, uid := extractAuthInfo(c)
		if auth {
			t.Error("should not be authenticated")
		}
		if uid != 0 {
			t.Error("should have zero user ID")
		}
	})

	t.Run("authenticated with user ID", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Set("authenticated", true)
		c.Set("user_id", int32(42))
		auth, uid := extractAuthInfo(c)
		if !auth {
			t.Error("should be authenticated")
		}
		if uid != 42 {
			t.Errorf("user ID = %d, want 42", uid)
		}
	})
}

func TestUnifiedConfidenceRoundTrip_CB13(t *testing.T) {
	original := unified.UnifiedConfidence{
		Level:           "High",
		Score:           0.85,
		AccuracyFactor:  0.9,
		CurrencyFactor:  0.8,
		MaturityCeiling: 0.95,
		MaturityLevel:   "Operational",
		WeakestLink:     "DKIM",
		WeakestDetail:   "Detail",
		Explanation:     "Explanation text",
		ProtocolCount:   9,
	}

	serialized := map[string]any{
		"level":            original.Level,
		"score":            original.Score,
		"accuracy_factor":  original.AccuracyFactor,
		"currency_factor":  original.CurrencyFactor,
		"maturity_ceiling": original.MaturityCeiling,
		"maturity_level":   original.MaturityLevel,
		"weakest_link":     original.WeakestLink,
		"weakest_detail":   original.WeakestDetail,
		"explanation":      original.Explanation,
		"protocol_count":   float64(original.ProtocolCount),
	}

	restored := restoreUnifiedConfidence(serialized)
	if restored.Level != original.Level {
		t.Errorf("Level mismatch: %q vs %q", restored.Level, original.Level)
	}
	if restored.Score != original.Score {
		t.Errorf("Score mismatch: %f vs %f", restored.Score, original.Score)
	}
	if restored.ProtocolCount != original.ProtocolCount {
		t.Errorf("ProtocolCount mismatch: %d vs %d", restored.ProtocolCount, original.ProtocolCount)
	}
}

func TestNormalizeVerdicts_CB13(t *testing.T) {
	t.Run("no verdicts key", func(t *testing.T) {
		posture := map[string]interface{}{}
		normalizeVerdicts(map[string]interface{}{}, posture)
	})

	t.Run("with verdicts", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"dns_tampering": map[string]interface{}{
				"label": "Protected",
			},
		}
		posture := map[string]interface{}{
			"verdicts": verdicts,
		}
		normalizeVerdicts(map[string]interface{}{}, posture)
		dt := verdicts["dns_tampering"].(map[string]interface{})
		if dt["answer"] != "No" {
			t.Errorf("Protected should map to No, got %v", dt["answer"])
		}
	})
}

func TestNormalizeLLMsTxtVerdict_CB13(t *testing.T) {
	t.Run("found and full found", func(t *testing.T) {
		v := normalizeLLMsTxtVerdict(map[string]interface{}{"found": true, "full_found": true})
		if v["answer"] != "Yes" {
			t.Error("both found should be Yes")
		}
	})
	t.Run("found only", func(t *testing.T) {
		v := normalizeLLMsTxtVerdict(map[string]interface{}{"found": true, "full_found": false})
		if v["answer"] != "Yes" {
			t.Error("found only should be Yes")
		}
	})
	t.Run("not found", func(t *testing.T) {
		v := normalizeLLMsTxtVerdict(map[string]interface{}{"found": false})
		if v["answer"] != "No" {
			t.Error("not found should be No")
		}
	})
}

func TestNormalizeRobotsTxtVerdict_CB13(t *testing.T) {
	t.Run("found with AI blocking", func(t *testing.T) {
		v := normalizeRobotsTxtVerdict(map[string]interface{}{"found": true, "blocks_ai_crawlers": true})
		if v["answer"] != "Yes" {
			t.Error("blocking AI crawlers should be Yes")
		}
		if v["color"] != "success" {
			t.Error("blocking should be success color")
		}
	})
	t.Run("found without AI blocking", func(t *testing.T) {
		v := normalizeRobotsTxtVerdict(map[string]interface{}{"found": true, "blocks_ai_crawlers": false})
		if v["answer"] != "No" {
			t.Error("not blocking should be No")
		}
		if v["color"] != "warning" {
			t.Error("not blocking should be warning color")
		}
	})
	t.Run("not found", func(t *testing.T) {
		v := normalizeRobotsTxtVerdict(map[string]interface{}{"found": false})
		if v["answer"] != "No" {
			t.Error("not found should be No")
		}
		if v["color"] != "secondary" {
			t.Error("not found should be secondary color")
		}
	})
}

func TestProtocolResultKeys_CB13(t *testing.T) {
	if len(protocolResultKeys) != 9 {
		t.Errorf("expected 9 protocol result keys, got %d", len(protocolResultKeys))
	}
	expectedKeys := []string{"SPF", "DKIM", "DMARC", "DANE", "DNSSEC", "BIMI", "MTA_STS", "TLS_RPT", "CAA"}
	for _, k := range expectedKeys {
		if _, ok := protocolResultKeys[k]; !ok {
			t.Errorf("missing protocol key: %s", k)
		}
	}
}

func TestNormalizeCountVerdict_CB13(t *testing.T) {
	t.Run("positive count", func(t *testing.T) {
		section := map[string]interface{}{"ioc_count": float64(3)}
		v := normalizeCountVerdict(section, "ioc_count", "issues found", "clean")
		if v["answer"] != "Yes" {
			t.Error("positive count should be Yes")
		}
		if v["color"] != "danger" {
			t.Error("positive count should be danger")
		}
	})
	t.Run("zero count", func(t *testing.T) {
		section := map[string]interface{}{"ioc_count": float64(0)}
		v := normalizeCountVerdict(section, "ioc_count", "issues found", "clean")
		if v["answer"] != "No" {
			t.Error("zero count should be No")
		}
		if v["color"] != "success" {
			t.Error("zero count should be success")
		}
	})
	t.Run("missing key", func(t *testing.T) {
		section := map[string]interface{}{}
		v := normalizeCountVerdict(section, "missing", "issues found", "clean")
		if v["answer"] != "No" {
			t.Error("missing key should be No")
		}
	})
}
