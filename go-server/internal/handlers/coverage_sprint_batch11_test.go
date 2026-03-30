package handlers

import (
        "net/http/httptest"
        "testing"

        "github.com/gin-gonic/gin"
)

func TestNormalizeLLMsTxtVerdict_BothFound_B11(t *testing.T) {
        v := normalizeLLMsTxtVerdict(map[string]interface{}{"found": true, "full_found": true})
        if v["answer"] != "Yes" {
                t.Fatalf("expected Yes, got %v", v["answer"])
        }
        if v["color"] != "success" {
                t.Fatalf("expected success, got %v", v["color"])
        }
}

func TestNormalizeLLMsTxtVerdict_FoundOnly_B11(t *testing.T) {
        v := normalizeLLMsTxtVerdict(map[string]interface{}{"found": true, "full_found": false})
        if v["answer"] != "Yes" {
                t.Fatalf("expected Yes, got %v", v["answer"])
        }
}

func TestNormalizeLLMsTxtVerdict_NotFound_B11(t *testing.T) {
        v := normalizeLLMsTxtVerdict(map[string]interface{}{"found": false})
        if v["answer"] != "No" {
                t.Fatalf("expected No, got %v", v["answer"])
        }
        if v["color"] != "secondary" {
                t.Fatalf("expected secondary, got %v", v["color"])
        }
}

func TestNormalizeLLMsTxtVerdict_MissingFields_B11(t *testing.T) {
        v := normalizeLLMsTxtVerdict(map[string]interface{}{})
        if v["answer"] != "No" {
                t.Fatalf("expected No for missing fields, got %v", v["answer"])
        }
}

func TestNormalizeVerdictEntry_NoExistingAnswer_B11(t *testing.T) {
        verdicts := map[string]interface{}{
                "dns_tampering": map[string]interface{}{
                        "label":  "Protected",
                        "reason": "No — DNS is secured via DNSSEC",
                },
        }
        normalizeVerdictEntry(verdicts, "dns_tampering", map[string]string{
                "Protected": "No",
                "Exposed":   "Yes",
        })
        v := verdicts["dns_tampering"].(map[string]interface{})
        if v["answer"] != "No" {
                t.Fatalf("expected answer=No, got %v", v["answer"])
        }
        if v["reason"] != "DNS is secured via DNSSEC" {
                t.Fatalf("expected trimmed reason, got %v", v["reason"])
        }
}

func TestNormalizeVerdictEntry_ExistingAnswer_B11(t *testing.T) {
        verdicts := map[string]interface{}{
                "dns_tampering": map[string]interface{}{
                        "label":  "Protected",
                        "answer": "Already Set",
                },
        }
        normalizeVerdictEntry(verdicts, "dns_tampering", map[string]string{
                "Protected": "No",
        })
        v := verdicts["dns_tampering"].(map[string]interface{})
        if v["answer"] != "Already Set" {
                t.Fatalf("expected existing answer preserved, got %v", v["answer"])
        }
}

func TestNormalizeVerdictEntry_MissingKey_B11(t *testing.T) {
        verdicts := map[string]interface{}{}
        normalizeVerdictEntry(verdicts, "missing", map[string]string{})
}

func TestNormalizeVerdictEntry_WrongType_B11(t *testing.T) {
        verdicts := map[string]interface{}{
                "dns_tampering": "not a map",
        }
        normalizeVerdictEntry(verdicts, "dns_tampering", map[string]string{})
}

func TestNormalizeVerdictAnswers_AllKeys_B11(t *testing.T) {
        verdicts := map[string]interface{}{
                "dns_tampering": map[string]interface{}{
                        "label": "Exposed",
                },
                "brand_impersonation": map[string]interface{}{
                        "label": "Protected",
                },
                "certificate_control": map[string]interface{}{
                        "label": "Configured",
                },
                "transport": map[string]interface{}{
                        "label": "Fully Protected",
                },
        }
        normalizeVerdictAnswers(verdicts)

        if v, ok := verdicts["dns_tampering"].(map[string]interface{}); ok {
                if v["answer"] != "Yes" {
                        t.Fatalf("dns_tampering: expected Yes, got %v", v["answer"])
                }
        }
        if v, ok := verdicts["brand_impersonation"].(map[string]interface{}); ok {
                if v["answer"] != "No" {
                        t.Fatalf("brand_impersonation: expected No, got %v", v["answer"])
                }
        }
        if v, ok := verdicts["certificate_control"].(map[string]interface{}); ok {
                if v["answer"] != "Yes" {
                        t.Fatalf("certificate_control: expected Yes, got %v", v["answer"])
                }
        }
        if v, ok := verdicts["transport"].(map[string]interface{}); ok {
                if v["answer"] != "Yes" {
                        t.Fatalf("transport: expected Yes, got %v", v["answer"])
                }
        }
}

func TestNormalizeAIVerdicts_Full_B11(t *testing.T) {
        results := map[string]interface{}{
                "ai_surface": map[string]interface{}{
                        "llms_txt": map[string]interface{}{
                                "found":      true,
                                "full_found": false,
                        },
                        "robots_txt": map[string]interface{}{
                                "found":             true,
                                "blocks_ai_crawlers": true,
                        },
                        "poisoning": map[string]interface{}{
                                "ioc_count": float64(0),
                        },
                        "hidden_prompts": map[string]interface{}{
                                "artifact_count": float64(2),
                        },
                },
        }
        verdicts := map[string]interface{}{}
        normalizeAIVerdicts(results, verdicts)

        if verdicts["ai_llms_txt"] == nil {
                t.Fatal("expected ai_llms_txt verdict")
        }
        if verdicts["ai_crawler_governance"] == nil {
                t.Fatal("expected ai_crawler_governance verdict")
        }
        if verdicts["ai_poisoning"] == nil {
                t.Fatal("expected ai_poisoning verdict")
        }
        if verdicts["ai_hidden_prompts"] == nil {
                t.Fatal("expected ai_hidden_prompts verdict")
        }
        hp := verdicts["ai_hidden_prompts"].(map[string]interface{})
        if hp["answer"] != "Yes" {
                t.Fatalf("expected hidden prompts answer=Yes, got %v", hp["answer"])
        }
}

func TestNormalizeAIVerdicts_AlreadySet_B11(t *testing.T) {
        results := map[string]interface{}{
                "ai_surface": map[string]interface{}{
                        "llms_txt": map[string]interface{}{"found": true},
                },
        }
        verdicts := map[string]interface{}{
                "ai_llms_txt": map[string]interface{}{"answer": "existing"},
        }
        normalizeAIVerdicts(results, verdicts)
        v := verdicts["ai_llms_txt"].(map[string]interface{})
        if v["answer"] != "existing" {
                t.Fatal("expected existing verdict preserved")
        }
}

func TestNormalizeAIVerdicts_NoAISurface_B11(t *testing.T) {
        results := map[string]interface{}{}
        verdicts := map[string]interface{}{}
        normalizeAIVerdicts(results, verdicts)
        if len(verdicts) != 0 {
                t.Fatal("expected no verdicts for missing ai_surface")
        }
}

func TestParseSortedElement_JSONNumber_B11(t *testing.T) {
        result := parseSortedElement("42", false)
        if v, ok := result.(float64); !ok || v != 42 {
                t.Fatalf("expected float64 42, got %v (%T)", result, result)
        }
}

func TestParseSortedElement_String_B11(t *testing.T) {
        result := parseSortedElement("hello", true)
        if v, ok := result.(string); !ok || v != "hello" {
                t.Fatalf("expected string hello, got %v (%T)", result, result)
        }
}

func TestParseSortedElement_JSONObjectFirstIsString_B11(t *testing.T) {
        result := parseSortedElement(`{"a":1}`, true)
        if _, ok := result.(string); !ok {
                t.Fatal("expected string when firstIsString=true")
        }
}

func TestIsTwoPartSuffix_TrueCase_B11(t *testing.T) {
        got := isTwoPartSuffix("co.uk")
        if !got {
                t.Fatal("expected true for co.uk")
        }
}

func TestIsTwoPartSuffix_SinglePart_B11(t *testing.T) {
        got := isTwoPartSuffix("com")
        if got {
                t.Fatal("expected false for single part")
        }
}

func TestIsTwoPartSuffix_ThreePart_B11(t *testing.T) {
        got := isTwoPartSuffix("a.b.c")
        if got {
                t.Fatal("expected false for three parts")
        }
}

func TestIsPublicSuffixDomain_PublicSuffix_B11(t *testing.T) {
        if !isPublicSuffixDomain("com") {
                t.Fatal("expected true for com")
        }
}

func TestIsPublicSuffixDomain_TwoPartSuffix_B11(t *testing.T) {
        if !isPublicSuffixDomain("co.uk") {
                t.Fatal("expected true for co.uk")
        }
}

func TestIsPublicSuffixDomain_RegularDomain_B11(t *testing.T) {
        if isPublicSuffixDomain("example.com") {
                t.Fatal("expected false for example.com")
        }
}

func TestNormalizeVerdictEntry_ReasonPrefixes_B11(t *testing.T) {
        tests := []struct {
                prefix   string
                expected string
        }{
                {"Yes — Good config", "Good config"},
                {"Possible — Maybe", "Maybe"},
        }
        for _, tt := range tests {
                verdicts := map[string]interface{}{
                        "test": map[string]interface{}{
                                "label":  "TestLabel",
                                "reason": tt.prefix,
                        },
                }
                normalizeVerdictEntry(verdicts, "test", map[string]string{"TestLabel": "Yes"})
                v := verdicts["test"].(map[string]interface{})
                if v["reason"] != tt.expected {
                        t.Fatalf("expected reason=%s, got %v", tt.expected, v["reason"])
                }
        }
}

func TestNormalizeVerdictEntry_NoLabel_B11(t *testing.T) {
        verdicts := map[string]interface{}{
                "test": map[string]interface{}{
                        "reason": "some reason",
                },
        }
        normalizeVerdictEntry(verdicts, "test", map[string]string{"": "DefaultAnswer"})
        v := verdicts["test"].(map[string]interface{})
        if v["answer"] != "DefaultAnswer" {
                t.Fatalf("expected DefaultAnswer for empty label, got %v", v["answer"])
        }
}

func TestApplyWelcomeOrFlash_Welcome_B11(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/?welcome=TestUser", nil)
        data := gin.H{}
        applyWelcomeOrFlash(c, data)
        if data["WelcomeName"] != "TestUser" {
                t.Fatalf("expected WelcomeName=TestUser, got %v", data["WelcomeName"])
        }
}

func TestApplyWelcomeOrFlash_LongName_B11(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        longName := ""
        for i := 0; i < 150; i++ {
                longName += "a"
        }
        c.Request = httptest.NewRequest("GET", "/?welcome="+longName, nil)
        data := gin.H{}
        applyWelcomeOrFlash(c, data)
        name := data["WelcomeName"].(string)
        if len(name) != 100 {
                t.Fatalf("expected name truncated to 100, got %d", len(name))
        }
}

func TestApplyFlashFromQuery_Basic_B11(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/?flash=Something+happened&flash_cat=success", nil)
        data := gin.H{}
        applyFlashFromQuery(c, data)
        flashes := data["FlashMessages"].([]FlashMessage)
        if len(flashes) != 1 || flashes[0].Category != "success" {
                t.Fatalf("unexpected flash: %+v", flashes)
        }
}

func TestApplyFlashFromQuery_InvalidCategory_B11(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/?flash=test&flash_cat=evil", nil)
        data := gin.H{}
        applyFlashFromQuery(c, data)
        flashes := data["FlashMessages"].([]FlashMessage)
        if flashes[0].Category != "warning" {
                t.Fatalf("expected warning for invalid category, got %s", flashes[0].Category)
        }
}

func TestApplyFlashFromQuery_WithDomain_B11(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/?flash=test&domain=example.com", nil)
        data := gin.H{}
        applyFlashFromQuery(c, data)
        if data["PrefillDomain"] != "example.com" {
                t.Fatalf("expected PrefillDomain=example.com, got %v", data["PrefillDomain"])
        }
}

func TestApplyFlashFromQuery_Empty_B11(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/", nil)
        data := gin.H{}
        applyFlashFromQuery(c, data)
        if _, ok := data["FlashMessages"]; ok {
                t.Fatal("expected no FlashMessages for empty flash")
        }
}

func TestApplyFlashFromQuery_DangerCategory_B11(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/?flash=error&flash_cat=danger", nil)
        data := gin.H{}
        applyFlashFromQuery(c, data)
        flashes := data["FlashMessages"].([]FlashMessage)
        if flashes[0].Category != "danger" {
                t.Fatalf("expected danger, got %s", flashes[0].Category)
        }
}
