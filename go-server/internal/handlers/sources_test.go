package handlers

import (
	"encoding/json"
	"testing"

	"dnstool/go-server/internal/config"
)

func TestGetDNSSources(t *testing.T) {
	sources := getDNSSources()
	if len(sources) == 0 {
		t.Fatal("expected non-empty DNS sources")
	}

	first := sources[0]
	if first.Name == "" {
		t.Error("expected DNS source to have a name")
	}
	if first.Category == "" {
		t.Error("expected DNS source to have a category")
	}
	if first.Purpose == "" {
		t.Error("expected DNS source to have a purpose")
	}
	if !first.Free {
		t.Error("expected DNS source to be free")
	}

	foundCloudflare := false
	foundGoogle := false
	for _, s := range sources {
		if s.Name == "Cloudflare DNS (1.1.1.1)" {
			foundCloudflare = true
		}
		if s.Name == "Google Public DNS (8.8.8.8)" {
			foundGoogle = true
		}
	}
	if !foundCloudflare {
		t.Error("expected Cloudflare DNS in DNS sources")
	}
	if !foundGoogle {
		t.Error("expected Google Public DNS in DNS sources")
	}
}

func TestGetInfraSources(t *testing.T) {
	sources := getInfraSources()
	if len(sources) == 0 {
		t.Fatal("expected non-empty infra sources")
	}

	for _, s := range sources {
		if s.Name == "" {
			t.Error("infra source missing name")
		}
		if s.Purpose == "" {
			t.Error("infra source missing purpose")
		}
	}

	foundPTR := false
	foundSMTP := false
	for _, s := range sources {
		if s.Name == "Reverse DNS (PTR Records)" {
			foundPTR = true
		}
		if s.Name == "SMTP Transport Probing" {
			foundSMTP = true
		}
	}
	if !foundPTR {
		t.Error("expected PTR records in infra sources")
	}
	if !foundSMTP {
		t.Error("expected SMTP Transport Probing in infra sources")
	}
}

func TestGetThreatSources(t *testing.T) {
	sources := getThreatSources()
	if len(sources) == 0 {
		t.Fatal("expected non-empty threat sources")
	}

	found := false
	for _, s := range sources {
		if s.Name == "OpenPhish Community Feed" {
			found = true
			if s.Category != "Community" {
				t.Errorf("expected OpenPhish category 'Community', got %s", s.Category)
			}
		}
	}
	if !found {
		t.Error("expected OpenPhish in threat sources")
	}
}

func TestGetHistorySources(t *testing.T) {
	sources := getHistorySources()
	if len(sources) == 0 {
		t.Fatal("expected non-empty history sources")
	}

	found := false
	for _, s := range sources {
		if s.Name == "Certificate Transparency (crt.sh)" {
			found = true
			if s.Category != "Public Log" {
				t.Errorf("expected crt.sh category 'Public Log', got %s", s.Category)
			}
		}
	}
	if !found {
		t.Error("expected crt.sh in history sources")
	}
}

func TestGetMetaSources(t *testing.T) {
	sources := getMetaSources()
	if len(sources) == 0 {
		t.Fatal("expected non-empty meta sources")
	}

	foundRDAP := false
	foundIETF := false
	for _, s := range sources {
		if s.Name == "IANA RDAP" {
			foundRDAP = true
			if s.Category != "Registry" {
				t.Errorf("expected RDAP category 'Registry', got %s", s.Category)
			}
		}
		if s.Name == "IETF Datatracker" {
			foundIETF = true
			if s.Category != "Reference" {
				t.Errorf("expected IETF category 'Reference', got %s", s.Category)
			}
		}
	}
	if !foundRDAP {
		t.Error("expected IANA RDAP in meta sources")
	}
	if !foundIETF {
		t.Error("expected IETF Datatracker in meta sources")
	}
}

func TestNewSourcesHandler(t *testing.T) {
	h := NewSourcesHandler(nil)
	if h == nil {
		t.Fatal("expected non-nil SourcesHandler")
	}
}

func TestNewStaticHandlerConstructor(t *testing.T) {
	h := NewStaticHandler("/tmp/test", "1.0.0", "https://dnstool.it-help.tech")
	if h == nil {
		t.Fatal("expected non-nil StaticHandler")
	}
	if h.StaticDir != "/tmp/test" {
		t.Errorf("expected StaticDir '/tmp/test', got %s", h.StaticDir)
	}
	if h.AppVersion != "1.0.0" {
		t.Errorf("expected AppVersion '1.0.0', got %s", h.AppVersion)
	}
}

func TestIntelSourceFields(t *testing.T) {
	allSources := [][]IntelSource{
		getDNSSources(),
		getInfraSources(),
		getThreatSources(),
		getHistorySources(),
		getMetaSources(),
	}

	for i, sources := range allSources {
		for j, s := range sources {
			if s.Name == "" {
				t.Errorf("source group %d, index %d: missing Name", i, j)
			}
			if s.Icon == "" {
				t.Errorf("source group %d, index %d (%s): missing Icon", i, j, s.Name)
			}
			if s.Category == "" {
				t.Errorf("source group %d, index %d (%s): missing Category", i, j, s.Name)
			}
			if s.Purpose == "" {
				t.Errorf("source group %d, index %d (%s): missing Purpose", i, j, s.Name)
			}
			if s.Method == "" {
				t.Errorf("source group %d, index %d (%s): missing Method", i, j, s.Name)
			}
		}
	}
}

func TestSourceConstants(t *testing.T) {
	if rateLimitNone != "No rate limits." {
		t.Errorf("unexpected rateLimitNone value: %s", rateLimitNone)
	}
	if methodHTTPSREST != "HTTPS REST API (no authentication required)" {
		t.Errorf("unexpected methodHTTPSREST value: %s", methodHTTPSREST)
	}
}

func TestGetBrandPalette(t *testing.T) {
	palette := getBrandPalette()
	if len(palette) == 0 {
		t.Fatal("expected non-empty brand palette")
	}
	for _, c := range palette {
		if c.Name == "" || c.Token == "" || c.Value == "" {
			t.Errorf("brand palette entry missing fields: %+v", c)
		}
	}
}

func TestGetStatusColors(t *testing.T) {
	colors := getStatusColors()
	if len(colors) == 0 {
		t.Fatal("expected non-empty status colors")
	}
	names := map[string]bool{}
	for _, c := range colors {
		names[c.Name] = true
	}
	for _, expected := range []string{"Success", "Warning", "Danger", "Info", "Neutral"} {
		if !names[expected] {
			t.Errorf("expected status color %q", expected)
		}
	}
}

func TestGetSurfaceColors(t *testing.T) {
	colors := getSurfaceColors()
	if len(colors) == 0 {
		t.Fatal("expected non-empty surface colors")
	}
	for _, c := range colors {
		if c.Name == "" || c.Token == "" || c.Value == "" {
			t.Errorf("surface color entry missing fields: %+v", c)
		}
	}
}

func TestGetTLPColors(t *testing.T) {
	colors := getTLPColors()
	if len(colors) < 4 {
		t.Fatalf("expected at least 4 TLP colors, got %d", len(colors))
	}
	foundRed := false
	foundAmber := false
	for _, c := range colors {
		if c.Name == "TLP:RED" {
			foundRed = true
			if c.Source != "FIRST TLP v2.0" {
				t.Errorf("expected TLP:RED source 'FIRST TLP v2.0', got %s", c.Source)
			}
		}
		if c.Name == "TLP:AMBER" {
			foundAmber = true
		}
	}
	if !foundRed {
		t.Error("expected TLP:RED in TLP colors")
	}
	if !foundAmber {
		t.Error("expected TLP:AMBER in TLP colors")
	}
}

func TestGetCVSSColors(t *testing.T) {
	colors := getCVSSColors()
	if len(colors) < 4 {
		t.Fatalf("expected at least 4 CVSS colors, got %d", len(colors))
	}
	foundCritical := false
	for _, c := range colors {
		if c.Name == "Critical (9.0–10.0)" {
			foundCritical = true
		}
		if c.SourceURL == "" {
			t.Errorf("CVSS color %q missing SourceURL", c.Name)
		}
	}
	if !foundCritical {
		t.Error("expected Critical CVSS color")
	}
}

func TestNewBrandColorsHandler(t *testing.T) {
	h := NewBrandColorsHandler(nil)
	if h == nil {
		t.Fatal("expected non-nil BrandColorsHandler")
	}
}

func TestNewPagination(t *testing.T) {
	tests := []struct {
		name      string
		page      int
		perPage   int
		total     int64
		wantPages int
		wantPrev  bool
		wantNext  bool
	}{
		{"first page", 1, 10, 25, 3, false, true},
		{"middle page", 2, 10, 25, 3, true, true},
		{"last page", 3, 10, 25, 3, true, false},
		{"zero page normalizes", 0, 10, 25, 3, false, true},
		{"single page", 1, 10, 5, 1, false, false},
		{"empty results", 1, 10, 0, 1, false, false},
		{"exact fit", 1, 10, 10, 1, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPagination(tt.page, tt.perPage, tt.total)
			if p.TotalPages != tt.wantPages {
				t.Errorf("TotalPages = %d, want %d", p.TotalPages, tt.wantPages)
			}
			if p.HasPrev != tt.wantPrev {
				t.Errorf("HasPrev = %v, want %v", p.HasPrev, tt.wantPrev)
			}
			if p.HasNext != tt.wantNext {
				t.Errorf("HasNext = %v, want %v", p.HasNext, tt.wantNext)
			}
		})
	}
}

func TestPaginationOffset(t *testing.T) {
	p := NewPagination(3, 10, 50)
	if p.Offset() != 20 {
		t.Errorf("Offset = %d, want 20", p.Offset())
	}
}

func TestPaginationLimit(t *testing.T) {
	p := NewPagination(1, 25, 100)
	if p.Limit() != 25 {
		t.Errorf("Limit = %d, want 25", p.Limit())
	}
}

func TestPaginationPages(t *testing.T) {
	p := NewPagination(1, 10, 35)
	pages := p.Pages()
	if len(pages) != 4 {
		t.Fatalf("expected 4 pages, got %d", len(pages))
	}
	for i, v := range pages {
		if v != i+1 {
			t.Errorf("page[%d] = %d, want %d", i, v, i+1)
		}
	}
}

func TestNormalizeResults(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		result := NormalizeResults(nil)
		if result != nil {
			t.Error("expected nil for empty input")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		result := NormalizeResults([]byte("not json"))
		if result != nil {
			t.Error("expected nil for invalid JSON")
		}
	})

	t.Run("adds defaults", func(t *testing.T) {
		result := NormalizeResults([]byte(`{"basic_records": {"A": "1.2.3.4"}}`))
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if _, ok := result["spf_analysis"]; !ok {
			t.Error("expected spf_analysis default to be added")
		}
		if _, ok := result["dmarc_analysis"]; !ok {
			t.Error("expected dmarc_analysis default to be added")
		}
		if _, ok := result["posture"]; !ok {
			t.Error("expected posture default to be added")
		}
	})

	t.Run("normalizes legacy posture states", func(t *testing.T) {
		input := `{"posture": {"state": "STRONG", "label": "test"}}`
		result := NormalizeResults([]byte(input))
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		posture, ok := result["posture"].(map[string]interface{})
		if !ok {
			t.Fatal("expected posture map")
		}
		if posture["state"] != "Secure" {
			t.Errorf("expected posture state 'Secure', got %v", posture["state"])
		}
		if posture["color"] != "success" {
			t.Errorf("expected posture color 'success', got %v", posture["color"])
		}
	})

	t.Run("normalizes all legacy states", func(t *testing.T) {
		cases := map[string]string{
			"Low": "Low Risk", "Medium": "Medium Risk", "High": "High Risk",
			"Critical": "Critical Risk", "MODERATE": "Medium Risk",
			"WEAK": "High Risk", "NONE": "Critical Risk",
			"Informational": "Secure",
		}
		for input, expected := range cases {
			raw := `{"posture": {"state": "` + input + `"}}`
			result := NormalizeResults([]byte(raw))
			posture := result["posture"].(map[string]interface{})
			if posture["state"] != expected {
				t.Errorf("state %q: expected %q, got %v", input, expected, posture["state"])
			}
		}
	})

	t.Run("normalizes email answer", func(t *testing.T) {
		input := `{"posture": {"state": "test", "verdicts": {"email_answer": "No — Domain is protected"}}}`
		result := NormalizeResults([]byte(input))
		posture := result["posture"].(map[string]interface{})
		verdicts := posture["verdicts"].(map[string]interface{})
		if verdicts["email_answer_short"] != "No" {
			t.Errorf("expected email_answer_short 'No', got %v", verdicts["email_answer_short"])
		}
		if verdicts["email_answer_color"] != "success" {
			t.Errorf("expected email_answer_color 'success', got %v", verdicts["email_answer_color"])
		}
	})

	t.Run("normalizes email answer Yes", func(t *testing.T) {
		input := `{"posture": {"state": "test", "verdicts": {"email_answer": "Yes — Domain is exposed"}}}`
		result := NormalizeResults([]byte(input))
		posture := result["posture"].(map[string]interface{})
		verdicts := posture["verdicts"].(map[string]interface{})
		if verdicts["email_answer_short"] != "Yes" {
			t.Errorf("expected 'Yes', got %v", verdicts["email_answer_short"])
		}
		if verdicts["email_answer_color"] != "danger" {
			t.Errorf("expected 'danger', got %v", verdicts["email_answer_color"])
		}
	})

	t.Run("normalizes email answer Partially", func(t *testing.T) {
		input := `{"posture": {"state": "test", "verdicts": {"email_answer": "Partially — Some protection"}}}`
		result := NormalizeResults([]byte(input))
		posture := result["posture"].(map[string]interface{})
		verdicts := posture["verdicts"].(map[string]interface{})
		if verdicts["email_answer_color"] != "warning" {
			t.Errorf("expected 'warning', got %v", verdicts["email_answer_color"])
		}
	})

	t.Run("normalizes AI verdicts from ai_surface", func(t *testing.T) {
		input := `{
                        "posture": {"state": "test", "verdicts": {}},
                        "ai_surface": {
                                "llms_txt": {"found": true, "full_found": true},
                                "robots_txt": {"found": true, "blocks_ai_crawlers": true},
                                "poisoning": {"ioc_count": 3},
                                "hidden_prompts": {"artifact_count": 2}
                        }
                }`
		result := NormalizeResults([]byte(input))
		posture := result["posture"].(map[string]interface{})
		verdicts := posture["verdicts"].(map[string]interface{})

		llms := verdicts["ai_llms_txt"].(map[string]interface{})
		if llms["answer"] != "Yes" {
			t.Errorf("expected ai_llms_txt answer 'Yes', got %v", llms["answer"])
		}

		crawler := verdicts["ai_crawler_governance"].(map[string]interface{})
		if crawler["answer"] != "Yes" {
			t.Errorf("expected ai_crawler_governance answer 'Yes', got %v", crawler["answer"])
		}

		poisoning := verdicts["ai_poisoning"].(map[string]interface{})
		if poisoning["answer"] != "Yes" {
			t.Errorf("expected ai_poisoning answer 'Yes', got %v", poisoning["answer"])
		}

		hidden := verdicts["ai_hidden_prompts"].(map[string]interface{})
		if hidden["answer"] != "Yes" {
			t.Errorf("expected ai_hidden_prompts answer 'Yes', got %v", hidden["answer"])
		}
	})
}

func TestGetNumValue(t *testing.T) {
	tests := []struct {
		name     string
		m        map[string]interface{}
		key      string
		expected float64
	}{
		{"float64", map[string]interface{}{"k": float64(5)}, "k", 5},
		{"int", map[string]interface{}{"k": int(3)}, "k", 3},
		{"int64", map[string]interface{}{"k": int64(7)}, "k", 7},
		{"missing key", map[string]interface{}{}, "k", 0},
		{"string value", map[string]interface{}{"k": "nope"}, "k", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getNumValue(tt.m, tt.key)
			if got != tt.expected {
				t.Errorf("got %f, want %f", got, tt.expected)
			}
		})
	}
}

func TestGetStatus(t *testing.T) {
	tests := []struct {
		name     string
		section  map[string]interface{}
		expected string
	}{
		{"with status", map[string]interface{}{"status": "success"}, "success"},
		{"with state", map[string]interface{}{"state": "High Risk"}, "High Risk"},
		{"empty", map[string]interface{}{}, "unknown"},
		{"status preferred", map[string]interface{}{"status": "ok", "state": "bad"}, "ok"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getStatus(tt.section)
			if got != tt.expected {
				t.Errorf("got %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestComputeSectionDiff(t *testing.T) {
	t.Run("identical sections", func(t *testing.T) {
		sec := map[string]interface{}{"status": "success", "records": "v=spf1"}
		diff := ComputeSectionDiff(sec, sec, "spf", "SPF", "fa-envelope")
		if diff.Changed {
			t.Error("expected no change for identical sections")
		}
		if diff.StatusA != "success" || diff.StatusB != "success" {
			t.Error("expected both statuses to be success")
		}
	})

	t.Run("different status", func(t *testing.T) {
		secA := map[string]interface{}{"status": "success"}
		secB := map[string]interface{}{"status": "warning"}
		diff := ComputeSectionDiff(secA, secB, "spf", "SPF", "fa-envelope")
		if !diff.Changed {
			t.Error("expected change for different statuses")
		}
	})

	t.Run("different values", func(t *testing.T) {
		secA := map[string]interface{}{"status": "success", "record": "v=spf1 -all"}
		secB := map[string]interface{}{"status": "success", "record": "v=spf1 ~all"}
		diff := ComputeSectionDiff(secA, secB, "spf", "SPF", "fa-envelope")
		if !diff.Changed {
			t.Error("expected change for different record values")
		}
		if len(diff.DetailChanges) != 1 {
			t.Errorf("expected 1 detail change, got %d", len(diff.DetailChanges))
		}
	})

	t.Run("skip keys not included", func(t *testing.T) {
		secA := map[string]interface{}{"status": "success", "_schema_version": "1"}
		secB := map[string]interface{}{"status": "success", "_schema_version": "2"}
		diff := ComputeSectionDiff(secA, secB, "spf", "SPF", "fa-envelope")
		if diff.Changed {
			t.Error("skip keys should not cause changes")
		}
	})
}

func TestComputeAllDiffs(t *testing.T) {
	resultsA := map[string]interface{}{
		"spf_analysis": map[string]interface{}{"status": "success"},
	}
	resultsB := map[string]interface{}{
		"spf_analysis": map[string]interface{}{"status": "warning"},
	}
	diffs := ComputeAllDiffs(resultsA, resultsB)
	if len(diffs) != len(CompareSections) {
		t.Errorf("expected %d diffs, got %d", len(CompareSections), len(diffs))
	}
}

func TestGetSection(t *testing.T) {
	results := map[string]interface{}{
		"spf_analysis": map[string]interface{}{"status": "ok"},
	}
	sec := getSection(results, "spf_analysis")
	if sec["status"] != "ok" {
		t.Error("expected status ok")
	}
	missing := getSection(results, "nonexistent")
	if len(missing) != 0 {
		t.Error("expected empty map for missing section")
	}
}

func TestNormalizeForCompare(t *testing.T) {
	t.Run("non-array passthrough", func(t *testing.T) {
		val := normalizeForCompare("hello")
		if val != "hello" {
			t.Errorf("expected passthrough, got %v", val)
		}
	})

	t.Run("single element array passthrough", func(t *testing.T) {
		arr := []interface{}{"one"}
		val := normalizeForCompare(arr)
		result, ok := val.([]interface{})
		if ok && len(result) != 1 {
			t.Errorf("unexpected result: %v", val)
		}
	})

	t.Run("sorts string array", func(t *testing.T) {
		arr := []interface{}{"banana", "apple"}
		val := normalizeForCompare(arr)
		result, ok := val.([]interface{})
		if !ok {
			t.Fatal("expected array result")
		}
		if result[0] != "apple" || result[1] != "banana" {
			t.Errorf("expected sorted array, got %v", result)
		}
	})
}

func TestExtractRootDomain(t *testing.T) {
	tests := []struct {
		domain string
		isSub  bool
		root   string
	}{
		{"www.example.com", true, "example.com"},
		{"example.com", false, ""},
		{"sub.deep.example.com", true, "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			isSub, root := extractRootDomain(tt.domain)
			if isSub != tt.isSub {
				t.Errorf("isSubdomain = %v, want %v", isSub, tt.isSub)
			}
			if root != tt.root {
				t.Errorf("root = %q, want %q", root, tt.root)
			}
		})
	}
}

func TestIsPublicSuffixDomain(t *testing.T) {
	tests := []struct {
		domain   string
		expected bool
	}{
		{"com", true},
		{"co.uk", true},
		{"example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := isPublicSuffixDomain(tt.domain)
			if got != tt.expected {
				t.Errorf("isPublicSuffixDomain(%q) = %v, want %v", tt.domain, got, tt.expected)
			}
		})
	}
}

func TestGetChangelog(t *testing.T) {
	entries := GetChangelog()
	if len(entries) == 0 {
		t.Fatal("expected non-empty changelog")
	}
	for i, e := range entries {
		if e.Version == "" {
			t.Errorf("entry %d missing version", i)
		}
		if e.Date == "" {
			t.Errorf("entry %d missing date", i)
		}
		if e.Title == "" {
			t.Errorf("entry %d missing title", i)
		}
	}
}

func TestGetRecentChangelog(t *testing.T) {
	recent := GetRecentChangelog(3)
	if len(recent) != 3 {
		t.Errorf("expected 3 recent entries, got %d", len(recent))
	}

	all := GetChangelog()
	allRecent := GetRecentChangelog(len(all) + 10)
	if len(allRecent) != len(all) {
		t.Errorf("expected all entries when n > len, got %d", len(allRecent))
	}
}

func TestNormalizeVerdictAnswers(t *testing.T) {
	verdicts := map[string]interface{}{
		"dns_tampering": map[string]interface{}{
			"label":  "Protected",
			"reason": "No — Domain is secured with DNSSEC",
		},
		"brand_impersonation": map[string]interface{}{
			"label": "Exposed",
		},
	}

	normalizeVerdictAnswers(verdicts)

	dns := verdicts["dns_tampering"].(map[string]interface{})
	if dns["answer"] != "No" {
		t.Errorf("expected 'No', got %v", dns["answer"])
	}
	if dns["reason"] != "Domain is secured with DNSSEC" {
		t.Errorf("expected trimmed reason, got %v", dns["reason"])
	}

	brand := verdicts["brand_impersonation"].(map[string]interface{})
	if brand["answer"] != "Yes" {
		t.Errorf("expected 'Yes', got %v", brand["answer"])
	}
}

func TestNormalizeAIVerdicts(t *testing.T) {
	t.Run("llms_txt only found", func(t *testing.T) {
		results := map[string]interface{}{
			"ai_surface": map[string]interface{}{
				"llms_txt": map[string]interface{}{"found": true, "full_found": false},
			},
		}
		verdicts := map[string]interface{}{}
		normalizeAIVerdicts(results, verdicts)
		llms := verdicts["ai_llms_txt"].(map[string]interface{})
		if llms["answer"] != "Yes" {
			t.Errorf("expected 'Yes', got %v", llms["answer"])
		}
	})

	t.Run("llms_txt not found", func(t *testing.T) {
		results := map[string]interface{}{
			"ai_surface": map[string]interface{}{
				"llms_txt": map[string]interface{}{"found": false, "full_found": false},
			},
		}
		verdicts := map[string]interface{}{}
		normalizeAIVerdicts(results, verdicts)
		llms := verdicts["ai_llms_txt"].(map[string]interface{})
		if llms["answer"] != "No" {
			t.Errorf("expected 'No', got %v", llms["answer"])
		}
	})

	t.Run("robots_txt no block", func(t *testing.T) {
		results := map[string]interface{}{
			"ai_surface": map[string]interface{}{
				"robots_txt": map[string]interface{}{"found": true, "blocks_ai_crawlers": false},
			},
		}
		verdicts := map[string]interface{}{}
		normalizeAIVerdicts(results, verdicts)
		crawler := verdicts["ai_crawler_governance"].(map[string]interface{})
		if crawler["answer"] != "No" {
			t.Errorf("expected 'No', got %v", crawler["answer"])
		}
	})

	t.Run("robots_txt not found", func(t *testing.T) {
		results := map[string]interface{}{
			"ai_surface": map[string]interface{}{
				"robots_txt": map[string]interface{}{"found": false, "blocks_ai_crawlers": false},
			},
		}
		verdicts := map[string]interface{}{}
		normalizeAIVerdicts(results, verdicts)
		crawler := verdicts["ai_crawler_governance"].(map[string]interface{})
		if crawler["answer"] != "No" {
			t.Errorf("expected 'No', got %v", crawler["answer"])
		}
	})

	t.Run("poisoning zero", func(t *testing.T) {
		results := map[string]interface{}{
			"ai_surface": map[string]interface{}{
				"poisoning": map[string]interface{}{"ioc_count": float64(0)},
			},
		}
		verdicts := map[string]interface{}{}
		normalizeAIVerdicts(results, verdicts)
		p := verdicts["ai_poisoning"].(map[string]interface{})
		if p["answer"] != "No" {
			t.Errorf("expected 'No', got %v", p["answer"])
		}
	})

	t.Run("hidden prompts zero", func(t *testing.T) {
		results := map[string]interface{}{
			"ai_surface": map[string]interface{}{
				"hidden_prompts": map[string]interface{}{"artifact_count": float64(0)},
			},
		}
		verdicts := map[string]interface{}{}
		normalizeAIVerdicts(results, verdicts)
		h := verdicts["ai_hidden_prompts"].(map[string]interface{})
		if h["answer"] != "No" {
			t.Errorf("expected 'No', got %v", h["answer"])
		}
	})

	t.Run("skips if ai_llms_txt already exists", func(t *testing.T) {
		results := map[string]interface{}{
			"ai_surface": map[string]interface{}{
				"llms_txt": map[string]interface{}{"found": true},
			},
		}
		verdicts := map[string]interface{}{
			"ai_llms_txt": "already set",
		}
		normalizeAIVerdicts(results, verdicts)
		if verdicts["ai_llms_txt"] != "already set" {
			t.Error("should not overwrite existing ai_llms_txt")
		}
	})
}

func TestNormalizeEmailAnswer(t *testing.T) {
	t.Run("Unlikely", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"email_answer": "Unlikely — Well protected",
		}
		normalizeEmailAnswer(verdicts)
		if verdicts["email_answer_short"] != "Unlikely" {
			t.Errorf("expected 'Unlikely', got %v", verdicts["email_answer_short"])
		}
		if verdicts["email_answer_color"] != "success" {
			t.Errorf("expected 'success', got %v", verdicts["email_answer_color"])
		}
	})

	t.Run("Likely", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"email_answer": "Likely — Very exposed",
		}
		normalizeEmailAnswer(verdicts)
		if verdicts["email_answer_color"] != "danger" {
			t.Errorf("expected 'danger', got %v", verdicts["email_answer_color"])
		}
	})

	t.Run("Uncertain", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"email_answer": "Uncertain — Needs review",
		}
		normalizeEmailAnswer(verdicts)
		if verdicts["email_answer_color"] != "warning" {
			t.Errorf("expected 'warning', got %v", verdicts["email_answer_color"])
		}
	})

	t.Run("already has short answer", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"email_answer":       "Yes — Bad",
			"email_answer_short": "Already",
		}
		normalizeEmailAnswer(verdicts)
		if verdicts["email_answer_short"] != "Already" {
			t.Error("should not overwrite existing email_answer_short")
		}
	})

	t.Run("empty email answer", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"email_answer": "",
		}
		normalizeEmailAnswer(verdicts)
		if _, ok := verdicts["email_answer_short"]; ok {
			t.Error("should not set email_answer_short for empty answer")
		}
	})

	t.Run("no separator", func(t *testing.T) {
		verdicts := map[string]interface{}{
			"email_answer": "JustOneWord",
		}
		normalizeEmailAnswer(verdicts)
		if _, ok := verdicts["email_answer_short"]; ok {
			t.Error("should not set email_answer_short without separator")
		}
	})
}

func TestCompareSectionsStructure(t *testing.T) {
	if len(CompareSections) == 0 {
		t.Fatal("expected non-empty CompareSections")
	}
	for _, s := range CompareSections {
		if s.Key == "" || s.Label == "" || s.Icon == "" {
			t.Errorf("CompareSections entry has empty field: %+v", s)
		}
	}
}

func TestChangelogEntryFields(t *testing.T) {
	entries := GetChangelog()
	categories := map[string]bool{}
	for _, e := range entries {
		categories[e.Category] = true
		if e.Icon == "" {
			t.Errorf("changelog entry %q missing icon", e.Title)
		}
	}
	if len(categories) < 3 {
		t.Errorf("expected at least 3 categories, got %d", len(categories))
	}
}

func TestNormalizeResultsWithVerdicts(t *testing.T) {
	input := `{
                "posture": {
                        "state": "test",
                        "verdicts": {
                                "transport": {"label": "Fully Protected"},
                                "certificate_control": {"label": "Configured"}
                        }
                }
        }`
	result := NormalizeResults(json.RawMessage(input))
	posture := result["posture"].(map[string]interface{})
	verdicts := posture["verdicts"].(map[string]interface{})

	transport := verdicts["transport"].(map[string]interface{})
	if transport["answer"] != "Yes" {
		t.Errorf("expected transport answer 'Yes', got %v", transport["answer"])
	}

	cert := verdicts["certificate_control"].(map[string]interface{})
	if cert["answer"] != "Yes" {
		t.Errorf("expected certificate_control answer 'Yes', got %v", cert["answer"])
	}
}

func TestAllSourcesHaveUniqueNames(t *testing.T) {
	allSources := []IntelSource{}
	allSources = append(allSources, getDNSSources()...)
	allSources = append(allSources, getInfraSources()...)
	allSources = append(allSources, getThreatSources()...)
	allSources = append(allSources, getHistorySources()...)
	allSources = append(allSources, getMetaSources()...)

	seen := map[string]bool{}
	for _, s := range allSources {
		if seen[s.Name] {
			t.Errorf("duplicate source name: %s", s.Name)
		}
		seen[s.Name] = true
	}
}

func TestAllSourcesAreFree(t *testing.T) {
	allSources := []IntelSource{}
	allSources = append(allSources, getDNSSources()...)
	allSources = append(allSources, getInfraSources()...)
	allSources = append(allSources, getThreatSources()...)
	allSources = append(allSources, getHistorySources()...)
	allSources = append(allSources, getMetaSources()...)

	for _, s := range allSources {
		if !s.Free {
			t.Errorf("source %q is not free", s.Name)
		}
	}
}

func TestDNSSourcesHaveVerifyCmd(t *testing.T) {
	for _, s := range getDNSSources() {
		if s.VerifyCmd == "" {
			t.Errorf("DNS source %q missing VerifyCmd", s.Name)
		}
	}
}

func TestInfraSourcesHaveVerifyCmd(t *testing.T) {
	for _, s := range getInfraSources() {
		if s.VerifyCmd == "" {
			t.Errorf("infra source %q missing VerifyCmd", s.Name)
		}
	}
}

func TestThreatSourcesHaveURL(t *testing.T) {
	for _, s := range getThreatSources() {
		if s.URL == "" {
			t.Errorf("threat source %q missing URL", s.Name)
		}
	}
}

func TestMetaSourcesHaveURL(t *testing.T) {
	for _, s := range getMetaSources() {
		if s.URL == "" {
			t.Errorf("meta source %q missing URL", s.Name)
		}
	}
}

func TestDNSSourceCount(t *testing.T) {
	sources := getDNSSources()
	if len(sources) < 5 {
		t.Errorf("expected at least 5 DNS sources, got %d", len(sources))
	}
}

func TestInfraSourceCount(t *testing.T) {
	sources := getInfraSources()
	if len(sources) < 2 {
		t.Errorf("expected at least 2 infra sources, got %d", len(sources))
	}
}

func TestSourcesHandlerWithConfig(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0.0", MaintenanceNote: "test"}
	h := NewSourcesHandler(cfg)
	if h.Config != cfg {
		t.Error("expected Config to match")
	}
	if h.Config.AppVersion != "1.0.0" {
		t.Errorf("AppVersion = %q, want %q", h.Config.AppVersion, "1.0.0")
	}
}

func TestBrandColorConstants(t *testing.T) {
	if cvssSpecURL == "" {
		t.Error("cvssSpecURL should not be empty")
	}
	if firstTLPv2 == "" {
		t.Error("firstTLPv2 should not be empty")
	}
	if firstTLPURL == "" {
		t.Error("firstTLPURL should not be empty")
	}
}

func TestTLPColorsHaveSourceURL(t *testing.T) {
	for _, c := range getTLPColors() {
		if c.SourceURL == "" {
			t.Errorf("TLP color %q missing SourceURL", c.Name)
		}
		if c.Source == "" {
			t.Errorf("TLP color %q missing Source", c.Name)
		}
	}
}

func TestCVSSColorsCount(t *testing.T) {
	colors := getCVSSColors()
	if len(colors) != 5 {
		t.Errorf("expected 5 CVSS severity levels, got %d", len(colors))
	}
}

func TestTLPColorsCount(t *testing.T) {
	colors := getTLPColors()
	if len(colors) != 5 {
		t.Errorf("expected 5 TLP colors, got %d", len(colors))
	}
}

func TestBrandPaletteHasBackgroundPrimary(t *testing.T) {
	palette := getBrandPalette()
	found := false
	for _, c := range palette {
		if c.Name == "Background Primary" {
			found = true
			if c.Token != "--bg-primary" {
				t.Errorf("expected token --bg-primary, got %s", c.Token)
			}
		}
	}
	if !found {
		t.Error("expected Background Primary in brand palette")
	}
}

func TestAnalysisItemStruct(t *testing.T) {
	item := AnalysisItem{
		ID:               1,
		Domain:           "example.com",
		AsciiDomain:      "example.com",
		SpfStatus:        "success",
		DmarcStatus:      "warning",
		DkimStatus:       "success",
		AnalysisSuccess:  true,
		AnalysisDuration: 1.5,
		CreatedAt:        "2025-01-01",
		ToolVersion:      "1.0.0",
	}
	if item.ID != 1 {
		t.Errorf("ID = %d, want 1", item.ID)
	}
	if item.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", item.Domain, "example.com")
	}
	if !item.AnalysisSuccess {
		t.Error("expected AnalysisSuccess to be true")
	}
}

func TestCountryStatStruct(t *testing.T) {
	cs := CountryStat{Code: "US", Name: "United States", Count: 100, Flag: "🇺🇸"}
	if cs.Code != "US" {
		t.Errorf("Code = %q, want %q", cs.Code, "US")
	}
	if cs.Count != 100 {
		t.Errorf("Count = %d, want 100", cs.Count)
	}
}

func TestPopularDomainStruct(t *testing.T) {
	pd := PopularDomain{Domain: "google.com", Count: 500}
	if pd.Domain != "google.com" {
		t.Errorf("Domain = %q, want %q", pd.Domain, "google.com")
	}
	if pd.Count != 500 {
		t.Errorf("Count = %d, want 500", pd.Count)
	}
}

func TestDailyStatStruct(t *testing.T) {
	ds := DailyStat{
		Date:               "2025-01-01",
		TotalAnalyses:      100,
		SuccessfulAnalyses: 95,
		FailedAnalyses:     5,
		UniqueDomains:      80,
		AvgAnalysisTime:    2.5,
		HasAvgTime:         true,
	}
	if ds.TotalAnalyses != 100 {
		t.Errorf("TotalAnalyses = %d, want 100", ds.TotalAnalyses)
	}
	if ds.SuccessfulAnalyses+ds.FailedAnalyses != ds.TotalAnalyses {
		t.Error("successful + failed should equal total")
	}
	if !ds.HasAvgTime {
		t.Error("expected HasAvgTime to be true")
	}
}

func TestPageItemStruct(t *testing.T) {
	active := PageItem{Number: 1, IsActive: true, IsGap: false}
	if !active.IsActive {
		t.Error("expected active page")
	}
	gap := PageItem{IsGap: true}
	if !gap.IsGap {
		t.Error("expected gap page")
	}
}

func TestPaginationDataStruct(t *testing.T) {
	pd := BuildPagination(2, 5, 25)
	if pd.CurrentPage != 2 {
		t.Errorf("CurrentPage = %d, want 2", pd.CurrentPage)
	}
	if pd.TotalPages != 5 {
		t.Errorf("TotalPages = %d, want 5", pd.TotalPages)
	}
	if !pd.HasPrev {
		t.Error("expected HasPrev on page 2")
	}
	if !pd.HasNext {
		t.Error("expected HasNext on page 2 of 5")
	}
	if pd.PrevPage != 1 {
		t.Errorf("PrevPage = %d, want 1", pd.PrevPage)
	}
	if pd.NextPage != 3 {
		t.Errorf("NextPage = %d, want 3", pd.NextPage)
	}
}

func TestBuildPaginationFirstPage(t *testing.T) {
	pd := BuildPagination(1, 3, 30)
	if pd.HasPrev {
		t.Error("first page should not have prev")
	}
	if !pd.HasNext {
		t.Error("first page of 3 should have next")
	}
}

func TestBuildPaginationLastPage(t *testing.T) {
	pd := BuildPagination(3, 3, 30)
	if !pd.HasPrev {
		t.Error("last page should have prev")
	}
	if pd.HasNext {
		t.Error("last page should not have next")
	}
}

func TestBuildPaginationSinglePage(t *testing.T) {
	pd := BuildPagination(1, 1, 5)
	if pd.HasPrev {
		t.Error("single page should not have prev")
	}
	if pd.HasNext {
		t.Error("single page should not have next")
	}
	if len(pd.Pages) != 1 {
		t.Errorf("expected 1 page item, got %d", len(pd.Pages))
	}
}

func TestIterPagesSmall(t *testing.T) {
	pages := iterPages(1, 3)
	if len(pages) != 3 {
		t.Errorf("expected 3 page items, got %d", len(pages))
	}
	if !pages[0].IsActive {
		t.Error("first page should be active")
	}
	if pages[1].IsActive {
		t.Error("second page should not be active")
	}
}

func TestIterPagesLargeWithGaps(t *testing.T) {
	pages := iterPages(10, 20)
	hasGap := false
	for _, p := range pages {
		if p.IsGap {
			hasGap = true
			break
		}
	}
	if !hasGap {
		t.Error("expected gaps in large pagination")
	}
}

func TestDiffItemStruct(t *testing.T) {
	di := DiffItem{
		Label:   "SPF",
		Icon:    "fa-envelope",
		Changed: true,
		StatusA: "success",
		StatusB: "warning",
	}
	if di.Label != "SPF" {
		t.Errorf("Label = %q, want %q", di.Label, "SPF")
	}
	if !di.Changed {
		t.Error("expected Changed to be true")
	}
}

func TestCompareAnalysisStruct(t *testing.T) {
	ca := CompareAnalysis{
		CreatedAt:        "2025-01-01",
		ToolVersion:      "1.0.0",
		AnalysisDuration: "2.5s",
		HasToolVersion:   true,
		HasDuration:      true,
	}
	if !ca.HasToolVersion {
		t.Error("expected HasToolVersion")
	}
	if ca.ToolVersion != "1.0.0" {
		t.Errorf("ToolVersion = %q, want %q", ca.ToolVersion, "1.0.0")
	}
}
