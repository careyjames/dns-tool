package citation

import (
        "strings"
        "testing"
)

func TestRegistryLoads(t *testing.T) {
        r := Global()
        all := r.All()
        if len(all) == 0 {
                t.Fatal("expected non-empty registry")
        }
}

func TestLookupByID(t *testing.T) {
        r := Global()
        tests := []struct {
                id    string
                found bool
                title string
        }{
                {"rfc:7208", true, "Sender Policy Framework"},
                {"rfc:7489", true, "DMARC"},
                {"rfc:6376", true, "DKIM"},
                {"nist:800-177", true, "Trustworthy Email"},
                {"odni:icd-203", true, "Analytic Standards"},
                {"iso:25012", true, "Data Quality"},
                {"nonexistent:123", false, ""},
        }
        for _, tt := range tests {
                e, ok := r.Lookup(tt.id)
                if ok != tt.found {
                        t.Errorf("Lookup(%q): got found=%v, want %v", tt.id, ok, tt.found)
                        continue
                }
                if ok && !strings.Contains(e.Title, tt.title) {
                        t.Errorf("Lookup(%q): title=%q, want it to contain %q", tt.id, e.Title, tt.title)
                }
        }
}

func TestLookupWithSection(t *testing.T) {
        r := Global()
        e, ok := r.Lookup("rfc:7489§6.3")
        if !ok {
                t.Fatal("expected to find rfc:7489 when looking up rfc:7489§6.3")
        }
        if e.ID != "rfc:7489" {
                t.Errorf("expected ID rfc:7489, got %s", e.ID)
        }
}

func TestResolveRFC(t *testing.T) {
        r := Global()
        label, url := r.ResolveRFC("rfc:7489§6.3")
        if label != "RFC 7489 §6.3" {
                t.Errorf("label=%q, want RFC 7489 §6.3", label)
        }
        if !strings.Contains(url, "section-6.3") {
                t.Errorf("url=%q, want section-6.3", url)
        }

        label2, url2 := r.ResolveRFC("rfc:7208")
        if label2 != "RFC 7208" {
                t.Errorf("label=%q, want RFC 7208", label2)
        }
        if url2 != "https://datatracker.ietf.org/doc/html/rfc7208" {
                t.Errorf("url=%q", url2)
        }
}

func TestIsObsolete(t *testing.T) {
        r := Global()
        if !r.IsObsolete("rfc:8624") {
                t.Error("expected rfc:8624 to be obsolete")
        }
        if r.IsObsolete("rfc:7208") {
                t.Error("expected rfc:7208 to not be obsolete")
        }
}

func TestFilter(t *testing.T) {
        r := Global()
        rfcs := r.ByType("rfc")
        if len(rfcs) == 0 {
                t.Fatal("expected non-empty RFC list")
        }
        for _, e := range rfcs {
                if e.Type != "rfc" {
                        t.Errorf("ByType(rfc): got type=%q for %s", e.Type, e.ID)
                }
        }

        email := r.ByFunctionalArea("email-authentication")
        if len(email) == 0 {
                t.Fatal("expected non-empty email-authentication list")
        }

        filtered := r.Filter("rfc", "standards-track", "email-authentication", "")
        if len(filtered) == 0 {
                t.Fatal("expected non-empty filtered list")
        }
}

func TestSearch(t *testing.T) {
        r := Global()
        results := r.Search("DMARC")
        if len(results) == 0 {
                t.Fatal("expected search for DMARC to return results")
        }
}

func TestManifest(t *testing.T) {
        m := NewManifest()
        m.Cite("rfc:7208")
        m.Cite("rfc:7489")
        m.Cite("rfc:7208")

        ids := m.IDs()
        if len(ids) != 2 {
                t.Errorf("expected 2 unique IDs, got %d", len(ids))
        }

        r := Global()
        entries := m.Entries(r)
        if len(entries) != 2 {
                t.Errorf("expected 2 manifest entries, got %d", len(entries))
        }
}

func TestBibTeXExport(t *testing.T) {
        entries := []ManifestEntry{
                {ID: "rfc:7208", Title: "SPF", URL: "https://example.com", Type: "rfc"},
        }
        out := EntriesToBibTeX(entries)
        if !strings.Contains(out, "@misc{rfc_7208") {
                t.Errorf("BibTeX output missing key: %s", out)
        }
        if !strings.Contains(out, "SPF") {
                t.Errorf("BibTeX output missing title: %s", out)
        }
}

func TestRISExport(t *testing.T) {
        entries := []ManifestEntry{
                {ID: "rfc:7208", Title: "SPF", URL: "https://example.com", Type: "rfc"},
        }
        out := EntriesToRIS(entries)
        if !strings.Contains(out, "TY  - ELEC") {
                t.Errorf("RIS output missing type: %s", out)
        }
}

func TestCSLJSONExport(t *testing.T) {
        entries := []ManifestEntry{
                {ID: "rfc:7208", Title: "SPF", URL: "https://example.com", Type: "rfc"},
        }
        out, err := EntriesToCSLJSON(entries)
        if err != nil {
                t.Fatalf("CSL-JSON export error: %v", err)
        }
        if !strings.Contains(out, `"id"`) {
                t.Errorf("CSL-JSON output missing id: %s", out)
        }
}

func TestSoftwareExport(t *testing.T) {
        bib := SoftwareToBibTeX("DNS Tool", "1.0", "10.5281/z", "https://x.com", "Doe", "John", "2026-01-01")
        if !strings.Contains(bib, "@software{dnstool") {
                t.Errorf("software BibTeX missing key: %s", bib)
        }
        ris := SoftwareToRIS("DNS Tool", "1.0", "10.5281/z", "https://x.com", "Doe", "John", "2026-01-01")
        if !strings.Contains(ris, "TY  - COMP") {
                t.Errorf("software RIS missing type: %s", ris)
        }
        csl, err := SoftwareToCSLJSON("DNS Tool", "1.0", "10.5281/z", "https://x.com", "Doe", "John", "2026-01-01")
        if err != nil {
                t.Fatalf("software CSL-JSON error: %v", err)
        }
        if !strings.Contains(csl, `"software"`) {
                t.Errorf("software CSL-JSON missing type: %s", csl)
        }
}

func TestDuplicateIDDetection(t *testing.T) {
        yamlData := []byte(`citations:
  - id: "rfc:1234"
    type: rfc
    title: "First"
    url: "https://example.com/1"
    status: current
    area: dns
  - id: "rfc:1234"
    type: rfc
    title: "Duplicate"
    url: "https://example.com/2"
    status: current
    area: dns
`)
        _, err := parseRegistry(yamlData)
        if err == nil {
                t.Fatal("expected error for duplicate ID, got nil")
        }
        if !strings.Contains(err.Error(), "duplicate citation ID") {
                t.Errorf("expected 'duplicate citation ID' error, got: %v", err)
        }
}

func TestEmptyIDDetection(t *testing.T) {
        yamlData := []byte(`citations:
  - id: ""
    type: rfc
    title: "No ID"
    url: "https://example.com"
    status: current
    area: dns
`)
        _, err := parseRegistry(yamlData)
        if err == nil {
                t.Fatal("expected error for empty ID, got nil")
        }
        if !strings.Contains(err.Error(), "empty ID") {
                t.Errorf("expected 'empty ID' error, got: %v", err)
        }
}

func TestNoDuplicateIDsInProductionRegistry(t *testing.T) {
        r := Global()
        all := r.All()
        seen := make(map[string]bool, len(all))
        for _, e := range all {
                if seen[e.ID] {
                        t.Fatalf("production registry has duplicate ID: %s", e.ID)
                }
                seen[e.ID] = true
        }
}

func TestAuthoritiesMDSyncWithRegistry(t *testing.T) {
        for _, path := range []string{
                "../../../AUTHORITIES.md",
                "../../AUTHORITIES.md",
                "../AUTHORITIES.md",
                "AUTHORITIES.md",
        } {
                result, err := ValidateAuthoritiesMD(path)
                if err != nil {
                        continue
                }
                if !result.OK {
                        for _, msg := range result.Messages {
                                t.Error(msg)
                        }
                }
                return
        }
        t.Skip("AUTHORITIES.md not found in expected locations")
}

func TestMustLookup_Found(t *testing.T) {
        r := Global()
        e := r.MustLookup("rfc:7208")
        if e.ID != "rfc:7208" {
                t.Errorf("MustLookup found ID = %q, want rfc:7208", e.ID)
        }
        if e.Title == "" {
                t.Error("MustLookup found entry has empty title")
        }
}

func TestMustLookup_NotFound(t *testing.T) {
        r := Global()
        e := r.MustLookup("nonexistent:999")
        if e.ID != "nonexistent:999" {
                t.Errorf("MustLookup fallback ID = %q, want nonexistent:999", e.ID)
        }
        if e.Title != "nonexistent:999" {
                t.Errorf("MustLookup fallback Title = %q, want nonexistent:999", e.Title)
        }
        if e.URL != "" {
                t.Errorf("MustLookup fallback URL = %q, want empty", e.URL)
        }
}

func TestResolveSectionURL(t *testing.T) {
        r := Global()

        url := r.ResolveSectionURL("rfc:7208", "5")
        if !strings.Contains(url, "#section-5") {
                t.Errorf("ResolveSectionURL with section: got %q, want #section-5", url)
        }

        url2 := r.ResolveSectionURL("rfc:7208", "")
        if strings.Contains(url2, "#section") {
                t.Errorf("ResolveSectionURL without section should not have anchor: %q", url2)
        }
        if url2 == "" {
                t.Error("ResolveSectionURL without section returned empty URL")
        }

        url3 := r.ResolveSectionURL("nonexistent:999", "5")
        if url3 != "" {
                t.Errorf("ResolveSectionURL for unknown ID = %q, want empty", url3)
        }
}

func TestByStatus(t *testing.T) {
        r := Global()
        entries := r.ByStatus("standards-track")
        if len(entries) == 0 {
                t.Fatal("expected non-empty standards-track list")
        }
        for _, e := range entries {
                if e.Status != "standards-track" {
                        t.Errorf("ByStatus(standards-track): got status=%q for %s", e.Status, e.ID)
                }
        }

        empty := r.ByStatus("nonexistent-status")
        if len(empty) != 0 {
                t.Errorf("ByStatus(nonexistent) = %d entries, want 0", len(empty))
        }
}

func TestCiteSection(t *testing.T) {
        m := NewManifest()
        m.CiteSection("rfc:7208", "5")
        m.CiteSection("rfc:7208", "5")

        ids := m.IDs()
        if len(ids) != 1 {
                t.Errorf("expected 1 unique ID after duplicate CiteSection, got %d", len(ids))
        }
        if ids[0] != "rfc:7208§5" {
                t.Errorf("expected rfc:7208§5, got %s", ids[0])
        }
}

func TestMapCSLType(t *testing.T) {
        tests := []struct {
                input string
                want  string
        }{
                {"rfc", "report"},
                {"draft", "report"},
                {"standard", "standard"},
                {"directive", "standard"},
                {"tool", "software"},
                {"data-source", "webpage"},
                {"unknown", "document"},
                {"", "document"},
        }
        for _, tt := range tests {
                got := mapCSLType(tt.input)
                if got != tt.want {
                        t.Errorf("mapCSLType(%q) = %q, want %q", tt.input, got, tt.want)
                }
        }
}

func TestBibTeXExport_WithSection(t *testing.T) {
        entries := []ManifestEntry{
                {ID: "rfc:7208", Section: "5", Title: "SPF", URL: "https://example.com#section-5", Type: "rfc"},
        }
        out := EntriesToBibTeX(entries)
        if !strings.Contains(out, "Section 5") {
                t.Errorf("BibTeX with section missing Section 5: %s", out)
        }
        if !strings.Contains(out, "_s5") {
                t.Errorf("BibTeX with section missing key suffix: %s", out)
        }
}

func TestRISExport_WithSection(t *testing.T) {
        entries := []ManifestEntry{
                {ID: "rfc:7208", Section: "5", Title: "SPF", URL: "https://example.com#section-5", Type: "rfc"},
        }
        out := EntriesToRIS(entries)
        if !strings.Contains(out, "Section 5") {
                t.Errorf("RIS with section missing Section 5: %s", out)
        }
        if !strings.Contains(out, "§5") {
                t.Errorf("RIS with section missing §5 in ID: %s", out)
        }
}

func TestCSLJSONExport_WithSection(t *testing.T) {
        entries := []ManifestEntry{
                {ID: "rfc:7208", Section: "5", Title: "SPF", URL: "https://example.com#section-5", Type: "rfc"},
        }
        out, err := EntriesToCSLJSON(entries)
        if err != nil {
                t.Fatalf("CSL-JSON export error: %v", err)
        }
        if !strings.Contains(out, `"section"`) {
                t.Errorf("CSL-JSON with section missing section field: %s", out)
        }
}

func TestBibTeXExport_Empty(t *testing.T) {
        out := EntriesToBibTeX(nil)
        if out != "" {
                t.Errorf("expected empty output for nil entries, got %q", out)
        }
}

func TestRISExport_Empty(t *testing.T) {
        out := EntriesToRIS(nil)
        if out != "" {
                t.Errorf("expected empty output for nil entries, got %q", out)
        }
}

func TestCSLJSONExport_Empty(t *testing.T) {
        out, err := EntriesToCSLJSON(nil)
        if err != nil {
                t.Fatalf("error: %v", err)
        }
        if out != "[]" {
                t.Errorf("expected empty array, got %q", out)
        }
}

func TestEscapeBibTeX(t *testing.T) {
        tests := []struct {
                input string
                want  string
        }{
                {"Hello & World", `Hello \& World`},
                {"100%", `100\%`},
                {"#tag", `\#tag`},
                {"under_score", `under\_score`},
                {"no special", "no special"},
        }
        for _, tt := range tests {
                got := escapeBibTeX(tt.input)
                if got != tt.want {
                        t.Errorf("escapeBibTeX(%q) = %q, want %q", tt.input, got, tt.want)
                }
        }
}

func TestBibKey(t *testing.T) {
        tests := []struct {
                input string
                want  string
        }{
                {"rfc:7208", "rfc_7208"},
                {"a.b-c d", "a_b_c_d"},
        }
        for _, tt := range tests {
                got := bibKey(tt.input)
                if got != tt.want {
                        t.Errorf("bibKey(%q) = %q, want %q", tt.input, got, tt.want)
                }
        }
}

func TestResolveRFC_NotFound(t *testing.T) {
        r := Global()
        label, url := r.ResolveRFC("nonexistent:999")
        if label != "nonexistent:999" {
                t.Errorf("label = %q, want nonexistent:999", label)
        }
        if url != "" {
                t.Errorf("url = %q, want empty", url)
        }
}

func TestIsObsolete_NotFound(t *testing.T) {
        r := Global()
        if r.IsObsolete("nonexistent:999") {
                t.Error("nonexistent ID should not be obsolete")
        }
}

func TestFilter_WithQuery(t *testing.T) {
        r := Global()
        filtered := r.Filter("", "", "", "SPF")
        if len(filtered) == 0 {
                t.Fatal("expected results for query 'SPF'")
        }
}

func TestFilter_NoMatch(t *testing.T) {
        r := Global()
        filtered := r.Filter("nonexistent-type", "", "", "")
        if len(filtered) != 0 {
                t.Errorf("expected 0 results, got %d", len(filtered))
        }
}

func TestManifest_EntriesUnknownID(t *testing.T) {
        m := NewManifest()
        m.Cite("nonexistent:999")
        r := Global()
        entries := m.Entries(r)
        if len(entries) != 0 {
                t.Errorf("expected 0 entries for unknown ID, got %d", len(entries))
        }
}

func TestParseRegistry_InvalidYAML(t *testing.T) {
        _, err := parseRegistry([]byte("not: [valid: yaml: {{"))
        if err == nil {
                t.Fatal("expected error for invalid YAML")
        }
}

func TestManifestSectionPreservation(t *testing.T) {
        m := NewManifest()
        m.Cite("rfc:7489§6.3")
        m.Cite("rfc:7208")

        reg := Global()
        entries := m.Entries(reg)

        if len(entries) != 2 {
                t.Fatalf("expected 2 entries, got %d", len(entries))
        }

        var sectionEntry *ManifestEntry
        for i := range entries {
                if entries[i].Section != "" {
                        sectionEntry = &entries[i]
                }
        }
        if sectionEntry == nil {
                t.Fatal("expected one entry with section, got none")
        }
        if sectionEntry.ID != "rfc:7489" {
                t.Errorf("expected base ID rfc:7489, got %s", sectionEntry.ID)
        }
        if sectionEntry.Section != "6.3" {
                t.Errorf("expected section 6.3, got %s", sectionEntry.Section)
        }
        if !strings.Contains(sectionEntry.URL, "#section-6.3") {
                t.Errorf("expected URL with section anchor, got %s", sectionEntry.URL)
        }
}
