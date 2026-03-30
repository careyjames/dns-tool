package handlers

import (
        "testing"
)

func TestChangelogEntries(t *testing.T) {
        entries := GetChangelog()
        if len(entries) == 0 {
                t.Fatal("expected non-empty changelog")
        }

        for i, e := range entries {
                if e.Version == "" {
                        t.Errorf("entry[%d] has empty Version", i)
                }
                if e.Date == "" {
                        t.Errorf("entry[%d] (%s) has empty Date", i, e.Title)
                }
                if e.Title == "" {
                        t.Errorf("entry[%d] has empty Title", i)
                }
                if e.Description == "" {
                        t.Errorf("entry[%d] (%s) has empty Description", i, e.Title)
                }
                if e.Icon == "" {
                        t.Errorf("entry[%d] (%s) has empty Icon", i, e.Title)
                }
        }
}

func TestRecentChangelogSlicing(t *testing.T) {
        all := GetChangelog()

        tests := []struct {
                name    string
                n       int
                wantLen int
        }{
                {"zero", 0, 0},
                {"one", 1, 1},
                {"five", 5, 5},
                {"more than total", len(all) + 10, len(all)},
                {"exact total", len(all), len(all)},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := GetRecentChangelog(tt.n)
                        if len(got) != tt.wantLen {
                                t.Errorf("GetRecentChangelog(%d) returned %d entries, want %d", tt.n, len(got), tt.wantLen)
                        }
                })
        }

        t.Run("returns first N entries", func(t *testing.T) {
                recent := GetRecentChangelog(3)
                for i := 0; i < 3; i++ {
                        if recent[i].Title != all[i].Title {
                                t.Errorf("entry[%d] title mismatch: got %q, want %q", i, recent[i].Title, all[i].Title)
                        }
                }
        })
}

func TestGetLegacyChangelog(t *testing.T) {
        entries := GetLegacyChangelog()
        if len(entries) == 0 {
                t.Fatal("expected non-empty legacy changelog")
        }

        for i, e := range entries {
                if !e.IsLegacy {
                        t.Errorf("legacy entry[%d] (%s) has IsLegacy=false", i, e.Title)
                }
                if e.Version == "" {
                        t.Errorf("legacy entry[%d] has empty Version", i)
                }
                if e.Date == "" {
                        t.Errorf("legacy entry[%d] (%s) has empty Date", i, e.Title)
                }
                if e.Title == "" {
                        t.Errorf("legacy entry[%d] has empty Title", i)
                }
                if e.Description == "" {
                        t.Errorf("legacy entry[%d] (%s) has empty Description", i, e.Title)
                }
                if e.Icon == "" {
                        t.Errorf("legacy entry[%d] (%s) has empty Icon", i, e.Title)
                }
        }
}

func TestChangelogEntryCategories(t *testing.T) {
        entries := GetChangelog()
        validCategories := map[string]bool{
                catIntelligence: true, catSecurity: true, catTransparency: true,
                catBrand: true, catOrigins: true, catCore: true, catUX: true,
                "Architecture": true, "PWA": true, "Analytics": true, "Admin": true,
                "Reliability": true, "Quality": true, "Licensing": true,
                "Integrity": true,
        }

        for i, e := range entries {
                if e.Category == "" {
                        t.Errorf("entry[%d] (%s) has empty Category", i, e.Title)
                }
                if !validCategories[e.Category] {
                        validCategories[e.Category] = true
                }
        }
}

func TestChangelogNoDuplicateTitles(t *testing.T) {
        entries := GetChangelog()
        seen := make(map[string]bool)
        for _, e := range entries {
                if seen[e.Title] {
                        t.Errorf("duplicate changelog title: %q", e.Title)
                }
                seen[e.Title] = true
        }
}

func TestChangelogDateConstants(t *testing.T) {
        if dateFeb23 == "" || dateFeb21 == "" || dateFeb19 == "" {
                t.Error("expected non-empty date constants")
        }
        if dateFeb23 != "Feb 23, 2026" {
                t.Errorf("unexpected dateFeb23: %q", dateFeb23)
        }
}

func TestChangelogVersionConstants(t *testing.T) {
        versions := []struct {
                name string
                val  string
        }{
                {"ver262525", ver262525},
                {"ver262225", ver262225},
                {"ver262088", ver262088},
                {"ver262076", ver262076},
        }
        for _, v := range versions {
                if v.val == "" {
                        t.Errorf("%s is empty", v.name)
                }
        }
}

func TestChangelogIconConstants(t *testing.T) {
        if iconShieldAlt != "shield-alt" {
                t.Errorf("unexpected iconShieldAlt: %q", iconShieldAlt)
        }
}

func TestChangelogCategoryConstants(t *testing.T) {
        cats := map[string]string{
                "catIntelligence": catIntelligence,
                "catSecurity":     catSecurity,
                "catTransparency": catTransparency,
                "catBrand":        catBrand,
                "catOrigins":      catOrigins,
                "catCore":         catCore,
                "catUX":           catUX,
        }
        for name, val := range cats {
                if val == "" {
                        t.Errorf("%s is empty", name)
                }
        }
}

func TestChangelogEntryStructFields(t *testing.T) {
        entry := ChangelogEntry{
                Version:     "1.0.0",
                Date:        "Jan 1, 2026",
                Category:    "Test",
                Title:       "Test Entry",
                Description: "A test",
                Icon:        "fas fa-test",
                IsIncident:  true,
                IsLegacy:    false,
        }
        if entry.Version != "1.0.0" {
                t.Errorf("unexpected Version: %q", entry.Version)
        }
        if !entry.IsIncident {
                t.Error("expected IsIncident=true")
        }
        if entry.IsLegacy {
                t.Error("expected IsLegacy=false")
        }
}

func TestGetRecentChangelogZero(t *testing.T) {
        recent := GetRecentChangelog(0)
        if len(recent) != 0 {
                t.Errorf("expected 0 entries for n=0, got %d", len(recent))
        }
}

func TestGetRecentChangelogPreservesOrder(t *testing.T) {
        all := GetChangelog()
        if len(all) < 5 {
                t.Skip("not enough changelog entries")
        }
        recent := GetRecentChangelog(5)
        for i := 0; i < 5; i++ {
                if recent[i].Version != all[i].Version || recent[i].Title != all[i].Title {
                        t.Errorf("entry[%d] mismatch between recent and all", i)
                }
        }
}

func TestChangelogAllIconsHavePrefix(t *testing.T) {
        entries := GetChangelog()
        for i, e := range entries {
                if e.Icon == "" {
                        t.Errorf("entry[%d] (%s) icon is empty", i, e.Title)
                }
        }
}

func TestLegacyChangelogAllIsLegacy(t *testing.T) {
        entries := GetLegacyChangelog()
        for i, e := range entries {
                if !e.IsLegacy {
                        t.Errorf("legacy entry[%d] (%s) should have IsLegacy=true", i, e.Title)
                }
        }
}

func TestChangelogNonLegacy(t *testing.T) {
        entries := GetChangelog()
        for i, e := range entries {
                if e.IsLegacy {
                        t.Errorf("entry[%d] (%s) should not have IsLegacy=true in main changelog", i, e.Title)
                }
        }
}

func TestNewChangelogHandler(t *testing.T) {
        h := NewChangelogHandler(nil)
        if h == nil {
                t.Fatal("expected non-nil ChangelogHandler")
        }
}
