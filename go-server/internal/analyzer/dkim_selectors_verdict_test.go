package analyzer

import (
        "strings"
        "testing"
)

func TestDetectGoogleLegacyMX_CB12(t *testing.T) {
        tests := []struct {
                name       string
                mxRecords  []string
                mxProvider string
                wantEmpty  bool
                wantSub    string
        }{
                {
                        name:       "not google provider",
                        mxRecords:  []string{"10 mail.example.com."},
                        mxProvider: "Microsoft 365",
                        wantEmpty:  true,
                },
                {
                        name:       "google fewer than 4 records",
                        mxRecords:  []string{"10 aspmx.l.google.com.", "20 alt1.aspmx.l.google.com."},
                        mxProvider: providerGoogleWS,
                        wantEmpty:  true,
                },
                {
                        name: "google legacy 5 MX records",
                        mxRecords: []string{
                                "1 aspmx.l.google.com.",
                                "5 alt1.aspmx.l.google.com.",
                                "5 alt2.aspmx.l.google.com.",
                                "10 aspmx2.googlemail.com.",
                                "10 aspmx3.googlemail.com.",
                        },
                        mxProvider: providerGoogleWS,
                        wantEmpty:  false,
                        wantSub:    "legacy Google MX records",
                },
                {
                        name: "exactly 4 google MX records",
                        mxRecords: []string{
                                "1 aspmx.l.google.com.",
                                "5 alt1.aspmx.l.google.com.",
                                "10 aspmx2.googlemail.com.",
                                "10 aspmx3.googlemail.com.",
                        },
                        mxProvider: providerGoogleWS,
                        wantEmpty:  false,
                        wantSub:    "consolidated",
                },
                {
                        name:       "empty mx records",
                        mxRecords:  nil,
                        mxProvider: providerGoogleWS,
                        wantEmpty:  true,
                },
                {
                        name: "google provider but non-google MX records",
                        mxRecords: []string{
                                "10 mail1.example.com.",
                                "20 mail2.example.com.",
                                "30 mail3.example.com.",
                                "40 mail4.example.com.",
                        },
                        mxProvider: providerGoogleWS,
                        wantEmpty:  true,
                },
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := detectGoogleLegacyMX(tt.mxRecords, tt.mxProvider)
                        if tt.wantEmpty && got != "" {
                                t.Errorf("detectGoogleLegacyMX() = %q, want empty", got)
                        }
                        if !tt.wantEmpty && got == "" {
                                t.Error("detectGoogleLegacyMX() = empty, want non-empty")
                        }
                        if tt.wantSub != "" && !strings.Contains(got, tt.wantSub) {
                                t.Errorf("detectGoogleLegacyMX() = %q, want substring %q", got, tt.wantSub)
                        }
                })
        }
}

func TestDetectAllSPFMailboxProviders_CB12(t *testing.T) {
        tests := []struct {
                name    string
                spf     string
                wantMin int
        }{
                {"empty", "", 0},
                {"google spf", "v=spf1 include:_spf.google.com -all", 1},
                {"outlook spf", "v=spf1 include:spf.protection.outlook.com -all", 1},
                {"multi provider", "v=spf1 include:_spf.google.com include:spf.protection.outlook.com -all", 2},
                {"no provider", "v=spf1 ip4:1.2.3.4 -all", 0},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := detectAllSPFMailboxProviders(tt.spf)
                        if len(got) < tt.wantMin {
                                t.Errorf("detectAllSPFMailboxProviders() len = %d, want >= %d", len(got), tt.wantMin)
                        }
                })
        }
}

func TestInferUnattributedSelectors_CB12(t *testing.T) {
        foundSelectors := map[string]map[string]any{
                "custom1._domainkey": {mapKeyProvider: providerUnknown},
                "custom2._domainkey": {mapKeyProvider: providerUnknown},
        }
        unattributed := []string{"custom1._domainkey", "custom2._domainkey"}
        foundProviders := map[string]bool{}

        note := inferUnattributedSelectors(foundSelectors, unattributed, providerGoogleWS, foundProviders)

        if note == "" {
                t.Error("expected non-empty note")
        }
        if !strings.Contains(note, providerGoogleWS) {
                t.Errorf("note %q does not mention primary provider", note)
        }
        for _, sel := range unattributed {
                if foundSelectors[sel][mapKeyProvider] != providerGoogleWS {
                        t.Errorf("selector %q provider = %v, want %q", sel, foundSelectors[sel][mapKeyProvider], providerGoogleWS)
                }
                if foundSelectors[sel]["inferred"] != true {
                        t.Errorf("selector %q inferred = %v, want true", sel, foundSelectors[sel]["inferred"])
                }
        }
        if !foundProviders[providerGoogleWS] {
                t.Error("foundProviders should include primary provider")
        }
}

func TestAttributeSelectors_CB12(t *testing.T) {
        t.Run("unknown primary returns early", func(t *testing.T) {
                foundSelectors := map[string]map[string]any{}
                foundProviders := map[string]bool{}
                inferred, note, thirdParty := attributeSelectors(foundSelectors, providerUnknown, foundProviders)
                if inferred || note != "" || thirdParty {
                        t.Errorf("attributeSelectors with unknown primary: inferred=%v note=%q thirdParty=%v", inferred, note, thirdParty)
                }
        })

        t.Run("primary has DKIM", func(t *testing.T) {
                foundSelectors := map[string]map[string]any{
                        "google._domainkey": {mapKeyProvider: providerGoogleWS},
                }
                foundProviders := map[string]bool{providerGoogleWS: true}
                inferred, _, thirdParty := attributeSelectors(foundSelectors, providerGoogleWS, foundProviders)
                if !inferred {
                        t.Error("expected inferred=true when primary has DKIM")
                }
                if thirdParty {
                        t.Error("primary has DKIM: thirdParty should be false")
                }
        })

        t.Run("third party only no unattributed", func(t *testing.T) {
                foundSelectors := map[string]map[string]any{
                        "sendgrid._domainkey": {mapKeyProvider: "SendGrid"},
                }
                foundProviders := map[string]bool{"SendGrid": true}
                _, note, thirdParty := attributeSelectors(foundSelectors, providerGoogleWS, foundProviders)
                if !thirdParty {
                        t.Error("expected thirdParty = true")
                }
                if !strings.Contains(note, providerGoogleWS) {
                        t.Errorf("note = %q, want mention of primary provider", note)
                }
        })
}

func TestBuildDKIMVerdict_CB12(t *testing.T) {
        tests := []struct {
                name           string
                selectors      map[string]map[string]any
                keyIssues      []string
                keyStrengths   []string
                primary        string
                primaryHasDKIM bool
                thirdPartyOnly bool
        }{
                {
                        name:           "no selectors",
                        selectors:      map[string]map[string]any{},
                        primary:        providerGoogleWS,
                        primaryHasDKIM: false,
                        thirdPartyOnly: false,
                },
                {
                        name: "primary found",
                        selectors: map[string]map[string]any{
                                "google._domainkey": {mapKeyProvider: providerGoogleWS},
                        },
                        keyStrengths:   []string{"2048-bit"},
                        primary:        providerGoogleWS,
                        primaryHasDKIM: true,
                },
                {
                        name: "weak keys",
                        selectors: map[string]map[string]any{
                                "sel._domainkey": {mapKeyProvider: "Custom"},
                        },
                        keyIssues:      []string{"1024-bit key"},
                        primary:        "Custom",
                        primaryHasDKIM: true,
                },
                {
                        name: "third party only",
                        selectors: map[string]map[string]any{
                                "sendgrid._domainkey": {mapKeyProvider: "SendGrid"},
                        },
                        primary:        providerGoogleWS,
                        primaryHasDKIM: false,
                        thirdPartyOnly: true,
                },
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        verdict, detail := buildDKIMVerdict(tt.selectors, tt.keyIssues, tt.keyStrengths, tt.primary, tt.primaryHasDKIM, tt.thirdPartyOnly)
                        if verdict == "" {
                                t.Error("expected non-empty verdict")
                        }
                        if detail == "" {
                                t.Error("expected non-empty detail")
                        }
                })
        }
}

func TestAnalyzeRecordKeys_CB12(t *testing.T) {
        t.Run("revoked key", func(t *testing.T) {
                keyInfoList, issues, _ := analyzeRecordKeys([]string{"v=DKIM1; k=rsa; p="})
                if len(keyInfoList) != 1 {
                        t.Fatalf("keyInfoList len = %d, want 1", len(keyInfoList))
                }
                if len(issues) == 0 {
                        t.Error("expected issues for revoked key")
                }
        })

        t.Run("empty records", func(t *testing.T) {
                keyInfoList, issues, strengths := analyzeRecordKeys(nil)
                if len(keyInfoList) != 0 {
                        t.Errorf("keyInfoList len = %d, want 0", len(keyInfoList))
                }
                if len(issues) != 0 {
                        t.Errorf("issues len = %d, want 0", len(issues))
                }
                if len(strengths) != 0 {
                        t.Errorf("strengths len = %d, want 0", len(strengths))
                }
        })

        t.Run("test mode key", func(t *testing.T) {
                keyInfoList, issues, _ := analyzeRecordKeys([]string{"v=DKIM1; t=y; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA"})
                if len(keyInfoList) != 1 {
                        t.Fatalf("keyInfoList len = %d, want 1", len(keyInfoList))
                }
                testMode, _ := keyInfoList[0]["test_mode"].(bool)
                if !testMode {
                        t.Error("expected test_mode = true")
                }
                if len(issues) == 0 {
                        t.Error("expected issues for test mode key")
                }
        })
}

func TestReclassifyAmbiguousSelectors_CB12(t *testing.T) {
        t.Run("no ambiguous selectors", func(t *testing.T) {
                selectors := map[string]map[string]any{
                        "google._domainkey": {mapKeyProvider: providerGoogleWS},
                }
                reclassifyAmbiguousSelectors(selectors, providerGoogleWS)
                if selectors["google._domainkey"][mapKeyProvider] != providerGoogleWS {
                        t.Error("should not change non-ambiguous selector")
                }
        })
}

func TestCollectFoundProviders_CB12(t *testing.T) {
        selectors := map[string]map[string]any{
                "google._domainkey":    {mapKeyProvider: providerGoogleWS},
                "selector1._domainkey": {mapKeyProvider: "Microsoft 365"},
                "unknown._domainkey":   {mapKeyProvider: providerUnknown},
        }
        providers := collectFoundProviders(selectors)
        if !providers[providerGoogleWS] {
                t.Error("expected Google Workspace in providers")
        }
        if !providers["Microsoft 365"] {
                t.Error("expected Microsoft 365 in providers")
        }
        if providers[providerUnknown] {
                t.Error("Unknown should not be in providers")
        }
}

func TestIsCustomSelector_CB12(t *testing.T) {
        tests := []struct {
                name   string
                sel    string
                custom []string
                want   bool
        }{
                {"in custom list", "myselector._domainkey", []string{"myselector"}, true},
                {"not in custom list", "google._domainkey", []string{"myselector"}, false},
                {"empty custom list", "google._domainkey", nil, false},
                {"with suffix in custom", "s1._domainkey", []string{"s1._domainkey"}, true},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := isCustomSelector(tt.sel, tt.custom)
                        if got != tt.want {
                                t.Errorf("isCustomSelector(%q, %v) = %v, want %v", tt.sel, tt.custom, got, tt.want)
                        }
                })
        }
}
