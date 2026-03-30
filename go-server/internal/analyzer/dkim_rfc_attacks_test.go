package analyzer

import (
        "context"
        "strings"
        "testing"
)

type mockDKIMDNS struct {
        responses map[string][]string
}

func (m *mockDKIMDNS) QueryDNS(ctx context.Context, recordType, domain string) []string {
        key := recordType + ":" + domain
        if r, ok := m.responses[key]; ok {
                return r
        }
        return nil
}

func TestDKIMRFCAttackMalformedPublicKey(t *testing.T) {
        tests := []struct {
                name        string
                record      string
                wantRevoked bool
                wantNilBits bool
                wantIssues  bool
        }{
                {
                        name:        "missing p= tag entirely",
                        record:      "v=DKIM1; k=rsa",
                        wantRevoked: false,
                        wantNilBits: true,
                        wantIssues:  false,
                },
                {
                        name:        "empty p= (revoked key per RFC 6376 §3.6.1)",
                        record:      "v=DKIM1; k=rsa; p=",
                        wantRevoked: true,
                        wantNilBits: true,
                        wantIssues:  true,
                },
                {
                        name:        "invalid base64 in p=",
                        record:      "v=DKIM1; k=rsa; p=!!!not-base64!!!",
                        wantRevoked: false,
                        wantNilBits: true,
                        wantIssues:  false,
                },
                {
                        name:        "valid short key (1024-bit weak)",
                        record:      "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3QZ6gC4W1",
                        wantRevoked: false,
                        wantNilBits: false,
                        wantIssues:  true,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        bits, revoked, issues := analyzePublicKey(tt.record)
                        if revoked != tt.wantRevoked {
                                t.Errorf("revoked = %v, want %v", revoked, tt.wantRevoked)
                        }
                        if tt.wantNilBits && bits != nil {
                                t.Errorf("expected nil bits, got %v", bits)
                        }
                        if !tt.wantNilBits && bits == nil {
                                t.Error("expected non-nil bits")
                        }
                        if tt.wantIssues && len(issues) == 0 {
                                t.Error("expected issues but got none")
                        }
                        if !tt.wantIssues && len(issues) > 0 {
                                t.Errorf("expected no issues, got %v", issues)
                        }
                })
        }
}

func TestDKIMRFCAttackKeyTypeValidation(t *testing.T) {
        tests := []struct {
                name        string
                record      string
                wantKeyType string
        }{
                {
                        name:        "rsa key type (default)",
                        record:      "v=DKIM1; k=rsa; p=AAAA",
                        wantKeyType: "rsa",
                },
                {
                        name:        "ed25519 key type",
                        record:      "v=DKIM1; k=ed25519; p=AAAA",
                        wantKeyType: "ed25519",
                },
                {
                        name:        "no explicit key type defaults to rsa",
                        record:      "v=DKIM1; p=AAAA",
                        wantKeyType: "rsa",
                },
                {
                        name:        "case insensitive key type",
                        record:      "v=DKIM1; K=RSA; p=AAAA",
                        wantKeyType: "rsa",
                },
                {
                        name:        "unsupported algorithm type",
                        record:      "v=DKIM1; k=dsa; p=AAAA",
                        wantKeyType: "dsa",
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        result := analyzeDKIMKey(tt.record)
                        got := result["key_type"].(string)
                        if got != tt.wantKeyType {
                                t.Errorf("key_type = %q, want %q", got, tt.wantKeyType)
                        }
                })
        }
}

func TestDKIMRFCAttackTestModeFlag(t *testing.T) {
        tests := []struct {
                name         string
                record       string
                wantTestMode bool
        }{
                {
                        name:         "t=y flag present (RFC 6376 §3.6.1 test mode)",
                        record:       "v=DKIM1; k=rsa; t=y; p=AAAA",
                        wantTestMode: true,
                },
                {
                        name:         "no t=y flag",
                        record:       "v=DKIM1; k=rsa; p=AAAA",
                        wantTestMode: false,
                },
                {
                        name:         "t=s flag (not test mode)",
                        record:       "v=DKIM1; k=rsa; t=s; p=AAAA",
                        wantTestMode: false,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        result := analyzeDKIMKey(tt.record)
                        got := result["test_mode"].(bool)
                        if got != tt.wantTestMode {
                                t.Errorf("test_mode = %v, want %v", got, tt.wantTestMode)
                        }
                })
        }
}

func TestDKIMRFCAttackSelectorNamingEdgeCases(t *testing.T) {
        tests := []struct {
                name       string
                selector   string
                wantKnown  bool
        }{
                {
                        name:      "standard google selector",
                        selector:  "google._domainkey",
                        wantKnown: true,
                },
                {
                        name:      "microsoft selector1",
                        selector:  "selector1._domainkey",
                        wantKnown: true,
                },
                {
                        name:      "microsoft selector2",
                        selector:  "selector2._domainkey",
                        wantKnown: true,
                },
                {
                        name:      "unknown custom selector",
                        selector:  "verylongcustomselectorname12345._domainkey",
                        wantKnown: false,
                },
                {
                        name:      "selector with special chars attempt",
                        selector:  "my-custom-sel._domainkey",
                        wantKnown: false,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := AllSelectorsKnown([]string{tt.selector})
                        if got != tt.wantKnown {
                                t.Errorf("AllSelectorsKnown(%q) = %v, want %v", tt.selector, got, tt.wantKnown)
                        }
                })
        }
}

func TestDKIMRFCAttackProviderDetection(t *testing.T) {
        tests := []struct {
                name         string
                selector     string
                wantProvider string
        }{
                {
                        name:         "Google selector",
                        selector:     selGoogle,
                        wantProvider: providerGoogleWS,
                },
                {
                        name:         "Microsoft selector1",
                        selector:     selSelector1,
                        wantProvider: providerMicrosoft365,
                },
                {
                        name:         "Microsoft selector2",
                        selector:     selSelector2,
                        wantProvider: providerMicrosoft365,
                },
                {
                        name:         "SendGrid s1",
                        selector:     selS1,
                        wantProvider: providerSendGrid,
                },
                {
                        name:         "SendGrid s2",
                        selector:     selS2,
                        wantProvider: providerSendGrid,
                },
                {
                        name:         "Amazon SES",
                        selector:     selAmazonSES,
                        wantProvider: providerAmazonSES,
                },
                {
                        name:         "Postmark",
                        selector:     selPostmark,
                        wantProvider: providerPostmark,
                },
                {
                        name:         "Mailchimp k1",
                        selector:     selK1,
                        wantProvider: providerMailChimp,
                },
                {
                        name:         "unknown selector returns Unknown",
                        selector:     "nonexistent._domainkey",
                        wantProvider: providerUnknown,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := classifySelectorProvider(tt.selector, tt.wantProvider)
                        if got != tt.wantProvider {
                                t.Errorf("classifySelectorProvider(%q) = %q, want %q", tt.selector, got, tt.wantProvider)
                        }
                })
        }
}

func TestDKIMRFCAttackAmbiguousSelectorWithUnknownPrimary(t *testing.T) {
        ambiguous := []string{selSelector1, selSelector2, selS1, selS2, selDefault, selK1, selK2}
        for _, sel := range ambiguous {
                t.Run(sel, func(t *testing.T) {
                        got := classifySelectorProvider(sel, providerUnknown)
                        if got != providerUnknown {
                                t.Errorf("ambiguous selector %q with unknown primary should return %q, got %q", sel, providerUnknown, got)
                        }
                })
        }
}

func TestDKIMRFCAttackMatchProviderFromRecords(t *testing.T) {
        tests := []struct {
                name        string
                records     string
                providerMap map[string]string
                want        string
        }{
                {
                        name:        "case insensitive matching",
                        records:     "ASPMX.L.GOOGLE.COM",
                        providerMap: mxToDKIMProvider,
                        want:        providerGoogleWS,
                },
                {
                        name:        "empty records",
                        records:     "",
                        providerMap: mxToDKIMProvider,
                        want:        "",
                },
                {
                        name:        "no match",
                        records:     "mx.customdomain.example.net",
                        providerMap: mxToDKIMProvider,
                        want:        "",
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := matchProviderFromRecords(tt.records, tt.providerMap)
                        if got != tt.want {
                                t.Errorf("matchProviderFromRecords = %q, want %q", got, tt.want)
                        }
                })
        }
}

func TestDKIMRFCAttackDetectPrimaryMailProvider(t *testing.T) {
        tests := []struct {
                name        string
                mxRecords   []string
                spfRecord   string
                wantPrimary string
        }{
                {
                        name:        "no MX no SPF",
                        mxRecords:   nil,
                        spfRecord:   "",
                        wantPrimary: providerUnknown,
                },
                {
                        name:        "Google MX only",
                        mxRecords:   []string{"aspmx.l.google.com"},
                        spfRecord:   "",
                        wantPrimary: providerGoogleWS,
                },
                {
                        name:        "Microsoft MX only",
                        mxRecords:   []string{"mail.protection.outlook.com"},
                        spfRecord:   "",
                        wantPrimary: providerMicrosoft365,
                },
                {
                        name:        "SPF includes Google",
                        mxRecords:   nil,
                        spfRecord:   "v=spf1 include:_spf.google.com ~all",
                        wantPrimary: providerGoogleWS,
                },
                {
                        name:        "Proofpoint MX with Google SPF (gateway detection)",
                        mxRecords:   []string{"us1.mx.pphosted.com"},
                        spfRecord:   "v=spf1 include:_spf.google.com ~all",
                        wantPrimary: providerGoogleWS,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        res := detectPrimaryMailProvider(tt.mxRecords, tt.spfRecord)
                        if res.Primary != tt.wantPrimary {
                                t.Errorf("Primary = %q, want %q", res.Primary, tt.wantPrimary)
                        }
                })
        }
}

func TestDKIMRFCAttackCheckDKIMSelector(t *testing.T) {
        tests := []struct {
                name       string
                selector   string
                domain     string
                responses  map[string][]string
                wantSel    string
                wantNilRec bool
        }{
                {
                        name:     "valid DKIM record found",
                        selector: "google._domainkey",
                        domain:   "example.com",
                        responses: map[string][]string{
                                "TXT:google._domainkey.example.com": {"v=DKIM1; k=rsa; p=AAAA"},
                        },
                        wantSel:    "google._domainkey",
                        wantNilRec: false,
                },
                {
                        name:       "no records returned",
                        selector:   "google._domainkey",
                        domain:     "example.com",
                        responses:  map[string][]string{},
                        wantSel:    "",
                        wantNilRec: true,
                },
                {
                        name:     "TXT record but not DKIM",
                        selector: "google._domainkey",
                        domain:   "example.com",
                        responses: map[string][]string{
                                "TXT:google._domainkey.example.com": {"some-non-dkim-record"},
                        },
                        wantSel:    "",
                        wantNilRec: true,
                },
                {
                        name:     "multiple DKIM records for same selector",
                        selector: "selector1._domainkey",
                        domain:   "example.com",
                        responses: map[string][]string{
                                "TXT:selector1._domainkey.example.com": {
                                        "v=DKIM1; k=rsa; p=AAAA",
                                        "v=DKIM1; k=rsa; p=BBBB",
                                },
                        },
                        wantSel:    "selector1._domainkey",
                        wantNilRec: false,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        dns := &mockDKIMDNS{responses: tt.responses}
                        sel, recs := checkDKIMSelector(context.Background(), dns, tt.selector, tt.domain)
                        if sel != tt.wantSel {
                                t.Errorf("selector = %q, want %q", sel, tt.wantSel)
                        }
                        if tt.wantNilRec && recs != nil {
                                t.Errorf("expected nil records, got %v", recs)
                        }
                        if !tt.wantNilRec && recs == nil {
                                t.Error("expected non-nil records")
                        }
                })
        }
}

func TestDKIMRFCAttackHashAlgorithmDeprecation(t *testing.T) {
        tests := []struct {
                name       string
                keyType    string
                keyBits    int
                wantWeak   bool
                wantDeprec bool
        }{
                {
                        name:       "RSA 2048 strong",
                        keyType:    "rsa",
                        keyBits:    2048,
                        wantWeak:   false,
                        wantDeprec: false,
                },
                {
                        name:       "RSA 1024 weak per RFC 8301",
                        keyType:    "rsa",
                        keyBits:    1024,
                        wantWeak:   true,
                        wantDeprec: false,
                },
                {
                        name:       "RSA 512 deprecated",
                        keyType:    "rsa",
                        keyBits:    512,
                        wantWeak:   false,
                        wantDeprec: true,
                },
                {
                        name:       "ed25519 any size is strong",
                        keyType:    "ed25519",
                        keyBits:    256,
                        wantWeak:   false,
                        wantDeprec: false,
                },
                {
                        name:       "RSA 4096 strong",
                        keyType:    "rsa",
                        keyBits:    4096,
                        wantWeak:   false,
                        wantDeprec: false,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        c := ClassifyDKIMKey(tt.keyType, tt.keyBits)
                        if tt.wantWeak && c.Strength != "weak" {
                                t.Errorf("expected weak strength, got %q", c.Strength)
                        }
                        if tt.wantDeprec && c.Strength != "deprecated" {
                                t.Errorf("expected deprecated strength, got %q", c.Strength)
                        }
                        if !tt.wantWeak && !tt.wantDeprec && (c.Strength == "weak" || c.Strength == "deprecated") {
                                t.Errorf("expected non-weak/non-deprecated strength, got %q", c.Strength)
                        }
                })
        }
}

func TestDKIMRFCAttackBuildDKIMVerdict(t *testing.T) {
        tests := []struct {
                name           string
                selectors      map[string]map[string]any
                keyIssues      []string
                keyStrengths   []string
                primary        string
                primaryHasDKIM bool
                thirdPartyOnly bool
                wantStatus     string
        }{
                {
                        name:       "no selectors found",
                        selectors:  nil,
                        wantStatus: "info",
                },
                {
                        name: "selectors with revoked key",
                        selectors: map[string]map[string]any{
                                "sel1": {"provider": providerGoogleWS},
                        },
                        keyIssues:      []string{"Key revoked (p= empty)"},
                        primary:        providerGoogleWS,
                        primaryHasDKIM: true,
                        wantStatus:     "warning",
                },
                {
                        name: "selectors with weak key",
                        selectors: map[string]map[string]any{
                                "sel1": {"provider": providerGoogleWS},
                        },
                        keyIssues:      []string{"1024-bit key (weak)"},
                        primary:        providerGoogleWS,
                        primaryHasDKIM: true,
                        wantStatus:     "warning",
                },
                {
                        name: "third party only",
                        selectors: map[string]map[string]any{
                                "sel1": {"provider": providerSendGrid},
                        },
                        primary:        providerGoogleWS,
                        primaryHasDKIM: false,
                        thirdPartyOnly: true,
                        wantStatus:     "partial",
                },
                {
                        name: "healthy DKIM with strong keys",
                        selectors: map[string]map[string]any{
                                "sel1": {"provider": providerGoogleWS},
                        },
                        keyStrengths:   []string{"2048-bit"},
                        primary:        providerGoogleWS,
                        primaryHasDKIM: true,
                        wantStatus:     "success",
                },
                {
                        name: "healthy DKIM without key strengths",
                        selectors: map[string]map[string]any{
                                "sel1": {"provider": providerGoogleWS},
                        },
                        primary:        providerGoogleWS,
                        primaryHasDKIM: true,
                        wantStatus:     "success",
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        status, msg := buildDKIMVerdict(tt.selectors, tt.keyIssues, tt.keyStrengths, tt.primary, tt.primaryHasDKIM, tt.thirdPartyOnly)
                        if status != tt.wantStatus {
                                t.Errorf("status = %q, want %q (message: %s)", status, tt.wantStatus, msg)
                        }
                })
        }
}

func TestDKIMRFCAttackAnalyzeDKIMKeyRevokedState(t *testing.T) {
        result := analyzeDKIMKey("v=DKIM1; k=rsa; p=")
        if !result["revoked"].(bool) {
                t.Fatal("expected revoked=true for empty p=")
        }
        issues := result["issues"].([]string)
        foundRevoked := false
        for _, i := range issues {
                if strings.Contains(i, "revoked") {
                        foundRevoked = true
                }
        }
        if !foundRevoked {
                t.Fatal("expected revocation message in issues")
        }
}

func TestDKIMRFCAttackAnalyzeDKIMKeyEd25519(t *testing.T) {
        result := analyzeDKIMKey("v=DKIM1; k=ed25519; p=AAAA")
        if result["key_type"] != "ed25519" {
                t.Fatalf("expected key_type=ed25519, got %v", result["key_type"])
        }
        if result["revoked"].(bool) {
                t.Fatal("expected revoked=false for valid key")
        }
}

func TestDKIMRFCAttackAnalyzeRecordKeysMultiple(t *testing.T) {
        records := []string{
                "v=DKIM1; k=rsa; p=",
                "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3QZ6gC4W1",
        }
        keyInfoList, issues, strengths := analyzeRecordKeys(records)
        if len(keyInfoList) != 2 {
                t.Fatalf("expected 2 key infos, got %d", len(keyInfoList))
        }
        if len(issues) == 0 {
                t.Fatal("expected issues from revoked key and weak key")
        }
        if len(strengths) != 0 {
                t.Fatalf("expected no strengths (both keys are weak/revoked), got %v", strengths)
        }
}

func TestDKIMRFCAttackBuildSelectorListDedup(t *testing.T) {
        list := buildSelectorList([]string{"google"})
        count := 0
        for _, s := range list {
                if s == "google._domainkey" {
                        count++
                }
        }
        if count != 1 {
                t.Fatalf("expected exactly 1 google._domainkey, got %d", count)
        }
}

func TestDKIMRFCAttackBuildSelectorListCustomPrepend(t *testing.T) {
        list := buildSelectorList([]string{"mycustom"})
        if list[0] != "mycustom._domainkey" {
                t.Fatalf("expected custom selector first, got %s", list[0])
        }
        if len(list) != len(defaultDKIMSelectors)+1 {
                t.Fatalf("expected %d selectors, got %d", len(defaultDKIMSelectors)+1, len(list))
        }
}

func TestDKIMRFCAttackMultipleDKIMRecordsSameSelector(t *testing.T) {
        dns := &mockDKIMDNS{
                responses: map[string][]string{
                        "TXT:selector1._domainkey.example.com": {
                                "v=DKIM1; k=rsa; p=AAAA",
                                "v=DKIM1; k=ed25519; p=BBBB",
                        },
                },
        }
        sel, recs := checkDKIMSelector(context.Background(), dns, "selector1._domainkey", "example.com")
        if sel != "selector1._domainkey" {
                t.Fatalf("expected selector name, got %q", sel)
        }
        if len(recs) != 2 {
                t.Fatalf("expected 2 DKIM records, got %d", len(recs))
        }
}

func TestDKIMRFCAttackEstimateKeyBitsBoundaries(t *testing.T) {
        tests := []struct {
                name     string
                keyBytes int
                want     int
        }{
                {"exactly 140 bytes (1024-bit boundary)", 140, 1024},
                {"exactly 141 bytes (crosses to 2048)", 141, 2048},
                {"exactly 300 bytes (2048-bit boundary)", 300, 2048},
                {"exactly 301 bytes (crosses to 4096)", 301, 4096},
                {"exactly 600 bytes (4096-bit boundary)", 600, 4096},
                {"exactly 601 bytes (above 4096)", 601, 601 * 8 / 10},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := estimateKeyBits(tt.keyBytes)
                        if got != tt.want {
                                t.Errorf("estimateKeyBits(%d) = %d, want %d", tt.keyBytes, got, tt.want)
                        }
                })
        }
}

func TestDKIMRFCAttackInferMailboxBehindGateway(t *testing.T) {
        t.Run("security gateway with single mailbox candidate", func(t *testing.T) {
                res := &ProviderResolution{Primary: providerProofpoint}
                providers := map[string]bool{providerGoogleWS: true}
                inferMailboxBehindGateway(res, providers)
                if res.Primary != providerGoogleWS {
                        t.Errorf("expected primary = %q, got %q", providerGoogleWS, res.Primary)
                }
                if res.Gateway != providerProofpoint {
                        t.Errorf("expected gateway = %q, got %q", providerProofpoint, res.Gateway)
                }
        })

        t.Run("non-gateway provider unchanged", func(t *testing.T) {
                res := &ProviderResolution{Primary: providerGoogleWS}
                providers := map[string]bool{providerSendGrid: true}
                inferMailboxBehindGateway(res, providers)
                if res.Primary != providerGoogleWS {
                        t.Errorf("expected primary unchanged, got %q", res.Primary)
                }
        })

        t.Run("multiple mailbox candidates behind gateway", func(t *testing.T) {
                res := &ProviderResolution{Primary: providerMimecast}
                providers := map[string]bool{providerGoogleWS: true, providerMicrosoft365: true}
                inferMailboxBehindGateway(res, providers)
                if res.Primary != providerMimecast {
                        t.Errorf("expected primary unchanged for ambiguous, got %q", res.Primary)
                }
                if res.DKIMInferenceNote == "" {
                        t.Error("expected inference note for multiple candidates")
                }
        })
}
