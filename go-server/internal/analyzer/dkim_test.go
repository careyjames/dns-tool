package analyzer

import (
	"strings"
	"testing"
)

func TestEstimateKeyBits(t *testing.T) {
	tests := []struct {
		name     string
		keyBytes int
		want     int
	}{
		{"1024-bit range", 128, 1024},
		{"2048-bit range", 256, 2048},
		{"4096-bit range", 512, 4096},
		{"large key", 700, 700 * 8 / 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := estimateKeyBits(tt.keyBytes)
			if got != tt.want {
				t.Fatalf("estimateKeyBits(%d) = %d, want %d", tt.keyBytes, got, tt.want)
			}
		})
	}
}

func TestAnalyzePublicKey_EmptyP(t *testing.T) {
	_, revoked, issues := analyzePublicKey("v=DKIM1; k=rsa; p=")
	if !revoked {
		t.Fatal("expected revoked=true for empty p=")
	}
	if len(issues) == 0 {
		t.Fatal("expected revocation issue")
	}
}

func TestAnalyzePublicKey_NoP(t *testing.T) {
	bits, revoked, issues := analyzePublicKey("v=DKIM1; k=rsa")
	if bits != nil {
		t.Fatalf("expected nil bits, got %v", bits)
	}
	if revoked {
		t.Fatal("expected revoked=false")
	}
	if len(issues) != 0 {
		t.Fatalf("expected no issues, got %v", issues)
	}
}

func TestAnalyzeDKIMKey_RSADefault(t *testing.T) {
	result := analyzeDKIMKey("v=DKIM1; k=rsa; p=")
	if result["key_type"] != "rsa" {
		t.Fatalf("expected key_type=rsa, got %v", result["key_type"])
	}
	if !result["revoked"].(bool) {
		t.Fatal("expected revoked=true")
	}
}

func TestAnalyzeDKIMKey_TestMode(t *testing.T) {
	result := analyzeDKIMKey("v=DKIM1; k=rsa; t=y; p=AAAA")
	if !result["test_mode"].(bool) {
		t.Fatal("expected test_mode=true")
	}
	issues := result["issues"].([]string)
	found := false
	for _, i := range issues {
		if strings.Contains(i, "test mode") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected test mode issue")
	}
}

func TestAnalyzeDKIMKey_Ed25519(t *testing.T) {
	result := analyzeDKIMKey("v=DKIM1; k=ed25519; p=AAAA")
	if result["key_type"] != "ed25519" {
		t.Fatalf("expected key_type=ed25519, got %v", result["key_type"])
	}
}

func TestAllSelectorsKnown(t *testing.T) {
	if !AllSelectorsKnown(nil) {
		t.Fatal("expected true for nil selectors")
	}
	if !AllSelectorsKnown([]string{}) {
		t.Fatal("expected true for empty selectors")
	}
	if !AllSelectorsKnown([]string{"default._domainkey"}) {
		t.Fatal("expected true for known selector")
	}
	if !AllSelectorsKnown([]string{"default"}) {
		t.Fatal("expected true for known selector without suffix")
	}
	if AllSelectorsKnown([]string{"randomcustom123._domainkey"}) {
		t.Fatal("expected false for unknown selector")
	}
}

func TestBuildSelectorList(t *testing.T) {
	list := buildSelectorList(nil)
	if len(list) != len(defaultDKIMSelectors) {
		t.Fatalf("expected %d selectors, got %d", len(defaultDKIMSelectors), len(list))
	}

	list = buildSelectorList([]string{"custom"})
	if list[0] != "custom._domainkey" {
		t.Fatalf("expected custom._domainkey first, got %s", list[0])
	}
	if len(list) != len(defaultDKIMSelectors)+1 {
		t.Fatalf("expected %d selectors, got %d", len(defaultDKIMSelectors)+1, len(list))
	}

	list = buildSelectorList([]string{"default._domainkey"})
	if len(list) != len(defaultDKIMSelectors) {
		t.Fatalf("expected no duplicate, got %d selectors", len(list))
	}
}

func TestFindSPFRecord(t *testing.T) {
	tests := []struct {
		name    string
		records []string
		want    string
	}{
		{"empty", nil, ""},
		{"no spf", []string{"google-site-verification=abc"}, ""},
		{"has spf", []string{"google-site-verification=abc", "v=spf1 -all"}, "v=spf1 -all"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findSPFRecord(tt.records)
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestDetectMXProvider(t *testing.T) {
	tests := []struct {
		name string
		mx   []string
		want string
	}{
		{"empty", nil, ""},
		{"google", []string{"aspmx.l.google.com"}, providerGoogleWS},
		{"outlook", []string{"mail.protection.outlook.com"}, providerMicrosoft365},
		{"unknown", []string{"mail.custom.example.com"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectMXProvider(tt.mx)
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestDetectSPFMailboxProvider(t *testing.T) {
	if detectSPFMailboxProvider("") != "" {
		t.Fatal("expected empty for empty input")
	}
	got := detectSPFMailboxProvider("include:_spf.google.com ~all")
	if got != providerGoogleWS {
		t.Fatalf("expected %s, got %s", providerGoogleWS, got)
	}
}

func TestDetectSPFAncillaryProvider(t *testing.T) {
	if detectSPFAncillaryProvider("") != "" {
		t.Fatal("expected empty for empty input")
	}
	got := detectSPFAncillaryProvider("include:sendgrid.net ~all")
	if got != providerSendGrid {
		t.Fatalf("expected %s, got %s", providerSendGrid, got)
	}
}

func TestResolveProviderWithGateway(t *testing.T) {
	primary, gw := resolveProviderWithGateway(providerProofpoint, providerGoogleWS)
	if primary != providerGoogleWS {
		t.Fatalf("expected primary=%s, got %s", providerGoogleWS, primary)
	}
	if gw != providerProofpoint {
		t.Fatalf("expected gateway=%s, got %s", providerProofpoint, gw)
	}

	primary, gw = resolveProviderWithGateway(providerGoogleWS, "")
	if primary != providerGoogleWS {
		t.Fatalf("expected primary=%s, got %s", providerGoogleWS, primary)
	}
	if gw != "" {
		t.Fatalf("expected no gateway, got %s", gw)
	}

	primary, gw = resolveProviderWithGateway("", providerGoogleWS)
	if primary != providerGoogleWS {
		t.Fatalf("expected primary=%s, got %s", providerGoogleWS, primary)
	}

	primary, _ = resolveProviderWithGateway("", "")
	if primary != providerUnknown {
		t.Fatalf("expected %s, got %s", providerUnknown, primary)
	}
}

func TestDetectPrimaryMailProvider(t *testing.T) {
	res := detectPrimaryMailProvider(nil, "")
	if res.Primary != providerUnknown {
		t.Fatalf("expected Unknown, got %s", res.Primary)
	}

	res = detectPrimaryMailProvider([]string{"aspmx.l.google.com"}, "")
	if res.Primary != providerGoogleWS {
		t.Fatalf("expected %s, got %s", providerGoogleWS, res.Primary)
	}
}

func TestClassifySelectorProvider(t *testing.T) {
	got := classifySelectorProvider(selGoogle, providerGoogleWS)
	if got != providerGoogleWS {
		t.Fatalf("expected %s, got %s", providerGoogleWS, got)
	}

	got = classifySelectorProvider(selSelector1, providerUnknown)
	if got != providerUnknown {
		t.Fatalf("expected %s for ambiguous selector with unknown primary, got %s", providerUnknown, got)
	}

	got = classifySelectorProvider(selSelector1, providerMicrosoft365)
	if got != providerMicrosoft365 {
		t.Fatalf("expected %s, got %s", providerMicrosoft365, got)
	}

	got = classifySelectorProvider("nonexistent._domainkey", providerGoogleWS)
	if got != providerUnknown {
		t.Fatalf("expected %s for unknown selector, got %s", providerUnknown, got)
	}
}

func TestCollectUnattributed(t *testing.T) {
	selectors := map[string]map[string]any{
		"sel1": {"provider": providerGoogleWS},
		"sel2": {"provider": providerUnknown},
	}
	result := collectUnattributed(selectors)
	if len(result) != 1 {
		t.Fatalf("expected 1 unattributed, got %d", len(result))
	}
}

func TestCheckPrimaryHasDKIM(t *testing.T) {
	selectors := map[string]map[string]any{
		selGoogle: {"provider": providerGoogleWS},
	}
	providers := map[string]bool{providerGoogleWS: true}

	if !checkPrimaryHasDKIM(selectors, providerGoogleWS, providers) {
		t.Fatal("expected true for matching selector")
	}

	if checkPrimaryHasDKIM(selectors, providerMicrosoft365, providers) {
		t.Fatal("expected false for non-matching selector")
	}
}

func TestBuildDKIMVerdict(t *testing.T) {
	status, _ := buildDKIMVerdict(nil, nil, nil, providerUnknown, false, false)
	if status != "info" {
		t.Fatalf("expected info for empty selectors, got %s", status)
	}

	selectors := map[string]map[string]any{
		"sel1": {"provider": providerGoogleWS},
	}

	status, _ = buildDKIMVerdict(selectors, nil, nil, providerGoogleWS, true, false)
	if status != "success" {
		t.Fatalf("expected success, got %s", status)
	}

	status, _ = buildDKIMVerdict(selectors, []string{"1024-bit key (weak)"}, nil, providerGoogleWS, true, false)
	if status != "warning" {
		t.Fatalf("expected warning for weak key, got %s", status)
	}

	status, _ = buildDKIMVerdict(selectors, []string{"Key revoked (p= empty)"}, nil, providerGoogleWS, true, false)
	if status != "warning" {
		t.Fatalf("expected warning for revoked key, got %s", status)
	}

	status, _ = buildDKIMVerdict(selectors, nil, nil, providerGoogleWS, false, true)
	if status != "partial" {
		t.Fatalf("expected partial for third-party only, got %s", status)
	}

	status, msg := buildDKIMVerdict(selectors, nil, []string{"2048-bit"}, providerGoogleWS, true, false)
	if status != "success" {
		t.Fatalf("expected success with strengths, got %s", status)
	}
	if !strings.Contains(msg, "2048-bit") {
		t.Fatalf("expected strength in message, got %s", msg)
	}
}

func TestIsCustomSelector(t *testing.T) {
	if isCustomSelector("custom._domainkey", []string{"custom"}) != true {
		t.Fatal("expected true for matching custom selector")
	}
	if isCustomSelector("custom._domainkey", []string{"custom._domainkey"}) != true {
		t.Fatal("expected true for matching custom selector with suffix")
	}
	if isCustomSelector("custom._domainkey", nil) != false {
		t.Fatal("expected false for nil custom selectors")
	}
	if isCustomSelector("custom._domainkey", []string{"other"}) != false {
		t.Fatal("expected false for non-matching")
	}
}

func TestMatchDKIMNSProvider(t *testing.T) {
	got := matchDKIMNSProvider([]string{"ns1.ondmarc.com"})
	if got != "Red Sift OnDMARC" {
		t.Fatalf("expected Red Sift OnDMARC, got %s", got)
	}

	got = matchDKIMNSProvider([]string{"ns1.example.com"})
	if got != "" {
		t.Fatalf("expected empty, got %s", got)
	}

	got = matchDKIMNSProvider(nil)
	if got != "" {
		t.Fatalf("expected empty for nil, got %s", got)
	}
}

func TestNormalizeDKIMNS(t *testing.T) {
	result := normalizeDKIMNS([]string{"NS1.EXAMPLE.COM.", "ns2.example.com", ""})
	if len(result) != 2 {
		t.Fatalf("expected 2 nameservers, got %d", len(result))
	}
	if result[0] != "ns1.example.com" {
		t.Fatalf("expected lowercase without trailing dot, got %s", result[0])
	}
}

func TestProviderResolution_GatewayOrNil(t *testing.T) {
	pr := ProviderResolution{Primary: providerGoogleWS, Gateway: ""}
	if pr.GatewayOrNil() != nil {
		t.Fatal("expected nil for empty gateway")
	}

	pr.Gateway = providerProofpoint
	if pr.GatewayOrNil() != providerProofpoint {
		t.Fatalf("expected %s, got %v", providerProofpoint, pr.GatewayOrNil())
	}
}

func TestCollectFoundProviders(t *testing.T) {
	selectors := map[string]map[string]any{
		"sel1": {"provider": providerGoogleWS},
		"sel2": {"provider": providerUnknown},
		"sel3": {"provider": providerSendGrid},
	}
	providers := collectFoundProviders(selectors)
	if !providers[providerGoogleWS] {
		t.Fatal("expected Google Workspace in providers")
	}
	if !providers[providerSendGrid] {
		t.Fatal("expected SendGrid in providers")
	}
	if providers[providerUnknown] {
		t.Fatal("expected Unknown to be excluded")
	}
}

func TestBuildThirdPartyNote(t *testing.T) {
	providers := map[string]bool{providerSendGrid: true}
	note := buildThirdPartyNote(providers, providerGoogleWS)
	if !strings.Contains(note, providerSendGrid) {
		t.Fatal("expected SendGrid in note")
	}
	if !strings.Contains(note, providerGoogleWS) {
		t.Fatal("expected Google Workspace in note")
	}
}

func TestReclassifyAmbiguousSelectors(t *testing.T) {
	selectors := map[string]map[string]any{
		selSelector1: {"provider": providerUnknown},
		selGoogle:    {"provider": providerGoogleWS},
	}
	reclassifyAmbiguousSelectors(selectors, providerMicrosoft365)
	if selectors[selSelector1]["provider"] != providerMicrosoft365 {
		t.Fatalf("expected reclassified to %s, got %v", providerMicrosoft365, selectors[selSelector1]["provider"])
	}
	if selectors[selGoogle]["provider"] != providerGoogleWS {
		t.Fatal("expected Google selector to remain unchanged")
	}
}

func TestAnalyzeRecordKeys(t *testing.T) {
	records := []string{"v=DKIM1; k=rsa; p="}
	keyInfoList, issues, strengths := analyzeRecordKeys(records)
	if len(keyInfoList) != 1 {
		t.Fatalf("expected 1 key info, got %d", len(keyInfoList))
	}
	if len(issues) == 0 {
		t.Fatal("expected revocation issue")
	}
	if len(strengths) != 0 {
		t.Fatalf("expected no strengths, got %v", strengths)
	}
}

func TestAttributeSelectors_UnknownPrimary(t *testing.T) {
	selectors := map[string]map[string]any{
		selGoogle: {"provider": providerGoogleWS},
	}
	providers := map[string]bool{providerGoogleWS: true}
	hasDKIM, note, thirdParty := attributeSelectors(selectors, providerUnknown, providers)
	if hasDKIM {
		t.Fatal("expected false for unknown primary")
	}
	if note != "" {
		t.Fatalf("expected empty note, got %s", note)
	}
	if thirdParty {
		t.Fatal("expected false")
	}
}

func TestInferMailboxBehindGateway_NoGateway(t *testing.T) {
	res := &ProviderResolution{Primary: providerGoogleWS}
	providers := map[string]bool{providerGoogleWS: true}
	inferMailboxBehindGateway(res, providers)
	if res.Primary != providerGoogleWS {
		t.Fatal("expected primary unchanged for non-gateway")
	}
}

func TestInferMailboxBehindGateway_SingleMailbox(t *testing.T) {
	res := &ProviderResolution{Primary: providerProofpoint}
	providers := map[string]bool{providerGoogleWS: true}
	inferMailboxBehindGateway(res, providers)
	if res.Primary != providerGoogleWS {
		t.Fatalf("expected primary inferred as %s, got %s", providerGoogleWS, res.Primary)
	}
	if res.Gateway != providerProofpoint {
		t.Fatalf("expected gateway=%s, got %s", providerProofpoint, res.Gateway)
	}
}

func TestInferMailboxBehindGateway_MultipleMailbox(t *testing.T) {
	res := &ProviderResolution{Primary: providerProofpoint}
	providers := map[string]bool{providerGoogleWS: true, providerMicrosoft365: true}
	inferMailboxBehindGateway(res, providers)
	if res.Primary != providerProofpoint {
		t.Fatalf("expected primary unchanged for ambiguous, got %s", res.Primary)
	}
	if res.DKIMInferenceNote == "" {
		t.Fatal("expected inference note for multiple candidates")
	}
}
