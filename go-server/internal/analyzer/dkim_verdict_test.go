package analyzer

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestEstimateKeyBits_Boundaries(t *testing.T) {
	tests := []struct {
		name     string
		keyBytes int
		want     int
	}{
		{"exactly 140", 140, 1024},
		{"141 is 2048", 141, 2048},
		{"exactly 300", 300, 2048},
		{"301 is 4096", 301, 4096},
		{"exactly 600", 600, 4096},
		{"601 is large", 601, 601 * 8 / 10},
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

func makeBase64Key(byteLen int) string {
	raw := make([]byte, byteLen)
	for i := range raw {
		raw[i] = byte(i % 256)
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	if strings.HasSuffix(encoded, "==") {
		encoded = strings.TrimRight(encoded, "=")
	}
	return encoded
}

func TestAnalyzePublicKey_ValidKey(t *testing.T) {
	key := makeBase64Key(256)
	record := "v=DKIM1; k=rsa; p=" + key
	bits, revoked, _ := analyzePublicKey(record)
	if bits == nil {
		t.Fatal("expected non-nil bits")
	}
	if revoked {
		t.Fatal("expected not revoked")
	}
}

func TestAnalyzePublicKey_WeakKey(t *testing.T) {
	key := makeBase64Key(130)
	record := "v=DKIM1; k=rsa; p=" + key
	bits, _, issues := analyzePublicKey(record)
	if bits == nil {
		t.Fatal("expected non-nil bits")
	}
	b := bits.(int)
	if b != 1024 {
		t.Fatalf("expected 1024 bits, got %d", b)
	}
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "1024-bit") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected 1024-bit weakness issue")
	}
}

func TestAnalyzeDKIMKey_NoKeyType(t *testing.T) {
	result := analyzeDKIMKey("v=DKIM1; p=AAAA")
	if result["key_type"] != "rsa" {
		t.Fatalf("expected default key_type=rsa, got %v", result["key_type"])
	}
}

func TestAnalyzeDKIMKey_RevokedKey(t *testing.T) {
	result := analyzeDKIMKey("v=DKIM1; k=rsa; p=")
	if !result["revoked"].(bool) {
		t.Fatal("expected revoked=true")
	}
}

func TestAnalyzeDKIMKey_NoTestMode(t *testing.T) {
	result := analyzeDKIMKey("v=DKIM1; k=rsa; p=AAAA")
	if result["test_mode"].(bool) {
		t.Fatal("expected test_mode=false")
	}
}

func TestAnalyzeDKIMKey_IssuesAlwaysSlice(t *testing.T) {
	result := analyzeDKIMKey("v=DKIM1; k=rsa; p=AAAA")
	issues := result["issues"].([]string)
	if issues == nil {
		t.Fatal("expected non-nil issues slice")
	}
}

func TestBuildSelectorList_CustomWithSuffix(t *testing.T) {
	list := buildSelectorList([]string{"mycustom._domainkey"})
	if list[0] != "mycustom._domainkey" {
		t.Fatalf("expected mycustom._domainkey first, got %s", list[0])
	}
}

func TestBuildSelectorList_CustomWithoutSuffix(t *testing.T) {
	list := buildSelectorList([]string{"mycustom"})
	if list[0] != "mycustom._domainkey" {
		t.Fatalf("expected mycustom._domainkey first, got %s", list[0])
	}
}

func TestBuildSelectorList_NoDuplicateDefaults(t *testing.T) {
	list := buildSelectorList([]string{"google._domainkey"})
	count := 0
	for _, s := range list {
		if s == "google._domainkey" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected google._domainkey once, got %d times", count)
	}
}

func TestAllSelectorsKnown_WithSuffix(t *testing.T) {
	if !AllSelectorsKnown([]string{"google._domainkey"}) {
		t.Fatal("expected true for known selector with suffix")
	}
}

func TestAllSelectorsKnown_CaseInsensitive(t *testing.T) {
	if !AllSelectorsKnown([]string{"GOOGLE._DOMAINKEY"}) {
		t.Fatal("expected true for uppercase known selector")
	}
}

func TestAllSelectorsKnown_EmptyString(t *testing.T) {
	if !AllSelectorsKnown([]string{""}) {
		t.Fatal("expected true for empty string selector")
	}
}

func TestAllSelectorsKnown_TrailingDot(t *testing.T) {
	if !AllSelectorsKnown([]string{"google._domainkey."}) {
		t.Fatal("expected true for selector with trailing dot")
	}
}

func TestFindSPFRecord_CaseInsensitive(t *testing.T) {
	got := findSPFRecord([]string{"V=SPF1 -all"})
	if got != "V=SPF1 -all" {
		t.Fatalf("expected V=SPF1 -all, got %q", got)
	}
}

func TestDetectMXProvider_Proofpoint(t *testing.T) {
	got := detectMXProvider([]string{"mx1.pphosted.com"})
	if got != providerProofpoint {
		t.Fatalf("expected %s, got %s", providerProofpoint, got)
	}
}

func TestDetectMXProvider_Mimecast(t *testing.T) {
	got := detectMXProvider([]string{"us-smtp-inbound-1.mimecast.com"})
	if got != providerMimecast {
		t.Fatalf("expected %s, got %s", providerMimecast, got)
	}
}

func TestDetectPrimaryMailProvider_GatewayDetection(t *testing.T) {
	res := detectPrimaryMailProvider(
		[]string{"mx1.pphosted.com"},
		"v=spf1 include:_spf.google.com ~all",
	)
	if res.Primary != providerGoogleWS {
		t.Fatalf("expected primary=%s, got %s", providerGoogleWS, res.Primary)
	}
	if res.Gateway != providerProofpoint {
		t.Fatalf("expected gateway=%s, got %s", providerProofpoint, res.Gateway)
	}
}

func TestDetectPrimaryMailProvider_AncillaryNote(t *testing.T) {
	res := detectPrimaryMailProvider(
		[]string{"aspmx.l.google.com"},
		"v=spf1 include:spf.protection.outlook.com ~all",
	)
	if res.SPFAncillaryNote == "" {
		t.Fatal("expected ancillary note when SPF and MX disagree")
	}
}

func TestDetectPrimaryMailProvider_DualSPFWithMXMatch(t *testing.T) {
	res := detectPrimaryMailProvider(
		[]string{"aspmx.l.google.com", "alt1.aspmx.l.google.com", "alt2.aspmx.l.google.com"},
		"v=spf1 include:_spf.google.com include:spf.protection.outlook.com -all",
	)
	if res.Primary != providerGoogleWS {
		t.Fatalf("expected primary=%s, got %s", providerGoogleWS, res.Primary)
	}
	if res.SPFAncillaryNote == "" {
		t.Fatal("expected ancillary note for secondary SPF provider")
	}
	if !strings.Contains(res.SPFAncillaryNote, providerMicrosoft365) {
		t.Fatalf("ancillary note should mention %s, got: %s", providerMicrosoft365, res.SPFAncillaryNote)
	}
	if strings.Contains(res.SPFAncillaryNote, "but MX records point to") {
		t.Fatal("note should NOT frame as mismatch when MX matches one of the SPF providers")
	}
}

func TestDetectPrimaryMailProvider_SelfHostedWithSPF(t *testing.T) {
	res := detectPrimaryMailProvider(
		[]string{"mail.example.com"},
		"v=spf1 include:_spf.google.com ~all",
	)
	if res.SPFAncillaryNote == "" {
		t.Fatal("expected ancillary note for self-hosted with known SPF provider")
	}
}

func TestClassifySelectorProvider_KnownNonAmbiguous(t *testing.T) {
	got := classifySelectorProvider(selMailjet, providerUnknown)
	if got != providerMailjet {
		t.Fatalf("expected %s, got %s", providerMailjet, got)
	}
}

func TestCollectUnattributed_AllKnown(t *testing.T) {
	selectors := map[string]map[string]any{
		"sel1": {"provider": providerGoogleWS},
		"sel2": {"provider": providerSendGrid},
	}
	result := collectUnattributed(selectors)
	if len(result) != 0 {
		t.Fatalf("expected 0 unattributed, got %d", len(result))
	}
}

func TestCheckPrimaryHasDKIM_NoExpectedSelectors(t *testing.T) {
	selectors := map[string]map[string]any{
		"custom._domainkey": {"provider": "CustomProvider"},
	}
	providers := map[string]bool{"CustomProvider": true}
	if !checkPrimaryHasDKIM(selectors, "CustomProvider", providers) {
		t.Fatal("expected true when provider is in foundProviders but has no expected selectors")
	}
}

func TestBuildDKIMVerdict_ThirdPartyWithStrengths(t *testing.T) {
	selectors := map[string]map[string]any{
		"sel1": {"provider": providerSendGrid},
	}
	status, msg := buildDKIMVerdict(selectors, nil, []string{"2048-bit"}, providerGoogleWS, false, true)
	if status != "partial" {
		t.Fatalf("expected partial, got %s", status)
	}
	if !strings.Contains(msg, "2048-bit") {
		t.Fatalf("expected strength in message, got %s", msg)
	}
}

func TestBuildDKIMVerdict_SuccessWithMultipleStrengths(t *testing.T) {
	selectors := map[string]map[string]any{
		"sel1": {"provider": providerGoogleWS},
		"sel2": {"provider": providerSendGrid},
	}
	status, msg := buildDKIMVerdict(selectors, nil, []string{"2048-bit", "4096-bit"}, providerGoogleWS, true, false)
	if status != "success" {
		t.Fatalf("expected success, got %s", status)
	}
	if !strings.Contains(msg, "strong keys") {
		t.Fatalf("expected 'strong keys' in message, got %s", msg)
	}
}

func TestIsCustomSelector_WithSuffix(t *testing.T) {
	if !isCustomSelector("myselector._domainkey", []string{"myselector._domainkey"}) {
		t.Fatal("expected true")
	}
}

func TestIsCustomSelector_WithoutSuffix(t *testing.T) {
	if !isCustomSelector("myselector._domainkey", []string{"myselector"}) {
		t.Fatal("expected true")
	}
}

func TestIsCustomSelector_NoMatch(t *testing.T) {
	if isCustomSelector("myselector._domainkey", []string{"other"}) {
		t.Fatal("expected false")
	}
}

func TestMatchDKIMNSProvider_Multiple(t *testing.T) {
	got := matchDKIMNSProvider([]string{"ns1.example.com", "ns2.easydmarc.com"})
	if got != "EasyDMARC" {
		t.Fatalf("expected EasyDMARC, got %s", got)
	}
}

func TestNormalizeDKIMNS_Empty(t *testing.T) {
	result := normalizeDKIMNS(nil)
	if len(result) != 0 {
		t.Fatalf("expected empty, got %v", result)
	}
}

func TestNormalizeDKIMNS_AllEmpty(t *testing.T) {
	result := normalizeDKIMNS([]string{"", ""})
	if len(result) != 0 {
		t.Fatalf("expected empty, got %v", result)
	}
}

func TestAnalyzeRecordKeys_StrongKey(t *testing.T) {
	key := makeBase64Key(256)
	records := []string{"v=DKIM1; k=rsa; p=" + key}
	keyInfoList, issues, strengths := analyzeRecordKeys(records)
	if len(keyInfoList) != 1 {
		t.Fatalf("expected 1 key info, got %d", len(keyInfoList))
	}
	if len(issues) != 0 {
		t.Fatalf("expected no issues for strong key, got %v", issues)
	}
	if len(strengths) == 0 {
		t.Fatal("expected strength for large key")
	}
}

func TestAnalyzeRecordKeys_MultipleRecords(t *testing.T) {
	records := []string{
		"v=DKIM1; k=rsa; p=",
		"v=DKIM1; k=rsa; p=AAAA",
	}
	keyInfoList, issues, _ := analyzeRecordKeys(records)
	if len(keyInfoList) != 2 {
		t.Fatalf("expected 2 key infos, got %d", len(keyInfoList))
	}
	if len(issues) == 0 {
		t.Fatal("expected at least one issue (revoked key)")
	}
}

func TestCollectFoundProviders_Empty(t *testing.T) {
	providers := collectFoundProviders(map[string]map[string]any{})
	if len(providers) != 0 {
		t.Fatalf("expected empty, got %v", providers)
	}
}

func TestInferMailboxBehindGateway_NonGateway(t *testing.T) {
	res := &ProviderResolution{Primary: providerGoogleWS}
	providers := map[string]bool{providerSendGrid: true}
	inferMailboxBehindGateway(res, providers)
	if res.Primary != providerGoogleWS {
		t.Fatalf("expected primary unchanged, got %s", res.Primary)
	}
	if res.DKIMInferenceNote != "" {
		t.Fatal("expected empty inference note for non-gateway")
	}
}

func TestReclassifyAmbiguousSelectors_NonAmbiguous(t *testing.T) {
	selectors := map[string]map[string]any{
		selGoogle: {"provider": providerUnknown},
	}
	reclassifyAmbiguousSelectors(selectors, providerGoogleWS)
	if selectors[selGoogle]["provider"] != providerUnknown {
		t.Fatal("expected non-ambiguous selector to remain unchanged")
	}
}

func TestReclassifyAmbiguousSelectors_UnknownPrimary(t *testing.T) {
	selectors := map[string]map[string]any{
		selSelector1: {"provider": providerUnknown},
	}
	reclassifyAmbiguousSelectors(selectors, providerUnknown)
	if selectors[selSelector1]["provider"] != providerUnknown {
		t.Fatal("expected selector to remain Unknown when primary is Unknown")
	}
}

func TestAttributeSelectors_InferUnattributed(t *testing.T) {
	selectors := map[string]map[string]any{
		"custom._domainkey": {"provider": providerUnknown},
	}
	providers := map[string]bool{}
	hasDKIM, note, thirdParty := attributeSelectors(selectors, providerGoogleWS, providers)
	if !hasDKIM {
		t.Fatal("expected hasDKIM=true after inference")
	}
	if note == "" {
		t.Fatal("expected inference note")
	}
	if thirdParty {
		t.Fatal("expected thirdParty=false after inference")
	}
	if selectors["custom._domainkey"]["provider"] != providerGoogleWS {
		t.Fatalf("expected provider inferred as %s", providerGoogleWS)
	}
}

func TestAttributeSelectors_ThirdPartyOnly(t *testing.T) {
	selectors := map[string]map[string]any{
		selSendgrid: {"provider": providerSendGrid},
	}
	providers := map[string]bool{providerSendGrid: true}
	_, note, thirdParty := attributeSelectors(selectors, providerGoogleWS, providers)
	if !thirdParty {
		t.Fatal("expected thirdParty=true")
	}
	if note == "" {
		t.Fatal("expected third-party note")
	}
}

func TestBuildThirdPartyNote_EmptyProviders(t *testing.T) {
	note := buildThirdPartyNote(map[string]bool{}, providerGoogleWS)
	if !strings.Contains(note, "third-party") {
		t.Fatalf("expected 'third-party' in note, got %s", note)
	}
}

func TestInferUnattributedSelectors(t *testing.T) {
	selectors := map[string]map[string]any{
		"custom._domainkey": {"provider": providerUnknown},
	}
	providers := map[string]bool{}
	note := inferUnattributedSelectors(selectors, []string{"custom._domainkey"}, providerGoogleWS, providers)
	if !strings.Contains(note, providerGoogleWS) {
		t.Fatalf("expected provider name in note, got %s", note)
	}
	if selectors["custom._domainkey"]["provider"] != providerGoogleWS {
		t.Fatal("expected provider to be updated")
	}
	if !providers[providerGoogleWS] {
		t.Fatal("expected provider added to foundProviders")
	}
}

func TestMatchProviderFromRecords(t *testing.T) {
	got := matchProviderFromRecords("include:_spf.google.com", spfMailboxProviders)
	if got != providerGoogleWS {
		t.Fatalf("expected %s, got %s", providerGoogleWS, got)
	}

	got = matchProviderFromRecords("nothing here", spfMailboxProviders)
	if got != "" {
		t.Fatalf("expected empty, got %s", got)
	}
}

func TestResolveProviderWithGateway_BothEmpty(t *testing.T) {
	primary, gw := resolveProviderWithGateway("", "")
	if primary != providerUnknown {
		t.Fatalf("expected Unknown, got %s", primary)
	}
	if gw != "" {
		t.Fatalf("expected empty gateway, got %s", gw)
	}
}

func TestResolveProviderWithGateway_MXOnly(t *testing.T) {
	primary, gw := resolveProviderWithGateway(providerGoogleWS, "")
	if primary != providerGoogleWS {
		t.Fatalf("expected %s, got %s", providerGoogleWS, primary)
	}
	if gw != "" {
		t.Fatalf("expected empty gateway, got %s", gw)
	}
}

func TestResolveProviderWithGateway_SPFOnly(t *testing.T) {
	primary, gw := resolveProviderWithGateway("", providerMicrosoft365)
	if primary != providerMicrosoft365 {
		t.Fatalf("expected %s, got %s", providerMicrosoft365, primary)
	}
	if gw != "" {
		t.Fatalf("expected empty gateway, got %s", gw)
	}
}
