package handlers

import (
	"context"
	"encoding/json"
	"testing"
)

type mockDNSQuerier struct {
	responses map[string][]string
}

func (m *mockDNSQuerier) QueryDNS(_ context.Context, recordType, domain string) []string {
	key := recordType + ":" + domain
	if r, ok := m.responses[key]; ok {
		return r
	}
	return nil
}

func TestCoverageBoost17_ComputeSubdomainEmailScope_LocalSPFAndDMARC(t *testing.T) {
	dns := &mockDNSQuerier{responses: map[string][]string{
		"TXT:_dmarc.example.com": {"v=DMARC1; p=reject"},
	}}
	results := map[string]any{
		mapKeySpfAnalysis:   map[string]any{mapKeyStatus: mapKeySuccess},
		mapKeyDmarcAnalysis: map[string]any{mapKeyStatus: mapKeySuccess},
		"basic_records":     map[string]any{"MX": []any{"mx.sub.example.com"}},
	}
	scope := computeSubdomainEmailScope(context.Background(), dns, "sub.example.com", "example.com", results)
	if !scope.IsSubdomain {
		t.Error("expected IsSubdomain=true")
	}
	if scope.ParentDomain != "example.com" {
		t.Errorf("ParentDomain = %q", scope.ParentDomain)
	}
	if scope.SPFScope != "local" {
		t.Errorf("SPFScope = %q, want local", scope.SPFScope)
	}
	if scope.DMARCScope != "local" {
		t.Errorf("DMARCScope = %q, want local", scope.DMARCScope)
	}
	if !scope.HasLocalEmail {
		t.Error("expected HasLocalEmail=true")
	}
}

func TestCoverageBoost17_ComputeSubdomainEmailScope_InheritedDMARC(t *testing.T) {
	dns := &mockDNSQuerier{responses: map[string][]string{
		"TXT:_dmarc.example.com": {"v=DMARC1; p=quarantine"},
	}}
	results := map[string]any{
		mapKeySpfAnalysis:   map[string]any{mapKeyStatus: "danger"},
		mapKeyDmarcAnalysis: map[string]any{mapKeyStatus: "danger"},
	}
	scope := computeSubdomainEmailScope(context.Background(), dns, "sub.example.com", "example.com", results)
	if scope.SPFScope != "none" {
		t.Errorf("SPFScope = %q, want none", scope.SPFScope)
	}
	if scope.DMARCScope != "inherited" {
		t.Errorf("DMARCScope = %q, want inherited", scope.DMARCScope)
	}
	if scope.HasLocalEmail {
		t.Error("expected HasLocalEmail=false")
	}
}

func TestCoverageBoost17_ComputeSubdomainEmailScope_NoDMARC(t *testing.T) {
	dns := &mockDNSQuerier{responses: map[string][]string{}}
	results := map[string]any{}
	scope := computeSubdomainEmailScope(context.Background(), dns, "sub.example.com", "example.com", results)
	if scope.SPFScope != "none" {
		t.Errorf("SPFScope = %q, want none", scope.SPFScope)
	}
	if scope.DMARCScope != "none" {
		t.Errorf("DMARCScope = %q, want none", scope.DMARCScope)
	}
}

func TestCoverageBoost17_ComputeSubdomainEmailScope_MissingAnalysisKeys(t *testing.T) {
	dns := &mockDNSQuerier{responses: map[string][]string{}}
	results := map[string]any{
		mapKeySpfAnalysis:   "not a map",
		mapKeyDmarcAnalysis: 42,
	}
	scope := computeSubdomainEmailScope(context.Background(), dns, "sub.example.com", "example.com", results)
	if scope.SPFScope != "none" {
		t.Errorf("SPFScope = %q, want none", scope.SPFScope)
	}
	if scope.DMARCScope != "none" {
		t.Errorf("DMARCScope = %q, want none", scope.DMARCScope)
	}
}

func TestCoverageBoost17_ComputeSubdomainEmailScope_StatusNotString(t *testing.T) {
	dns := &mockDNSQuerier{responses: map[string][]string{}}
	results := map[string]any{
		mapKeySpfAnalysis:   map[string]any{mapKeyStatus: 123},
		mapKeyDmarcAnalysis: map[string]any{},
	}
	scope := computeSubdomainEmailScope(context.Background(), dns, "sub.example.com", "example.com", results)
	if scope.SPFScope != "none" {
		t.Errorf("SPFScope = %q, want none", scope.SPFScope)
	}
}

func TestCoverageBoost17_NormalizeForCompare_MixedTypeArray(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"z": 1},
		map[string]interface{}{"a": 2},
	}
	got := normalizeForCompare(arr)
	sorted, ok := got.([]interface{})
	if !ok {
		t.Fatal("expected array result")
	}
	if len(sorted) != 2 {
		t.Fatalf("expected 2 elements, got %d", len(sorted))
	}
}

func TestCoverageBoost17_NormalizeForCompare_NilValue(t *testing.T) {
	got := normalizeForCompare(nil)
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestCoverageBoost17_NormalizeForCompare_EmptyArray(t *testing.T) {
	arr := []interface{}{}
	got := normalizeForCompare(arr)
	gotArr, ok := got.([]interface{})
	if !ok {
		t.Fatal("expected array result")
	}
	if len(gotArr) != 0 {
		t.Errorf("expected empty array, got %v", gotArr)
	}
}

func TestCoverageBoost17_NormalizeForCompare_NumberArray(t *testing.T) {
	arr := []interface{}{float64(3), float64(1), float64(2)}
	got := normalizeForCompare(arr)
	sorted, ok := got.([]interface{})
	if !ok {
		t.Fatal("expected array result")
	}
	if len(sorted) != 3 {
		t.Fatalf("expected 3 elements, got %d", len(sorted))
	}
	first, ok := sorted[0].(float64)
	if !ok || first != 1 {
		t.Errorf("first element = %v, want 1", sorted[0])
	}
}

func TestCoverageBoost17_NormalizeForCompare_BooleanValue(t *testing.T) {
	got := normalizeForCompare(true)
	if got != true {
		t.Errorf("expected true, got %v", got)
	}
}

func TestCoverageBoost17_NormalizeForCompare_MapValue(t *testing.T) {
	m := map[string]interface{}{"key": "val"}
	got := normalizeForCompare(m)
	gotMap, ok := got.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if gotMap["key"] != "val" {
		t.Errorf("expected val, got %v", gotMap["key"])
	}
}

func TestCoverageBoost17_NormalizeForCompare_NestedMapArray(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"name": "beta"},
		map[string]interface{}{"name": "alpha"},
	}
	got := normalizeForCompare(arr)
	sorted, ok := got.([]interface{})
	if !ok {
		t.Fatal("expected array result")
	}
	if len(sorted) != 2 {
		t.Fatalf("expected 2 elements, got %d", len(sorted))
	}
	b0, _ := json.Marshal(sorted[0])
	b1, _ := json.Marshal(sorted[1])
	if string(b0) >= string(b1) {
		t.Errorf("expected sorted order, got %s then %s", b0, b1)
	}
}

func TestCoverageBoost17_ParseOrgDMARC_SpaceDelimited(t *testing.T) {
	found, policy := parseOrgDMARC([]string{"v=DMARC1 p=reject"})
	if !found {
		t.Error("expected found=true")
	}
	if policy != "reject" {
		t.Errorf("policy = %q, want reject", policy)
	}
}

func TestCoverageBoost17_ParseOrgDMARC_WhitespaceAround(t *testing.T) {
	found, policy := parseOrgDMARC([]string{"  v=DMARC1; p=none  "})
	if !found {
		t.Error("expected found=true")
	}
	if policy != "none" {
		t.Errorf("policy = %q, want none", policy)
	}
}

func TestCoverageBoost17_ParseOrgDMARC_NoPolicyTag(t *testing.T) {
	found, policy := parseOrgDMARC([]string{"v=DMARC1; rua=mailto:a@b.com"})
	if !found {
		t.Error("expected found=true")
	}
	if policy != "" {
		t.Errorf("policy = %q, want empty", policy)
	}
}

func TestCoverageBoost17_HasLocalMXRecords_NilBasicRecords(t *testing.T) {
	got := hasLocalMXRecords(map[string]any{"basic_records": nil})
	if got {
		t.Error("expected false for nil basic_records")
	}
}

func TestCoverageBoost17_HasLocalMXRecords_IntMXValue(t *testing.T) {
	got := hasLocalMXRecords(map[string]any{"basic_records": map[string]any{"MX": 42}})
	if got {
		t.Error("expected false for int MX value")
	}
}

func TestCoverageBoost17_DetermineSPFScope_Details(t *testing.T) {
	scope, note := determineSPFScope(true)
	if scope != "local" {
		t.Errorf("scope = %q, want local", scope)
	}
	if note != "SPF record published at this subdomain" {
		t.Errorf("note = %q", note)
	}

	scope, note = determineSPFScope(false)
	if scope != "none" {
		t.Errorf("scope = %q, want none", scope)
	}
	if note != "No SPF record at this subdomain — SPF does not inherit from parent domains" {
		t.Errorf("note = %q", note)
	}
}

func TestCoverageBoost17_DetermineDMARCScope_AllPaths(t *testing.T) {
	scope, note := determineDMARCScope(true, true, "reject", "example.com")
	if scope != "local" {
		t.Errorf("expected local when sub has DMARC, got %q", scope)
	}
	if note != "DMARC record published at this subdomain" {
		t.Errorf("unexpected note for local: %q", note)
	}

	scope, note = determineDMARCScope(false, true, "quarantine", "example.com")
	if scope != "inherited" {
		t.Errorf("expected inherited, got %q", scope)
	}
	if note == "" {
		t.Error("expected non-empty note for inherited")
	}

	scope, note = determineDMARCScope(false, true, "", "example.com")
	if scope != "inherited" {
		t.Errorf("expected inherited, got %q", scope)
	}

	scope, note = determineDMARCScope(false, false, "", "example.com")
	if scope != "none" {
		t.Errorf("expected none, got %q", scope)
	}
	if note == "" {
		t.Error("expected non-empty note for none")
	}
}

func TestCoverageBoost17_ComputeSubdomainEmailScope_WarningStatus(t *testing.T) {
	dns := &mockDNSQuerier{responses: map[string][]string{
		"TXT:_dmarc.example.com": {},
	}}
	results := map[string]any{
		mapKeySpfAnalysis:   map[string]any{mapKeyStatus: mapKeyWarning},
		mapKeyDmarcAnalysis: map[string]any{mapKeyStatus: mapKeyWarning},
		"basic_records":     map[string]any{"MX": []string{"mx.sub.example.com"}},
	}
	scope := computeSubdomainEmailScope(context.Background(), dns, "sub.example.com", "example.com", results)
	if scope.SPFScope != "local" {
		t.Errorf("SPFScope = %q, want local (warning is active)", scope.SPFScope)
	}
	if scope.DMARCScope != "local" {
		t.Errorf("DMARCScope = %q, want local (warning is active)", scope.DMARCScope)
	}
	if !scope.HasLocalEmail {
		t.Error("expected HasLocalEmail=true with string MX")
	}
}
