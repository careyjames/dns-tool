// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

//go:build confidence_bridge

package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"dnstool/go-server/internal/telemetry"
)

var expectedProtocolKeys = []string{
	"spf_analysis",
	"dmarc_analysis",
	"dkim_analysis",
	"dane_analysis",
	"dnssec_analysis",
	"caa_analysis",
	"mta_sts_analysis",
	"tlsrpt_analysis",
	"bimi_analysis",
	"basic_records",
	"posture",
}

var expectedTopLevelKeys = []string{
	"spf_analysis",
	"dmarc_analysis",
	"dkim_analysis",
	"dane_analysis",
	"dnssec_analysis",
	"caa_analysis",
	"mta_sts_analysis",
	"tlsrpt_analysis",
	"bimi_analysis",
	"basic_records",
	"posture",
	"domain_exists",
	"domain_status",
	"section_status",
	"authoritative_records",
	"propagation_status",
}

type goldenFixture struct {
	Domain string
	Data   map[string]any
}

func fixturesDir() string {
	candidates := []string{
		filepath.Join("..", "..", "..", "tests", "golden_fixtures"),
		filepath.Join("tests", "golden_fixtures"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return filepath.Join("..", "..", "..", "tests", "golden_fixtures")
}

func loadGoldenFixtures(t *testing.T) []goldenFixture {
	t.Helper()
	dir := fixturesDir()

	manifestPath := filepath.Join(dir, "manifest.json")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("Failed to read manifest: %v", err)
	}

	var manifest struct {
		Domains []string `json:"domains"`
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatalf("Failed to parse manifest: %v", err)
	}

	var fixtures []goldenFixture
	for _, domain := range manifest.Domains {
		filename := strings.ReplaceAll(domain, ".", "_")
		filename = strings.ReplaceAll(filename, "-", "-")
		filePath := filepath.Join(dir, filename+".json")

		data, err := os.ReadFile(filePath)
		if err != nil {
			t.Logf("WARN: skipping %s — file not found: %v", domain, err)
			continue
		}

		var fixture map[string]any
		if err := json.Unmarshal(data, &fixture); err != nil {
			t.Logf("WARN: skipping %s — JSON parse error: %v", domain, err)
			continue
		}

		fixtures = append(fixtures, goldenFixture{Domain: domain, Data: fixture})
	}

	if len(fixtures) == 0 {
		t.Fatal("No golden fixtures loaded")
	}
	return fixtures
}

func TestGoldenFixtureStructuralIntegrity(t *testing.T) {
	fixtures := loadGoldenFixtures(t)

	for _, fix := range fixtures {
		t.Run(fix.Domain, func(t *testing.T) {
			domainExists, _ := fix.Data["domain_exists"].(bool)
			if !domainExists {
				t.Logf("Domain %s does not exist in fixture — reduced key requirements", fix.Domain)
				return
			}

			var missing []string
			for _, key := range expectedTopLevelKeys {
				if _, ok := fix.Data[key]; !ok {
					missing = append(missing, key)
				}
			}

			if len(missing) > 0 {
				t.Errorf("Golden fixture %s missing top-level keys: %v", fix.Domain, missing)
			} else {
				t.Logf("✓ %s: all %d expected top-level keys present", fix.Domain, len(expectedTopLevelKeys))
			}

			for _, key := range expectedProtocolKeys {
				section, ok := fix.Data[key]
				if !ok {
					continue
				}
				sectionMap, isMap := section.(map[string]any)
				if !isMap {
					continue
				}
				if _, hasStatus := sectionMap["status"]; !hasStatus {
					if key != "basic_records" && key != "posture" {
						t.Errorf("Golden fixture %s: section %s missing 'status' field", fix.Domain, key)
					}
				}
			}
		})
	}
}

func TestConfidenceBridge_StructuralComparison(t *testing.T) {
	fixtures := loadGoldenFixtures(t)

	type protocolScore struct {
		Protocol    string
		GoldenKeys  int
		MockKeys    int
		MatchedKeys int
		Confidence  float64
	}

	protocols := []string{
		"spf_analysis",
		"dmarc_analysis",
		"dkim_analysis",
		"dane_analysis",
		"dnssec_analysis",
		"caa_analysis",
		"mta_sts_analysis",
		"tlsrpt_analysis",
		"bimi_analysis",
		"basic_records",
		"posture",
	}

	overallPass := true

	for _, fix := range fixtures {
		t.Run(fix.Domain, func(t *testing.T) {
			domainExists, _ := fix.Data["domain_exists"].(bool)
			if !domainExists {
				t.Logf("Skipping %s — domain does not exist", fix.Domain)
				return
			}

			a := newConfidenceBridgeAnalyzer(fix)
			ctx := context.Background()
			mockResult := a.AnalyzeDomain(ctx, fix.Domain, nil)

			var scores []protocolScore
			var totalMatched, totalKeys int

			for _, proto := range protocols {
				goldenSection, goldenOK := fix.Data[proto].(map[string]any)
				mockSection, mockOK := mockResult[proto].(map[string]any)

				if !goldenOK {
					t.Logf("  %s: not present in golden fixture", proto)
					continue
				}

				if !mockOK {
					scores = append(scores, protocolScore{
						Protocol:   proto,
						GoldenKeys: len(goldenSection),
						Confidence: 0,
					})
					totalKeys += len(goldenSection)
					continue
				}

				goldenKeySet := goldenMapKeys(goldenSection)
				mockKeySet := goldenMapKeys(mockSection)
				matched := intersectKeys(goldenKeySet, mockKeySet)

				allKeys := unionKeys(goldenKeySet, mockKeySet)
				confidence := 0.0
				if len(allKeys) > 0 {
					confidence = float64(len(matched)) / float64(len(allKeys)) * 100
				}

				scores = append(scores, protocolScore{
					Protocol:    proto,
					GoldenKeys:  len(goldenKeySet),
					MockKeys:    len(mockKeySet),
					MatchedKeys: len(matched),
					Confidence:  confidence,
				})

				totalMatched += len(matched)
				totalKeys += len(allKeys)

				goldenOnly := diffKeys(goldenKeySet, mockKeySet)
				mockOnly := diffKeys(mockKeySet, goldenKeySet)
				if len(goldenOnly) > 0 {
					t.Logf("  %s: keys in golden but not mock: %v", proto, goldenOnly)
				}
				if len(mockOnly) > 0 {
					t.Logf("  %s: keys in mock but not golden: %v", proto, mockOnly)
				}
			}

			overallConfidence := 0.0
			if totalKeys > 0 {
				overallConfidence = float64(totalMatched) / float64(totalKeys) * 100
			}

			t.Logf("\n=== Confidence Report: %s ===", fix.Domain)
			t.Logf("%-25s %8s %8s %8s %10s", "Protocol", "Golden", "Mock", "Match", "Confidence")
			t.Logf("%-25s %8s %8s %8s %10s", strings.Repeat("-", 25), "------", "------", "------", "----------")
			for _, s := range scores {
				t.Logf("%-25s %8d %8d %8d %9.1f%%", s.Protocol, s.GoldenKeys, s.MockKeys, s.MatchedKeys, s.Confidence)
			}
			t.Logf("%-25s %8s %8s %8d %9.1f%%", "OVERALL", "", "", totalMatched, overallConfidence)

			if overallConfidence < 80 {
				t.Errorf("FAIL: %s confidence %.1f%% < 80%%", fix.Domain, overallConfidence)
				overallPass = false
			} else if overallConfidence < 90 {
				t.Logf("WARN: %s confidence %.1f%% (80-90%% range)", fix.Domain, overallConfidence)
			} else {
				t.Logf("PASS: %s confidence %.1f%% >= 90%%", fix.Domain, overallConfidence)
			}
		})
	}

	if !overallPass {
		t.Error("One or more domains failed the confidence threshold")
	}
}

func newConfidenceBridgeAnalyzer(fix goldenFixture) *Analyzer {
	mockDNS := NewMockDNSClient()
	mockHTTP := NewMockHTTPClient()

	seedMockFromGolden(mockDNS, mockHTTP, fix)

	return &Analyzer{
		DNS:           mockDNS,
		HTTP:          mockHTTP,
		SlowHTTP:      mockHTTP,
		RDAPHTTP:      mockHTTP,
		IANARDAPMap:   make(map[string][]string),
		Telemetry:     telemetry.NewRegistry(),
		RDAPCache:     telemetry.NewTTLCache[map[string]any]("rdap_cb", 100, 1*time.Hour),
		ctCache:       make(map[string]ctCacheEntry),
		ctCacheTTL:    1 * time.Hour,
		maxConcurrent: 5,
		semaphore:     make(chan struct{}, 5),
		SMTPProbeMode: "skip",
	}
}

func seedMockFromGolden(mock *MockDNSClient, httpMock *MockHTTPClient, fix goldenFixture) {
	domain := fix.Domain

	basicRecords, _ := fix.Data["basic_records"].(map[string]any)
	if basicRecords == nil {
		return
	}

	recordTypes := []string{"A", "AAAA", "MX", "NS", "SOA", "TXT", "CAA", "CNAME", "SRV"}
	for _, rtype := range recordTypes {
		if records := extractStringSlice(basicRecords, rtype); len(records) > 0 {
			mock.AddResponse(rtype, domain, records)
		}
	}

	if dmarc := extractStringSlice(basicRecords, "DMARC"); len(dmarc) > 0 {
		mock.AddResponse("TXT", "_dmarc."+domain, dmarc)
	} else {
		dmarcAnalysis, _ := fix.Data["dmarc_analysis"].(map[string]any)
		if dmarcAnalysis != nil {
			if records := extractStringSlice(dmarcAnalysis, "records"); len(records) > 0 {
				mock.AddResponse("TXT", "_dmarc."+domain, records)
			} else if records := extractStringSlice(dmarcAnalysis, "valid_records"); len(records) > 0 {
				mock.AddResponse("TXT", "_dmarc."+domain, records)
			}
		}
	}

	if mtaSts := extractStringSlice(basicRecords, "MTA-STS"); len(mtaSts) > 0 {
		mock.AddResponse("TXT", "_mta-sts."+domain, mtaSts)
	}

	if tlsRpt := extractStringSlice(basicRecords, "TLS-RPT"); len(tlsRpt) > 0 {
		mock.AddResponse("TXT", "_smtp._tls."+domain, tlsRpt)
	}

	bimiAnalysis, _ := fix.Data["bimi_analysis"].(map[string]any)
	if bimiAnalysis != nil {
		if record, ok := bimiAnalysis["record"].(string); ok && record != "" {
			mock.AddResponse("TXT", "default._bimi."+domain, []string{record})
		}
	}

	mock.AddProbeResult(domain, true, "")

	mtaStsAnalysis, _ := fix.Data["mta_sts_analysis"].(map[string]any)
	if mtaStsAnalysis != nil {
		policy, _ := mtaStsAnalysis["policy"].(string)
		if policy != "" {
			mtaStsURL := fmt.Sprintf("https://mta-sts.%s/.well-known/mta-sts.txt", domain)
			httpMock.AddResponse(mtaStsURL, 200, policy)
		}
	}
}

func extractStringSlice(m map[string]any, key string) []string {
	val, ok := m[key]
	if !ok || val == nil {
		return nil
	}

	switch v := val.(type) {
	case []string:
		return v
	case []any:
		var result []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

func goldenMapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func intersectKeys(a, b []string) []string {
	set := make(map[string]bool)
	for _, k := range b {
		set[k] = true
	}
	var result []string
	for _, k := range a {
		if set[k] {
			result = append(result, k)
		}
	}
	return result
}

func unionKeys(a, b []string) []string {
	set := make(map[string]bool)
	for _, k := range a {
		set[k] = true
	}
	for _, k := range b {
		set[k] = true
	}
	result := make([]string, 0, len(set))
	for k := range set {
		result = append(result, k)
	}
	sort.Strings(result)
	return result
}

func diffKeys(a, b []string) []string {
	set := make(map[string]bool)
	for _, k := range b {
		set[k] = true
	}
	var result []string
	for _, k := range a {
		if !set[k] {
			result = append(result, k)
		}
	}
	return result
}

type mockPattern struct {
	Protocol    string
	HasRecord   bool
	HasVersion  bool
	HasPolicy   bool
	HasIncludes bool
	HasMechAll  bool
	HasRUA      bool
	HasRUF      bool
	HasSelector bool
	HasIssuer   bool
	HasWildcard bool
	HasIodef    bool
}

func extractSPFPattern(record string) mockPattern {
	p := mockPattern{Protocol: "SPF"}
	if record == "" {
		return p
	}
	p.HasRecord = true
	p.HasVersion = strings.HasPrefix(record, "v=spf1")
	p.HasIncludes = strings.Contains(record, "include:")
	p.HasMechAll = strings.Contains(record, "all")
	return p
}

func extractDMARCPattern(record string) mockPattern {
	p := mockPattern{Protocol: "DMARC"}
	if record == "" {
		return p
	}
	p.HasRecord = true
	p.HasVersion = strings.HasPrefix(record, "v=DMARC1")
	p.HasPolicy = strings.Contains(record, "p=")
	p.HasRUA = strings.Contains(record, "rua=")
	p.HasRUF = strings.Contains(record, "ruf=")
	return p
}

func extractDKIMPattern(section map[string]any) mockPattern {
	p := mockPattern{Protocol: "DKIM"}
	if section == nil {
		return p
	}
	p.HasRecord = true
	if selectors, ok := section["selectors"].(map[string]any); ok && len(selectors) > 0 {
		p.HasSelector = true
	}
	if _, ok := section["primary_provider"]; ok {
		p.HasIncludes = true
	}
	return p
}

func extractCAAPattern(section map[string]any) mockPattern {
	p := mockPattern{Protocol: "CAA"}
	if section == nil {
		return p
	}
	p.HasRecord = true
	if issuers, ok := section["issuers"].([]any); ok && len(issuers) > 0 {
		p.HasIssuer = true
	}
	if hw, ok := section["has_wildcard"].(bool); ok {
		p.HasWildcard = hw
	}
	if hi, ok := section["has_iodef"].(bool); ok {
		p.HasIodef = hi
	}
	return p
}

func extractTLSRPTPattern(record string) mockPattern {
	p := mockPattern{Protocol: "TLSRPT"}
	if record == "" {
		return p
	}
	p.HasRecord = true
	p.HasVersion = strings.HasPrefix(record, "v=TLSRPTv1")
	p.HasRUA = strings.Contains(record, "rua=")
	return p
}

func extractBIMIPattern(section map[string]any) mockPattern {
	p := mockPattern{Protocol: "BIMI"}
	if section == nil {
		return p
	}
	if record, ok := section["record"].(string); ok && record != "" {
		p.HasRecord = true
		p.HasVersion = strings.HasPrefix(record, "v=BIMI1")
	}
	return p
}

func extractMTASTSPattern(section map[string]any) mockPattern {
	p := mockPattern{Protocol: "MTA-STS"}
	if section == nil {
		return p
	}
	p.HasRecord = true
	if policy, ok := section["policy"].(string); ok && policy != "" {
		p.HasPolicy = true
	}
	return p
}

func patternString(p mockPattern) string {
	var parts []string
	if p.HasRecord {
		parts = append(parts, "record")
	}
	if p.HasVersion {
		parts = append(parts, "version")
	}
	if p.HasPolicy {
		parts = append(parts, "policy")
	}
	if p.HasIncludes {
		parts = append(parts, "includes")
	}
	if p.HasMechAll {
		parts = append(parts, "all_mech")
	}
	if p.HasRUA {
		parts = append(parts, "rua")
	}
	if p.HasRUF {
		parts = append(parts, "ruf")
	}
	if p.HasSelector {
		parts = append(parts, "selector")
	}
	if p.HasIssuer {
		parts = append(parts, "issuer")
	}
	if p.HasWildcard {
		parts = append(parts, "wildcard")
	}
	if p.HasIodef {
		parts = append(parts, "iodef")
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, ",")
}

func patternsStructurallyMatch(mock, golden mockPattern) bool {
	if !mock.HasRecord && !golden.HasRecord {
		return true
	}
	if mock.HasRecord != golden.HasRecord {
		return false
	}
	matchCount := 0
	totalChecks := 0

	checks := []struct{ m, g bool }{
		{mock.HasVersion, golden.HasVersion},
		{mock.HasPolicy, golden.HasPolicy},
		{mock.HasIncludes, golden.HasIncludes},
		{mock.HasMechAll, golden.HasMechAll},
		{mock.HasRUA, golden.HasRUA},
		{mock.HasRUF, golden.HasRUF},
		{mock.HasSelector, golden.HasSelector},
		{mock.HasIssuer, golden.HasIssuer},
	}

	for _, c := range checks {
		if c.m || c.g {
			totalChecks++
			if c.m == c.g {
				matchCount++
			}
		}
	}

	if totalChecks == 0 {
		return true
	}
	return float64(matchCount)/float64(totalChecks) >= 0.5
}

func getMockSPFPatterns() []mockPattern {
	records := []string{
		"v=spf1 include:_spf.google.com ~all",
		"v=spf1 ip4:192.0.2.0/24 -all",
		"v=spf1 -all",
		"v=spf1 include:sendgrid.net ~all",
		"v=spf1 mx ip4:10.0.0.0/24 -all",
		"v=spf1 +all",
	}
	var patterns []mockPattern
	for _, r := range records {
		patterns = append(patterns, extractSPFPattern(r))
	}
	return patterns
}

func getMockDMARCPatterns() []mockPattern {
	records := []string{
		"v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:dmarc-ruf@example.com; pct=100",
		"v=DMARC1; p=quarantine; aspf=s; adkim=s",
		"v=DMARC1; p=reject; rua=mailto:dmarc@reject.example.com",
		"v=DMARC1; p=quarantine",
		"v=DMARC1; p=none; rua=mailto:dmarc@none.example.com",
	}
	var patterns []mockPattern
	for _, r := range records {
		patterns = append(patterns, extractDMARCPattern(r))
	}
	return patterns
}

func getMockCAAPatterns() []mockPattern {
	return []mockPattern{
		{Protocol: "CAA", HasRecord: true, HasIssuer: true, HasWildcard: true, HasIodef: true},
		{Protocol: "CAA", HasRecord: true, HasIssuer: true, HasWildcard: false, HasIodef: true},
		{Protocol: "CAA", HasRecord: true, HasIssuer: true, HasWildcard: true, HasIodef: false},
		{Protocol: "CAA", HasRecord: false},
	}
}

func getMockTLSRPTPatterns() []mockPattern {
	records := []string{
		"v=TLSRPTv1; rua=mailto:tlsrpt@example.com",
	}
	var patterns []mockPattern
	for _, r := range records {
		patterns = append(patterns, extractTLSRPTPattern(r))
	}
	patterns = append(patterns, mockPattern{Protocol: "TLSRPT"})
	return patterns
}

func bestMockMatch(golden mockPattern, mocks []mockPattern) (mockPattern, bool) {
	if len(mocks) == 0 {
		return mockPattern{}, false
	}
	best := mocks[0]
	bestMatch := false
	for _, m := range mocks {
		if patternsStructurallyMatch(m, golden) {
			return m, true
		}
		if m.HasRecord == golden.HasRecord {
			best = m
			bestMatch = false
		}
	}
	return best, bestMatch
}

func TestMockRealityDrift(t *testing.T) {
	fixtures := loadGoldenFixtures(t)

	type protocolDrift struct {
		Protocol      string
		MockPattern   string
		GoldenPattern string
		Match         bool
	}

	overallMatched := 0
	overallTotal := 0

	for _, fix := range fixtures {
		t.Run(fix.Domain, func(t *testing.T) {
			domainExists, _ := fix.Data["domain_exists"].(bool)
			if !domainExists {
				t.Logf("Skipping %s — domain does not exist", fix.Domain)
				return
			}

			var results []protocolDrift

			basicRecords, _ := fix.Data["basic_records"].(map[string]any)

			goldenSPF := mockPattern{Protocol: "SPF"}
			if basicRecords != nil {
				if txts := extractStringSlice(basicRecords, "TXT"); len(txts) > 0 {
					for _, txt := range txts {
						if strings.HasPrefix(txt, "v=spf1") {
							goldenSPF = extractSPFPattern(txt)
							break
						}
					}
				}
			}
			mockSPFs := getMockSPFPatterns()
			bestSPF, spfMatch := bestMockMatch(goldenSPF, mockSPFs)
			results = append(results, protocolDrift{
				Protocol:      "SPF",
				MockPattern:   patternString(bestSPF),
				GoldenPattern: patternString(goldenSPF),
				Match:         spfMatch,
			})

			goldenDMARC := mockPattern{Protocol: "DMARC"}
			if basicRecords != nil {
				if dmarcs := extractStringSlice(basicRecords, "DMARC"); len(dmarcs) > 0 {
					goldenDMARC = extractDMARCPattern(dmarcs[0])
				}
			}
			mockDMARCs := getMockDMARCPatterns()
			bestDMARC, dmarcMatch := bestMockMatch(goldenDMARC, mockDMARCs)
			results = append(results, protocolDrift{
				Protocol:      "DMARC",
				MockPattern:   patternString(bestDMARC),
				GoldenPattern: patternString(goldenDMARC),
				Match:         dmarcMatch,
			})

			dkimSection, _ := fix.Data["dkim_analysis"].(map[string]any)
			goldenDKIM := extractDKIMPattern(dkimSection)
			mockDKIM := mockPattern{Protocol: "DKIM", HasRecord: true, HasSelector: true, HasIncludes: true}
			dkimMatch := patternsStructurallyMatch(mockDKIM, goldenDKIM)
			results = append(results, protocolDrift{
				Protocol:      "DKIM",
				MockPattern:   patternString(mockDKIM),
				GoldenPattern: patternString(goldenDKIM),
				Match:         dkimMatch,
			})

			caaSection, _ := fix.Data["caa_analysis"].(map[string]any)
			goldenCAA := extractCAAPattern(caaSection)
			mockCAAs := getMockCAAPatterns()
			bestCAA, caaMatch := bestMockMatch(goldenCAA, mockCAAs)
			results = append(results, protocolDrift{
				Protocol:      "CAA",
				MockPattern:   patternString(bestCAA),
				GoldenPattern: patternString(goldenCAA),
				Match:         caaMatch,
			})

			goldenTLSRPT := mockPattern{Protocol: "TLSRPT"}
			if basicRecords != nil {
				if rpts := extractStringSlice(basicRecords, "TLS-RPT"); len(rpts) > 0 {
					goldenTLSRPT = extractTLSRPTPattern(rpts[0])
				}
			}
			mockTLSRPTs := getMockTLSRPTPatterns()
			bestTLSRPT, tlsrptMatch := bestMockMatch(goldenTLSRPT, mockTLSRPTs)
			results = append(results, protocolDrift{
				Protocol:      "TLSRPT",
				MockPattern:   patternString(bestTLSRPT),
				GoldenPattern: patternString(goldenTLSRPT),
				Match:         tlsrptMatch,
			})

			bimiSection, _ := fix.Data["bimi_analysis"].(map[string]any)
			goldenBIMI := extractBIMIPattern(bimiSection)
			mockBIMI := mockPattern{Protocol: "BIMI"}
			bimiMatch := patternsStructurallyMatch(mockBIMI, goldenBIMI)
			results = append(results, protocolDrift{
				Protocol:      "BIMI",
				MockPattern:   patternString(mockBIMI),
				GoldenPattern: patternString(goldenBIMI),
				Match:         bimiMatch,
			})

			mtaStsSection, _ := fix.Data["mta_sts_analysis"].(map[string]any)
			goldenMTASTS := extractMTASTSPattern(mtaStsSection)
			mockMTASTS := mockPattern{Protocol: "MTA-STS", HasRecord: true, HasPolicy: true}
			mtaStsMatch := patternsStructurallyMatch(mockMTASTS, goldenMTASTS)
			results = append(results, protocolDrift{
				Protocol:      "MTA-STS",
				MockPattern:   patternString(mockMTASTS),
				GoldenPattern: patternString(goldenMTASTS),
				Match:         mtaStsMatch,
			})

			matched := 0
			for _, r := range results {
				if r.Match {
					matched++
				}
			}
			total := len(results)
			overallMatched += matched
			overallTotal += total

			confidence := 0.0
			if total > 0 {
				confidence = float64(matched) / float64(total) * 100
			}

			t.Logf("\n=== Mock Reality Drift Report: %s ===", fix.Domain)
			t.Logf("%-12s | %-40s | %-40s | %s", "Protocol", "Mock Pattern", "Golden Pattern", "Match?")
			t.Logf("%-12s-+-%-40s-+-%-40s-+-%s", strings.Repeat("-", 12), strings.Repeat("-", 40), strings.Repeat("-", 40), strings.Repeat("-", 6))
			for _, r := range results {
				matchStr := "YES"
				if !r.Match {
					matchStr = "NO"
				}
				t.Logf("%-12s | %-40s | %-40s | %s", r.Protocol, r.MockPattern, r.GoldenPattern, matchStr)
			}
			t.Logf("Overall Mock Confidence: %.1f%% (%d/%d protocols)", confidence, matched, total)

			if confidence < 50 {
				t.Errorf("FAIL: %s mock confidence %.1f%% < 50%%", fix.Domain, confidence)
			} else if confidence < 70 {
				t.Logf("WARN: %s mock confidence %.1f%% (50-70%% range)", fix.Domain, confidence)
			} else {
				t.Logf("PASS: %s mock confidence %.1f%% >= 70%%", fix.Domain, confidence)
			}
		})
	}

	if overallTotal > 0 {
		overallConfidence := float64(overallMatched) / float64(overallTotal) * 100
		t.Logf("\n=== Overall Mock Reality Drift Summary ===")
		t.Logf("Total protocols checked: %d", overallTotal)
		t.Logf("Structural matches: %d", overallMatched)
		t.Logf("Overall Mock Confidence: %.1f%%", overallConfidence)
	}
}
