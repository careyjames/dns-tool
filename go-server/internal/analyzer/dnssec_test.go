package analyzer

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseAlgorithm(t *testing.T) {
	tests := []struct {
		name         string
		dsRecords    []string
		wantAlgo     *int
		wantAlgoName string
		wantNilAlgo  bool
		wantNilName  bool
	}{
		{
			"empty records",
			[]string{},
			nil, "", true, true,
		},
		{
			"RSA/SHA-256 algo 8",
			[]string{"12345 8 2 AABBCCDD"},
			intPtr(8), "RSA/SHA-256", false, false,
		},
		{
			"ECDSA P-256 algo 13",
			[]string{"12345 13 2 AABBCCDD"},
			intPtr(13), "ECDSA P-256/SHA-256", false, false,
		},
		{
			"Ed25519 algo 15",
			[]string{"12345 15 2 AABBCCDD"},
			intPtr(15), "Ed25519", false, false,
		},
		{
			"unknown algo 99",
			[]string{"12345 99 2 AABBCCDD"},
			intPtr(99), "Algorithm 99", false, false,
		},
		{
			"too few fields",
			[]string{"12345"},
			nil, "", true, true,
		},
		{
			"non-numeric algo",
			[]string{"12345 abc 2 AABBCCDD"},
			nil, "", true, true,
		},
		{
			"multiple records uses first",
			[]string{"12345 8 2 AABBCCDD", "67890 13 2 EEFF"},
			intPtr(8), "RSA/SHA-256", false, false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algo, name := parseAlgorithm(tt.dsRecords)
			if tt.wantNilAlgo {
				if algo != nil {
					t.Errorf("expected nil algorithm, got %d", *algo)
				}
			} else {
				if algo == nil {
					t.Fatal("expected non-nil algorithm")
				}
				if *algo != *tt.wantAlgo {
					t.Errorf("algorithm = %d, want %d", *algo, *tt.wantAlgo)
				}
			}
			if tt.wantNilName {
				if name != nil {
					t.Errorf("expected nil name, got %q", *name)
				}
			} else {
				if name == nil {
					t.Fatal("expected non-nil name")
				}
				if *name != tt.wantAlgoName {
					t.Errorf("name = %q, want %q", *name, tt.wantAlgoName)
				}
			}
		})
	}
}

func TestAlgorithmObservation(t *testing.T) {
	t.Run("nil algorithm", func(t *testing.T) {
		got := algorithmObservation(nil)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("known algorithm 13", func(t *testing.T) {
		algo := 13
		got := algorithmObservation(&algo)
		if got == nil {
			t.Fatal("expected non-nil result")
		}
		if got["strength"] != "modern" {
			t.Errorf("strength = %v, want modern", got["strength"])
		}
		if got["label"] != "Modern" {
			t.Errorf("label = %v, want Modern", got["label"])
		}
		if got["rfc"] == nil || got["rfc"] == "" {
			t.Error("rfc should not be empty")
		}
		if got["observation"] == nil || got["observation"] == "" {
			t.Error("observation should not be empty")
		}
		if got["quantum_note"] == nil || got["quantum_note"] == "" {
			t.Error("quantum_note should not be empty")
		}
	})

	t.Run("deprecated algorithm 1", func(t *testing.T) {
		algo := 1
		got := algorithmObservation(&algo)
		if got == nil {
			t.Fatal("expected non-nil result")
		}
		if got["strength"] != "deprecated" {
			t.Errorf("strength = %v, want deprecated", got["strength"])
		}
	})

	t.Run("unknown algorithm", func(t *testing.T) {
		algo := 999
		got := algorithmObservation(&algo)
		if got == nil {
			t.Fatal("expected non-nil result")
		}
		if got["strength"] != "adequate" {
			t.Errorf("strength = %v, want adequate", got["strength"])
		}
	})
}

func TestCollectDNSKEYRecords(t *testing.T) {
	tests := []struct {
		name      string
		results   []string
		wantHas   bool
		wantCount int
	}{
		{"empty", []string{}, false, 0},
		{"single short record", []string{"256 3 13 KEY"}, true, 1},
		{"three records", []string{"rec1", "rec2", "rec3"}, true, 3},
		{
			"more than three records truncated",
			[]string{"rec1", "rec2", "rec3", "rec4", "rec5"},
			true, 3,
		},
		{
			"long record truncated at 100",
			[]string{
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			},
			true, 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			has, records := collectDNSKEYRecords(tt.results)
			if has != tt.wantHas {
				t.Errorf("has = %v, want %v", has, tt.wantHas)
			}
			if len(records) != tt.wantCount {
				t.Errorf("count = %d, want %d", len(records), tt.wantCount)
			}
		})
	}

	t.Run("long record ends with ellipsis", func(t *testing.T) {
		longRec := make([]byte, 150)
		for i := range longRec {
			longRec[i] = 'A'
		}
		_, records := collectDNSKEYRecords([]string{string(longRec)})
		if len(records) != 1 {
			t.Fatal("expected 1 record")
		}
		if len(records[0]) != 103 {
			t.Errorf("truncated record length = %d, want 103", len(records[0]))
		}
	})
}

func TestCollectDSRecords(t *testing.T) {
	tests := []struct {
		name      string
		results   []string
		wantHas   bool
		wantCount int
	}{
		{"empty", []string{}, false, 0},
		{"single record", []string{"12345 8 2 AABB"}, true, 1},
		{"three records", []string{"r1", "r2", "r3"}, true, 3},
		{"more than three", []string{"r1", "r2", "r3", "r4"}, true, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			has, records := collectDSRecords(tt.results)
			if has != tt.wantHas {
				t.Errorf("has = %v, want %v", has, tt.wantHas)
			}
			if len(records) != tt.wantCount {
				t.Errorf("count = %d, want %d", len(records), tt.wantCount)
			}
		})
	}
}

func TestBuildDNSSECResult(t *testing.T) {
	algo8 := 8
	algoName := "RSA/SHA-256"
	resolver := "8.8.8.8"

	t.Run("full DNSSEC with AD flag", func(t *testing.T) {
		r := buildDNSSECResult(dnssecParams{
			hasDNSKEY:     true,
			hasDS:         true,
			adFlag:        true,
			dnskeyRecords: []string{"key1"},
			dsRecords:     []string{"ds1"},
			algorithm:     &algo8,
			algorithmName: &algoName,
			adResolver:    &resolver,
		})
		if r[mapKeyStatus] != "success" {
			t.Errorf("status = %v, want success", r[mapKeyStatus])
		}
		if r[mapKeyChainOfTrust] != "complete" {
			t.Errorf("chain_of_trust = %v, want complete", r[mapKeyChainOfTrust])
		}
		if r[mapKeyAdFlag] != true {
			t.Errorf("ad_flag = %v, want true", r[mapKeyAdFlag])
		}
		if r[mapKeyHasDnskey] != true {
			t.Error("has_dnskey should be true")
		}
		if r[mapKeyHasDs] != true {
			t.Error("has_ds should be true")
		}
	})

	t.Run("full DNSSEC without AD flag", func(t *testing.T) {
		r := buildDNSSECResult(dnssecParams{
			hasDNSKEY:     true,
			hasDS:         true,
			adFlag:        false,
			dnskeyRecords: []string{"key1"},
			dsRecords:     []string{"ds1"},
			algorithm:     &algo8,
			algorithmName: &algoName,
			adResolver:    &resolver,
		})
		if r[mapKeyStatus] != "success" {
			t.Errorf("status = %v, want success", r[mapKeyStatus])
		}
		if r[mapKeyAdFlag] != false {
			t.Errorf("ad_flag = %v, want false", r[mapKeyAdFlag])
		}
	})

	t.Run("DNSKEY only no DS", func(t *testing.T) {
		r := buildDNSSECResult(dnssecParams{
			hasDNSKEY:     true,
			hasDS:         false,
			dnskeyRecords: []string{"key1"},
			adResolver:    &resolver,
		})
		if r[mapKeyStatus] != "warning" {
			t.Errorf("status = %v, want warning", r[mapKeyStatus])
		}
		if r[mapKeyChainOfTrust] != "broken" {
			t.Errorf("chain_of_trust = %v, want broken", r[mapKeyChainOfTrust])
		}
	})

	t.Run("no DNSSEC", func(t *testing.T) {
		r := buildDNSSECResult(dnssecParams{
			hasDNSKEY:  false,
			hasDS:      false,
			adResolver: &resolver,
		})
		if r[mapKeyStatus] != "warning" {
			t.Errorf("status = %v, want warning", r[mapKeyStatus])
		}
		if r[mapKeyChainOfTrust] != "none" {
			t.Errorf("chain_of_trust = %v, want none", r[mapKeyChainOfTrust])
		}
		if r[mapKeyHasDnskey] != false {
			t.Error("has_dnskey should be false")
		}
		if r[mapKeyHasDs] != false {
			t.Error("has_ds should be false")
		}
	})
}

func TestBuildInheritedDNSSECResult(t *testing.T) {
	resolver := "8.8.8.8"
	algo := 13
	algoName := "ECDSA P-256/SHA-256"

	t.Run("with parent zone", func(t *testing.T) {
		r := buildInheritedDNSSECResult("example.com", &resolver, &algo, &algoName)
		if r[mapKeyStatus] != "success" {
			t.Errorf("status = %v, want success", r[mapKeyStatus])
		}
		if r[mapKeyChainOfTrust] != "inherited" {
			t.Errorf("chain_of_trust = %v, want inherited", r[mapKeyChainOfTrust])
		}
		if r[mapKeyAdFlag] != true {
			t.Errorf("ad_flag = %v, want true", r[mapKeyAdFlag])
		}
		if r["is_subdomain"] != true {
			t.Error("is_subdomain should be true")
		}
		if r["parent_zone"] != "example.com" {
			t.Errorf("parent_zone = %v, want example.com", r["parent_zone"])
		}
	})

	t.Run("without parent zone", func(t *testing.T) {
		r := buildInheritedDNSSECResult("", &resolver, nil, nil)
		if r[mapKeyStatus] != "success" {
			t.Errorf("status = %v, want success", r[mapKeyStatus])
		}
		msg, _ := r[mapKeyMessage].(string)
		if msg == "" {
			t.Error("message should not be empty")
		}
	})
}

func TestParseAlgorithm_EmptyFields(t *testing.T) {
	algo, name := parseAlgorithm([]string{""})
	if algo != nil {
		t.Errorf("expected nil algo for empty string, got %d", *algo)
	}
	if name != nil {
		t.Errorf("expected nil name for empty string, got %q", *name)
	}
}

func TestParseAlgorithm_AllKnownAlgorithms(t *testing.T) {
	knownAlgos := map[int]string{
		1: "RSAMD5", 3: "DSA", 5: "RSA/SHA-1", 6: "DSA-NSEC3-SHA1",
		7: "RSASHA1-NSEC3-SHA1", 8: "RSA/SHA-256", 10: "RSA/SHA-512",
		12: "ECC-GOST", 13: "ECDSA P-256/SHA-256", 14: "ECDSA P-384/SHA-384",
		15: "Ed25519", 16: "Ed448",
	}
	for num, expectedName := range knownAlgos {
		ds := []string{fmt.Sprintf("12345 %d 2 AABBCCDD", num)}
		algo, name := parseAlgorithm(ds)
		if algo == nil || *algo != num {
			t.Errorf("algo %d: expected %d, got %v", num, num, algo)
		}
		if name == nil || *name != expectedName {
			t.Errorf("algo %d: expected name %q, got %v", num, expectedName, name)
		}
	}
}

func TestCollectDNSKEYRecords_NilInput(t *testing.T) {
	has, records := collectDNSKEYRecords(nil)
	if has {
		t.Error("expected has=false for nil input")
	}
	if records != nil {
		t.Errorf("expected nil records for nil input, got %v", records)
	}
}

func TestCollectDSRecords_NilInput(t *testing.T) {
	has, records := collectDSRecords(nil)
	if has {
		t.Error("expected has=false for nil input")
	}
	if records != nil {
		t.Errorf("expected nil records for nil input, got %v", records)
	}
}

func TestBuildDNSSECResult_MessageContent(t *testing.T) {
	resolver := "1.1.1.1"
	algo := 13
	algoName := "ECDSA P-256/SHA-256"

	t.Run("AD flag message mentions resolver", func(t *testing.T) {
		r := buildDNSSECResult(dnssecParams{
			hasDNSKEY:     true,
			hasDS:         true,
			adFlag:        true,
			dnskeyRecords: []string{"key1"},
			dsRecords:     []string{"ds1"},
			algorithm:     &algo,
			algorithmName: &algoName,
			adResolver:    &resolver,
		})
		msg := r[mapKeyMessage].(string)
		if !strings.Contains(msg, "1.1.1.1") {
			t.Errorf("message should mention resolver, got: %s", msg)
		}
		if !strings.Contains(msg, "AD") {
			t.Errorf("message should mention AD flag, got: %s", msg)
		}
	})

	t.Run("no AD flag message mentions broken chain", func(t *testing.T) {
		r := buildDNSSECResult(dnssecParams{
			hasDNSKEY:     true,
			hasDS:         true,
			adFlag:        false,
			dnskeyRecords: []string{"key1"},
			dsRecords:     []string{"ds1"},
			algorithm:     &algo,
			algorithmName: &algoName,
			adResolver:    &resolver,
		})
		msg := r[mapKeyMessage].(string)
		if !strings.Contains(msg, "AD flag not set") {
			t.Errorf("message should mention AD flag not set, got: %s", msg)
		}
	})

	t.Run("DNSKEY only mentions DS missing", func(t *testing.T) {
		r := buildDNSSECResult(dnssecParams{
			hasDNSKEY:     true,
			hasDS:         false,
			dnskeyRecords: []string{"key1"},
		})
		msg := r[mapKeyMessage].(string)
		if !strings.Contains(msg, "DS record missing") {
			t.Errorf("message should mention DS missing, got: %s", msg)
		}
	})

	t.Run("no DNSSEC mentions unsigned", func(t *testing.T) {
		r := buildDNSSECResult(dnssecParams{
			hasDNSKEY: false,
			hasDS:     false,
		})
		msg := r[mapKeyMessage].(string)
		if !strings.Contains(msg, "unsigned") {
			t.Errorf("message should mention unsigned, got: %s", msg)
		}
	})
}

func TestBuildInheritedDNSSECResult_MessageContent(t *testing.T) {
	resolver := "8.8.8.8"

	t.Run("parent zone in message", func(t *testing.T) {
		r := buildInheritedDNSSECResult("example.com", &resolver, nil, nil)
		msg := r[mapKeyMessage].(string)
		if !strings.Contains(msg, "example.com") {
			t.Errorf("message should mention parent zone, got: %s", msg)
		}
		if !strings.Contains(msg, "inherited") {
			t.Errorf("message should mention inherited, got: %s", msg)
		}
	})

	t.Run("no parent zone uses generic message", func(t *testing.T) {
		r := buildInheritedDNSSECResult("", &resolver, nil, nil)
		msg := r[mapKeyMessage].(string)
		if !strings.Contains(msg, "validated by resolver") {
			t.Errorf("message should mention resolver validation, got: %s", msg)
		}
	})
}

func TestBuildDNSSECResult_AlgorithmObservationIncluded(t *testing.T) {
	algo := 15
	algoName := "Ed25519"
	resolver := "8.8.8.8"
	r := buildDNSSECResult(dnssecParams{
		hasDNSKEY:     true,
		hasDS:         true,
		adFlag:        true,
		dnskeyRecords: []string{"key1"},
		dsRecords:     []string{"ds1"},
		algorithm:     &algo,
		algorithmName: &algoName,
		adResolver:    &resolver,
	})
	obs := r[mapKeyAlgorithmObservation]
	if obs == nil {
		t.Fatal("expected algorithm_observation to be non-nil")
	}
	obsMap, ok := obs.(map[string]any)
	if !ok {
		t.Fatal("expected algorithm_observation to be map[string]any")
	}
	if obsMap["strength"] != "modern" {
		t.Errorf("strength = %v, want modern", obsMap["strength"])
	}
}

func TestBuildDNSSECResult_NoDNSKEYWithDS(t *testing.T) {
	algo := 8
	algoName := "RSA/SHA-256"
	r := buildDNSSECResult(dnssecParams{
		hasDNSKEY:     false,
		hasDS:         true,
		adFlag:        false,
		dnskeyRecords: nil,
		dsRecords:     []string{"12345 8 2 AABB"},
		algorithm:     &algo,
		algorithmName: &algoName,
	})
	if r[mapKeyStatus] != "warning" {
		t.Errorf("status = %v, want warning", r[mapKeyStatus])
	}
	if r[mapKeyChainOfTrust] != "none" {
		t.Errorf("chain_of_trust = %v, want none", r[mapKeyChainOfTrust])
	}
}

func TestBuildDNSSECResult_NilAlgorithm(t *testing.T) {
	r := buildDNSSECResult(dnssecParams{
		hasDNSKEY:     true,
		hasDS:         true,
		adFlag:        true,
		dnskeyRecords: []string{"key1"},
		dsRecords:     []string{"ds1"},
		algorithm:     nil,
		algorithmName: nil,
		adResolver:    nil,
	})
	if r[mapKeyStatus] != "success" {
		t.Errorf("status = %v, want success", r[mapKeyStatus])
	}
	if r[mapKeyAlgorithm] != nil {
		t.Errorf("algorithm = %v, want nil", r[mapKeyAlgorithm])
	}
	if r[mapKeyAlgorithmName] != nil {
		t.Errorf("algorithm_name = %v, want nil", r[mapKeyAlgorithmName])
	}
}

func TestCollectDNSKEYRecords_ExactLength100(t *testing.T) {
	rec := strings.Repeat("A", 100)
	has, records := collectDNSKEYRecords([]string{rec})
	if !has {
		t.Error("expected has=true")
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0] != rec {
		t.Errorf("expected record to be unchanged at exactly 100 chars")
	}
}

func TestCollectDNSKEYRecords_Length101Truncated(t *testing.T) {
	rec := strings.Repeat("B", 101)
	_, records := collectDNSKEYRecords([]string{rec})
	if len(records[0]) != 103 {
		t.Errorf("expected truncated to 103 (100+...), got %d", len(records[0]))
	}
	if !strings.HasSuffix(records[0], "...") {
		t.Error("expected truncated record to end with ...")
	}
}

func TestCollectDSRecords_PreservesRecordContent(t *testing.T) {
	input := []string{"12345 8 2 AABBCCDD", "67890 13 2 EEFF0011"}
	has, records := collectDSRecords(input)
	if !has {
		t.Error("expected has=true")
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	for i, r := range records {
		if r != input[i] {
			t.Errorf("record %d = %q, want %q", i, r, input[i])
		}
	}
}

func TestBuildInheritedDNSSECResult_NilResolver(t *testing.T) {
	r := buildInheritedDNSSECResult("example.com", nil, nil, nil)
	if r[mapKeyStatus] != "success" {
		t.Errorf("status = %v, want success", r[mapKeyStatus])
	}
	if r[mapKeyAdResolver] != nil {
		t.Errorf("ad_resolver = %v, want nil", r[mapKeyAdResolver])
	}
	if r[mapKeyAlgorithm] != nil {
		t.Errorf("algorithm = %v, want nil", r[mapKeyAlgorithm])
	}
}

func TestBuildInheritedDNSSECResult_WithAlgorithm(t *testing.T) {
	resolver := "9.9.9.9"
	algo := 15
	algoName := "Ed25519"
	r := buildInheritedDNSSECResult("sub.example.com", &resolver, &algo, &algoName)
	if r[mapKeyAlgorithm] != 15 {
		t.Errorf("algorithm = %v, want 15", r[mapKeyAlgorithm])
	}
	if r[mapKeyAlgorithmName] != "Ed25519" {
		t.Errorf("algorithm_name = %v, want Ed25519", r[mapKeyAlgorithmName])
	}
	obs := r[mapKeyAlgorithmObservation]
	if obs == nil {
		t.Fatal("expected algorithm_observation to be non-nil")
	}
	obsMap := obs.(map[string]any)
	if obsMap["strength"] != "modern" {
		t.Errorf("strength = %v, want modern", obsMap["strength"])
	}
}

func TestParseAlgorithm_WhitespaceFields(t *testing.T) {
	algo, name := parseAlgorithm([]string{"12345  8  2  AABB"})
	if algo == nil || *algo != 8 {
		t.Errorf("expected algorithm 8 with extra whitespace, got %v", algo)
	}
	if name == nil || *name != "RSA/SHA-256" {
		t.Errorf("expected name RSA/SHA-256, got %v", name)
	}
}

func TestAlgorithmObservation_AllKnownAlgorithms(t *testing.T) {
	knownAlgos := []int{1, 3, 5, 6, 7, 8, 10, 12, 13, 14, 15, 16}
	for _, alg := range knownAlgos {
		a := alg
		obs := algorithmObservation(&a)
		if obs == nil {
			t.Errorf("algorithm %d: expected non-nil observation", alg)
			continue
		}
		if obs["strength"] == nil {
			t.Errorf("algorithm %d: missing strength field", alg)
		}
		if obs["label"] == nil {
			t.Errorf("algorithm %d: missing label field", alg)
		}
		if obs["rfc"] == nil {
			t.Errorf("algorithm %d: missing rfc field", alg)
		}
		if obs["observation"] == nil {
			t.Errorf("algorithm %d: missing observation field", alg)
		}
		if obs["quantum_note"] == nil {
			t.Errorf("algorithm %d: missing quantum_note field", alg)
		}
	}
}

func intPtr(n int) *int {
	return &n
}
