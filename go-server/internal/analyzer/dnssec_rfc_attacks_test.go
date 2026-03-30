package analyzer

import (
	"fmt"
	"testing"
)

func TestDNSSECRFCAttack_MissingDSRecord(t *testing.T) {
	tests := []struct {
		name           string
		hasDNSKEY      bool
		hasDS          bool
		wantStatus     string
		wantChain      string
	}{
		{
			"DNSKEY present but no DS at parent — broken chain of trust",
			true, false, "warning", "broken",
		},
		{
			"neither DNSKEY nor DS — DNSSEC not deployed",
			false, false, "warning", "none",
		},
		{
			"both DNSKEY and DS present — complete chain",
			true, true, "success", "complete",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := buildDNSSECResult(dnssecParams{
				hasDNSKEY:     tt.hasDNSKEY,
				hasDS:         tt.hasDS,
				dnskeyRecords: func() []string {
					if tt.hasDNSKEY {
						return []string{"256 3 13 KEY"}
					}
					return []string{}
				}(),
				dsRecords: func() []string {
					if tt.hasDS {
						return []string{"12345 13 2 AABB"}
					}
					return []string{}
				}(),
			})
			if r[mapKeyStatus] != tt.wantStatus {
				t.Errorf("status = %v, want %v", r[mapKeyStatus], tt.wantStatus)
			}
			if r[mapKeyChainOfTrust] != tt.wantChain {
				t.Errorf("chain_of_trust = %v, want %v", r[mapKeyChainOfTrust], tt.wantChain)
			}
		})
	}
}

func TestDNSSECRFCAttack_IncompleteDeployment(t *testing.T) {
	resolver := "8.8.8.8"

	t.Run("DNSKEY exists but DS missing at registrar", func(t *testing.T) {
		r := buildDNSSECResult(dnssecParams{
			hasDNSKEY:     true,
			hasDS:         false,
			adFlag:        false,
			dnskeyRecords: []string{"257 3 13 PUBLICKEY"},
			dsRecords:     []string{},
			adResolver:    &resolver,
		})
		if r[mapKeyStatus] != "warning" {
			t.Errorf("status = %v, want warning", r[mapKeyStatus])
		}
		if r[mapKeyChainOfTrust] != "broken" {
			t.Errorf("chain_of_trust = %v, want broken", r[mapKeyChainOfTrust])
		}
		if r[mapKeyHasDnskey] != true {
			t.Error("has_dnskey should be true")
		}
		if r[mapKeyHasDs] != false {
			t.Error("has_ds should be false")
		}
		if r[mapKeyAlgorithm] != nil {
			t.Errorf("algorithm should be nil for broken chain, got %v", r[mapKeyAlgorithm])
		}
	})

	t.Run("DS present but no DNSKEY — falls to no-DNSSEC path", func(t *testing.T) {
		algo := 8
		algoName := "RSA/SHA-256"
		r := buildDNSSECResult(dnssecParams{
			hasDNSKEY:     false,
			hasDS:         true,
			adFlag:        false,
			dsRecords:     []string{"12345 8 2 AABB"},
			algorithm:     &algo,
			algorithmName: &algoName,
			adResolver:    &resolver,
		})
		if r[mapKeyStatus] != "warning" {
			t.Errorf("status = %v, want warning for DS-only deployment", r[mapKeyStatus])
		}
		if r[mapKeyChainOfTrust] != "none" {
			t.Errorf("chain_of_trust = %v, want none", r[mapKeyChainOfTrust])
		}
	})
}

func TestDNSSECRFCAttack_AlgorithmClassification(t *testing.T) {
	tests := []struct {
		name         string
		algoNum      int
		wantStrength string
	}{
		{"RSAMD5 (1) — MUST NOT use per RFC 8624", 1, "deprecated"},
		{"DSA (3) — MUST NOT use per RFC 8624", 3, "deprecated"},
		{"RSA/SHA-1 (5) — legacy per RFC 8624", 5, "legacy"},
		{"DSA-NSEC3-SHA1 (6) — MUST NOT use per RFC 8624", 6, "deprecated"},
		{"RSASHA1-NSEC3-SHA1 (7) — legacy per RFC 8624", 7, "legacy"},
		{"RSA/SHA-256 (8) — adequate, MUST implement", 8, "adequate"},
		{"RSA/SHA-512 (10) — legacy per RFC 8624", 10, "legacy"},
		{"ECC-GOST (12) — deprecated", 12, "deprecated"},
		{"ECDSA P-256/SHA-256 (13) — modern, MUST implement", 13, "modern"},
		{"ECDSA P-384/SHA-384 (14) — modern", 14, "modern"},
		{"Ed25519 (15) — modern, RECOMMENDED", 15, "modern"},
		{"Ed448 (16) — modern", 16, "modern"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ClassifyDNSSECAlgorithm(tt.algoNum)
			if c.Strength != tt.wantStrength {
				t.Errorf("algorithm %d strength = %q, want %q", tt.algoNum, c.Strength, tt.wantStrength)
			}
			if c.RFC == "" {
				t.Errorf("algorithm %d: RFC field should not be empty", tt.algoNum)
			}
			if c.Observation == "" {
				t.Errorf("algorithm %d: Observation should not be empty", tt.algoNum)
			}
			if c.QuantumNote == "" {
				t.Errorf("algorithm %d: QuantumNote should not be empty", tt.algoNum)
			}
		})
	}
}

func TestDNSSECRFCAttack_DeprecatedAlgorithms(t *testing.T) {
	deprecated := []int{1, 3, 6, 12}
	for _, alg := range deprecated {
		t.Run(fmt.Sprintf("algorithm_%d_deprecated", alg), func(t *testing.T) {
			c := ClassifyDNSSECAlgorithm(alg)
			if c.Strength != "deprecated" {
				t.Errorf("algorithm %d should be deprecated, got %q", alg, c.Strength)
			}
			if c.Label != "Deprecated" {
				t.Errorf("algorithm %d label = %q, want Deprecated", alg, c.Label)
			}
		})
	}
}

func TestDNSSECRFCAttack_RecommendedAlgorithms(t *testing.T) {
	recommended := []int{13, 15}
	for _, alg := range recommended {
		t.Run(fmt.Sprintf("algorithm_%d_modern", alg), func(t *testing.T) {
			c := ClassifyDNSSECAlgorithm(alg)
			if c.Strength != "modern" {
				t.Errorf("algorithm %d should be modern, got %q", alg, c.Strength)
			}
			if c.Label != "Modern" {
				t.Errorf("algorithm %d label = %q, want Modern", alg, c.Label)
			}
		})
	}
}

func TestDNSSECRFCAttack_ADFlagHandling(t *testing.T) {
	algo := 13
	algoName := "ECDSA P-256/SHA-256"
	resolver := "8.8.8.8"

	tests := []struct {
		name       string
		adFlag     bool
		wantADFlag bool
	}{
		{"AD flag present — resolver validated chain of trust", true, true},
		{"AD flag absent — resolver did not validate", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := buildDNSSECResult(dnssecParams{
				hasDNSKEY:     true,
				hasDS:         true,
				adFlag:        tt.adFlag,
				dnskeyRecords: []string{"257 3 13 KEY"},
				dsRecords:     []string{"12345 13 2 AABB"},
				algorithm:     &algo,
				algorithmName: &algoName,
				adResolver:    &resolver,
			})
			if r[mapKeyStatus] != "success" {
				t.Errorf("status = %v, want success", r[mapKeyStatus])
			}
			if r[mapKeyAdFlag] != tt.wantADFlag {
				t.Errorf("ad_flag = %v, want %v", r[mapKeyAdFlag], tt.wantADFlag)
			}
			msg := r[mapKeyMessage].(string)
			if tt.adFlag && len(msg) == 0 {
				t.Error("message should not be empty when AD flag is set")
			}
		})
	}
}

func TestDNSSECRFCAttack_InvalidAlgorithmNumbers(t *testing.T) {
	tests := []struct {
		name    string
		algoNum int
	}{
		{"algorithm 0 — reserved", 0},
		{"algorithm 2 — unassigned", 2},
		{"algorithm 4 — unassigned", 4},
		{"algorithm 9 — unassigned", 9},
		{"algorithm 11 — unassigned", 11},
		{"algorithm 17 — unassigned", 17},
		{"algorithm 99 — far out of range", 99},
		{"algorithm 255 — private use", 255},
		{"algorithm 999 — well out of range", 999},
		{"negative wrapped as large positive", 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ClassifyDNSSECAlgorithm(tt.algoNum)
			if c.Strength != "adequate" {
				t.Errorf("unknown algorithm %d strength = %q, want adequate (default)", tt.algoNum, c.Strength)
			}
			if c.Observation == "" {
				t.Errorf("unknown algorithm %d: Observation should not be empty", tt.algoNum)
			}
		})
	}
}

func TestDNSSECRFCAttack_MixedAlgorithmDeployments(t *testing.T) {
	t.Run("parse only uses first DS record algorithm", func(t *testing.T) {
		dsRecords := []string{
			"12345 8 2 AABBCCDD",
			"12345 13 2 EEFF0011",
		}
		algo, name := parseAlgorithm(dsRecords)
		if algo == nil || *algo != 8 {
			t.Errorf("expected algorithm 8 from first DS record, got %v", algo)
		}
		if name == nil || *name != "RSA/SHA-256" {
			t.Errorf("expected RSA/SHA-256, got %v", name)
		}
	})

	t.Run("deprecated first record with modern second — reports deprecated", func(t *testing.T) {
		dsRecords := []string{
			"12345 1 1 AABBCCDD",
			"12345 13 2 EEFF0011",
		}
		algo, _ := parseAlgorithm(dsRecords)
		if algo == nil || *algo != 1 {
			t.Errorf("expected algorithm 1 (deprecated RSAMD5), got %v", algo)
		}
		obs := algorithmObservation(algo)
		if obs == nil {
			t.Fatal("expected non-nil observation")
		}
		if obs["strength"] != "deprecated" {
			t.Errorf("strength = %v, want deprecated for RSAMD5", obs["strength"])
		}
	})

	t.Run("modern first record — classified as modern", func(t *testing.T) {
		dsRecords := []string{
			"12345 13 2 AABBCCDD",
			"12345 8 2 EEFF0011",
		}
		algo, _ := parseAlgorithm(dsRecords)
		if algo == nil || *algo != 13 {
			t.Errorf("expected algorithm 13, got %v", algo)
		}
		obs := algorithmObservation(algo)
		if obs["strength"] != "modern" {
			t.Errorf("strength = %v, want modern", obs["strength"])
		}
	})
}

func TestDNSSECRFCAttack_ParseAlgorithmEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		dsRecords   []string
		wantNilAlgo bool
		wantAlgo    int
	}{
		{"empty DS record list", []string{}, true, 0},
		{"DS record with only key tag", []string{"12345"}, true, 0},
		{"DS record with non-numeric algorithm", []string{"12345 abc 2 AABB"}, true, 0},
		{"DS record with empty string", []string{""}, true, 0},
		{"DS record with only whitespace", []string{"   "}, true, 0},
		{"DS record with negative algorithm", []string{"12345 -1 2 AABB"}, false, -1},
		{"DS record with zero algorithm", []string{"12345 0 2 AABB"}, false, 0},
		{"DS record with very large algorithm", []string{"12345 65535 2 AABB"}, false, 65535},
		{"DS record with extra whitespace", []string{"12345  13  2  AABB"}, false, 13},
		{"DS record with tab separators", []string{"12345\t8\t2\tAABB"}, false, 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algo, name := parseAlgorithm(tt.dsRecords)
			if tt.wantNilAlgo {
				if algo != nil {
					t.Errorf("expected nil algorithm, got %d", *algo)
				}
				if name != nil {
					t.Errorf("expected nil name, got %q", *name)
				}
			} else {
				if algo == nil {
					t.Fatal("expected non-nil algorithm")
				}
				if *algo != tt.wantAlgo {
					t.Errorf("algorithm = %d, want %d", *algo, tt.wantAlgo)
				}
				if name == nil {
					t.Fatal("expected non-nil name")
				}
			}
		})
	}
}

func TestDNSSECRFCAttack_BuildResultAlgorithmObservation(t *testing.T) {
	tests := []struct {
		name         string
		algo         int
		wantStrength string
	}{
		{"RSAMD5 in result", 1, "deprecated"},
		{"RSA/SHA-256 in result", 8, "adequate"},
		{"ECDSA P-256 in result", 13, "modern"},
		{"Ed25519 in result", 15, "modern"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algoName := algorithmNames[tt.algo]
			resolver := "8.8.8.8"
			r := buildDNSSECResult(dnssecParams{
				hasDNSKEY:     true,
				hasDS:         true,
				adFlag:        true,
				dnskeyRecords: []string{"key"},
				dsRecords:     []string{fmt.Sprintf("12345 %d 2 AABB", tt.algo)},
				algorithm:     &tt.algo,
				algorithmName: &algoName,
				adResolver:    &resolver,
			})
			obs, ok := r[mapKeyAlgorithmObservation].(map[string]any)
			if !ok {
				t.Fatal("expected algorithm_observation to be map[string]any")
			}
			if obs["strength"] != tt.wantStrength {
				t.Errorf("strength = %v, want %v", obs["strength"], tt.wantStrength)
			}
		})
	}
}

func TestDNSSECRFCAttack_NoObservationForBrokenChain(t *testing.T) {
	r := buildDNSSECResult(dnssecParams{
		hasDNSKEY:     true,
		hasDS:         false,
		dnskeyRecords: []string{"257 3 13 KEY"},
		dsRecords:     []string{},
	})
	if r[mapKeyAlgorithmObservation] != nil {
		t.Errorf("algorithm_observation should be nil for broken chain, got %v", r[mapKeyAlgorithmObservation])
	}
}

func TestDNSSECRFCAttack_NoObservationForNoDNSSEC(t *testing.T) {
	r := buildDNSSECResult(dnssecParams{
		hasDNSKEY: false,
		hasDS:     false,
	})
	if r[mapKeyAlgorithmObservation] != nil {
		t.Errorf("algorithm_observation should be nil when DNSSEC not deployed, got %v", r[mapKeyAlgorithmObservation])
	}
}

func TestDNSSECRFCAttack_InheritedDNSSEC(t *testing.T) {
	resolver := "8.8.8.8"
	algo := 13
	algoName := "ECDSA P-256/SHA-256"

	t.Run("inherited from parent zone", func(t *testing.T) {
		r := buildInheritedDNSSECResult("example.com", &resolver, &algo, &algoName)
		if r[mapKeyStatus] != "success" {
			t.Errorf("status = %v, want success", r[mapKeyStatus])
		}
		if r[mapKeyChainOfTrust] != "inherited" {
			t.Errorf("chain_of_trust = %v, want inherited", r[mapKeyChainOfTrust])
		}
		if r["is_subdomain"] != true {
			t.Error("is_subdomain should be true")
		}
		if r[mapKeyAdFlag] != true {
			t.Error("ad_flag should be true for inherited DNSSEC")
		}
	})

	t.Run("inherited with deprecated parent algorithm", func(t *testing.T) {
		depAlgo := 1
		depAlgoName := "RSAMD5"
		r := buildInheritedDNSSECResult("example.com", &resolver, &depAlgo, &depAlgoName)
		obs, ok := r[mapKeyAlgorithmObservation].(map[string]any)
		if !ok {
			t.Fatal("expected algorithm_observation map")
		}
		if obs["strength"] != "deprecated" {
			t.Errorf("inherited from deprecated parent: strength = %v, want deprecated", obs["strength"])
		}
	})
}

func TestDNSSECRFCAttack_CollectRecordsTruncation(t *testing.T) {
	t.Run("more than 3 DNSKEY records truncated to 3", func(t *testing.T) {
		records := []string{"key1", "key2", "key3", "key4", "key5"}
		has, collected := collectDNSKEYRecords(records)
		if !has {
			t.Error("expected has=true")
		}
		if len(collected) != 3 {
			t.Errorf("expected 3 records, got %d", len(collected))
		}
	})

	t.Run("more than 3 DS records truncated to 3", func(t *testing.T) {
		records := []string{"ds1", "ds2", "ds3", "ds4"}
		has, collected := collectDSRecords(records)
		if !has {
			t.Error("expected has=true")
		}
		if len(collected) != 3 {
			t.Errorf("expected 3 records, got %d", len(collected))
		}
	})
}

func TestDNSSECRFCAttack_AlgorithmNameMapping(t *testing.T) {
	expected := map[int]string{
		1: "RSAMD5", 3: "DSA", 5: "RSA/SHA-1", 6: "DSA-NSEC3-SHA1",
		7: "RSASHA1-NSEC3-SHA1", 8: "RSA/SHA-256", 10: "RSA/SHA-512",
		12: "ECC-GOST", 13: "ECDSA P-256/SHA-256", 14: "ECDSA P-384/SHA-384",
		15: "Ed25519", 16: "Ed448",
	}

	for num, wantName := range expected {
		t.Run(fmt.Sprintf("algorithm_%d_%s", num, wantName), func(t *testing.T) {
			ds := []string{fmt.Sprintf("12345 %d 2 AABB", num)}
			_, name := parseAlgorithm(ds)
			if name == nil {
				t.Fatalf("expected non-nil name for algorithm %d", num)
			}
			if *name != wantName {
				t.Errorf("algorithm %d name = %q, want %q", num, *name, wantName)
			}
		})
	}
}

func TestDNSSECRFCAttack_UnknownAlgorithmFallback(t *testing.T) {
	unknowns := []int{0, 2, 4, 9, 11, 17, 50, 100, 254}
	for _, alg := range unknowns {
		t.Run(fmt.Sprintf("algorithm_%d_unknown", alg), func(t *testing.T) {
			ds := []string{fmt.Sprintf("12345 %d 2 AABB", alg)}
			algo, name := parseAlgorithm(ds)
			if algo == nil || *algo != alg {
				t.Errorf("expected algorithm %d, got %v", alg, algo)
			}
			wantName := fmt.Sprintf("Algorithm %d", alg)
			if name == nil || *name != wantName {
				t.Errorf("expected name %q, got %v", wantName, name)
			}
		})
	}
}

func TestDNSSECRFCAttack_FullDeploymentWithADFlag(t *testing.T) {
	algo := 13
	algoName := "ECDSA P-256/SHA-256"
	resolver := "1.1.1.1"

	r := buildDNSSECResult(dnssecParams{
		hasDNSKEY:     true,
		hasDS:         true,
		adFlag:        true,
		dnskeyRecords: []string{"257 3 13 PUBLICKEY"},
		dsRecords:     []string{"12345 13 2 AABBCCDD"},
		algorithm:     &algo,
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
		t.Error("ad_flag should be true")
	}
	if r[mapKeyHasDnskey] != true {
		t.Error("has_dnskey should be true")
	}
	if r[mapKeyHasDs] != true {
		t.Error("has_ds should be true")
	}
	if r[mapKeyAlgorithm] != 13 {
		t.Errorf("algorithm = %v, want 13", r[mapKeyAlgorithm])
	}
	msg := r[mapKeyMessage].(string)
	if len(msg) == 0 {
		t.Error("message should not be empty")
	}
}

func TestDNSSECRFCAttack_FullDeploymentWithoutADFlag(t *testing.T) {
	algo := 8
	algoName := "RSA/SHA-256"
	resolver := "8.8.8.8"

	r := buildDNSSECResult(dnssecParams{
		hasDNSKEY:     true,
		hasDS:         true,
		adFlag:        false,
		dnskeyRecords: []string{"257 3 8 PUBLICKEY"},
		dsRecords:     []string{"12345 8 2 AABBCCDD"},
		algorithm:     &algo,
		algorithmName: &algoName,
		adResolver:    &resolver,
	})

	if r[mapKeyStatus] != "success" {
		t.Errorf("status = %v, want success", r[mapKeyStatus])
	}
	if r[mapKeyAdFlag] != false {
		t.Error("ad_flag should be false")
	}
	msg := r[mapKeyMessage].(string)
	if msg == "" {
		t.Error("message should not be empty")
	}
}

func TestDNSSECRFCAttack_DNSSECOpsKeyRoleClassification(t *testing.T) {
	tests := []struct {
		name     string
		flags    uint16
		wantRole string
	}{
		{"KSK flags 257", 257, "KSK"},
		{"ZSK flags 256", 256, "ZSK"},
		{"KSK-like odd flags", 259, "KSK-like"},
		{"unknown flags 0", 0, "unknown"},
		{"unknown flags 512", 512, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := classifyKeyRole(tt.flags)
			if role != tt.wantRole {
				t.Errorf("classifyKeyRole(%d) = %q, want %q", tt.flags, role, tt.wantRole)
			}
		})
	}
}

func TestDNSSECRFCAttack_KeySizeEstimation(t *testing.T) {
	tests := []struct {
		name     string
		algo     uint8
		wantSize int
	}{
		{"ECDSA P-256 always 256 bits", 13, 256},
		{"ECDSA P-384 always 384 bits", 14, 384},
		{"Ed25519 always 256 bits", 15, 256},
		{"Ed448 always 456 bits", 16, 456},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			size := estimateKeySize(tt.algo, "dummypublickey")
			if size != tt.wantSize {
				t.Errorf("estimateKeySize(%d) = %d, want %d", tt.algo, size, tt.wantSize)
			}
		})
	}
}
