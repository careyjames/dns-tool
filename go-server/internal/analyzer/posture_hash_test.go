// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
	"testing"
)

func TestGoldenRulePostureHashDeterministic(t *testing.T) {
	results := map[string]any{
		"spf_analysis": map[string]any{
			"status":  "pass",
			"records": []any{"v=spf1 include:_spf.google.com ~all"},
		},
		"dmarc_analysis": map[string]any{
			"status":  "pass",
			"policy":  "reject",
			"records": []any{"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"},
		},
		"dkim_analysis": map[string]any{
			"status": "pass",
			"selectors": []any{
				map[string]any{"selector": "google"},
				map[string]any{"selector": "default"},
			},
		},
		"mta_sts_analysis": map[string]any{
			"status": "pass",
			"mode":   "enforce",
		},
		"tlsrpt_analysis": map[string]any{
			"status": "pass",
		},
		"bimi_analysis": map[string]any{
			"status": "pass",
		},
		"dane_analysis": map[string]any{
			"status":   "pass",
			"has_dane": true,
		},
		"caa_analysis": map[string]any{
			"status": "pass",
			"records": []any{
				map[string]any{"tag": "issue", "value": "letsencrypt.org"},
			},
		},
		"dnssec_analysis": map[string]any{
			"status": "pass",
		},
		"mail_posture": map[string]any{
			"label": "Strongly Protected",
		},
		"basic_records": map[string]any{
			"mx": []any{
				map[string]any{"host": "mx2.example.com", "priority": 20},
				map[string]any{"host": "mx1.example.com", "priority": 10},
			},
			"ns": []any{"ns2.example.com.", "ns1.example.com."},
		},
	}

	hash1 := CanonicalPostureHash(results)
	hash2 := CanonicalPostureHash(results)

	if hash1 != hash2 {
		t.Errorf("Posture hash is not deterministic: %s != %s", hash1, hash2)
	}

	if len(hash1) != 128 {
		t.Errorf("Expected SHA-3-512 hex (128 chars), got %d chars: %s", len(hash1), hash1)
	}
}

func TestGoldenRulePostureHashChangesOnDrift(t *testing.T) {
	baseResults := func() map[string]any {
		return map[string]any{
			"spf_analysis": map[string]any{
				"status":  "pass",
				"records": []any{"v=spf1 include:_spf.google.com ~all"},
			},
			"dmarc_analysis": map[string]any{
				"status":  "pass",
				"policy":  "reject",
				"records": []any{"v=DMARC1; p=reject"},
			},
			"dkim_analysis": map[string]any{
				"status":    "pass",
				"selectors": []any{},
			},
			"mta_sts_analysis": map[string]any{"status": "warning"},
			"tlsrpt_analysis":  map[string]any{"status": "warning"},
			"bimi_analysis":    map[string]any{"status": "warning"},
			"dane_analysis":    map[string]any{"status": "info", "has_dane": false},
			"caa_analysis":     map[string]any{"status": "warning"},
			"dnssec_analysis":  map[string]any{"status": "warning"},
			"mail_posture":     map[string]any{"label": "Strongly Protected"},
			"basic_records": map[string]any{
				"mx": []any{map[string]any{"host": "mx.example.com"}},
				"ns": []any{"ns1.example.com."},
			},
		}
	}

	original := baseResults()
	originalHash := CanonicalPostureHash(original)

	t.Run("SPF change triggers drift", func(t *testing.T) {
		modified := baseResults()
		modified["spf_analysis"].(map[string]any)["status"] = "fail"
		if CanonicalPostureHash(modified) == originalHash {
			t.Error("SPF status change did not change posture hash")
		}
	})

	t.Run("DMARC policy change triggers drift", func(t *testing.T) {
		modified := baseResults()
		modified["dmarc_analysis"].(map[string]any)["policy"] = "none"
		if CanonicalPostureHash(modified) == originalHash {
			t.Error("DMARC policy change did not change posture hash")
		}
	})

	t.Run("MX change triggers drift", func(t *testing.T) {
		modified := baseResults()
		modified["basic_records"].(map[string]any)["mx"] = []any{
			map[string]any{"host": "mx-new.example.com"},
		}
		if CanonicalPostureHash(modified) == originalHash {
			t.Error("MX record change did not change posture hash")
		}
	})

	t.Run("NS change triggers drift", func(t *testing.T) {
		modified := baseResults()
		modified["basic_records"].(map[string]any)["ns"] = []any{"ns-new.example.com."}
		if CanonicalPostureHash(modified) == originalHash {
			t.Error("NS record change did not change posture hash")
		}
	})

	t.Run("DNSSEC change triggers drift", func(t *testing.T) {
		modified := baseResults()
		modified["dnssec_analysis"].(map[string]any)["status"] = "pass"
		if CanonicalPostureHash(modified) == originalHash {
			t.Error("DNSSEC status change did not change posture hash")
		}
	})

	t.Run("DANE change triggers drift", func(t *testing.T) {
		modified := baseResults()
		modified["dane_analysis"].(map[string]any)["has_dane"] = true
		if CanonicalPostureHash(modified) == originalHash {
			t.Error("DANE has_dane change did not change posture hash")
		}
	})
}

func TestGoldenRulePostureHashOrderIndependent(t *testing.T) {
	results1 := map[string]any{
		"basic_records": map[string]any{
			"mx": []any{
				map[string]any{"host": "mx1.example.com"},
				map[string]any{"host": "mx2.example.com"},
			},
			"ns": []any{"ns1.example.com.", "ns2.example.com."},
		},
		"dkim_analysis": map[string]any{
			"status": "pass",
			"selectors": []any{
				map[string]any{"selector": "alpha"},
				map[string]any{"selector": "beta"},
			},
		},
		"spf_analysis":     map[string]any{"status": "pass", "records": []any{"v=spf1 ~all"}},
		"dmarc_analysis":   map[string]any{"status": "pass", "policy": "reject", "records": []any{"v=DMARC1; p=reject"}},
		"mta_sts_analysis": map[string]any{"status": "warning"},
		"tlsrpt_analysis":  map[string]any{"status": "warning"},
		"bimi_analysis":    map[string]any{"status": "warning"},
		"dane_analysis":    map[string]any{"status": "info", "has_dane": false},
		"caa_analysis":     map[string]any{"status": "warning"},
		"dnssec_analysis":  map[string]any{"status": "warning"},
		"mail_posture":     map[string]any{"label": "Moderately Protected"},
	}

	results2 := map[string]any{
		"basic_records": map[string]any{
			"mx": []any{
				map[string]any{"host": "mx2.example.com"},
				map[string]any{"host": "mx1.example.com"},
			},
			"ns": []any{"ns2.example.com.", "ns1.example.com."},
		},
		"dkim_analysis": map[string]any{
			"status": "pass",
			"selectors": []any{
				map[string]any{"selector": "beta"},
				map[string]any{"selector": "alpha"},
			},
		},
		"spf_analysis":     map[string]any{"status": "pass", "records": []any{"v=spf1 ~all"}},
		"dmarc_analysis":   map[string]any{"status": "pass", "policy": "reject", "records": []any{"v=DMARC1; p=reject"}},
		"mta_sts_analysis": map[string]any{"status": "warning"},
		"tlsrpt_analysis":  map[string]any{"status": "warning"},
		"bimi_analysis":    map[string]any{"status": "warning"},
		"dane_analysis":    map[string]any{"status": "info", "has_dane": false},
		"caa_analysis":     map[string]any{"status": "warning"},
		"dnssec_analysis":  map[string]any{"status": "warning"},
		"mail_posture":     map[string]any{"label": "Moderately Protected"},
	}

	hash1 := CanonicalPostureHash(results1)
	hash2 := CanonicalPostureHash(results2)

	if hash1 != hash2 {
		t.Errorf("Posture hash should be order-independent for MX/NS/selectors: %s != %s", hash1, hash2)
	}
}

func TestGoldenRulePostureHashEmptyResults(t *testing.T) {
	hash := CanonicalPostureHash(map[string]any{})
	if len(hash) != 128 {
		t.Errorf("Expected SHA-3-512 hex (128 chars) even for empty results, got %d chars", len(hash))
	}
}
