package analyzer

import (
	"testing"
)

func TestIdentifyCAIssuer(t *testing.T) {
	tests := []struct {
		name   string
		record string
		want   string
	}{
		{"letsencrypt", "0 issue \"letsencrypt.org\"", "Let's Encrypt"},
		{"digicert", "0 issue \"digicert.com\"", "DigiCert"},
		{"sectigo", "0 issue \"sectigo.com\"", "Sectigo"},
		{"comodo", "0 issue \"comodoca.com\"", "Sectigo"},
		{"globalsign", "0 issue \"globalsign.com\"", "GlobalSign"},
		{"amazon", "0 issue \"amazon.com\"", "Amazon"},
		{"google", "0 issue \"pki.goog\"", "pki.goog"},
		{"unknown with parts", "0 issue \"unknownca.com\"", "unknownca.com"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := identifyCAIssuer(tt.record)
			if got != tt.want {
				t.Errorf("identifyCAIssuer(%q) = %q, want %q", tt.record, got, tt.want)
			}
		})
	}
}

func TestParseCAARecords(t *testing.T) {
	records := []string{
		"0 issue \"letsencrypt.org\"",
		"0 issuewild \"digicert.com\"",
		"0 iodef \"mailto:admin@example.com\"",
	}
	parsed := parseCAARecords(records)

	if len(parsed.issueSet) != 1 {
		t.Errorf("expected 1 issuer, got %d", len(parsed.issueSet))
	}
	if !parsed.issueSet["Let's Encrypt"] {
		t.Error("expected Let's Encrypt in issueSet")
	}
	if !parsed.hasWildcard {
		t.Error("expected hasWildcard")
	}
	if len(parsed.issuewildSet) != 1 {
		t.Errorf("expected 1 wildcard issuer, got %d", len(parsed.issuewildSet))
	}
	if !parsed.hasIodef {
		t.Error("expected hasIodef")
	}
}

func TestParseSingleCAARecord(t *testing.T) {
	parsed := &caaParsedRecords{
		issueSet:     make(map[string]bool),
		issuewildSet: make(map[string]bool),
	}

	parseSingleCAARecord("0 issue \"letsencrypt.org\"", parsed)
	if len(parsed.issueSet) != 1 {
		t.Errorf("expected 1 issuer, got %d", len(parsed.issueSet))
	}

	parseSingleCAARecord("0 issuewild \"digicert.com\"", parsed)
	if !parsed.hasWildcard {
		t.Error("expected hasWildcard")
	}

	parseSingleCAARecord("0 iodef \"mailto:admin@example.com\"", parsed)
	if !parsed.hasIodef {
		t.Error("expected hasIodef")
	}
}

func TestCollectMapKeys(t *testing.T) {
	m := map[string]bool{"a": true, "b": true}
	keys := collectMapKeys(m)
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}

	empty := collectMapKeys(map[string]bool{})
	if len(empty) != 0 {
		t.Errorf("expected 0 keys, got %d", len(empty))
	}
}

func TestBuildCAAMessage(t *testing.T) {
	tests := []struct {
		name     string
		issuers  []string
		wildcard []string
		hasWild  bool
	}{
		{"with issuers", []string{"Let's Encrypt"}, nil, false},
		{"no issuers", nil, nil, false},
		{"with wildcard issuers", []string{"Let's Encrypt"}, []string{"DigiCert"}, true},
		{"wildcard no issuers", nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := buildCAAMessage(tt.issuers, tt.wildcard, tt.hasWild)
			if msg == "" {
				t.Error("expected non-empty message")
			}
		})
	}
}
