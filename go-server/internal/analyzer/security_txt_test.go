// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
	"testing"
	"time"
)

func TestSecurityTxtEvaluateExpiry(t *testing.T) {
	tests := []struct {
		name            string
		expiresStr      string
		expectedExpired bool
		expectedDateLen int
		expectError     bool
	}{
		{
			name:            "Empty string",
			expiresStr:      "",
			expectedExpired: false,
			expectedDateLen: 0,
			expectError:     false,
		},
		{
			name:            "Valid RFC3339 future date",
			expiresStr:      time.Now().AddDate(1, 0, 0).Format(time.RFC3339),
			expectedExpired: false,
			expectedDateLen: 10,
			expectError:     false,
		},
		{
			name:            "Valid RFC3339 past date",
			expiresStr:      time.Now().AddDate(-1, 0, 0).Format(time.RFC3339),
			expectedExpired: true,
			expectedDateLen: 10,
			expectError:     false,
		},
		{
			name:            "ISO8601 format without timezone offset",
			expiresStr:      time.Now().AddDate(1, 0, 0).Format("2006-01-02T15:04:05Z"),
			expectedExpired: false,
			expectedDateLen: 10,
			expectError:     false,
		},
		{
			name:            "ISO8601 format without timezone offset (past date)",
			expiresStr:      time.Now().AddDate(-1, 0, 0).Format("2006-01-02T15:04:05Z"),
			expectedExpired: true,
			expectedDateLen: 10,
			expectError:     false,
		},
		{
			name:            "Unparseable string",
			expiresStr:      "not-a-valid-date",
			expectedExpired: false,
			expectedDateLen: len("unparseable"),
			expectError:     false,
		},
		{
			name:            "Unparseable malformed date",
			expiresStr:      "2024/13/45",
			expectedExpired: false,
			expectedDateLen: len("unparseable"),
			expectError:     false,
		},
		{
			name:            "Empty string should return empty date",
			expiresStr:      "",
			expectedExpired: false,
			expectedDateLen: 0,
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expired, dateStr := evaluateSecurityTxtExpiry(tt.expiresStr)

			if expired != tt.expectedExpired {
				t.Errorf("expected expired=%v, got %v", tt.expectedExpired, expired)
			}

			if tt.expiresStr == "" && dateStr != "" {
				t.Errorf("expected empty date string for empty input, got %q", dateStr)
			}

			if tt.expiresStr == "unparseable string" || tt.expiresStr == "not-a-valid-date" || tt.expiresStr == "2024/13/45" {
				if dateStr != "unparseable" {
					t.Errorf("expected 'unparseable' for invalid date, got %q", dateStr)
				}
			}

			if tt.expiresStr != "" && dateStr != "" && dateStr != "unparseable" {
				if len(dateStr) != tt.expectedDateLen {
					t.Errorf("expected date length %d, got %d for %q", tt.expectedDateLen, len(dateStr), dateStr)
				}
			}
		})
	}
}

func TestSecurityTxtParse(t *testing.T) {
	tests := []struct {
		name              string
		body              string
		expectedContacts  []string
		expectedExpires   string
		expectedPolicy    []string
		expectedSigned    bool
		expectedEncrypt   []string
		expectedCanonical []string
	}{
		{
			name: "Basic security.txt with contacts, expires, and policy",
			body: `Contact: security@example.com
Expires: 2025-12-31T23:59:59Z
Policy: https://example.com/security-policy.txt`,
			expectedContacts: []string{"security@example.com"},
			expectedExpires:  "2025-12-31T23:59:59Z",
			expectedPolicy:   []string{"https://example.com/security-policy.txt"},
			expectedSigned:   false,
		},
		{
			name: "Multiple contacts",
			body: `Contact: security@example.com
Contact: cert@example.com
Expires: 2025-12-31T23:59:59Z`,
			expectedContacts: []string{"security@example.com", "cert@example.com"},
			expectedExpires:  "2025-12-31T23:59:59Z",
			expectedPolicy:   []string{},
			expectedSigned:   false,
		},
		{
			name: "With comments",
			body: `# This is a comment
Contact: security@example.com
# Another comment
Expires: 2025-12-31T23:59:59Z`,
			expectedContacts: []string{"security@example.com"},
			expectedExpires:  "2025-12-31T23:59:59Z",
			expectedPolicy:   []string{},
			expectedSigned:   false,
		},
		{
			name: "PGP signed message",
			body: `-----BEGIN PGP SIGNED MESSAGE-----
Contact: security@example.com
Expires: 2025-12-31T23:59:59Z
-----END PGP SIGNATURE-----`,
			expectedContacts: []string{"security@example.com"},
			expectedExpires:  "2025-12-31T23:59:59Z",
			expectedPolicy:   []string{},
			expectedSigned:   true,
		},
		{
			name:             "Empty body",
			body:             ``,
			expectedContacts: []string{},
			expectedExpires:  "",
			expectedPolicy:   []string{},
			expectedSigned:   false,
		},
		{
			name: "Case insensitive field names",
			body: `contact: security@example.com
EXPIRES: 2025-12-31T23:59:59Z
PoLiCy: https://example.com/policy.txt
Encryption: https://example.com/pgp-key.txt`,
			expectedContacts: []string{"security@example.com"},
			expectedExpires:  "2025-12-31T23:59:59Z",
			expectedPolicy:   []string{"https://example.com/policy.txt"},
			expectedEncrypt:  []string{"https://example.com/pgp-key.txt"},
			expectedSigned:   false,
		},
		{
			name: "Whitespace handling",
			body: `Contact:   security@example.com   
Expires:  2025-12-31T23:59:59Z  
Policy:   https://example.com/policy.txt  `,
			expectedContacts: []string{"security@example.com"},
			expectedExpires:  "2025-12-31T23:59:59Z",
			expectedPolicy:   []string{"https://example.com/policy.txt"},
			expectedSigned:   false,
		},
		{
			name: "Multiple policies and encryption keys",
			body: `Contact: security@example.com
Policy: https://example.com/policy.txt
Policy: https://example.com/incident-response.txt
Encryption: https://example.com/pgp.txt
Encryption: https://example.com/gpg.txt
Expires: 2025-12-31T23:59:59Z`,
			expectedContacts: []string{"security@example.com"},
			expectedExpires:  "2025-12-31T23:59:59Z",
			expectedPolicy:   []string{"https://example.com/policy.txt", "https://example.com/incident-response.txt"},
			expectedEncrypt:  []string{"https://example.com/pgp.txt", "https://example.com/gpg.txt"},
			expectedSigned:   false,
		},
		{
			name: "All RFC 9116 fields",
			body: `Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59Z
Encryption: https://example.com/pgp.txt
Policy: https://example.com/policy.txt
Acknowledgments: https://example.com/acknowledgments.html
Hiring: https://example.com/careers.html
Canonical: https://example.com/.well-known/security.txt
Preferred-Languages: en`,
			expectedContacts:  []string{"mailto:security@example.com"},
			expectedExpires:   "2025-12-31T23:59:59Z",
			expectedPolicy:    []string{"https://example.com/policy.txt"},
			expectedEncrypt:   []string{"https://example.com/pgp.txt"},
			expectedCanonical: []string{"https://example.com/.well-known/security.txt"},
			expectedSigned:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields := parseSecurityTxt(tt.body)

			// Check contacts
			if len(fields.contacts) != len(tt.expectedContacts) {
				t.Errorf("expected %d contacts, got %d", len(tt.expectedContacts), len(fields.contacts))
			}
			for i, contact := range fields.contacts {
				if i < len(tt.expectedContacts) && contact != tt.expectedContacts[i] {
					t.Errorf("contact[%d]: expected %q, got %q", i, tt.expectedContacts[i], contact)
				}
			}

			// Check expires
			if fields.expires != tt.expectedExpires {
				t.Errorf("expected expires %q, got %q", tt.expectedExpires, fields.expires)
			}

			// Check policy
			if len(fields.policy) != len(tt.expectedPolicy) {
				t.Errorf("expected %d policies, got %d", len(tt.expectedPolicy), len(fields.policy))
			}
			for i, policy := range fields.policy {
				if i < len(tt.expectedPolicy) && policy != tt.expectedPolicy[i] {
					t.Errorf("policy[%d]: expected %q, got %q", i, tt.expectedPolicy[i], policy)
				}
			}

			// Check signed
			if fields.signed != tt.expectedSigned {
				t.Errorf("expected signed=%v, got %v", tt.expectedSigned, fields.signed)
			}

			// Check encryption keys if specified
			if len(tt.expectedEncrypt) > 0 {
				if len(fields.encrypt) != len(tt.expectedEncrypt) {
					t.Errorf("expected %d encryption keys, got %d", len(tt.expectedEncrypt), len(fields.encrypt))
				}
				for i, enc := range fields.encrypt {
					if i < len(tt.expectedEncrypt) && enc != tt.expectedEncrypt[i] {
						t.Errorf("encrypt[%d]: expected %q, got %q", i, tt.expectedEncrypt[i], enc)
					}
				}
			}

			// Check canonical if specified
			if len(tt.expectedCanonical) > 0 {
				if len(fields.canonical) != len(tt.expectedCanonical) {
					t.Errorf("expected %d canonical entries, got %d", len(tt.expectedCanonical), len(fields.canonical))
				}
				for i, can := range fields.canonical {
					if i < len(tt.expectedCanonical) && can != tt.expectedCanonical[i] {
						t.Errorf("canonical[%d]: expected %q, got %q", i, tt.expectedCanonical[i], can)
					}
				}
			}
		})
	}
}

func TestSecurityTxtExpiryEdgeCases(t *testing.T) {
	tests := []struct {
		name            string
		expiresStr      string
		expectedExpired bool
		expectedResp    string
	}{
		{
			name:            "Very old past date RFC3339",
			expiresStr:      "2000-01-01T00:00:00Z",
			expectedExpired: true,
			expectedResp:    "2000-01-01",
		},
		{
			name:            "Far future date RFC3339",
			expiresStr:      "2099-12-31T23:59:59Z",
			expectedExpired: false,
			expectedResp:    "2099-12-31",
		},
		{
			name:            "Date without seconds",
			expiresStr:      "2025-12-31T23:59Z",
			expectedExpired: false,
			expectedResp:    "unparseable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expired, dateStr := evaluateSecurityTxtExpiry(tt.expiresStr)

			// Check if expiration matches expected
			if expired != tt.expectedExpired {
				t.Errorf("expected expired=%v, got %v", tt.expectedExpired, expired)
			}

			// Check if response matches expected pattern
			if tt.expectedResp == "unparseable" && dateStr != "unparseable" {
				t.Errorf("expected 'unparseable', got %q", dateStr)
			} else if tt.expectedResp != "unparseable" && (dateStr == "" || dateStr == "unparseable") {
				t.Errorf("expected valid date, got %q", dateStr)
			}
		})
	}
}

func TestSecurityTxtEmpty(t *testing.T) {
	fields := parseSecurityTxt("")

	if len(fields.contacts) != 0 {
		t.Errorf("expected 0 contacts, got %d", len(fields.contacts))
	}
	if fields.expires != "" {
		t.Errorf("expected empty expires, got %q", fields.expires)
	}
	if len(fields.policy) != 0 {
		t.Errorf("expected 0 policies, got %d", len(fields.policy))
	}
	if fields.signed != false {
		t.Errorf("expected signed=false, got true")
	}
}
