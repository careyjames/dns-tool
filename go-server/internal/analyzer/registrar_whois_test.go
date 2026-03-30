package analyzer

import (
	"testing"
)

func TestGetTLDRegistrar(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"example.com", "com"},
		{"sub.example.co.uk", "uk"},
		{"example.org", "org"},
		{"localhost", "localhost"},
		{"a.b.c.d.io", "io"},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := getTLD(tt.domain)
			if got != tt.want {
				t.Errorf("getTLD(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

func TestIsDigits(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"12345", true},
		{"0", true},
		{"", false},
		{"123abc", false},
		{"abc", false},
		{"12 34", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isDigits(tt.input)
			if got != tt.want {
				t.Errorf("isDigits(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatRegistrarWithRegistrant(t *testing.T) {
	tests := []struct {
		registrar  string
		registrant string
		want       string
	}{
		{"GoDaddy", "ACME Corp", "GoDaddy (Registrant: ACME Corp)"},
		{"GoDaddy", "", "GoDaddy"},
		{"Namecheap", "Example Inc", "Namecheap (Registrant: Example Inc)"},
	}
	for _, tt := range tests {
		t.Run(tt.registrar+"_"+tt.registrant, func(t *testing.T) {
			got := formatRegistrarWithRegistrant(tt.registrar, tt.registrant)
			if got != tt.want {
				t.Errorf("formatRegistrarWithRegistrant(%q, %q) = %q, want %q", tt.registrar, tt.registrant, got, tt.want)
			}
		})
	}
}

func TestExtractRegistrarFromRDAP(t *testing.T) {
	tests := []struct {
		name string
		data map[string]any
		want string
	}{
		{
			name: "no entities",
			data: map[string]any{},
			want: "",
		},
		{
			name: "entities not array",
			data: map[string]any{"entities": "not_array"},
			want: "",
		},
		{
			name: "registrar with vcard fn",
			data: map[string]any{
				"entities": []any{
					map[string]any{
						"roles": []any{"registrar"},
						"vcardArray": []any{
							"vcard",
							[]any{
								[]any{"fn", map[string]any{}, "text", "GoDaddy Inc."},
							},
						},
					},
				},
			},
			want: "GoDaddy Inc.",
		},
		{
			name: "registrar with name field",
			data: map[string]any{
				"entities": []any{
					map[string]any{
						"roles": []any{"registrar"},
						"name":  "Namecheap",
					},
				},
			},
			want: "Namecheap",
		},
		{
			name: "registrar with handle only",
			data: map[string]any{
				"entities": []any{
					map[string]any{
						"roles":  []any{"registrar"},
						"handle": "REG-HANDLE",
					},
				},
			},
			want: "REG-HANDLE",
		},
		{
			name: "registrar with digit-only name falls through to handle",
			data: map[string]any{
				"entities": []any{
					map[string]any{
						"roles":  []any{"registrar"},
						"name":   "12345",
						"handle": "ActualName",
					},
				},
			},
			want: "ActualName",
		},
		{
			name: "nested registrar in sub-entities",
			data: map[string]any{
				"entities": []any{
					map[string]any{
						"roles": []any{"technical"},
						"entities": []any{
							map[string]any{
								"roles": []any{"registrar"},
								"name":  "SubRegistrar",
							},
						},
					},
				},
			},
			want: "SubRegistrar",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRegistrarFromRDAP(tt.data)
			if got != tt.want {
				t.Errorf("extractRegistrarFromRDAP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractRegistrantFromRDAP(t *testing.T) {
	tests := []struct {
		name string
		data map[string]any
		want string
	}{
		{
			name: "no entities",
			data: map[string]any{},
			want: "",
		},
		{
			name: "registrant with fn",
			data: map[string]any{
				"entities": []any{
					map[string]any{
						"roles": []any{"registrant"},
						"vcardArray": []any{
							"vcard",
							[]any{
								[]any{"fn", map[string]any{}, "text", "ACME Corp"},
							},
						},
					},
				},
			},
			want: "ACME Corp",
		},
		{
			name: "registrant redacted",
			data: map[string]any{
				"entities": []any{
					map[string]any{
						"roles": []any{"registrant"},
						"vcardArray": []any{
							"vcard",
							[]any{
								[]any{"fn", map[string]any{}, "text", "REDACTED"},
							},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "registrant not disclosed",
			data: map[string]any{
				"entities": []any{
					map[string]any{
						"roles": []any{"registrant"},
						"vcardArray": []any{
							"vcard",
							[]any{
								[]any{"fn", map[string]any{}, "text", "Not Disclosed"},
							},
						},
					},
				},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRegistrantFromRDAP(tt.data)
			if got != tt.want {
				t.Errorf("extractRegistrantFromRDAP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEntityHasRole(t *testing.T) {
	tests := []struct {
		name   string
		entity map[string]any
		role   string
		want   bool
	}{
		{"has registrar role", map[string]any{"roles": []any{"registrar"}}, "registrar", true},
		{"has registrant role", map[string]any{"roles": []any{"registrant", "technical"}}, "registrant", true},
		{"missing role", map[string]any{"roles": []any{"technical"}}, "registrar", false},
		{"no roles key", map[string]any{}, "registrar", false},
		{"roles not array", map[string]any{"roles": "registrar"}, "registrar", false},
		{"case insensitive", map[string]any{"roles": []any{"REGISTRAR"}}, "registrar", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := entityHasRole(tt.entity, tt.role)
			if got != tt.want {
				t.Errorf("entityHasRole() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractFNFromVCard(t *testing.T) {
	tests := []struct {
		name   string
		entity map[string]any
		want   string
	}{
		{
			name:   "no vcard",
			entity: map[string]any{},
			want:   "",
		},
		{
			name:   "invalid vcard structure",
			entity: map[string]any{"vcardArray": []any{"vcard"}},
			want:   "",
		},
		{
			name: "valid fn",
			entity: map[string]any{
				"vcardArray": []any{
					"vcard",
					[]any{
						[]any{"fn", map[string]any{}, "text", "Example Registrar"},
					},
				},
			},
			want: "Example Registrar",
		},
		{
			name: "no fn field",
			entity: map[string]any{
				"vcardArray": []any{
					"vcard",
					[]any{
						[]any{"n", map[string]any{}, "text", "Name"},
					},
				},
			},
			want: "",
		},
		{
			name: "short item skipped",
			entity: map[string]any{
				"vcardArray": []any{
					"vcard",
					[]any{
						[]any{"fn", "x"},
					},
				},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractFNFromVCard(tt.entity)
			if got != tt.want {
				t.Errorf("extractFNFromVCard() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractEntityName(t *testing.T) {
	tests := []struct {
		name   string
		entity map[string]any
		want   string
	}{
		{"name present", map[string]any{"name": "GoDaddy"}, "GoDaddy"},
		{"handle fallback", map[string]any{"handle": "REG-123A"}, "REG-123A"},
		{"digit name uses handle", map[string]any{"name": "999", "handle": "RealName"}, "RealName"},
		{"digit handle returns empty", map[string]any{"name": "999", "handle": "123"}, ""},
		{"empty name and handle", map[string]any{}, ""},
		{"empty string name", map[string]any{"name": ""}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractEntityName(tt.entity)
			if got != tt.want {
				t.Errorf("extractEntityName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsWhoisRestricted(t *testing.T) {
	tests := []struct {
		name       string
		output     string
		tld        string
		restricted bool
		empty      bool
	}{
		{"short output known restricted TLD", "ok", "es", true, true},
		{"short output unknown TLD", "ok", "com", false, true},
		{"contains not authorized", "This query is not authorized for this IP address range please contact support", "com", true, false},
		{"contains access denied", "Access Denied due to policy restrictions on this server please try later", "org", true, false},
		{"contains rate limit", "Query rate limit exceeded, please wait and try again later after some time", "io", true, false},
		{"normal whois output", "Registrar: GoDaddy\nCreation Date: 2020-01-01\nRegistrant Organization: ACME Corp\n" + string(make([]byte, 100)), "com", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restricted, empty := isWhoisRestricted(tt.output, tt.tld)
			if restricted != tt.restricted {
				t.Errorf("isWhoisRestricted() restricted = %v, want %v", restricted, tt.restricted)
			}
			if empty != tt.empty {
				t.Errorf("isWhoisRestricted() empty = %v, want %v", empty, tt.empty)
			}
		})
	}
}

func TestParseWhoisRegistrar(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{"found registrar", "Registrar: GoDaddy.com, LLC", "GoDaddy.com, LLC"},
		{"registrar name format", "Registrar Name: Namecheap, Inc.", "Namecheap, Inc."},
		{"sponsoring registrar", "Sponsoring Registrar: Network Solutions", "Network Solutions"},
		{"no match", "Creation Date: 2020-01-01", ""},
		{"http value filtered", "Registrar: http://example.com", ""},
		{"not available filtered", "Registrar: Not Available", ""},
		{"empty value", "Registrar:    ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseWhoisRegistrar(tt.output)
			if got != tt.want {
				t.Errorf("parseWhoisRegistrar() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseWhoisRegistrant(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{"found registrant org", "Registrant Organization: ACME Corp", "ACME Corp"},
		{"found registrant name", "Registrant Name: John Doe", "John Doe"},
		{"redacted", "Registrant Organization: REDACTED", ""},
		{"data protected", "Registrant Organization: Data Protected", ""},
		{"not disclosed", "Registrant Organization: Not Disclosed", ""},
		{"withheld", "Registrant Organization: Withheld", ""},
		{"no match", "Created: 2020-01-01", ""},
		{"empty value", "Registrant Organization:   ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseWhoisRegistrant(tt.output)
			if got != tt.want {
				t.Errorf("parseWhoisRegistrant() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatWhoisResult(t *testing.T) {
	tests := []struct {
		name       string
		registrar  string
		registrant string
		want       string
	}{
		{"both present", "GoDaddy", "ACME Corp", "GoDaddy (Registrant: ACME Corp)"},
		{"registrar only", "Namecheap", "", "Namecheap"},
		{"registrant only", "", "ACME Corp", "ACME Corp"},
		{"neither", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, _ := formatWhoisResult(tt.registrar, tt.registrant)
			if got != tt.want {
				t.Errorf("formatWhoisResult() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildRestrictedResult(t *testing.T) {
	tests := []struct {
		name          string
		restricted    bool
		restrictedTLD string
		wantStatus    string
	}{
		{"not restricted", false, "", "error"},
		{"restricted known TLD", true, "es", "restricted"},
		{"restricted unknown TLD", true, "xyz", "restricted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildRestrictedResult(tt.restricted, tt.restrictedTLD)
			if got["status"] != tt.wantStatus {
				t.Errorf("buildRestrictedResult() status = %v, want %v", got["status"], tt.wantStatus)
			}
			if tt.restricted {
				if got["registry_restricted"] != true {
					t.Error("expected registry_restricted = true")
				}
			}
		})
	}
}
