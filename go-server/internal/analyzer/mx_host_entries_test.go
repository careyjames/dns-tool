package analyzer

import (
	"testing"
)

func TestParseMXHostEntries_MapSlice_CB10(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  []string
	}{
		{
			name: "slice of map with exchange key",
			input: []map[string]any{
				{"exchange": "mail.example.com.", "preference": 10},
				{"exchange": "mail2.example.com.", "preference": 20},
			},
			want: []string{"mail.example.com", "mail2.example.com"},
		},
		{
			name: "slice of map with host key",
			input: []map[string]any{
				{"host": "mx1.example.com.", "priority": 10},
			},
			want: []string{"mx1.example.com"},
		},
		{
			name:  "empty slice of map",
			input: []map[string]any{},
			want:  nil,
		},
		{
			name: "slice of any containing maps",
			input: []any{
				map[string]any{"exchange": "mail3.example.com.", "preference": 10},
				map[string]any{"host": "mail4.example.com.", "preference": 20},
			},
			want: []string{"mail3.example.com", "mail4.example.com"},
		},
		{
			name:  "slice of strings",
			input: []string{"10 mail.example.com.", "20 backup.example.com."},
			want:  []string{"mail.example.com", "backup.example.com"},
		},
		{
			name:  "nil input",
			input: nil,
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMXHostEntries(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("parseMXHostEntries() len = %d, want %d; got %v", len(got), len(tt.want), got)
			}
			for i, g := range got {
				if g != tt.want[i] {
					t.Errorf("parseMXHostEntries()[%d] = %q, want %q", i, g, tt.want[i])
				}
			}
		})
	}
}

func TestAppendMXHost_Exchange_CB10(t *testing.T) {
	tests := []struct {
		name  string
		entry any
		want  string
	}{
		{
			name:  "map with exchange key",
			entry: map[string]any{"exchange": "mail.example.com."},
			want:  "mail.example.com",
		},
		{
			name:  "map with host key",
			entry: map[string]any{"host": "mx.example.com."},
			want:  "mx.example.com",
		},
		{
			name:  "map with empty exchange",
			entry: map[string]any{"exchange": "."},
			want:  "",
		},
		{
			name:  "map with neither key",
			entry: map[string]any{"server": "mx.example.com."},
			want:  "",
		},
		{
			name:  "string entry",
			entry: "10 mail.example.com.",
			want:  "mail.example.com",
		},
		{
			name:  "string entry single word",
			entry: "mail.example.com.",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hosts := appendMXHost(nil, tt.entry)
			if tt.want == "" {
				if len(hosts) != 0 {
					t.Errorf("appendMXHost() = %v, want empty", hosts)
				}
			} else {
				if len(hosts) != 1 || hosts[0] != tt.want {
					t.Errorf("appendMXHost() = %v, want [%q]", hosts, tt.want)
				}
			}
		})
	}
}

func TestParseSelectorEntries_SliceAny_CB10(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  int
	}{
		{
			name: "slice of any with selector maps",
			input: []any{
				map[string]any{"selector": "google", "provider": "Google Workspace"},
				map[string]any{"selector": "s1", "provider": "Custom"},
			},
			want: 2,
		},
		{
			name: "slice of any with name maps",
			input: []any{
				map[string]any{"name": "selector1"},
				map[string]any{"name": "selector2"},
			},
			want: 2,
		},
		{
			name:  "slice of any with strings",
			input: []any{"google", "selector1", "default"},
			want:  3,
		},
		{
			name: "slice of any mixed",
			input: []any{
				"google",
				map[string]any{"selector": "s1"},
			},
			want: 2,
		},
		{
			name: "map of selectors",
			input: map[string]any{
				"google._domainkey":    map[string]any{},
				"selector1._domainkey": map[string]any{},
			},
			want: 2,
		},
		{
			name: "slice of any with empty map",
			input: []any{
				map[string]any{"other": "value"},
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSelectorEntries(tt.input)
			if len(got) != tt.want {
				t.Errorf("parseSelectorEntries() len = %d, want %d; got %v", len(got), tt.want, got)
			}
		})
	}
}

func TestGenerateDMARCReportAuthCommands_CB10(t *testing.T) {
	tests := []struct {
		name       string
		domain     string
		results    map[string]any
		wantCount  int
		wantTarget string
	}{
		{
			name:   "external domains in dmarc_report_auth",
			domain: "example.com",
			results: map[string]any{
				"dmarc_report_auth": map[string]any{
					"external_domains": []any{"thirdparty.com", "reporting.net"},
				},
			},
			wantCount: 2,
		},
		{
			name:   "self domain excluded",
			domain: "example.com",
			results: map[string]any{
				"dmarc_report_auth": map[string]any{
					"external_domains": []any{"example.com", "thirdparty.com"},
				},
			},
			wantCount: 1,
		},
		{
			name:   "domains key fallback",
			domain: "example.com",
			results: map[string]any{
				"dmarc_report_auth": map[string]any{
					"domains": []any{"reporting.net"},
				},
			},
			wantCount: 1,
		},
		{
			name:   "nested in dmarc external_report_auth",
			domain: "example.com",
			results: map[string]any{
				"dmarc": map[string]any{
					"external_report_auth": map[string]any{
						"external_domains": []any{"reporter.com"},
					},
				},
			},
			wantCount: 1,
		},
		{
			name:      "no dmarc data",
			domain:    "example.com",
			results:   map[string]any{},
			wantCount: 0,
		},
		{
			name:   "map domain entries",
			domain: "example.com",
			results: map[string]any{
				"dmarc_report_auth": map[string]any{
					"external_domains": []any{
						map[string]any{"domain": "reporter.com"},
					},
				},
			},
			wantCount: 1,
		},
		{
			name:   "all self domain",
			domain: "example.com",
			results: map[string]any{
				"dmarc_report_auth": map[string]any{
					"external_domains": []any{"example.com"},
				},
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmds := generateDMARCReportAuthCommands(tt.domain, tt.results)
			if len(cmds) != tt.wantCount {
				t.Errorf("generateDMARCReportAuthCommands() len = %d, want %d", len(cmds), tt.wantCount)
			}
			for _, cmd := range cmds {
				if cmd.Section != sectionEmailAuth {
					t.Errorf("section = %q, want %q", cmd.Section, sectionEmailAuth)
				}
				if cmd.RFC != rfcDMARC7489 {
					t.Errorf("rfc = %q, want %q", cmd.RFC, rfcDMARC7489)
				}
			}
		})
	}
}

func TestExtractDKIMSelectors_CB10(t *testing.T) {
	tests := []struct {
		name    string
		results map[string]any
		want    int
	}{
		{
			name: "selectors as slice of any with maps",
			results: map[string]any{
				"dkim_analysis": map[string]any{
					"selectors": []any{
						map[string]any{"selector": "google", "provider": "Google"},
						map[string]any{"selector": "s1", "provider": "Custom"},
					},
				},
			},
			want: 2,
		},
		{
			name: "selectors as map",
			results: map[string]any{
				"dkim": map[string]any{
					"selectors": map[string]any{
						"google._domainkey": map[string]any{},
					},
				},
			},
			want: 1,
		},
		{
			name:    "no dkim data",
			results: map[string]any{},
			want:    0,
		},
		{
			name: "empty selectors",
			results: map[string]any{
				"dkim_analysis": map[string]any{
					"selectors": []any{},
				},
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDKIMSelectors(tt.results)
			if len(got) != tt.want {
				t.Errorf("extractDKIMSelectors() len = %d, want %d; got %v", len(got), tt.want, got)
			}
		})
	}
}

func TestExtractMXHostsFromResults_CB10(t *testing.T) {
	tests := []struct {
		name    string
		results map[string]any
		want    int
	}{
		{
			name: "MX key uppercase",
			results: map[string]any{
				"basic_records": map[string]any{
					"MX": []any{
						map[string]any{"exchange": "mail.example.com."},
					},
				},
			},
			want: 1,
		},
		{
			name: "mx key lowercase",
			results: map[string]any{
				"basic_records": map[string]any{
					"mx": []string{"10 mail.example.com."},
				},
			},
			want: 1,
		},
		{
			name:    "no basic_records",
			results: map[string]any{},
			want:    0,
		},
		{
			name: "basic_records wrong type",
			results: map[string]any{
				"basic_records": "not a map",
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractMXHostsFromResults(tt.results)
			if len(got) != tt.want {
				t.Errorf("extractMXHostsFromResults() len = %d, want %d", len(got), tt.want)
			}
		})
	}
}

func TestExtractDMARCRuaTargets_CB10(t *testing.T) {
	tests := []struct {
		name    string
		results map[string]any
		want    int
	}{
		{
			name: "string targets",
			results: map[string]any{
				"dmarc_report_auth": map[string]any{
					"external_domains": []any{"a.com", "b.com"},
				},
			},
			want: 2,
		},
		{
			name: "map targets with domain key",
			results: map[string]any{
				"dmarc_report_auth": map[string]any{
					"external_domains": []any{
						map[string]any{"domain": "c.com"},
					},
				},
			},
			want: 1,
		},
		{
			name: "fallback domains key",
			results: map[string]any{
				"dmarc_report_auth": map[string]any{
					"domains": []any{"d.com"},
				},
			},
			want: 1,
		},
		{
			name: "non-slice targets",
			results: map[string]any{
				"dmarc_report_auth": map[string]any{
					"external_domains": "not-a-slice",
				},
			},
			want: 0,
		},
		{
			name:    "nil results",
			results: map[string]any{},
			want:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDMARCRuaTargets(tt.results)
			if len(got) != tt.want {
				t.Errorf("extractDMARCRuaTargets() len = %d, want %d", len(got), tt.want)
			}
		})
	}
}

func TestExtractIPsFromResults_CB10(t *testing.T) {
	tests := []struct {
		name    string
		results map[string]any
		want    int
	}{
		{
			name: "A records as []any",
			results: map[string]any{
				"basic_records": map[string]any{
					"A": []any{"1.2.3.4", "5.6.7.8", "9.10.11.12"},
				},
			},
			want: 2,
		},
		{
			name: "a records lowercase",
			results: map[string]any{
				"basic_records": map[string]any{
					"a": []string{"1.2.3.4"},
				},
			},
			want: 1,
		},
		{
			name:    "no basic_records",
			results: map[string]any{},
			want:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractIPsFromResults(tt.results)
			if len(got) != tt.want {
				t.Errorf("extractIPsFromResults() len = %d, want %d", len(got), tt.want)
			}
		})
	}
}

func TestReverseIP_CB10(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1.2.3.4", "4.3.2.1"},
		{"192.168.1.1", "1.1.168.192"},
		{"not-an-ip", "not-an-ip"},
		{"1.2.3", "1.2.3"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := reverseIP(tt.input)
			if got != tt.want {
				t.Errorf("reverseIP(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractSelectorName_CB10(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  string
	}{
		{"string", "google", "google"},
		{"map with selector", map[string]any{"selector": "s1"}, "s1"},
		{"map with name", map[string]any{"name": "default"}, "default"},
		{"map with neither", map[string]any{"other": "val"}, ""},
		{"int value", 42, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSelectorName(tt.input)
			if got != tt.want {
				t.Errorf("extractSelectorName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindExternalAuthMap_CB10(t *testing.T) {
	tests := []struct {
		name    string
		results map[string]any
		wantNil bool
	}{
		{
			name: "top-level dmarc_report_auth",
			results: map[string]any{
				"dmarc_report_auth": map[string]any{"external_domains": []any{"a.com"}},
			},
			wantNil: false,
		},
		{
			name: "nested in dmarc",
			results: map[string]any{
				"dmarc": map[string]any{
					"external_report_auth": map[string]any{"external_domains": []any{"b.com"}},
				},
			},
			wantNil: false,
		},
		{
			name:    "no auth data",
			results: map[string]any{},
			wantNil: true,
		},
		{
			name: "dmarc not a map",
			results: map[string]any{
				"dmarc": "not-a-map",
			},
			wantNil: true,
		},
		{
			name: "dmarc map without external_report_auth",
			results: map[string]any{
				"dmarc": map[string]any{
					"policy": "reject",
				},
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findExternalAuthMap(tt.results)
			if tt.wantNil && got != nil {
				t.Errorf("findExternalAuthMap() = %v, want nil", got)
			}
			if !tt.wantNil && got == nil {
				t.Error("findExternalAuthMap() = nil, want non-nil")
			}
		})
	}
}

func TestFindDKIMMap_CB10(t *testing.T) {
	tests := []struct {
		name    string
		results map[string]any
		wantNil bool
	}{
		{
			name:    "dkim_analysis key",
			results: map[string]any{"dkim_analysis": map[string]any{"selectors": map[string]any{}}},
			wantNil: false,
		},
		{
			name:    "dkim key",
			results: map[string]any{"dkim": map[string]any{"selectors": map[string]any{}}},
			wantNil: false,
		},
		{
			name:    "no dkim",
			results: map[string]any{},
			wantNil: true,
		},
		{
			name:    "dkim not a map",
			results: map[string]any{"dkim": "string"},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findDKIMMap(tt.results)
			if tt.wantNil && got != nil {
				t.Errorf("findDKIMMap() = %v, want nil", got)
			}
			if !tt.wantNil && got == nil {
				t.Error("findDKIMMap() = nil, want non-nil")
			}
		})
	}
}

func TestExtractIPsFromRecord_CB10(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  int
	}{
		{"string slice", []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}, 2},
		{"any slice", []any{"4.4.4.4"}, 1},
		{"any slice non-string", []any{42}, 0},
		{"nil", nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractIPsFromRecord(tt.input)
			if len(got) != tt.want {
				t.Errorf("extractIPsFromRecord() len = %d, want %d", len(got), tt.want)
			}
		})
	}
}
