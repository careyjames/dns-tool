package analyzer

import (
	"testing"
)

func TestParseTeamCymruResponse(t *testing.T) {
	tests := []struct {
		name       string
		record     string
		wantASN    string
		wantPrefix string
		wantCC     string
		wantSkip   bool
	}{
		{
			name:       "standard response",
			record:     "13335 | 104.16.0.0/12 | US",
			wantASN:    "13335",
			wantPrefix: "104.16.0.0/12",
			wantCC:     "US",
		},
		{
			name:       "quoted response",
			record:     `"13335 | 104.16.0.0/12 | US"`,
			wantASN:    "13335",
			wantPrefix: "104.16.0.0/12",
			wantCC:     "US",
		},
		{
			name:       "five part response",
			record:     "15169 | 8.8.8.0/24 | US | arin | 2023-01-01",
			wantASN:    "15169",
			wantPrefix: "8.8.8.0/24",
			wantCC:     "US",
		},
		{
			name:     "too few parts",
			record:   "13335 | 104.16.0.0/12",
			wantSkip: true,
		},
		{
			name:     "empty record",
			record:   "",
			wantSkip: true,
		},
		{
			name:       "extra whitespace",
			record:     "  16509  |  2600:1f18::/36  |  US  ",
			wantASN:    "16509",
			wantPrefix: "2600:1f18::/36",
			wantCC:     "US",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := map[string]any{}
			parseTeamCymruResponse(info, tt.record)
			if tt.wantSkip {
				if _, ok := info[mapKeyASN]; ok {
					t.Error("expected no ASN key in info map")
				}
				return
			}
			if got := info[mapKeyASN]; got != tt.wantASN {
				t.Errorf("ASN = %v, want %v", got, tt.wantASN)
			}
			if got := info["prefix"]; got != tt.wantPrefix {
				t.Errorf("prefix = %v, want %v", got, tt.wantPrefix)
			}
			if got := info[mapKeyCountry]; got != tt.wantCC {
				t.Errorf("country = %v, want %v", got, tt.wantCC)
			}
		})
	}
}

func TestMergeASNSet(t *testing.T) {
	tests := []struct {
		name      string
		existing  map[string]map[string]any
		info      map[string]any
		wantCount int
	}{
		{
			name:     "add new ASN",
			existing: map[string]map[string]any{},
			info: map[string]any{
				mapKeyASN:     "13335",
				mapKeyAsName:  "Cloudflare, Inc.",
				mapKeyCountry: "US",
			},
			wantCount: 1,
		},
		{
			name: "duplicate ASN not added",
			existing: map[string]map[string]any{
				"13335": {mapKeyASN: "13335", mapKeyAsName: "Cloudflare, Inc.", mapKeyCountry: "US"},
			},
			info: map[string]any{
				mapKeyASN:     "13335",
				mapKeyAsName:  "Cloudflare, Inc.",
				mapKeyCountry: "US",
			},
			wantCount: 1,
		},
		{
			name:     "empty ASN ignored",
			existing: map[string]map[string]any{},
			info: map[string]any{
				mapKeyASN: "",
			},
			wantCount: 0,
		},
		{
			name:      "missing ASN key ignored",
			existing:  map[string]map[string]any{},
			info:      map[string]any{},
			wantCount: 0,
		},
		{
			name: "add second distinct ASN",
			existing: map[string]map[string]any{
				"13335": {mapKeyASN: "13335"},
			},
			info: map[string]any{
				mapKeyASN:     "15169",
				mapKeyAsName:  "Google LLC",
				mapKeyCountry: "US",
			},
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mergeASNSet(tt.existing, tt.info)
			if len(tt.existing) != tt.wantCount {
				t.Errorf("set length = %d, want %d", len(tt.existing), tt.wantCount)
			}
		})
	}
}

func TestReverseIPv4(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want string
	}{
		{"standard", "1.2.3.4", "4.3.2.1"},
		{"same octets", "10.10.10.10", "10.10.10.10"},
		{"real IP", "192.168.1.100", "100.1.168.192"},
		{"too few parts", "1.2.3", ""},
		{"too many parts", "1.2.3.4.5", ""},
		{"empty", "", ""},
		{"single octet", "1", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reverseIPv4(tt.ip); got != tt.want {
				t.Errorf("reverseIPv4(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestReverseIPv6(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want string
	}{
		{
			name: "full address",
			ip:   "2001:0db8:0000:0000:0000:0000:0000:0001",
			want: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
		},
		{
			name: "loopback",
			ip:   "::1",
			want: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0",
		},
		{
			name: "all zeros",
			ip:   "::",
			want: "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0",
		},
		{
			name: "too short",
			ip:   "2001",
			want: "",
		},
		{
			name: "empty",
			ip:   "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := reverseIPv6(tt.ip)
			if got != tt.want {
				t.Errorf("reverseIPv6(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestExpandIPv6(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want string
	}{
		{
			name: "full already",
			ip:   "2001:0db8:0000:0000:0000:0000:0000:0001",
			want: "2001:0db8:0000:0000:0000:0000:0000:0001",
		},
		{
			name: "double colon at end",
			ip:   "2001:db8::",
			want: "2001:0db8:0000:0000:0000:0000:0000:0000",
		},
		{
			name: "double colon at start",
			ip:   "::1",
			want: "0000:0000:0000:0000:0000:0000:0000:0001",
		},
		{
			name: "double colon in middle",
			ip:   "2001:db8::1",
			want: "2001:0db8:0000:0000:0000:0000:0000:0001",
		},
		{
			name: "all zeros",
			ip:   "::",
			want: "0000:0000:0000:0000:0000:0000:0000:0000",
		},
		{
			name: "no padding needed",
			ip:   "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			want: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		},
		{
			name: "short groups",
			ip:   "2001:db8:85a3:0:0:8a2e:370:7334",
			want: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		},
		{
			name: "wrong number of groups",
			ip:   "2001:db8:1:2:3:4:5:6:7",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := expandIPv6(tt.ip); got != tt.want {
				t.Errorf("expandIPv6(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestPadHex(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"0", "0000"},
		{"1", "0001"},
		{"db8", "0db8"},
		{"abcd", "abcd"},
		{"ff", "00ff"},
		{"", "0000"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := padHex(tt.input); got != tt.want {
				t.Errorf("padHex(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFilterEmpty(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  int
	}{
		{"all empty", []string{"", "", ""}, 0},
		{"no empty", []string{"a", "b", "c"}, 3},
		{"mixed", []string{"a", "", "c"}, 2},
		{"nil input", nil, 0},
		{"single empty", []string{""}, 0},
		{"single non-empty", []string{"x"}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterEmpty(tt.input)
			if len(got) != tt.want {
				t.Errorf("filterEmpty(%v) returned %d items, want %d", tt.input, len(got), tt.want)
			}
			for _, s := range got {
				if s == "" {
					t.Error("filterEmpty returned an empty string")
				}
			}
		})
	}
}
