package analyzer

import (
	"testing"
)

func TestSplitDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   []string
	}{
		{"example.com", []string{"example", "com"}},
		{"sub.example.com", []string{"sub", "example", "com"}},
		{"a.b.c.d", []string{"a", "b", "c", "d"}},
		{"localhost", []string{"localhost"}},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := splitDomain(tt.domain)
			if len(got) != len(tt.want) {
				t.Fatalf("splitDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitDomain(%q)[%d] = %q, want %q", tt.domain, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestJoinDomain(t *testing.T) {
	tests := []struct {
		name  string
		parts []string
		want  string
	}{
		{"two parts", []string{"example", "com"}, "example.com"},
		{"three parts", []string{"sub", "example", "com"}, "sub.example.com"},
		{"single", []string{"localhost"}, "localhost"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := joinDomain(tt.parts)
			if got != tt.want {
				t.Errorf("joinDomain(%v) = %q, want %q", tt.parts, got, tt.want)
			}
		})
	}
}

func TestSplitString(t *testing.T) {
	tests := []struct {
		name string
		s    string
		sep  string
		want []string
	}{
		{"dot separator", "a.b.c", ".", []string{"a", "b", "c"}},
		{"no separator found", "abc", ".", []string{"abc"}},
		{"multi-char sep", "a::b::c", "::", []string{"a", "b", "c"}},
		{"empty parts", "a..b", ".", []string{"a", "", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitString(tt.s, tt.sep)
			if len(got) != len(tt.want) {
				t.Fatalf("splitString(%q, %q) = %v, want %v", tt.s, tt.sep, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitString(%q, %q)[%d] = %q, want %q", tt.s, tt.sep, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestIndexOf(t *testing.T) {
	tests := []struct {
		s    string
		sub  string
		want int
	}{
		{"hello world", "world", 6},
		{"hello", "xyz", -1},
		{"abcabc", "bc", 1},
		{"a", "ab", -1},
		{"", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.sub, func(t *testing.T) {
			got := indexOf(tt.s, tt.sub)
			if got != tt.want {
				t.Errorf("indexOf(%q, %q) = %d, want %d", tt.s, tt.sub, got, tt.want)
			}
		})
	}
}

func TestInitAuthResults(t *testing.T) {
	recordTypes := []string{"A", "AAAA", "MX"}
	emailSubdomains := map[string]string{
		"DMARC": "_dmarc.example.com",
	}

	results := initAuthResults(recordTypes, emailSubdomains)

	for _, rt := range recordTypes {
		if _, ok := results[rt]; !ok {
			t.Errorf("expected key %q in results", rt)
		}
	}
	if _, ok := results["DMARC"]; !ok {
		t.Error("expected key DMARC in results")
	}
	if _, ok := results["_query_status"]; !ok {
		t.Error("expected key _query_status in results")
	}
	if _, ok := results["_ttl"]; !ok {
		t.Error("expected key _ttl in results")
	}
}
