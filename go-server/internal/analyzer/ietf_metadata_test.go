package analyzer

import (
	"testing"
)

func TestClassifyRFCStatus(t *testing.T) {
	tests := []struct {
		name string
		doc  ietfDocResponse
		want string
	}{
		{"internet standard", ietfDocResponse{StdLevel: "/api/v1/name/stdlevelname/std/"}, "Internet Standard"},
		{"draft standard", ietfDocResponse{StdLevel: "/api/v1/name/stdlevelname/ds/"}, "Draft Standard"},
		{"proposed standard", ietfDocResponse{StdLevel: "/api/v1/name/stdlevelname/ps/"}, "Proposed Standard"},
		{"best current practice", ietfDocResponse{StdLevel: "/api/v1/name/stdlevelname/bcp/"}, "Best Current Practice"},
		{"informational", ietfDocResponse{StdLevel: "/api/v1/name/stdlevelname/inf/"}, "Informational"},
		{"experimental", ietfDocResponse{StdLevel: "/api/v1/name/stdlevelname/exp/"}, "Experimental"},
		{"historic", ietfDocResponse{StdLevel: "/api/v1/name/stdlevelname/hist/"}, "Historic"},
		{"empty level", ietfDocResponse{StdLevel: ""}, "Published"},
		{"unknown level", ietfDocResponse{StdLevel: "/api/v1/name/stdlevelname/unknown/"}, "Published"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyRFCStatus(tt.doc)
			if got != tt.want {
				t.Errorf("classifyRFCStatus() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractRFCNumbers(t *testing.T) {
	tests := []struct {
		name string
		refs []string
		want []string
	}{
		{"single rfc", []string{"/api/v1/doc/document/rfc8461/"}, []string{"8461"}},
		{"multiple", []string{"/api/v1/doc/document/rfc7208/", "/api/v1/doc/document/rfc8301/"}, []string{"7208", "8301"}},
		{"no rfc", []string{"/api/v1/doc/document/draft-something/"}, nil},
		{"empty", []string{}, nil},
		{"nil", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRFCNumbers(tt.refs)
			if len(got) != len(tt.want) {
				t.Errorf("extractRFCNumbers() = %v, want %v", got, tt.want)
				return
			}
			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("extractRFCNumbers()[%d] = %q, want %q", i, v, tt.want[i])
				}
			}
		})
	}
}

func TestExtractRFCNumberFromRef(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want string
	}{
		{"RFC prefix", "RFC 8461", "8461"},
		{"rfc prefix", "rfc7208", "7208"},
		{"just number", "8301", "8301"},
		{"with spaces", "  RFC 4033  ", "4033"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRFCNumberFromRef(tt.ref)
			if got != tt.want {
				t.Errorf("extractRFCNumberFromRef(%q) = %q, want %q", tt.ref, got, tt.want)
			}
		})
	}
}

func TestApplyRFCMetaToFix(t *testing.T) {
	fix := map[string]any{"rfc": "RFC 8461"}
	meta := &RFCMetadata{
		Title:       "SMTP MTA Strict Transport Security",
		Status:      "Proposed Standard",
		IsObsolete:  true,
		ObsoletedBy: []string{"9999"},
	}
	applyRFCMetaToFix(fix, meta)

	if fix["rfc_title"] != meta.Title {
		t.Errorf("rfc_title = %q, want %q", fix["rfc_title"], meta.Title)
	}
	if fix["rfc_status"] != meta.Status {
		t.Errorf("rfc_status = %q, want %q", fix["rfc_status"], meta.Status)
	}
	if fix["rfc_obsolete"] != true {
		t.Error("rfc_obsolete should be true")
	}
	if fix["rfc_obsoleted_by"] == nil {
		t.Error("rfc_obsoleted_by should be set")
	}
}

func TestApplyRFCMetaToFixNotObsolete(t *testing.T) {
	fix := map[string]any{"rfc": "RFC 7208"}
	meta := &RFCMetadata{
		Title:      "SPF",
		Status:     "Proposed Standard",
		IsObsolete: false,
	}
	applyRFCMetaToFix(fix, meta)

	if fix["rfc_obsolete"] != false {
		t.Error("rfc_obsolete should be false")
	}
	if _, exists := fix["rfc_obsoleted_by"]; exists {
		t.Error("rfc_obsoleted_by should not be set when not obsolete")
	}
}
