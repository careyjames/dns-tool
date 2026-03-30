package analyzer

import (
	"testing"
)

func TestBuildEmailEncryptionMessage(t *testing.T) {
	tests := []struct {
		name   string
		result map[string]any
		want   string
	}{
		{
			"both",
			map[string]any{"has_smimea": true, "has_openpgpkey": true},
			"S/MIME certificates published via SMIMEA (RFC 8162); OpenPGP keys published via OPENPGPKEY (RFC 7929)",
		},
		{
			"smimea only",
			map[string]any{"has_smimea": true, "has_openpgpkey": false},
			"S/MIME certificates published via SMIMEA (RFC 8162)",
		},
		{
			"openpgpkey only",
			map[string]any{"has_smimea": false, "has_openpgpkey": true},
			"OpenPGP keys published via OPENPGPKEY (RFC 7929)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildEmailEncryptionMessage(tt.result)
			if got != tt.want {
				t.Errorf("buildEmailEncryptionMessage() = %q, want %q", got, tt.want)
			}
		})
	}
}
