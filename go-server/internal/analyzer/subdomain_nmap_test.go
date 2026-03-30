package analyzer

import (
	"testing"
)

func TestExtractSANsFromSSLCert(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name: "standard SAN output",
			input: `Subject: commonName=example.com
Subject Alternative Name: DNS:example.com, DNS:www.example.com, DNS:api.example.com
Issuer: commonName=R3/organizationName=Let's Encrypt`,
			expected: []string{"example.com", "www.example.com", "api.example.com"},
		},
		{
			name:     "no SANs",
			input:    "Subject: commonName=example.com\nIssuer: commonName=R3",
			expected: nil,
		},
		{
			name:     "empty input",
			input:    "",
			expected: nil,
		},
		{
			name: "cloudflare-style many SANs",
			input: `Subject: commonName=cloudflare.com
Subject Alternative Name: DNS:cloudflare.com, DNS:ns.cloudflare.com, DNS:*.ns.cloudflare.com, DNS:secondary.cloudflare.com
Issuer: commonName=WE1`,
			expected: []string{"cloudflare.com", "ns.cloudflare.com", "*.ns.cloudflare.com", "secondary.cloudflare.com"},
		},
		{
			name:     "IP address SANs ignored",
			input:    `Subject Alternative Name: DNS:example.com, IP Address:192.168.1.1`,
			expected: []string{"example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractSANsFromSSLCert(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d SANs, got %d: %v", len(tt.expected), len(result), result)
				return
			}
			for i, expected := range tt.expected {
				if result[i] != expected {
					t.Errorf("SAN[%d]: expected %q, got %q", i, expected, result[i])
				}
			}
		})
	}
}

func TestExtractNmapIntel(t *testing.T) {
	tests := []struct {
		name           string
		input          *nmapProbeResponse
		expectServices int
		expectSANs     int
	}{
		{
			name:           "nil parsed",
			input:          &nmapProbeResponse{Parsed: nil},
			expectServices: 0,
			expectSANs:     0,
		},
		{
			name: "single open port with ssl-cert",
			input: &nmapProbeResponse{
				Parsed: &nmapParsed{
					Hosts: []nmapHost{
						{
							Ports: []nmapPort{
								{
									Port:     443,
									Protocol: "tcp",
									State:    "open",
									Service:  "https",
									Product:  "nginx",
									Scripts: []nmapScript{
										{
											ID:     "ssl-cert",
											Output: "Subject Alternative Name: DNS:example.com, DNS:api.example.com",
										},
										{
											ID:     "http-title",
											Output: "Example Domain",
										},
									},
								},
							},
						},
					},
				},
			},
			expectServices: 1,
			expectSANs:     2,
		},
		{
			name: "closed port ignored",
			input: &nmapProbeResponse{
				Parsed: &nmapParsed{
					Hosts: []nmapHost{
						{
							Ports: []nmapPort{
								{Port: 80, State: "closed", Service: "http"},
							},
						},
					},
				},
			},
			expectServices: 0,
			expectSANs:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			services, sans := extractNmapIntel(tt.input)
			if len(services) != tt.expectServices {
				t.Errorf("expected %d services, got %d", tt.expectServices, len(services))
			}
			if len(sans) != tt.expectSANs {
				t.Errorf("expected %d SANs, got %d", tt.expectSANs, len(sans))
			}
		})
	}
}

func TestSelectNmapTargets(t *testing.T) {
	subdomains := []map[string]any{
		{"name": "www.example.com", "is_current": true},
		{"name": "api.example.com", "is_current": true},
		{"name": "old.example.com", "is_current": false},
		{"name": "mail.example.com", "is_current": true},
	}

	targets := selectNmapTargets(subdomains, 2)
	if len(targets) != 2 {
		t.Errorf("expected 2 targets, got %d", len(targets))
	}
	if targets[0] != "www.example.com" {
		t.Errorf("expected www.example.com, got %s", targets[0])
	}
	if targets[1] != "api.example.com" {
		t.Errorf("expected api.example.com, got %s", targets[1])
	}
}

func TestNmapCapableProbe(t *testing.T) {
	a := &Analyzer{}

	probe := a.nmapCapableProbe()
	if probe != nil {
		t.Error("expected nil probe when no probes configured")
	}

	a.Probes = []ProbeEndpoint{
		{ID: "probe-01", Label: "US-East (Boston)", URL: "https://probe1.example.com", Key: "key1"},
		{ID: "probe-02", Label: "US-East (Kali/02)", URL: "https://probe2.example.com", Key: "key2"},
	}

	probe = a.nmapCapableProbe()
	if probe == nil {
		t.Fatal("expected non-nil probe")
	}
	if probe.ID != "probe-02" {
		t.Errorf("expected probe-02 (Kali), got %s", probe.ID)
	}
}
