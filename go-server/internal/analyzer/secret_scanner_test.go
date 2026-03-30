package analyzer

import "testing"

func TestIsMinifiedJSFalsePositive(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		{
			name:   "npm scope package - apple analytics",
			input:  `https://podcasts.apple.com",token:"podcasts-0-int_srch-apl",event:r.EVENTS.EVENT_300}]},{"@apple/analytics-omniture-constants`,
			expect: true,
		},
		{
			name:   "npm scope package - generic",
			input:  `https://example.com",foo:"bar"@myorg/my-package`,
			expect: true,
		},
		{
			name:   "real basic auth - hostname with dot",
			input:  `https://admin:secretpass@db.example.com/path`,
			expect: false,
		},
		{
			name:   "real basic auth - IP address",
			input:  `http://user:token123@192.168.1.100/admin`,
			expect: false,
		},
		{
			name:   "no @ sign at all",
			input:  `https://example.com/path`,
			expect: false,
		},
		{
			name:   "host without dot - likely JS artifact",
			input:  `https://cdn.example.com",key:"val@localhost/path`,
			expect: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isMinifiedJSFalsePositive(tc.input)
			if got != tc.expect {
				t.Errorf("isMinifiedJSFalsePositive(%q) = %v, want %v", tc.input, got, tc.expect)
			}
		})
	}
}
