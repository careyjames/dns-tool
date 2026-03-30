package scanner

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestIsHeuristicScanner(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{"normal domain", "example.com", false},
		{"short domain", "abc.example.com", false},
		{"four labels no hex", "a.b.c.example.com", false},
		{"five labels no hex", "a.b.c.d.example.com", false},
		{"five labels one long hex", "abcdef12345678.b.c.d.example.com", false},
		{"five labels two long hex", "abcdef1234567890.fedcba0987654321.sub.evil.example.com", true},
		{"hex labels too short", "abcdef12.abcdef34.sub.evil.example.com", false},
		{"mixed case hex", "ABCDEF1234567890.fedcba0987654321.sub.evil.example.com", true},
		{"six labels two hex", "aabbccdd11223344.eeff0011aabbccdd.a.b.c.example.com", true},
		{"five labels hex exactly 12 chars", "abcdef123456.abcdef789012.sub.evil.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isHeuristicScanner(tt.domain)
			if got != tt.want {
				t.Errorf("isHeuristicScanner(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestMatchCISAIP(t *testing.T) {
	_, cidr4, _ := net.ParseCIDR("192.0.2.0/24")
	_, cidr6, _ := net.ParseCIDR("2001:db8::/32")

	cisaListMu.Lock()
	origNets := cisaIPNets
	cisaIPNets = []*net.IPNet{cidr4, cidr6}
	cisaListMu.Unlock()

	defer func() {
		cisaListMu.Lock()
		cisaIPNets = origNets
		cisaListMu.Unlock()
	}()

	tests := []struct {
		name string
		ip   string
		want string
	}{
		{"empty IP", "", ""},
		{"invalid IP", "not-an-ip", ""},
		{"IPv4 in range", "192.0.2.100", "CISA Cyber Hygiene"},
		{"IPv4 out of range", "10.0.0.1", ""},
		{"IPv6 in range", "2001:db8::1", "CISA Cyber Hygiene"},
		{"IPv6 out of range", "2001:db9::1", ""},
		{"IPv4 boundary start", "192.0.2.0", "CISA Cyber Hygiene"},
		{"IPv4 boundary end", "192.0.2.255", "CISA Cyber Hygiene"},
		{"IPv4 just outside", "192.0.3.0", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchCISAIP(tt.ip)
			if got != tt.want {
				t.Errorf("matchCISAIP(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestMatchCISAIP_EmptyList(t *testing.T) {
	cisaListMu.Lock()
	origNets := cisaIPNets
	cisaIPNets = nil
	cisaListMu.Unlock()

	defer func() {
		cisaListMu.Lock()
		cisaIPNets = origNets
		cisaListMu.Unlock()
	}()

	got := matchCISAIP("192.0.2.1")
	if got != "" {
		t.Errorf("matchCISAIP with empty list should return empty, got %q", got)
	}
}

func TestCISAListSize(t *testing.T) {
	cisaListMu.Lock()
	origNets := cisaIPNets
	cisaIPNets = nil
	cisaListMu.Unlock()

	if CISAListSize() != 0 {
		t.Errorf("expected 0 for nil list")
	}

	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	cisaListMu.Lock()
	cisaIPNets = []*net.IPNet{cidr}
	cisaListMu.Unlock()

	if CISAListSize() != 1 {
		t.Errorf("expected 1, got %d", CISAListSize())
	}

	cisaListMu.Lock()
	cisaIPNets = origNets
	cisaListMu.Unlock()
}

func TestCISAListSize_Concurrent(t *testing.T) {
	cisaListMu.Lock()
	origNets := cisaIPNets
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	cisaIPNets = []*net.IPNet{cidr}
	cisaListMu.Unlock()

	defer func() {
		cisaListMu.Lock()
		cisaIPNets = origNets
		cisaListMu.Unlock()
	}()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			size := CISAListSize()
			if size < 0 {
				t.Errorf("negative list size: %d", size)
			}
		}()
	}
	wg.Wait()
}

func TestClassify_CISAIP(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("198.51.100.0/24")

	cisaListMu.Lock()
	origNets := cisaIPNets
	cisaIPNets = []*net.IPNet{cidr}
	cisaListMu.Unlock()

	defer func() {
		cisaListMu.Lock()
		cisaIPNets = origNets
		cisaListMu.Unlock()
	}()

	c := Classify("example.com", "198.51.100.50")
	if !c.IsScan {
		t.Error("expected CISA IP to be classified as scan")
	}
	if c.Source != "CISA Cyber Hygiene" {
		t.Errorf("expected source 'CISA Cyber Hygiene', got %q", c.Source)
	}
	if c.IP != "198.51.100.50" {
		t.Errorf("expected IP '198.51.100.50', got %q", c.IP)
	}
}

func TestClassify_NormalTraffic(t *testing.T) {
	cisaListMu.Lock()
	origNets := cisaIPNets
	cisaIPNets = nil
	cisaListMu.Unlock()

	defer func() {
		cisaListMu.Lock()
		cisaIPNets = origNets
		cisaListMu.Unlock()
	}()

	c := Classify("google.com", "8.8.8.8")
	if c.IsScan {
		t.Error("expected normal traffic not to be classified as scan")
	}
	if c.Source != "" {
		t.Errorf("expected empty source, got %q", c.Source)
	}
	if c.IP != "8.8.8.8" {
		t.Errorf("expected IP '8.8.8.8', got %q", c.IP)
	}
}

func TestClassify_AllKnownScannerDomains(t *testing.T) {
	tests := []struct {
		domain string
		source string
	}{
		{"test.qualysperiscope.com", "Qualys Periscope"},
		{"scan.qualys.com", "Qualys"},
		{"payload.burpcollaborator.net", "Burp Collaborator"},
		{"abc123.oastify.com", "Burp Suite OAST"},
		{"test.interact.sh", "Interactsh"},
		{"probe.bxss.me", "Blind XSS Hunter"},
		{"token.canarytokens.com", "Canary Tokens"},
		{"dns.dnslog.cn", "DNSLog"},
		{"dns.dnslog.link", "DNSLog"},
		{"test.ceye.io", "CEYE"},
		{"host.nessus.org", "Tenable Nessus"},
		{"scan.tenablesecurity.com", "Tenable"},
		{"probe.rapid7.com", "Rapid7"},
		{"scan.shodan.io", "Shodan"},
		{"host.censys.io", "Censys"},
		{"test.projectdiscovery.io", "ProjectDiscovery"},
		{"callback.r87.me", "r87 OAST"},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			c := Classify(tt.domain, "1.2.3.4")
			if !c.IsScan {
				t.Errorf("expected %q to be classified as scan", tt.domain)
			}
			if c.Source != tt.source {
				t.Errorf("expected source %q for %q, got %q", tt.source, tt.domain, c.Source)
			}
		})
	}
}

func TestClassify_CaseInsensitive(t *testing.T) {
	c := Classify("TEST.SHODAN.IO", "1.2.3.4")
	if !c.IsScan {
		t.Error("expected case-insensitive match for SHODAN.IO")
	}
	if c.Source != "Shodan" {
		t.Errorf("expected source 'Shodan', got %q", c.Source)
	}
}

func TestParseCISABody(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"empty", "", 0},
		{"comments and blanks", "# comment\n\n# another\n", 0},
		{"single IPv4 CIDR", "192.0.2.0/24\n", 1},
		{"single IPv4 no CIDR", "192.0.2.1\n", 1},
		{"single IPv6 CIDR", "2001:db8::/32\n", 1},
		{"single IPv6 no CIDR", "2001:db8::1\n", 1},
		{"mixed valid", "192.0.2.0/24\n2001:db8::/32\n10.0.0.1\n", 3},
		{"invalid line skipped", "not-a-cidr\n192.0.2.0/24\n", 1},
		{"comments interleaved", "# header\n192.0.2.0/24\n# footer\n10.0.0.0/8\n", 2},
		{"whitespace trimmed", "  192.0.2.0/24  \n  \n  10.0.0.0/8  \n", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nets := parseCISABody(strings.NewReader(tt.input))
			if len(nets) != tt.want {
				t.Errorf("parseCISABody(%q) returned %d nets, want %d", tt.input, len(nets), tt.want)
			}
		})
	}
}

func TestParseCISABody_CorrectNetworks(t *testing.T) {
	input := "192.0.2.0/24\n10.0.0.1\n2001:db8::1\n"
	nets := parseCISABody(strings.NewReader(input))

	if len(nets) != 3 {
		t.Fatalf("expected 3 networks, got %d", len(nets))
	}

	if !nets[0].Contains(net.ParseIP("192.0.2.100")) {
		t.Error("first network should contain 192.0.2.100")
	}

	if !nets[1].Contains(net.ParseIP("10.0.0.1")) {
		t.Error("second network should contain 10.0.0.1")
	}

	if !nets[2].Contains(net.ParseIP("2001:db8::1")) {
		t.Error("third network should contain 2001:db8::1")
	}
}

func TestClassify_PriorityOrder(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("1.2.3.0/24")
	cisaListMu.Lock()
	origNets := cisaIPNets
	cisaIPNets = []*net.IPNet{cidr}
	cisaListMu.Unlock()

	defer func() {
		cisaListMu.Lock()
		cisaIPNets = origNets
		cisaListMu.Unlock()
	}()

	c := Classify("test.shodan.io", "1.2.3.4")
	if c.Source != "Shodan" {
		t.Errorf("known domain should take priority over CISA IP, got %q", c.Source)
	}
}

func TestFetchCISAList_Success(t *testing.T) {
	body := "# Comment\n192.0.2.0/24\n10.0.0.1\n2001:db8::1\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	}))
	defer srv.Close()

	origURL := cisaURL
	cisaURL = srv.URL

	cisaListMu.Lock()
	origNets := cisaIPNets
	cisaIPNets = nil
	cisaListMu.Unlock()

	defer func() {
		cisaURL = origURL
		cisaListMu.Lock()
		cisaIPNets = origNets
		cisaListMu.Unlock()
	}()

	fetchCISAList()

	cisaListMu.RLock()
	count := len(cisaIPNets)
	cisaListMu.RUnlock()

	if count != 3 {
		t.Errorf("expected 3 nets after fetch, got %d", count)
	}
}

func TestFetchCISAList_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	origURL := cisaURL
	cisaURL = srv.URL

	cisaListMu.Lock()
	origNets := cisaIPNets
	cisaIPNets = nil
	cisaListMu.Unlock()

	defer func() {
		cisaURL = origURL
		cisaListMu.Lock()
		cisaIPNets = origNets
		cisaListMu.Unlock()
	}()

	fetchCISAList()

	cisaListMu.RLock()
	count := len(cisaIPNets)
	cisaListMu.RUnlock()

	if count != 0 {
		t.Errorf("expected 0 nets after non-OK response, got %d", count)
	}
}

func TestFetchCISAList_EmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	origURL := cisaURL
	cisaURL = srv.URL

	cisaListMu.Lock()
	origNets := cisaIPNets
	cisaIPNets = nil
	cisaListMu.Unlock()

	defer func() {
		cisaURL = origURL
		cisaListMu.Lock()
		cisaIPNets = origNets
		cisaListMu.Unlock()
	}()

	fetchCISAList()

	cisaListMu.RLock()
	count := len(cisaIPNets)
	cisaListMu.RUnlock()

	if count != 0 {
		t.Errorf("expected 0 nets after empty body, got %d", count)
	}
}

func TestFetchCISAList_ConnectionError(t *testing.T) {
	origURL := cisaURL
	cisaURL = "http://192.0.2.1:1"

	cisaListMu.Lock()
	origNets := cisaIPNets
	cisaIPNets = nil
	cisaListMu.Unlock()

	defer func() {
		cisaURL = origURL
		cisaListMu.Lock()
		cisaIPNets = origNets
		cisaListMu.Unlock()
	}()

	fetchCISAList()

	cisaListMu.RLock()
	count := len(cisaIPNets)
	cisaListMu.RUnlock()

	if count != 0 {
		t.Errorf("expected 0 nets after connection error, got %d", count)
	}
}

func TestClassify_HeuristicNotTriggeredByFourLabels(t *testing.T) {
	c := Classify("abcdef1234567890.fedcba0987654321.example.com", "1.2.3.4")
	if c.IsScan {
		t.Error("4-label domain with hex should NOT trigger heuristic (need 5+)")
	}
}

func TestClassify_EmptyDomain(t *testing.T) {
	cisaListMu.Lock()
	origNets := cisaIPNets
	cisaIPNets = nil
	cisaListMu.Unlock()
	defer func() {
		cisaListMu.Lock()
		cisaIPNets = origNets
		cisaListMu.Unlock()
	}()

	c := Classify("", "1.2.3.4")
	if c.IsScan {
		t.Error("empty domain should not be classified as scan")
	}
}

func TestClassify_EmptyIP(t *testing.T) {
	cisaListMu.Lock()
	origNets := cisaIPNets
	cisaIPNets = nil
	cisaListMu.Unlock()
	defer func() {
		cisaListMu.Lock()
		cisaIPNets = origNets
		cisaListMu.Unlock()
	}()

	c := Classify("example.com", "")
	if c.IsScan {
		t.Error("empty IP should not trigger CISA match")
	}
	if c.IP != "" {
		t.Errorf("expected empty IP, got %q", c.IP)
	}
}

func TestIsHeuristicScanner_ExactlyFiveLabelsOneHex(t *testing.T) {
	got := isHeuristicScanner("abcdef1234567890.normal.sub.evil.example.com")
	if got {
		t.Error("only one long hex label should not trigger heuristic")
	}
}

func TestIsHeuristicScanner_ShortHexLabels(t *testing.T) {
	got := isHeuristicScanner("abcdef12.abcdef34.sub.evil.example.com")
	if got {
		t.Error("short hex labels (< 12 chars) should not trigger")
	}
}
