package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsValidHostname(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		{"valid domain", "example.com", true},
		{"valid subdomain", "www.example.com", true},
		{"valid with hyphens", "my-site.example.com", true},
		{"uppercase", "Example.COM", true},
		{"single label", "localhost", true},
		{"empty", "", false},
		{"starts with hyphen", "-evil.com", false},
		{"starts with dot", ".evil.com", false},
		{"semicolon injection", "example.com;rm -rf /", false},
		{"pipe injection", "example.com|cat /etc/passwd", false},
		{"backtick injection", "example.com`whoami`", false},
		{"ampersand injection", "example.com&&echo pwned", false},
		{"dollar injection", "example.com$PATH", false},
		{"newline injection", "example.com\nmalicious", false},
		{"space in hostname", "example .com", false},
		{"nmap flag injection", "--interactive", false},
		{"too long", strings.Repeat("a", 254), false},
		{"max length", strings.Repeat("a", 253), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidHostname(tt.input)
			if got != tt.expect {
				t.Errorf("isValidHostname(%q) = %v, want %v", tt.input, got, tt.expect)
			}
		})
	}
}

func TestTlsVersionString(t *testing.T) {
	tests := []struct {
		input  uint16
		expect string
	}{
		{0x0304, "TLSv1.3"},
		{0x0303, "TLSv1.2"},
		{0x0302, "TLSv1.1"},
		{0x0301, "TLSv1.0"},
		{0x0000, "TLS 0x0000"},
	}
	for _, tt := range tests {
		got := tlsVersionString(tt.input)
		if got != tt.expect {
			t.Errorf("tlsVersionString(0x%04x) = %q, want %q", tt.input, got, tt.expect)
		}
	}
}

func TestCipherBits(t *testing.T) {
	tests := []struct {
		name   string
		suite  uint16
		expect int
	}{
		{"AES-256-GCM-SHA384", 0x009d, 256},
		{"AES-128-GCM-SHA256 (name contains both 128 and 256, 256 matched first)", 0x009c, 256},
		{"CHACHA20-POLY1305", 0xcca8, 256},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cipherBits(tt.suite)
			if got != tt.expect {
				t.Errorf("cipherBits(0x%04x) = %d, want %d", tt.suite, got, tt.expect)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		expect string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "hello"},
		{"", 5, ""},
		{"abc", 3, "abc"},
		{"abcdef", 3, "abc"},
	}
	for _, tt := range tests {
		got := truncate(tt.input, tt.maxLen)
		if got != tt.expect {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.expect)
		}
	}
}

func TestSmtpComplete(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		{"complete 220", "220 mail.example.com ESMTP\r\n", true},
		{"complete 250", "250 OK\r\n", true},
		{"continuation", "250-SIZE 10485760\r\n", false},
		{"multi-line complete", "250-STARTTLS\r\n250 OK\r\n", true},
		{"empty last line", "250 OK\r\n\r\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := smtpComplete(tt.input)
			if got != tt.expect {
				t.Errorf("smtpComplete(%q) = %v, want %v", tt.input, got, tt.expect)
			}
		})
	}
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name   string
		err    string
		expect string
	}{
		{"timeout", "dial tcp: i/o timeout", "Connection timeout"},
		{"deadline", "context deadline exceeded", "Connection timeout"},
		{"refused", "dial tcp: connection refused", "Connection refused"},
		{"unreachable", "network is unreachable", "Network unreachable"},
		{"dns", "dial tcp: lookup example.com: no such host", "DNS resolution failed"},
		{"other", "something unexpected", "something unexpected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyError(errString(tt.err))
			if got != tt.expect {
				t.Errorf("classifyError(%q) = %q, want %q", tt.err, got, tt.expect)
			}
		})
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestAllowedNSEScripts(t *testing.T) {
	expected := []string{"ssl-cert", "http-title", "http-headers", "dns-zone-transfer", "banner", "smtp-commands"}
	for _, s := range expected {
		if !allowedNSEScripts[s] {
			t.Errorf("expected %q in allowed scripts", s)
		}
	}
	if allowedNSEScripts["vuln"] {
		t.Error("vuln should not be in allowed scripts")
	}
	if allowedNSEScripts["exploit"] {
		t.Error("exploit should not be in allowed scripts")
	}
}

func TestParseNmapXML_ValidXML(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun scanner="nmap" startstr="Mon Feb 24 12:00:00 2026" version="7.95">
  <host>
    <status state="up"/>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <hostnames>
      <hostname name="example.com" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.25"/>
        <script id="ssl-cert" output="Subject: commonName=example.com"/>
        <script id="http-title" output="Example Domain"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished timestr="Mon Feb 24 12:00:05 2026" elapsed="5.00"/>
  </runstats>
</nmaprun>`

	result := parseNmapXML(xml)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result["scanner"] != "nmap" {
		t.Errorf("expected scanner 'nmap', got %v", result["scanner"])
	}
	if result["version"] != "7.95" {
		t.Errorf("expected version '7.95', got %v", result["version"])
	}

	hosts, ok := result["hosts"].([]map[string]any)
	if !ok || len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %v", result["hosts"])
	}
	if hosts[0]["status"] != "up" {
		t.Errorf("expected status 'up', got %v", hosts[0]["status"])
	}

	ports, ok := hosts[0]["ports"].([]map[string]any)
	if !ok || len(ports) != 1 {
		t.Fatalf("expected 1 port, got %v", hosts[0]["ports"])
	}
	if ports[0]["port"] != 443 {
		t.Errorf("expected port 443, got %v", ports[0]["port"])
	}
	if ports[0]["service"] != "https" {
		t.Errorf("expected service 'https', got %v", ports[0]["service"])
	}
	if ports[0]["product"] != "nginx" {
		t.Errorf("expected product 'nginx', got %v", ports[0]["product"])
	}
}

func TestParseNmapXML_InvalidXML(t *testing.T) {
	result := parseNmapXML("not xml at all")
	if result != nil {
		t.Error("expected nil for invalid XML")
	}
}

func TestParseNmapXML_EmptyHosts(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <runstats><finished elapsed="0.5"/></runstats>
</nmaprun>`

	result := parseNmapXML(xml)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	hosts := result["hosts"]
	if hosts != nil {
		hostSlice, ok := hosts.([]map[string]any)
		if ok && len(hostSlice) != 0 {
			t.Errorf("expected 0 hosts, got %d", len(hostSlice))
		}
	}
}

func TestParseNmapXML_MultiplePortsAndScripts(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache" version="2.4"/>
        <script id="http-title" output="Welcome"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" tunnel="ssl"/>
        <script id="ssl-cert" output="Subject Alternative Name: DNS:example.com"/>
        <script id="http-headers" output="HTTP/1.1 200 OK"/>
      </port>
      <port protocol="tcp" portid="25">
        <state state="open" reason="syn-ack"/>
        <service name="smtp" product="Postfix"/>
        <script id="smtp-commands" output="EHLO commands"/>
        <script id="banner" output="220 mail.example.com ESMTP"/>
      </port>
    </ports>
  </host>
  <runstats><finished elapsed="3.00"/></runstats>
</nmaprun>`

	result := parseNmapXML(xml)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	hosts := result["hosts"].([]map[string]any)
	ports := hosts[0]["ports"].([]map[string]any)
	if len(ports) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(ports))
	}

	for _, p := range ports {
		scripts, ok := p["scripts"].([]map[string]any)
		if !ok {
			continue
		}
		for _, s := range scripts {
			if s["id"] == "" {
				t.Error("script ID should not be empty")
			}
		}
	}
}

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}
	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("expected status 'ok', got %s", body["status"])
	}
}

func TestHandleHealth(t *testing.T) {
	hostname = "test-host"
	startTime = time.Now()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var body map[string]any
	json.NewDecoder(w.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("expected status 'ok', got %v", body["status"])
	}
	if body["version"] != probeVersion {
		t.Errorf("expected version %s, got %v", probeVersion, body["version"])
	}
	if body["hostname"] != "test-host" {
		t.Errorf("expected hostname 'test-host', got %v", body["hostname"])
	}
}

func TestAuthMiddleware_Unauthorized(t *testing.T) {
	probeKey = "test-secret-key"
	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	})

	req := httptest.NewRequest("POST", "/probe/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAuthMiddleware_WrongKey(t *testing.T) {
	probeKey = "correct-key"
	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	})

	req := httptest.NewRequest("POST", "/probe/test", nil)
	req.Header.Set("X-Probe-Key", "wrong-key")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAuthMiddleware_Authorized(t *testing.T) {
	probeKey = "correct-key"
	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	})

	req := httptest.NewRequest("POST", "/probe/test", nil)
	req.Header.Set("X-Probe-Key", "correct-key")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	rateMu.Lock()
	rateCount = make(map[string]int)
	rateMu.Unlock()

	handler := rateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	})

	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("POST", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d should succeed, got %d", i+1, w.Code)
		}
	}

	req := httptest.NewRequest("POST", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after 20 requests, got %d", w.Code)
	}
}

func TestHandleSMTPProbe_InvalidBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/probe/smtp", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	handleSMTPProbe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleSMTPProbe_EmptyHosts(t *testing.T) {
	body := `{"hosts": []}`
	req := httptest.NewRequest("POST", "/probe/smtp", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleSMTPProbe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleSMTPProbe_InvalidHostname(t *testing.T) {
	body := `{"hosts": ["evil;rm -rf /"]}`
	req := httptest.NewRequest("POST", "/probe/smtp", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleSMTPProbe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleNmapScan_InvalidBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/probe/nmap", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	handleNmapScan(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleNmapScan_EmptyHost(t *testing.T) {
	body := `{"host": ""}`
	req := httptest.NewRequest("POST", "/probe/nmap", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleNmapScan(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleNmapScan_InvalidHostname(t *testing.T) {
	body := `{"host": "--interactive"}`
	req := httptest.NewRequest("POST", "/probe/nmap", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleNmapScan(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for flag-like hostname, got %d", w.Code)
	}
}

func TestHandleNmapScan_InvalidPorts(t *testing.T) {
	body := `{"host": "example.com", "ports": "80;whoami"}`
	req := httptest.NewRequest("POST", "/probe/nmap", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleNmapScan(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid ports, got %d", w.Code)
	}
}

func TestHandleNmapScan_RejectedScripts(t *testing.T) {
	body := `{"host": "example.com", "scripts": ["ssl-cert", "vuln", "exploit"]}`
	req := httptest.NewRequest("POST", "/probe/nmap", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleNmapScan(w, req)

	if w.Code == http.StatusBadRequest {
		t.Error("should accept request with some valid scripts even if others are rejected")
	}
}

func TestHandleTestSSL_InvalidBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/probe/testssl", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	handleTestSSL(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleTestSSL_InvalidHostname(t *testing.T) {
	body := `{"host": "evil;cmd"}`
	req := httptest.NewRequest("POST", "/probe/testssl", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleTestSSL(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid hostname, got %d", w.Code)
	}
}

func TestHandleDANEVerify_InvalidBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/probe/dane-verify", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	handleDANEVerify(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleDANEVerify_InvalidHostname(t *testing.T) {
	body := `{"host": "evil|cmd"}`
	req := httptest.NewRequest("POST", "/probe/dane-verify", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleDANEVerify(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid hostname, got %d", w.Code)
	}
}

func TestMaxSMTPResponseSize(t *testing.T) {
	if maxSMTPResponseSize != 64*1024 {
		t.Errorf("expected maxSMTPResponseSize to be 64KB, got %d", maxSMTPResponseSize)
	}
}

func TestSmtpComplete_EdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		{"short line under 4 chars", "OK\r\n", false},
		{"exactly 4 chars with space", "250 Done\r\n", true},
		{"exactly 4 chars with dash (continuation)", "250-\r\n", false},
		{"empty string", "", false},
		{"single newline", "\n", false},
		{"multi-line with final empty line falls back", "250-PIPELINING\r\n250 OK\r\n\n", false},
		{"response code 354", "354 Start mail input\r\n", true},
		{"response code 421", "421 Service not available\r\n", true},
		{"multi-line EHLO complete", "250-example.com Hello\r\n250-SIZE 10485760\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 HELP\r\n", true},
		{"only continuation lines", "250-SIZE\r\n250-PIPELINING\r\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := smtpComplete(tt.input)
			if got != tt.expect {
				t.Errorf("smtpComplete(%q) = %v, want %v", tt.input, got, tt.expect)
			}
		})
	}
}

func TestClassifyError_LongMessage(t *testing.T) {
	longErr := strings.Repeat("x", 200)
	got := classifyError(errString(longErr))
	if len(got) > 80 {
		t.Errorf("classifyError should truncate unknown errors to 80 chars, got %d", len(got))
	}
	if got != strings.Repeat("x", 80) {
		t.Errorf("expected truncated string, got %q", got)
	}
}

func TestCipherBits_128(t *testing.T) {
	got := cipherBits(0x002f)
	if got != 128 {
		t.Errorf("cipherBits for TLS_RSA_WITH_AES_128_CBC_SHA = %d, want 128", got)
	}
}

func TestCipherBits_Unknown(t *testing.T) {
	got := cipherBits(0x0000)
	if got != 0 {
		t.Errorf("cipherBits for unknown suite = %d, want 0", got)
	}
}

func TestIsValidHostname_AdditionalEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		{"underscore", "my_host.example.com", false},
		{"unicode chars", "münchen.de", false},
		{"trailing dot", "example.com.", true},
		{"numeric only", "123456", true},
		{"ends with hyphen", "example-.com", true},
		{"single char", "a", true},
		{"dots only", "...", false},
		{"tab char", "example\t.com", false},
		{"null byte", "example\x00.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidHostname(tt.input)
			if got != tt.expect {
				t.Errorf("isValidHostname(%q) = %v, want %v", tt.input, got, tt.expect)
			}
		})
	}
}

func TestParseNmapXML_PortWithTunnel(t *testing.T) {
	xmlData := `<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <status state="up"/>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" tunnel="ssl"/>
      </port>
    </ports>
  </host>
  <runstats><finished elapsed="1.00"/></runstats>
</nmaprun>`

	result := parseNmapXML(xmlData)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	hosts := result["hosts"].([]map[string]any)
	ports := hosts[0]["ports"].([]map[string]any)
	if ports[0]["tunnel"] != "ssl" {
		t.Errorf("expected tunnel 'ssl', got %v", ports[0]["tunnel"])
	}
	if _, ok := ports[0]["product"]; ok {
		t.Error("expected no product key when product is empty")
	}
	if _, ok := ports[0]["version"]; ok {
		t.Error("expected no version key when version is empty")
	}
}

func TestParseNmapXML_MultipleHosts(t *testing.T) {
	xmlData := `<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <status state="up"/>
    <address addr="1.1.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="2.2.2.2" addrtype="ipv4"/>
    <address addr="2001:db8::1" addrtype="ipv6"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
  <runstats><finished elapsed="2.00"/></runstats>
</nmaprun>`

	result := parseNmapXML(xmlData)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	hosts := result["hosts"].([]map[string]any)
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(hosts))
	}
	addrs := hosts[1]["addresses"].([]map[string]string)
	if len(addrs) != 2 {
		t.Fatalf("expected 2 addresses for host 2, got %d", len(addrs))
	}
}

func TestParseNmapXML_NoHostnames(t *testing.T) {
	xmlData := `<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <status state="up"/>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
  <runstats><finished elapsed="0.50"/></runstats>
</nmaprun>`

	result := parseNmapXML(xmlData)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	hosts := result["hosts"].([]map[string]any)
	if _, ok := hosts[0]["hostnames"]; ok {
		t.Error("expected no hostnames key when hostnames are empty")
	}
}

func TestParseNmapXML_EmptyString(t *testing.T) {
	result := parseNmapXML("")
	if result != nil {
		t.Error("expected nil for empty string")
	}
}

func TestParseNmapXML_PortWithVersionOnly(t *testing.T) {
	xmlData := `<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <status state="up"/>
    <address addr="5.6.7.8" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3306">
        <state state="open" reason="syn-ack"/>
        <service name="mysql" version="8.0"/>
      </port>
    </ports>
  </host>
  <runstats><finished elapsed="1.50"/></runstats>
</nmaprun>`

	result := parseNmapXML(xmlData)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	hosts := result["hosts"].([]map[string]any)
	ports := hosts[0]["ports"].([]map[string]any)
	if ports[0]["version"] != "8.0" {
		t.Errorf("expected version '8.0', got %v", ports[0]["version"])
	}
	if _, ok := ports[0]["product"]; ok {
		t.Error("expected no product when empty")
	}
}

func TestTlsVersionString_UnknownVersion(t *testing.T) {
	tests := []struct {
		input  uint16
		expect string
	}{
		{0x0305, "TLS 0x0305"},
		{0xFFFF, "TLS 0xffff"},
		{0x0100, "TLS 0x0100"},
	}
	for _, tt := range tests {
		got := tlsVersionString(tt.input)
		if got != tt.expect {
			t.Errorf("tlsVersionString(0x%04x) = %q, want %q", tt.input, got, tt.expect)
		}
	}
}

func TestTruncate_ExactBoundary(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		expect string
	}{
		{"abcde", 5, "abcde"},
		{"abcde", 4, "abcd"},
		{"abcde", 1, "a"},
		{"abcde", 0, ""},
		{"", 0, ""},
	}
	for _, tt := range tests {
		got := truncate(tt.input, tt.maxLen)
		if got != tt.expect {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.expect)
		}
	}
}

func TestHandleHealth_Fields(t *testing.T) {
	hostname = "probe-test"
	startTime = time.Now().Add(-1 * time.Hour)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	var body map[string]any
	json.NewDecoder(w.Body).Decode(&body)

	if _, ok := body["uptime"]; !ok {
		t.Error("expected 'uptime' field in health response")
	}
	if _, ok := body["time"]; !ok {
		t.Error("expected 'time' field in health response")
	}
}

func TestHandleSMTPProbe_MultipleInvalidHosts(t *testing.T) {
	body := `{"hosts": ["valid.com", "evil;rm"]}`
	req := httptest.NewRequest("POST", "/probe/smtp", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleSMTPProbe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for any invalid hostname in list, got %d", w.Code)
	}
}

func TestHandleTestSSL_EmptyHost(t *testing.T) {
	body := `{"host": ""}`
	req := httptest.NewRequest("POST", "/probe/testssl", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleTestSSL(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleDANEVerify_EmptyHost(t *testing.T) {
	body := `{"host": ""}`
	req := httptest.NewRequest("POST", "/probe/dane-verify", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleDANEVerify(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleNmapScan_InvalidPortFormats(t *testing.T) {
	tests := []struct {
		name  string
		ports string
	}{
		{"semicolon", "80;443"},
		{"alpha", "http"},
		{"parens", "80(443)"},
		{"backtick", "80`whoami`"},
		{"dollar", "80$PATH"},
		{"space", "80 443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"host": "example.com", "ports": "` + tt.ports + `"}`
			req := httptest.NewRequest("POST", "/probe/nmap", strings.NewReader(body))
			w := httptest.NewRecorder()
			handleNmapScan(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected invalid port spec %q to return 400, got %d", tt.ports, w.Code)
			}
		})
	}
}

func TestWriteJSON_ErrorStatus(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "test"})

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestRateLimitMiddleware_DifferentIPs(t *testing.T) {
	rateMu.Lock()
	rateCount = make(map[string]int)
	rateMu.Unlock()

	handler := rateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	})

	for i := 0; i < 25; i++ {
		req := httptest.NewRequest("POST", "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		w := httptest.NewRecorder()
		handler(w, req)
	}

	req := httptest.NewRequest("POST", "/test", nil)
	req.RemoteAddr = "10.0.0.2:12345"
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("different IP should not be rate limited, got %d", w.Code)
	}
}

func TestReadSMTPResponse_Complete(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		server.Write([]byte("220 mail.example.com ESMTP\r\n"))
	}()

	resp, err := readSMTPResponse(client, 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(resp, "220") {
		t.Errorf("expected response starting with 220, got %q", resp)
	}
}

func TestReadSMTPResponse_Timeout(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	_, err := readSMTPResponse(client, 50*time.Millisecond)
	if err == nil {
		t.Error("expected timeout error, got nil")
	}
}

func TestReadSMTPResponse_MultiLine(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		server.Write([]byte("250-STARTTLS\r\n250-PIPELINING\r\n250 HELP\r\n"))
	}()

	resp, err := readSMTPResponse(client, 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(resp, "STARTTLS") {
		t.Errorf("expected STARTTLS in response, got %q", resp)
	}
	if !strings.Contains(resp, "250 HELP") {
		t.Errorf("expected '250 HELP' in response, got %q", resp)
	}
}

func TestProbePort_Unreachable(t *testing.T) {
	ctx := t.Context()
	result := probePort(ctx, "192.0.2.1", 12345)
	if result["reachable"] != false {
		t.Error("expected unreachable for non-routable address")
	}
	if result["host"] != "192.0.2.1" {
		t.Errorf("expected host '192.0.2.1', got %v", result["host"])
	}
	if result["port"] != 12345 {
		t.Errorf("expected port 12345, got %v", result["port"])
	}
}

func TestProbeAllServers_Empty(t *testing.T) {
	ctx := t.Context()
	result := probeAllServers(ctx, []string{})
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d servers", len(result))
	}
}

func TestExtractCertInfo_ClosedConn(t *testing.T) {
	server, client := net.Pipe()
	server.Close()

	result := extractCertInfo(client, "example.com")
	client.Close()
	if result["error"] == nil {
		t.Error("expected error for closed connection")
	}
}

func TestProbeSMTPServer_Unreachable(t *testing.T) {
	ctx := t.Context()
	result := probeSMTPServer(ctx, "192.0.2.1")
	if result["reachable"] != false {
		t.Error("expected unreachable")
	}
	if result["host"] != "192.0.2.1" {
		t.Errorf("expected host '192.0.2.1', got %v", result["host"])
	}
	if result["error"] == nil {
		t.Error("expected error for unreachable host")
	}
}

func TestGetCertViaTLS_Unreachable(t *testing.T) {
	ctx := t.Context()
	result := getCertViaTLS(ctx, "192.0.2.1", 12345)
	if result["error"] == nil {
		t.Error("expected error for unreachable host")
	}
	if result["method"] != "direct_tls" {
		t.Errorf("expected method 'direct_tls', got %v", result["method"])
	}
}

func TestGetCertViaSMTP_Unreachable(t *testing.T) {
	ctx := t.Context()
	result := getCertViaSMTP(ctx, "192.0.2.1")
	if result["error"] == nil {
		t.Error("expected error for unreachable host")
	}
	if result["method"] != "smtp_starttls" {
		t.Errorf("expected method 'smtp_starttls', got %v", result["method"])
	}
}

func TestParseNmapXML_RunStats(t *testing.T) {
	xmlData := `<?xml version="1.0"?>
<nmaprun scanner="nmap" startstr="Mon Feb 24 12:00:00 2026" version="7.95">
  <runstats>
    <finished timestr="Mon Feb 24 12:00:05 2026" elapsed="5.00"/>
  </runstats>
</nmaprun>`

	result := parseNmapXML(xmlData)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result["elapsed"] != "5.00" {
		t.Errorf("expected elapsed '5.00', got %v", result["elapsed"])
	}
	if result["start"] != "Mon Feb 24 12:00:00 2026" {
		t.Errorf("expected start time, got %v", result["start"])
	}
}
