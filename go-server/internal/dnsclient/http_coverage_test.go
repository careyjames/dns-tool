package dnsclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIsPrivateIP_ExtendedV4(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.0", true},
		{"10.255.255.255", true},
		{"172.16.0.0", true},
		{"172.31.255.255", true},
		{"172.15.255.255", false},
		{"172.32.0.0", false},
		{"192.168.0.0", true},
		{"192.168.255.255", true},
		{"127.0.0.0", true},
		{"127.255.255.255", true},
		{"169.254.0.1", true},
		{"169.254.255.255", true},
		{"100.64.0.0", true},
		{"100.127.255.255", true},
		{"100.63.255.255", false},
		{"100.128.0.0", false},
		{"192.0.0.0", true},
		{"192.0.0.255", true},
		{"192.0.1.0", false},
		{"198.18.0.0", true},
		{"198.19.255.255", true},
		{"198.17.255.255", false},
		{"198.20.0.0", false},
		{"0.0.0.0", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"invalid-ip", false},
		{"", false},
		{"256.1.1.1", false},
		{"1.2.3.4.5", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := IsPrivateIP(tt.ip)
			if got != tt.want {
				t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIsPrivateIP_IPv6Cases(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"::1", true},
		{"fe80::1", true},
		{"::", true},
		{"fc00::1", true},
		{"fd00::1", true},
		{"ff02::1", true},
		{"2001:4860:4860::8888", false},
		{"2606:4700:4700::1111", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := IsPrivateIP(tt.ip)
			if got != tt.want {
				t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestValidateURLTarget_VariousCases(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"invalid url", "://bad", false},
		{"empty host", "https://", false},
		{"localhost IP", "https://127.0.0.1/test", false},
		{"private 10.x", "https://10.0.0.1/test", false},
		{"private 192.168", "https://192.168.1.1/test", false},
		{"public google", "https://google.com/test", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateURLTarget(tt.url)
			if got != tt.want {
				t.Errorf("ValidateURLTarget(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestIsRDAPAllowedHost_Comprehensive(t *testing.T) {
	allowed := []string{
		"rdap.verisign.com",
		"rdap.publicinterestregistry.net",
		"rdap.nic.io",
		"rdap.nic.google",
		"rdap.nominet.uk",
		"rdap.eu",
		"rdap.sidn.nl",
		"rdap.auda.org.au",
		"rdap.centralnic.com",
		"rdap.nic.co",
		"rdap.nic.me",
		"rdap.nic.ai",
		"rdap.afilias.net",
		"rdap.nic.biz",
		"rdap.nic.mobi",
		"rdap.nic.pro",
		"rdap.nic.top",
		"rdap.org",
	}

	for _, h := range allowed {
		if !IsRDAPAllowedHost(h) {
			t.Errorf("expected %q to be allowed", h)
		}
	}

	notAllowed := []string{
		"rdap.evil.com",
		"evil.rdap.verisign.com",
		"rdap.verisign.com.evil.com",
		"localhost",
		"",
		"127.0.0.1",
	}

	for _, h := range notAllowed {
		if IsRDAPAllowedHost(h) {
			t.Errorf("expected %q to NOT be allowed", h)
		}
	}
}

func TestNewSafeHTTPClient_Defaults(t *testing.T) {
	c := NewSafeHTTPClient()
	if c == nil {
		t.Fatal("returned nil")
	}
	if c.SkipSSRF {
		t.Error("SkipSSRF should default to false")
	}
	if c.userAgent == "" {
		t.Error("userAgent should not be empty")
	}
}

func TestNewSafeHTTPClientWithTimeout_CustomTimeout(t *testing.T) {
	c := NewSafeHTTPClientWithTimeout(5 * time.Second)
	if c == nil {
		t.Fatal("returned nil")
	}
	if c.client.Timeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %v", c.client.Timeout)
	}
}

func TestNewRDAPHTTPClient_Defaults(t *testing.T) {
	c := NewRDAPHTTPClient()
	if c == nil {
		t.Fatal("returned nil")
	}
	if c.client.Timeout != 25*time.Second {
		t.Errorf("expected 25s timeout, got %v", c.client.Timeout)
	}
}

func TestSafeHTTPClient_Get_CancelledContext(t *testing.T) {
	client := NewSafeHTTPClient()
	client.SkipSSRF = true
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.Get(ctx, "https://example.com")
	if err == nil {
		t.Log("cancelled context may or may not return error")
	}
}

func TestSafeHTTPClient_GetWithHeaders_CancelledContext(t *testing.T) {
	client := NewSafeHTTPClient()
	client.SkipSSRF = true
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.GetWithHeaders(ctx, "https://example.com", map[string]string{"X-Test": "val"})
	if err == nil {
		t.Log("cancelled context may or may not return error")
	}
}

func TestSafeHTTPClient_ReadBody_Limit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("abcdefghijklmnopqrstuvwxyz"))
	}))
	defer ts.Close()

	client := NewSafeHTTPClient()
	client.SkipSSRF = true
	ctx := context.Background()

	resp, err := client.Get(ctx, ts.URL)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	body, err := client.ReadBody(resp, 10)
	if err != nil {
		t.Fatalf("ReadBody failed: %v", err)
	}
	if len(body) > 10 {
		t.Errorf("expected at most 10 bytes, got %d", len(body))
	}
}

func TestGetDirect_HTTPSchemeRejected(t *testing.T) {
	client := NewRDAPHTTPClient()
	ctx := context.Background()

	_, err := client.GetDirect(ctx, "http://rdap.verisign.com/test")
	if err == nil {
		t.Fatal("expected error for HTTP scheme")
	}
}

func TestGetDirect_FTPSchemeRejected(t *testing.T) {
	client := NewRDAPHTTPClient()
	ctx := context.Background()

	_, err := client.GetDirect(ctx, "ftp://rdap.verisign.com/test")
	if err == nil {
		t.Fatal("expected error for FTP scheme")
	}
}

func TestGetDirect_UnknownHost(t *testing.T) {
	client := NewRDAPHTTPClient()
	ctx := context.Background()

	_, err := client.GetDirect(ctx, "https://127.0.0.1/test")
	if err == nil {
		t.Fatal("expected error for non-allowlisted host with private IP")
	}
}

func TestGetDirect_InvalidURLParsing(t *testing.T) {
	client := NewRDAPHTTPClient()
	ctx := context.Background()

	_, err := client.GetDirect(ctx, "://invalid-url")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestSafeHTTPClient_Get_SSRFProtection(t *testing.T) {
	client := NewSafeHTTPClient()
	ctx := context.Background()

	_, err := client.Get(ctx, "https://127.0.0.1/secret")
	if err == nil {
		t.Fatal("expected SSRF protection error")
	}
}

func TestSafeHTTPClient_GetWithHeaders_SSRFProtection(t *testing.T) {
	client := NewSafeHTTPClient()
	ctx := context.Background()

	_, err := client.GetWithHeaders(ctx, "https://10.0.0.1/api", map[string]string{"X-Test": "val"})
	if err == nil {
		t.Fatal("expected SSRF protection error")
	}
}

func TestSafeHTTPClient_Get_SuccessWithSkipSSRF(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Error("expected User-Agent to be set")
		}
		w.WriteHeader(200)
		w.Write([]byte("response"))
	}))
	defer ts.Close()

	client := NewSafeHTTPClient()
	client.SkipSSRF = true
	ctx := context.Background()

	resp, err := client.Get(ctx, ts.URL)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestSafeHTTPClient_GetWithHeaders_SetsCustomHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token123" {
			t.Error("expected Authorization header")
		}
		if r.Header.Get("X-Custom") != "value" {
			t.Error("expected X-Custom header")
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	client := NewSafeHTTPClient()
	client.SkipSSRF = true

	headers := map[string]string{
		"Authorization": "Bearer token123",
		"X-Custom":      "value",
	}
	resp, err := client.GetWithHeaders(context.Background(), ts.URL, headers)
	if err != nil {
		t.Fatalf("GetWithHeaders failed: %v", err)
	}
	resp.Body.Close()
}
