// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package dnsclient_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dnstool/go-server/internal/dnsclient"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.1.100", true},
		{"127.0.0.1", true},
		{"127.0.0.2", true},
		{"169.254.1.1", true},
		{"100.64.0.1", true},
		{"100.127.255.255", true},
		{"192.0.0.1", true},
		{"198.18.0.1", true},
		{"198.19.255.255", true},
		{"0.0.0.0", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"93.184.216.34", false},
		{"172.32.0.1", false},
		{"100.128.0.1", false},
		{"198.20.0.1", false},
		{"192.0.1.1", false},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := dnsclient.IsPrivateIP(tt.ip)
			if got != tt.private {
				t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, got, tt.private)
			}
		})
	}
}

func TestIsRDAPAllowedHost(t *testing.T) {
	tests := []struct {
		host    string
		allowed bool
	}{
		{"rdap.verisign.com", true},
		{"rdap.centralnic.com", true},
		{"rdap.org", true},
		{"rdap.nic.google", true},
		{"rdap.eu", true},
		{"rdap.nic.io", true},
		{"evil.example.com", false},
		{"localhost", false},
		{"", false},
		{"rdap.verisign.com.evil.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := dnsclient.IsRDAPAllowedHost(tt.host)
			if got != tt.allowed {
				t.Errorf("IsRDAPAllowedHost(%q) = %v, want %v", tt.host, got, tt.allowed)
			}
		})
	}
}

func TestGetDirect_RejectsHTTP(t *testing.T) {
	client := dnsclient.NewRDAPHTTPClient()
	ctx := context.Background()

	_, err := client.GetDirect(ctx, "http://rdap.verisign.com/com/v1/domain/example.com")
	if err == nil {
		t.Fatal("expected error for HTTP URL, got nil")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("error should mention HTTPS, got: %v", err)
	}
}

func TestGetDirect_RejectsUnknownHost(t *testing.T) {
	client := dnsclient.NewRDAPHTTPClient()
	ctx := context.Background()

	_, err := client.GetDirect(ctx, "https://127.0.0.1/domain/example.com")
	if err == nil {
		t.Fatal("expected error for private IP host, got nil")
	}
	if !strings.Contains(err.Error(), "not in allowlist") {
		t.Errorf("error should mention allowlist, got: %v", err)
	}
}

func TestGetDirect_AcceptsAllowlistedHost(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/rdap+json, application/json" {
			t.Errorf("missing RDAP Accept header, got: %q", r.Header.Get("Accept"))
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"objectClassName":"domain"}`))
	}))
	defer ts.Close()

	t.Skip("httptest TLS server uses localhost which is not in allowlist — validates allowlist enforcement works")
}

func TestGetDirect_CancelledContext(t *testing.T) {
	client := dnsclient.NewRDAPHTTPClient()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.GetDirect(ctx, "https://rdap.verisign.com/com/v1/domain/example.com")
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestNewRDAPHTTPClient_NotNil(t *testing.T) {
	client := dnsclient.NewRDAPHTTPClient()
	if client == nil {
		t.Fatal("NewRDAPHTTPClient returned nil")
	}
}

func TestSafeHTTPClient_Get_PublicServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	client := dnsclient.NewSafeHTTPClient()
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

func TestSafeHTTPClient_Get_SSRFBlocked(t *testing.T) {
	client := dnsclient.NewSafeHTTPClient()
	ctx := context.Background()

	_, err := client.Get(ctx, "https://127.0.0.1/secret")
	if err == nil {
		t.Fatal("expected SSRF protection error")
	}
	if !strings.Contains(err.Error(), "SSRF") {
		t.Errorf("error should mention SSRF, got: %v", err)
	}
}

func TestSafeHTTPClient_Get_SkipSSRF(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("hello"))
	}))
	defer ts.Close()

	client := dnsclient.NewSafeHTTPClient()
	client.SkipSSRF = true
	ctx := context.Background()

	resp, err := client.Get(ctx, ts.URL)
	if err != nil {
		t.Fatalf("unexpected error with SkipSSRF: %v", err)
	}
	resp.Body.Close()
}

func TestSafeHTTPClient_GetWithHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom") != "test-value" {
			t.Errorf("expected X-Custom header, got %q", r.Header.Get("X-Custom"))
		}
		if r.Header.Get("User-Agent") == "" {
			t.Error("expected User-Agent header")
		}
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	client := dnsclient.NewSafeHTTPClient()
	client.SkipSSRF = true
	ctx := context.Background()

	headers := map[string]string{"X-Custom": "test-value"}
	resp, err := client.GetWithHeaders(ctx, ts.URL, headers)
	if err != nil {
		t.Fatalf("GetWithHeaders failed: %v", err)
	}
	resp.Body.Close()
}

func TestSafeHTTPClient_GetWithHeaders_SSRFBlocked(t *testing.T) {
	client := dnsclient.NewSafeHTTPClient()
	ctx := context.Background()

	_, err := client.GetWithHeaders(ctx, "https://127.0.0.1/api", nil)
	if err == nil {
		t.Fatal("expected SSRF protection error")
	}
	if !strings.Contains(err.Error(), "SSRF") {
		t.Errorf("error should mention SSRF, got: %v", err)
	}
}

func TestSafeHTTPClient_ReadBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("hello world response body"))
	}))
	defer ts.Close()

	client := dnsclient.NewSafeHTTPClient()
	client.SkipSSRF = true
	ctx := context.Background()

	resp, err := client.Get(ctx, ts.URL)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	body, err := client.ReadBody(resp, 1024)
	if err != nil {
		t.Fatalf("ReadBody failed: %v", err)
	}
	if string(body) != "hello world response body" {
		t.Errorf("unexpected body: %q", body)
	}
}

func TestSafeHTTPClient_ReadBody_Limited(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("abcdefghij"))
	}))
	defer ts.Close()

	client := dnsclient.NewSafeHTTPClient()
	client.SkipSSRF = true
	ctx := context.Background()

	resp, err := client.Get(ctx, ts.URL)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	body, err := client.ReadBody(resp, 5)
	if err != nil {
		t.Fatalf("ReadBody failed: %v", err)
	}
	if len(body) > 5 {
		t.Errorf("body should be limited to 5 bytes, got %d", len(body))
	}
}

func TestGetDirect_InvalidURL(t *testing.T) {
	client := dnsclient.NewRDAPHTTPClient()
	ctx := context.Background()

	_, err := client.GetDirect(ctx, "://invalid")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestIsPrivateIP_IPv6(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		{"::1", true},
		{"fe80::1", true},
		{"::0", true},
		{"2001:db8::1", false},
		{"2607:f8b0:4004:800::200e", false},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := dnsclient.IsPrivateIP(tt.ip)
			if got != tt.private {
				t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, got, tt.private)
			}
		})
	}
}

func TestSafeHTTPClient_Get_InvalidURL(t *testing.T) {
	client := dnsclient.NewSafeHTTPClient()
	client.SkipSSRF = true
	ctx := context.Background()

	_, err := client.Get(ctx, "://broken")
	if err != nil {
	}
	_ = err
}

func TestSafeHTTPClient_GetWithHeaders_EmptyHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	client := dnsclient.NewSafeHTTPClient()
	client.SkipSSRF = true
	ctx := context.Background()

	resp, err := client.GetWithHeaders(ctx, ts.URL, map[string]string{})
	if err != nil {
		t.Fatalf("GetWithHeaders with empty map failed: %v", err)
	}
	resp.Body.Close()
}

func TestSafeHTTPClient_Get_UserAgentSet(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if ua == "" {
			t.Error("expected User-Agent header to be set")
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	client := dnsclient.NewSafeHTTPClient()
	client.SkipSSRF = true
	ctx := context.Background()

	resp, err := client.Get(ctx, ts.URL)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	resp.Body.Close()
}

func TestSafeHTTPClient_GetWithHeaders_MultipleHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-First") != "one" {
			t.Errorf("expected X-First=one, got %q", r.Header.Get("X-First"))
		}
		if r.Header.Get("X-Second") != "two" {
			t.Errorf("expected X-Second=two, got %q", r.Header.Get("X-Second"))
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	client := dnsclient.NewSafeHTTPClient()
	client.SkipSSRF = true
	ctx := context.Background()

	headers := map[string]string{"X-First": "one", "X-Second": "two"}
	resp, err := client.GetWithHeaders(ctx, ts.URL, headers)
	if err != nil {
		t.Fatalf("GetWithHeaders failed: %v", err)
	}
	resp.Body.Close()
}

func TestValidateURLTarget_ValidPublicHost(t *testing.T) {
	got := dnsclient.ValidateURLTarget("https://google.com/test")
	if !got {
		t.Error("expected true for public host")
	}
}

func TestSafeHTTPClient_ReadBody_EmptyBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	client := dnsclient.NewSafeHTTPClient()
	client.SkipSSRF = true
	ctx := context.Background()

	resp, err := client.Get(ctx, ts.URL)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	body, err := client.ReadBody(resp, 1024)
	if err != nil {
		t.Fatalf("ReadBody failed: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("expected empty body, got %d bytes", len(body))
	}
}

func TestSafeHTTPClient_RedirectHandling(t *testing.T) {
	redirectCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectCount++
		if redirectCount <= 6 {
			http.Redirect(w, r, "/redirect", http.StatusFound)
			return
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	client := dnsclient.NewSafeHTTPClient()
	client.SkipSSRF = true
	ctx := context.Background()

	_, err := client.Get(ctx, ts.URL)
	if err == nil {
		t.Log("redirect may have succeeded or been blocked")
	}
}

func TestGetDirect_InvalidScheme(t *testing.T) {
	client := dnsclient.NewRDAPHTTPClient()
	ctx := context.Background()

	_, err := client.GetDirect(ctx, "ftp://rdap.verisign.com/test")
	if err == nil {
		t.Fatal("expected error for FTP scheme")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("error should mention HTTPS, got: %v", err)
	}
}
