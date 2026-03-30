package handlers

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"testing"
)

func TestValidateParsedURL(t *testing.T) {
	t.Run("valid HTTPS", func(t *testing.T) {
		u, _ := url.Parse("https://example.com/logo.svg")
		if err := validateParsedURL(u); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("HTTP rejected", func(t *testing.T) {
		u, _ := url.Parse("http://example.com/logo.svg")
		err := validateParsedURL(u)
		if err == nil {
			t.Fatal("expected error for HTTP")
		}
		if err.Error() != "Only HTTPS URLs allowed" {
			t.Errorf("error = %q", err.Error())
		}
	})

	t.Run("FTP rejected", func(t *testing.T) {
		u, _ := url.Parse("ftp://example.com/logo.svg")
		err := validateParsedURL(u)
		if err == nil {
			t.Fatal("expected error for FTP")
		}
	})

	t.Run("empty hostname rejected", func(t *testing.T) {
		u := &url.URL{Scheme: "https", Host: ""}
		err := validateParsedURL(u)
		if err == nil {
			t.Fatal("expected error for empty hostname")
		}
		if err.Error() != "Invalid URL" {
			t.Errorf("error = %q", err.Error())
		}
	})
}

func TestBuildSafeURL(t *testing.T) {
	t.Run("preserves host path query", func(t *testing.T) {
		u, _ := url.Parse("https://cdn.example.com/images/logo.svg?v=2")
		safe := buildSafeURL(u)
		if safe != "https://cdn.example.com/images/logo.svg?v=2" {
			t.Errorf("safe = %q", safe)
		}
	})

	t.Run("forces HTTPS scheme", func(t *testing.T) {
		u, _ := url.Parse("http://example.com/test")
		safe := buildSafeURL(u)
		parsed, _ := url.Parse(safe)
		if parsed.Scheme != "https" {
			t.Errorf("scheme = %q, want https", parsed.Scheme)
		}
	})

	t.Run("preserves fragment", func(t *testing.T) {
		u := &url.URL{
			Scheme:   "https",
			Host:     "example.com",
			Path:     "/path",
			Fragment: "frag",
		}
		safe := buildSafeURL(u)
		if safe != "https://example.com/path#frag" {
			t.Errorf("safe = %q", safe)
		}
	})

	t.Run("strips userinfo", func(t *testing.T) {
		u, _ := url.Parse("https://user:pass@example.com/logo.svg")
		safe := buildSafeURL(u)
		parsed, _ := url.Parse(safe)
		if parsed.User != nil {
			t.Error("expected userinfo to be stripped")
		}
	})
}

func TestValidateBIMIResponse(t *testing.T) {
	t.Run("non-200 status", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 404,
			Header:     http.Header{},
			Body:       io.NopCloser(bytes.NewReader(nil)),
		}
		_, _, err := validateBIMIResponse(resp)
		if err == nil {
			t.Fatal("expected error for 404")
		}
		fe, ok := err.(*bimiFetchError)
		if !ok {
			t.Fatalf("expected bimiFetchError, got %T", err)
		}
		if fe.status != http.StatusBadGateway {
			t.Errorf("status = %d", fe.status)
		}
	})

	t.Run("non-image content type", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": {"text/html"}},
			Body:       io.NopCloser(bytes.NewReader([]byte("hello"))),
		}
		_, _, err := validateBIMIResponse(resp)
		if err == nil {
			t.Fatal("expected error for text/html")
		}
	})

	t.Run("valid SVG response", func(t *testing.T) {
		svgData := []byte("<svg></svg>")
		resp := &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": {"image/svg+xml"}},
			Body:       io.NopCloser(bytes.NewReader(svgData)),
		}
		body, ct, err := validateBIMIResponse(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ct != "image/svg+xml" {
			t.Errorf("content-type = %q", ct)
		}
		if string(body) != "<svg></svg>" {
			t.Errorf("body = %q", string(body))
		}
	})

	t.Run("valid PNG response", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": {"image/png; charset=utf-8"}},
			Body:       io.NopCloser(bytes.NewReader([]byte("PNG data"))),
		}
		_, ct, err := validateBIMIResponse(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ct != "image/png" {
			t.Errorf("content-type = %q", ct)
		}
	})

	t.Run("unknown image type defaults to SVG", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": {"image/bmp"}},
			Body:       io.NopCloser(bytes.NewReader([]byte("bmp data"))),
		}
		_, ct, err := validateBIMIResponse(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ct != "image/svg+xml" {
			t.Errorf("content-type = %q, want image/svg+xml", ct)
		}
	})

	t.Run("response too large", func(t *testing.T) {
		bigData := make([]byte, bimiMaxResponseBytes+10)
		resp := &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": {"image/svg+xml"}},
			Body:       io.NopCloser(bytes.NewReader(bigData)),
		}
		_, _, err := validateBIMIResponse(resp)
		if err == nil {
			t.Fatal("expected error for oversized response")
		}
	})
}

func TestValidationErrorType(t *testing.T) {
	e := &validationError{msg: "test error"}
	if e.Error() != "test error" {
		t.Errorf("Error() = %q", e.Error())
	}
}

func TestBimiFetchErrorType(t *testing.T) {
	e := &bimiFetchError{status: 502, msg: "bad gateway"}
	if e.Error() != "bad gateway" {
		t.Errorf("Error() = %q", e.Error())
	}
	if e.status != 502 {
		t.Errorf("status = %d", e.status)
	}
}

func TestNewProxyHandler(t *testing.T) {
	h := NewProxyHandler()
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestBimiAllowedContentTypes(t *testing.T) {
	allowed := []string{"image/svg+xml", "image/png", "image/jpeg", "image/gif", "image/webp"}
	for _, ct := range allowed {
		if !bimiAllowedContentTypes[ct] {
			t.Errorf("%q should be allowed", ct)
		}
	}
	if bimiAllowedContentTypes["text/html"] {
		t.Error("text/html should not be allowed")
	}
}
