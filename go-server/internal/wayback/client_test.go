package wayback

import (
        "context"
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"
)

func TestIsValidArchiveURL(t *testing.T) {
        tests := []struct {
                url   string
                valid bool
        }{
                {"https://web.archive.org/web/20260101/http://example.com", true},
                {"https://web.archive.org/", true},
                {"https://evil.com/web/20260101", false},
                {"http://web.archive.org/web/20260101", false},
                {"", false},
                {"https://web.archive.org", false},
        }
        for _, tt := range tests {
                if got := isValidArchiveURL(tt.url); got != tt.valid {
                        t.Errorf("isValidArchiveURL(%q) = %v, want %v", tt.url, got, tt.valid)
                }
        }
}

func TestArchiveResult_Fields(t *testing.T) {
        r := ArchiveResult{URL: "https://web.archive.org/web/20260101/http://example.com", Err: nil}
        if r.URL == "" {
                t.Error("expected non-empty URL")
        }
        if r.Err != nil {
                t.Errorf("expected nil Err, got %v", r.Err)
        }
}

func TestArchive_CancelledContext(t *testing.T) {
        ctx, cancel := context.WithCancel(context.Background())
        cancel()

        result := Archive(ctx, "http://example.com")
        if result.Err == nil {
                t.Fatal("expected error for cancelled context")
        }
}

func TestConstants(t *testing.T) {
        if saveEndpoint == "" {
                t.Error("saveEndpoint is empty")
        }
        if archivePrefix == "" {
                t.Error("archivePrefix is empty")
        }
        if userAgent == "" {
                t.Error("userAgent is empty")
        }
        if httpTimeout <= 0 {
                t.Error("httpTimeout is non-positive")
        }
}

func TestArchive_RedirectWithValidLocation(t *testing.T) {
        server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                if r.Header.Get("User-Agent") != userAgent {
                        t.Errorf("expected User-Agent %q, got %q", userAgent, r.Header.Get("User-Agent"))
                }
                w.Header().Set("Location", "https://web.archive.org/web/20260101/http://example.com")
                w.WriteHeader(http.StatusFound)
        }))
        defer server.Close()

        result := archiveWithEndpoint(context.Background(), server.URL+"/save/", "http://example.com")
        if result.Err != nil {
                t.Fatalf("unexpected error: %v", result.Err)
        }
        if !strings.HasPrefix(result.URL, "https://web.archive.org/") {
                t.Errorf("expected archive.org URL, got %q", result.URL)
        }
}

func TestArchive_RedirectWithInvalidLocation(t *testing.T) {
        server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set("Location", "https://evil.com/some/path")
                w.WriteHeader(http.StatusFound)
        }))
        defer server.Close()

        result := archiveWithEndpoint(context.Background(), server.URL+"/save/", "http://example.com")
        if result.Err == nil {
                t.Fatal("expected error for invalid redirect location")
        }
        if !strings.Contains(result.Err.Error(), "unexpected status") {
                t.Errorf("unexpected error message: %v", result.Err)
        }
}

func TestArchive_200OK(t *testing.T) {
        server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusOK)
                w.Write([]byte("archived"))
        }))
        defer server.Close()

        result := archiveWithEndpoint(context.Background(), server.URL+"/save/", "http://example.com")
        if result.Err != nil {
                t.Fatalf("unexpected error: %v", result.Err)
        }
        if !strings.Contains(result.URL, "web.archive.org/web/") {
                t.Errorf("expected constructed snapshot URL, got %q", result.URL)
        }
        if !strings.Contains(result.URL, "example.com") {
                t.Errorf("expected target URL in snapshot, got %q", result.URL)
        }
}

func TestArchive_ServerError(t *testing.T) {
        server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusInternalServerError)
        }))
        defer server.Close()

        result := archiveWithEndpoint(context.Background(), server.URL+"/save/", "http://example.com")
        if result.Err == nil {
                t.Fatal("expected error for 500 status")
        }
        if !strings.Contains(result.Err.Error(), "unexpected status 500") {
                t.Errorf("unexpected error message: %v", result.Err)
        }
}

func TestArchive_BadURL(t *testing.T) {
        result := archiveWithEndpoint(context.Background(), "://invalid-url", "http://example.com")
        if result.Err == nil {
                t.Fatal("expected error for invalid URL")
        }
        if !strings.Contains(result.Err.Error(), "build request") {
                t.Errorf("expected 'build request' error, got: %v", result.Err)
        }
}

func TestArchive_ConnectionRefused(t *testing.T) {
        result := archiveWithEndpoint(context.Background(), "http://127.0.0.1:1/save/", "http://example.com")
        if result.Err == nil {
                t.Fatal("expected error for connection refused")
        }
        if !strings.Contains(result.Err.Error(), "request failed") {
                t.Errorf("expected 'request failed' error, got: %v", result.Err)
        }
}

func TestArchive_EmptyLocationHeader(t *testing.T) {
        server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusFound)
        }))
        defer server.Close()

        result := archiveWithEndpoint(context.Background(), server.URL+"/save/", "http://example.com")
        if result.Err == nil {
                t.Fatal("expected error for redirect without location")
        }
}
