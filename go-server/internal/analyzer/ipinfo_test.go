package analyzer

import (
        "context"
        "encoding/json"
        "net/http"
        "net/http/httptest"
        "strings"
        "sync"
        "testing"
)

type testRoundTripper struct {
        handler http.Handler
}

func (t *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
        w := httptest.NewRecorder()
        t.handler.ServeHTTP(w, req)
        return w.Result(), nil
}

func TestFetchIPInfo_EmptyToken(t *testing.T) {
        result, err := FetchIPInfo(context.Background(), "1.2.3.4", "")
        if err != nil {
                t.Errorf("unexpected error: %v", err)
        }
        if result != nil {
                t.Error("expected nil result for empty token")
        }
}

func TestFetchIPInfo_Success(t *testing.T) {
        expected := IPInfoResult{
                IP:       "8.8.8.8",
                Hostname: "dns.google",
                City:     "Mountain View",
                Region:   "California",
                Country:  "US",
                Org:      "AS15169 Google LLC",
        }

        var called bool
        handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                called = true
                if !strings.Contains(r.URL.Path, "8.8.8.8") {
                        t.Errorf("unexpected path: %s", r.URL.Path)
                }
                if r.Header.Get("Accept") != "application/json" {
                        t.Error("expected Accept: application/json header")
                }
                json.NewEncoder(w).Encode(expected)
        })

        origClient := ipInfoHTTPClient
        ipInfoHTTPClient = &http.Client{Transport: &testRoundTripper{handler: handler}}
        defer func() { ipInfoHTTPClient = origClient }()

        ipInfoCacheMu.Lock()
        delete(ipInfoCache, "8.8.8.8")
        ipInfoCacheMu.Unlock()

        result, err := FetchIPInfo(context.Background(), "8.8.8.8", "testtoken")
        if err != nil {
                t.Fatalf("unexpected error: %v", err)
        }
        if !called {
                t.Fatal("handler was never called")
        }
        if result == nil {
                t.Fatal("expected non-nil result")
        }
        if result.IP != expected.IP {
                t.Errorf("IP = %q, want %q", result.IP, expected.IP)
        }
        if result.Hostname != expected.Hostname {
                t.Errorf("Hostname = %q, want %q", result.Hostname, expected.Hostname)
        }
        if result.City != expected.City {
                t.Errorf("City = %q, want %q", result.City, expected.City)
        }
        if result.Org != expected.Org {
                t.Errorf("Org = %q, want %q", result.Org, expected.Org)
        }
}

func TestFetchIPInfo_CacheHit(t *testing.T) {
        expected := &IPInfoResult{
                IP:   "9.9.9.9",
                City: "Cached City",
        }
        var called bool
        handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                called = true
                json.NewEncoder(w).Encode(expected)
        })

        origClient := ipInfoHTTPClient
        ipInfoHTTPClient = &http.Client{Transport: &testRoundTripper{handler: handler}}
        defer func() { ipInfoHTTPClient = origClient }()

        ipInfoCacheMu.Lock()
        delete(ipInfoCache, "9.9.9.9")
        ipInfoCacheMu.Unlock()

        result1, err := FetchIPInfo(context.Background(), "9.9.9.9", "testtoken")
        if err != nil {
                t.Fatalf("first call error: %v", err)
        }
        if !called {
                t.Fatal("handler should be called on first request")
        }
        if result1 == nil {
                t.Fatal("expected non-nil result on first call")
        }

        called = false
        result2, err := FetchIPInfo(context.Background(), "9.9.9.9", "testtoken")
        if err != nil {
                t.Fatalf("second call error: %v", err)
        }
        if called {
                t.Error("handler should NOT be called on cached request")
        }
        if result2 == nil {
                t.Fatal("expected non-nil result from cache")
        }
        if result2.City != "Cached City" {
                t.Errorf("cached City = %q, want 'Cached City'", result2.City)
        }

        ipInfoCacheMu.Lock()
        delete(ipInfoCache, "9.9.9.9")
        ipInfoCacheMu.Unlock()
}

func TestFetchIPInfo_RateLimit(t *testing.T) {
        handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusTooManyRequests)
        })

        origClient := ipInfoHTTPClient
        ipInfoHTTPClient = &http.Client{Transport: &testRoundTripper{handler: handler}}
        defer func() { ipInfoHTTPClient = origClient }()

        ipInfoCacheMu.Lock()
        delete(ipInfoCache, "rate-limited-ip")
        ipInfoCacheMu.Unlock()

        result, err := FetchIPInfo(context.Background(), "rate-limited-ip", "testtoken")
        if err == nil {
                t.Error("expected error for 429 response")
        }
        if result != nil {
                t.Error("expected nil result for 429")
        }
}

func TestFetchIPInfo_Forbidden(t *testing.T) {
        handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusForbidden)
        })

        origClient := ipInfoHTTPClient
        ipInfoHTTPClient = &http.Client{Transport: &testRoundTripper{handler: handler}}
        defer func() { ipInfoHTTPClient = origClient }()

        ipInfoCacheMu.Lock()
        delete(ipInfoCache, "forbidden-ip")
        ipInfoCacheMu.Unlock()

        result, err := FetchIPInfo(context.Background(), "forbidden-ip", "badtoken")
        if err == nil {
                t.Error("expected error for 403 response")
        }
        if result != nil {
                t.Error("expected nil result for 403")
        }
}

func TestFetchIPInfo_ServerError(t *testing.T) {
        handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusInternalServerError)
        })

        origClient := ipInfoHTTPClient
        ipInfoHTTPClient = &http.Client{Transport: &testRoundTripper{handler: handler}}
        defer func() { ipInfoHTTPClient = origClient }()

        ipInfoCacheMu.Lock()
        delete(ipInfoCache, "server-error-ip")
        ipInfoCacheMu.Unlock()

        result, err := FetchIPInfo(context.Background(), "server-error-ip", "testtoken")
        if err == nil {
                t.Error("expected error for 500 response")
        }
        if result != nil {
                t.Error("expected nil result for 500")
        }
}

func TestFetchIPInfo_InvalidJSON(t *testing.T) {
        handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.Write([]byte("{invalid json}"))
        })

        origClient := ipInfoHTTPClient
        ipInfoHTTPClient = &http.Client{Transport: &testRoundTripper{handler: handler}}
        defer func() { ipInfoHTTPClient = origClient }()

        ipInfoCacheMu.Lock()
        delete(ipInfoCache, "bad-json-ip")
        ipInfoCacheMu.Unlock()

        _, err := FetchIPInfo(context.Background(), "bad-json-ip", "testtoken")
        if err == nil {
                t.Error("expected error for invalid JSON response")
        }
}

func TestFetchIPInfo_ConcurrentAccess(t *testing.T) {
        handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                json.NewEncoder(w).Encode(IPInfoResult{IP: "concurrent-ip", City: "Test"})
        })

        origClient := ipInfoHTTPClient
        ipInfoHTTPClient = &http.Client{Transport: &testRoundTripper{handler: handler}}
        defer func() { ipInfoHTTPClient = origClient }()

        ipInfoCacheMu.Lock()
        delete(ipInfoCache, "concurrent-ip")
        ipInfoCacheMu.Unlock()

        var wg sync.WaitGroup
        for i := 0; i < 10; i++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        result, err := FetchIPInfo(context.Background(), "concurrent-ip", "testtoken")
                        if err != nil {
                                t.Errorf("concurrent call error: %v", err)
                        }
                        if result == nil {
                                t.Error("expected non-nil result in concurrent call")
                        }
                }()
        }
        wg.Wait()

        ipInfoCacheMu.Lock()
        delete(ipInfoCache, "concurrent-ip")
        ipInfoCacheMu.Unlock()
}

func TestIPInfoCacheTTL(t *testing.T) {
        if ipInfoCacheTTL <= 0 {
                t.Error("ipInfoCacheTTL should be positive")
        }
}
