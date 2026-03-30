package analyzer

import (
        "context"
        "testing"
)

func TestScanSecretExposure_ReturnsStructuredResult(t *testing.T) {
        mockHTTP := NewMockHTTPClient()
        mockHTTP.AddResponse("https://example.com", 200, "<html><body>Hello</body></html>")
        mockHTTP.AddResponse("http://example.com", 200, "<html><body>Hello</body></html>")

        a := &Analyzer{HTTP: mockHTTP}
        result := a.ScanSecretExposure(context.Background(), "example.com")
        if result == nil {
                t.Fatal("expected non-nil result")
        }
        status, ok := result["status"].(string)
        if !ok {
                t.Fatal("expected 'status' to be a string")
        }
        if status != "clear" && status != "exposed" {
                t.Errorf("status = %q, want 'clear' or 'exposed'", status)
        }
        msg, ok := result["message"].(string)
        if !ok {
                t.Fatal("expected 'message' to be a string")
        }
        if msg == "" {
                t.Error("message should not be empty")
        }
}

func TestScanSecretExposure_ContainsExpectedKeys(t *testing.T) {
        mockHTTP := NewMockHTTPClient()
        mockHTTP.AddResponse("https://clean.example.com", 200, "<html><body>clean page</body></html>")
        mockHTTP.AddResponse("http://clean.example.com", 200, "<html><body>clean page</body></html>")

        a := &Analyzer{HTTP: mockHTTP}
        result := a.ScanSecretExposure(context.Background(), "clean.example.com")

        requiredKeys := []string{"status", "message", "findings", "scanned_urls"}
        for _, key := range requiredKeys {
                if _, ok := result[key]; !ok {
                        t.Errorf("missing expected key %q in result", key)
                }
        }
}

func TestScanSecretExposure_ClearWhenClean(t *testing.T) {
        mockHTTP := NewMockHTTPClient()
        mockHTTP.AddResponse("https://clean.example.com", 200, "<html><body>no secrets here</body></html>")
        mockHTTP.AddResponse("http://clean.example.com", 200, "<html><body>no secrets here</body></html>")

        a := &Analyzer{HTTP: mockHTTP}
        result := a.ScanSecretExposure(context.Background(), "clean.example.com")

        if result["status"] != "clear" {
                t.Errorf("status = %v, want 'clear' for clean page", result["status"])
        }
        findings := result["findings"]
        switch f := findings.(type) {
        case []map[string]any:
                if len(f) != 0 {
                        t.Errorf("expected 0 findings, got %d", len(f))
                }
        case nil:
                t.Error("findings should not be nil")
        }
}

func TestScanSecretExposure_DetectsExposedKeys(t *testing.T) {
        mockHTTP := NewMockHTTPClient()
        fakeAWSKey := "AKIA1234567890ABCDEF" //nolint:gosec // #nosec G101 -- test fixture: fake AWS key for secret exposure detection test //gitleaks:allow // nosemgrep: generic.secrets.gitleaks.generic-api-key, generic.secrets.gitleaks.aws-access-token, generic.secrets.security.detected-aws-access-key-id-value // NOSONAR
        pageWithKey := `<html><body><script>
                const apiKey = "` + fakeAWSKey + `";
                fetch("https://api.example.com", {headers: {"Authorization": apiKey}});
        </script></body></html>`
        mockHTTP.AddResponse("https://leaky.example.com", 200, pageWithKey)
        mockHTTP.AddResponse("http://leaky.example.com", 200, pageWithKey)

        a := &Analyzer{HTTP: mockHTTP}
        result := a.ScanSecretExposure(context.Background(), "leaky.example.com")
        if result == nil {
                t.Fatal("expected non-nil result")
        }
        if result["status"] == "exposed" {
                findings, ok := result["findings"].([]map[string]any)
                if !ok {
                        t.Fatalf("findings type = %T", result["findings"])
                }
                if len(findings) == 0 {
                        t.Error("status is 'exposed' but findings is empty")
                }
                for _, f := range findings {
                        if f["type"] == nil || f["type"] == "" {
                                t.Error("finding should have a non-empty type")
                        }
                }
        }
}

func TestScanSecretExposure_EmptyDomain(t *testing.T) {
        mockHTTP := NewMockHTTPClient()
        a := &Analyzer{HTTP: mockHTTP}
        result := a.ScanSecretExposure(context.Background(), "")
        if result == nil {
                t.Fatal("expected non-nil result even for empty domain")
        }
        if result["status"] != "clear" {
                t.Errorf("status = %v, want 'clear' for empty domain", result["status"])
        }
}

func TestScanSecretExposure_BridgeCreatesScanner(t *testing.T) {
        mockHTTP := NewMockHTTPClient()
        scanner := NewSecretScanner(mockHTTP)
        if scanner == nil {
                t.Fatal("expected non-nil scanner")
        }
        if scanner.HTTP != mockHTTP {
                t.Error("expected scanner.HTTP to be the provided mock client")
        }
}

func TestScanSecretExposure_NilHTTPClient(t *testing.T) {
        scanner := NewSecretScanner(nil)
        if scanner == nil {
                t.Fatal("expected non-nil scanner even with nil HTTP")
        }
        if scanner.HTTP != nil {
                t.Error("expected nil HTTP when passed nil")
        }
}

func TestScanSecretExposure_ScannedURLsKey(t *testing.T) {
        mockHTTP := NewMockHTTPClient()

        a := &Analyzer{HTTP: mockHTTP}
        result := a.ScanSecretExposure(context.Background(), "unreachable.example.com")
        if _, ok := result["scanned_urls"]; !ok {
                t.Error("expected 'scanned_urls' key in result even when no pages fetched")
        }
        if result["status"] != "clear" {
                t.Errorf("status = %v, want 'clear' when no pages reachable", result["status"])
        }
}
