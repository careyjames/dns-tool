package handlers

import (
        "encoding/json"
        "net/http"
        "net/http/httptest"
        "os"
        "strings"
        "testing"
)

func TestConfiguredProbes_NoEnv(t *testing.T) {
        os.Unsetenv("PROBE_API_URL")
        os.Unsetenv("PROBE_API_URL_2")
        h := &ProbeAdminHandler{}
        probes := h.configuredProbes()
        if len(probes) != 0 {
                t.Errorf("expected 0 probes with no env, got %d", len(probes))
        }
}

func TestConfiguredProbes_SingleProbe(t *testing.T) {
        t.Setenv("PROBE_API_URL", "https://probe1.example.com")
        t.Setenv("PROBE_LABEL", "Test Probe 1")
        os.Unsetenv("PROBE_API_URL_2")
        h := &ProbeAdminHandler{}
        probes := h.configuredProbes()
        if len(probes) != 1 {
                t.Fatalf("expected 1 probe, got %d", len(probes))
        }
        if probes[0].ID != "probe-01" {
                t.Errorf("expected probe-01, got %s", probes[0].ID)
        }
        if probes[0].Label != "Test Probe 1" {
                t.Errorf("expected label 'Test Probe 1', got %s", probes[0].Label)
        }
}

func TestConfiguredProbes_DefaultLabels(t *testing.T) {
        t.Setenv("PROBE_API_URL", "https://probe1.example.com")
        os.Unsetenv("PROBE_LABEL")
        t.Setenv("PROBE_API_URL_2", "https://probe2.example.com")
        os.Unsetenv("PROBE_LABEL_2")
        h := &ProbeAdminHandler{}
        probes := h.configuredProbes()
        if len(probes) != 2 {
                t.Fatalf("expected 2 probes, got %d", len(probes))
        }
        if probes[0].Label != "US-East (Boston)" {
                t.Errorf("expected default label for probe-01, got %s", probes[0].Label)
        }
        if probes[1].Label != "US-East (Kali/02)" {
                t.Errorf("expected default label for probe-02, got %s", probes[1].Label)
        }
}

func TestConfiguredProbes_BothProbes(t *testing.T) {
        t.Setenv("PROBE_API_URL", "https://probe1.example.com")
        t.Setenv("PROBE_LABEL", "Boston")
        t.Setenv("PROBE_API_URL_2", "https://probe2.example.com")
        t.Setenv("PROBE_LABEL_2", "Kali")
        h := &ProbeAdminHandler{}
        probes := h.configuredProbes()
        if len(probes) != 2 {
                t.Fatalf("expected 2 probes, got %d", len(probes))
        }
        if probes[1].ID != "probe-02" {
                t.Errorf("expected probe-02, got %s", probes[1].ID)
        }
}

func TestCheckProbeHealth_Success(t *testing.T) {
        server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                if r.URL.Path != "/health" {
                        t.Errorf("unexpected path: %s", r.URL.Path)
                }
                w.WriteHeader(http.StatusOK)
                json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
        }))
        defer server.Close()

        p := probeInfo{ID: "probe-test", Label: "Test", URL: server.URL}
        result := checkProbeHealth(p)
        if !result.Success {
                t.Errorf("expected success, got failure: %s", result.Output)
        }
        if result.Action != "health" {
                t.Errorf("expected action 'health', got %s", result.Action)
        }
        if result.Elapsed <= 0 {
                t.Error("expected positive elapsed time")
        }
}

func TestCheckProbeHealth_ServerDown(t *testing.T) {
        p := probeInfo{ID: "probe-down", Label: "Down", URL: "http://127.0.0.1:1"}
        result := checkProbeHealth(p)
        if result.Success {
                t.Error("expected failure for unreachable server")
        }
        if !strings.Contains(result.Output, "Connection failed") {
                t.Errorf("expected connection failure message, got: %s", result.Output)
        }
}

func TestCheckProbeHealth_ServerError(t *testing.T) {
        server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusInternalServerError)
                w.Write([]byte("internal error"))
        }))
        defer server.Close()

        p := probeInfo{ID: "probe-err", Label: "Error", URL: server.URL}
        result := checkProbeHealth(p)
        if result.Success {
                t.Error("expected failure for 500 response")
        }
}

func TestCheckProbeHealth_InvalidJSON(t *testing.T) {
        server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusOK)
                w.Write([]byte("not json"))
        }))
        defer server.Close()

        p := probeInfo{ID: "probe-bad", Label: "Bad", URL: server.URL}
        result := checkProbeHealth(p)
        if !result.Success {
                t.Error("expected success for 200 even with non-JSON body")
        }
}

func TestResolveProbeSSH_MissingCredentials(t *testing.T) {
        os.Unsetenv("PROBE_SSH_HOST")
        os.Unsetenv("PROBE_SSH_USER")
        os.Unsetenv("PROBE_SSH_PRIVATE_KEY")

        _, err := resolveProbeSSH("probe-01")
        if err == nil {
                t.Error("expected error for missing probe-01 credentials")
        }
        if !strings.Contains(err.Error(), "not configured") {
                t.Errorf("expected 'not configured' error, got: %v", err)
        }
}

func TestResolveProbeSSH_MissingProbe02Credentials(t *testing.T) {
        os.Unsetenv("PROBE_SSH_HOST_2")
        os.Unsetenv("PROBE2_SSH_USER")
        os.Unsetenv("PROBE_SSH_PRIVATE_KEY_2")

        _, err := resolveProbeSSH("probe-02")
        if err == nil {
                t.Error("expected error for missing probe-02 credentials")
        }
}

func TestResolveProbeSSH_UnknownProbe(t *testing.T) {
        _, err := resolveProbeSSH("probe-99")
        if err == nil {
                t.Error("expected error for unknown probe")
        }
        if !strings.Contains(err.Error(), "unknown probe") {
                t.Errorf("expected 'unknown probe' error, got: %v", err)
        }
}

func TestParseSSHKey_Base64(t *testing.T) {
        key := "LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFNd0FBQUF0emMyZ3RaVwpReU5UVXhPUUFBQUNEZEF2K25LK1FPSDBPMnFtNkI5YnFkNFNZS2lJaWFNV2dJTzhjbXkzSjYrUUFBQUppb1VISGNxRkJ4CjNBQUFBQXR6YzJndFpXUXlOVFV4T1FBQUFDRGRBdituSytRT0gwTzJxbTZCOWJxZDRTWUtpSWlhTVdnSU84Y215M0o2K1EKQUFBRUQ0Z1N5MHZBU3FHTzNqVTRUNS9zaGowMHBaMVFOQ3B3My95MzNFN0RkTzB0MEMvNmNyNUE0ZlE3YXFib0gxdXAzaApKZ3FJaUpveGFBZzd4eWJMY25yNUFBQUFFM0oxYm01bGNrQXhPRE0yWTJFMllUQXpZMk1CQWc9PQotLS0tLUVORCBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K" //nolint:gosec // gitleaks:allow // test fixture: throwaway ed25519 key for parseSSHKey unit test
        signer, err := parseSSHKey(key, "test")
        if err != nil {
                t.Fatalf("unexpected error: %v", err)
        }
        if signer == nil {
                t.Error("expected non-nil signer")
        }
}

func TestParseSSHKey_InvalidKey(t *testing.T) {
        _, err := parseSSHKey("not-base64-and-not-pem!!!", "test-bad")
        if err == nil {
                t.Error("expected error for invalid key data")
        }
}

func TestNormalizePEM_SpaceDelimited(t *testing.T) {
        input := "-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXktdjE AAAA -----END OPENSSH PRIVATE KEY-----"
        out := normalizePEM(input)
        if !strings.HasPrefix(out, "-----BEGIN OPENSSH PRIVATE KEY-----\n") {
                t.Errorf("expected header with newline, got: %q", out[:60])
        }
        if !strings.Contains(out, "-----END OPENSSH PRIVATE KEY-----") {
                t.Error("expected footer in output")
        }
        if strings.Count(out, "\n") < 3 {
                t.Errorf("expected at least 3 newlines, got %d", strings.Count(out, "\n"))
        }
}

func TestNormalizePEM_AlreadyValid(t *testing.T) {
        input := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE=\n-----END OPENSSH PRIVATE KEY-----\n"
        out := normalizePEM(input)
        if out != input {
                t.Errorf("expected unchanged output for valid PEM")
        }
}

func TestProbeScripts(t *testing.T) {
        tests := []struct {
                name   string
                fn     func() string
                expect string
        }{
                {"update", probeUpdateScript, "Starting system update"},
                {"restart", probeRestartScript, "Restarting dns-probe"},
                {"audit", probeAuditScript, "Security Audit"},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        script := tt.fn()
                        if script == "" {
                                t.Error("expected non-empty script")
                        }
                        if !strings.Contains(script, tt.expect) {
                                t.Errorf("expected script to contain %q", tt.expect)
                        }
                })
        }
}

func TestRunProbeSSH_MissingConfig(t *testing.T) {
        os.Unsetenv("PROBE_SSH_HOST")
        os.Unsetenv("PROBE_SSH_USER")
        os.Unsetenv("PROBE_SSH_PRIVATE_KEY")

        p := probeInfo{ID: "probe-01", Label: "Test", URL: "https://example.com"}
        result := runProbeSSH(p, "audit")
        if result.Success {
                t.Error("expected failure when SSH config is missing")
        }
        if !strings.Contains(result.Output, "SSH config error") {
                t.Errorf("expected SSH config error, got: %s", result.Output)
        }
}

func TestRunProbeSSH_UnknownAction(t *testing.T) {
        t.Setenv("PROBE_SSH_HOST", "example.com")
        t.Setenv("PROBE_SSH_USER", "root")
        t.Setenv("PROBE_SSH_PRIVATE_KEY", "LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFNd0FBQUF0emMyZ3RaVwpReU5UVXhPUUFBQUNEZEF2K25LK1FPSDBPMnFtNkI5YnFkNFNZS2lJaWFNV2dJTzhjbXkzSjYrUUFBQUppb1VISGNxRkJ4CjNBQUFBQXR6YzJndFpXUXlOVFV4T1FBQUFDRGRBdituSytRT0gwTzJxbTZCOWJxZDRTWUtpSWlhTVdnSU84Y215M0o2K1EKQUFBRUQ0Z1N5MHZBU3FHTzNqVTRUNS9zaGowMHBaMVFOQ3B3My95MzNFN0RkTzB0MEMvNmNyNUE0ZlE3YXFib0gxdXAzaApKZ3FJaUpveGFBZzd4eWJMY25yNUFBQUFFM0oxYm01bGNrQXhPRE0yWTJFMllUQXpZMk1CQWc9PQotLS0tLUVORCBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K") //nolint:gosec // gitleaks:allow // test fixture: throwaway ed25519 key

        p := probeInfo{ID: "probe-01", Label: "Test", URL: "https://example.com"}
        result := runProbeSSH(p, "unknown-action")
        if result.Success {
                t.Error("expected failure for unknown action")
        }
        if !strings.Contains(result.Output, "Unknown action") {
                t.Errorf("expected 'Unknown action' message, got: %s", result.Output)
        }
}

func TestProbeInfoStruct(t *testing.T) {
        p := probeInfo{ID: "probe-01", Label: "Test", URL: "https://test.com"}
        if p.ID != "probe-01" {
                t.Errorf("unexpected ID: %s", p.ID)
        }
        if p.Label != "Test" {
                t.Errorf("unexpected Label: %s", p.Label)
        }
        if p.URL != "https://test.com" {
                t.Errorf("unexpected URL: %s", p.URL)
        }
}

func TestProbeActionResult_Fields(t *testing.T) {
        r := probeActionResult{
                Probe:   probeInfo{ID: "probe-01"},
                Action:  "health",
                Success: true,
                Output:  "ok",
                Elapsed: 1.5,
        }
        if r.Probe.ID != "probe-01" {
                t.Errorf("unexpected probe ID: %s", r.Probe.ID)
        }
        if r.Elapsed != 1.5 {
                t.Errorf("unexpected elapsed: %f", r.Elapsed)
        }
}
