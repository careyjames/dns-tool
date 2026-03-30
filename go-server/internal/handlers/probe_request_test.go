package handlers

import (
        "encoding/json"
        "net/http"
        "net/http/httptest"
        "testing"

        "dnstool/go-server/internal/config"
)

func TestExecuteProbeRequest_Success_CB19(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                if r.Header.Get("X-Probe-Key") != "test-key" {
                        t.Error("missing probe key header")
                }
                w.Header().Set("Content-Type", "application/json")
                json.NewEncoder(w).Encode(map[string]any{"open": true, "latency_ms": 42})
        }))
        defer srv.Close()

        h := &ToolkitHandler{Config: &config.Config{}}
        pc := probeConfig{url: srv.URL, key: "test-key", label: "Test"}
        result, errMsg := h.executeProbeRequest(pc, "example.com", "443")
        if errMsg != "" {
                t.Fatalf("unexpected error: %s", errMsg)
        }
        if result == nil {
                t.Fatal("expected non-nil result")
        }
        if _, ok := result["open"]; !ok {
                t.Error("expected 'open' field in result")
        }
}

func TestExecuteProbeRequest_ServerError_CB19(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusInternalServerError)
                w.Write([]byte("internal error"))
        }))
        defer srv.Close()

        h := &ToolkitHandler{Config: &config.Config{}}
        pc := probeConfig{url: srv.URL, key: "k", label: "T"}
        result, errMsg := h.executeProbeRequest(pc, "example.com", "80")
        if result != nil {
                t.Error("expected nil result on server error")
        }
        if errMsg == "" {
                t.Error("expected error message on server error")
        }
}

func TestExecuteProbeRequest_InvalidJSON_CB19(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set("Content-Type", "application/json")
                w.Write([]byte("not json"))
        }))
        defer srv.Close()

        h := &ToolkitHandler{Config: &config.Config{}}
        pc := probeConfig{url: srv.URL, key: "k", label: "T"}
        result, errMsg := h.executeProbeRequest(pc, "example.com", "80")
        if result != nil {
                t.Error("expected nil result on invalid JSON")
        }
        if errMsg == "" {
                t.Error("expected error message on invalid JSON")
        }
}

func TestExecuteProbeRequest_ConnectionRefused_CB19(t *testing.T) {
        h := &ToolkitHandler{Config: &config.Config{}}
        pc := probeConfig{url: "http://127.0.0.1:1", key: "k", label: "T"}
        result, errMsg := h.executeProbeRequest(pc, "example.com", "80")
        if result != nil {
                t.Error("expected nil result on connection refused")
        }
        if errMsg == "" {
                t.Error("expected error message on connection refused")
        }
}

func TestExecuteProbeRequest_BadURL_CB19(t *testing.T) {
        h := &ToolkitHandler{Config: &config.Config{}}
        pc := probeConfig{url: "://invalid", key: "k", label: "T"}
        result, errMsg := h.executeProbeRequest(pc, "example.com", "80")
        if result != nil {
                t.Error("expected nil result on bad URL")
        }
        if errMsg == "" {
                t.Error("expected error message on bad URL")
        }
}
