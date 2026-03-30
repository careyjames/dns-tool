// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "encoding/json"
        "fmt"
        "net/http"
        "net/http/httptest"
        "sync/atomic"
        "testing"
        "time"
)

func makeIPFSProbeServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
        t.Helper()
        return httptest.NewServer(handler)
}

func TestIPFSFleetProbe_NoProbesConfigured(t *testing.T) {
        a := &Analyzer{
                IPFSProbeMode: "remote",
                Probes:        nil,
        }
        result := a.RunIPFSFleetProbe(context.Background(), "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")
        if result != nil {
                t.Fatal("expected nil result when no probes configured")
        }
}

func TestIPFSFleetProbe_InvalidCID(t *testing.T) {
        a := &Analyzer{
                IPFSProbeMode: "remote",
                Probes:        []ProbeEndpoint{{ID: "test", URL: "http://localhost:9999", Key: "k"}},
        }
        result := a.RunIPFSFleetProbe(context.Background(), "not-a-valid-cid")
        if result != nil {
                t.Fatal("expected nil result for invalid CID")
        }
}

func TestIPFSFleetProbe_EmptyCID(t *testing.T) {
        a := &Analyzer{
                IPFSProbeMode: "remote",
                Probes:        []ProbeEndpoint{{ID: "test", URL: "http://localhost:9999", Key: "k"}},
        }
        result := a.RunIPFSFleetProbe(context.Background(), "")
        if result != nil {
                t.Fatal("expected nil result for empty CID")
        }
}

func TestIPFSFleetProbe_SingleProbeAllReachable(t *testing.T) {
        ts := makeIPFSProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
                var req IPFSFleetProbeRequest
                json.NewDecoder(r.Body).Decode(&req)
                results := make([]IPFSFleetGatewayResult, len(req.Gateways))
                for i, gw := range req.Gateways {
                        results[i] = IPFSFleetGatewayResult{
                                Gateway:      gw,
                                Reachable:    true,
                                StatusCode:   200,
                                ContentType:  "text/html",
                                LatencyMs:    42,
                                ServerHeader: "nginx",
                                TLSVersion:   "TLS 1.3",
                                FinalURL:     gw + "/ipfs/" + req.CID,
                        }
                }
                json.NewEncoder(w).Encode(IPFSFleetProbeResponse{
                        ProbeHost:      "test-host",
                        Version:        "test",
                        ElapsedSeconds: 0.5,
                        CID:            req.CID,
                        Results:        results,
                })
        })
        defer ts.Close()

        a := &Analyzer{
                IPFSProbeMode: "remote",
                Probes:        []ProbeEndpoint{{ID: "probe-01", Label: "Test Probe", URL: ts.URL, Key: ""}},
        }

        cid := "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
        result := a.RunIPFSFleetProbe(context.Background(), cid)
        if result == nil {
                t.Fatal("expected non-nil result")
        }
        if len(result.Probes) != 1 {
                t.Fatalf("expected 1 probe entry, got %d", len(result.Probes))
        }
        if result.Probes[0].Status != "completed" {
                t.Errorf("expected status=completed, got %s", result.Probes[0].Status)
        }
        if result.Consensus.HealthyProbes != 1 {
                t.Errorf("expected 1 healthy probe, got %d", result.Consensus.HealthyProbes)
        }
        if result.Consensus.Persistence != persistenceUnproven {
                t.Errorf("single probe should remain unproven, got %s", result.Consensus.Persistence)
        }
}

func TestIPFSFleetProbe_TwoProbesVerified(t *testing.T) {
        ts := makeIPFSProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
                var req IPFSFleetProbeRequest
                json.NewDecoder(r.Body).Decode(&req)
                results := make([]IPFSFleetGatewayResult, len(req.Gateways))
                for i, gw := range req.Gateways {
                        results[i] = IPFSFleetGatewayResult{
                                Gateway:    gw,
                                Reachable:  true,
                                StatusCode: 200,
                                LatencyMs:  30,
                                FinalURL:   gw + "/ipfs/" + req.CID,
                        }
                }
                json.NewEncoder(w).Encode(IPFSFleetProbeResponse{
                        ProbeHost:      "test-host",
                        Version:        "test",
                        ElapsedSeconds: 0.3,
                        CID:            req.CID,
                        Results:        results,
                })
        })
        defer ts.Close()

        a := &Analyzer{
                IPFSProbeMode: "remote",
                Probes: []ProbeEndpoint{
                        {ID: "probe-01", Label: "Probe 1", URL: ts.URL, Key: ""},
                        {ID: "probe-02", Label: "Probe 2", URL: ts.URL, Key: ""},
                },
        }

        cid := "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
        result := a.RunIPFSFleetProbe(context.Background(), cid)
        if result == nil {
                t.Fatal("expected non-nil result")
        }
        if result.Consensus.HealthyProbes != 2 {
                t.Errorf("expected 2 healthy probes, got %d", result.Consensus.HealthyProbes)
        }
        if result.Consensus.Persistence != persistenceVerified {
                t.Errorf("expected persistence_verified with 2 probes + 4 gateways, got %s", result.Consensus.Persistence)
        }
}

func TestIPFSFleetProbe_ProbeDown(t *testing.T) {
        goodServer := makeIPFSProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
                var req IPFSFleetProbeRequest
                json.NewDecoder(r.Body).Decode(&req)
                json.NewEncoder(w).Encode(IPFSFleetProbeResponse{
                        ProbeHost:      "good-host",
                        Version:        "test",
                        ElapsedSeconds: 0.1,
                        CID:            req.CID,
                        Results: []IPFSFleetGatewayResult{
                                {Gateway: "https://dweb.link", Reachable: true, StatusCode: 200, LatencyMs: 10},
                                {Gateway: "https://ipfs.io", Reachable: true, StatusCode: 200, LatencyMs: 15},
                        },
                })
        })
        defer goodServer.Close()

        a := &Analyzer{
                IPFSProbeMode: "remote",
                Probes: []ProbeEndpoint{
                        {ID: "probe-01", Label: "Good Probe", URL: goodServer.URL, Key: ""},
                        {ID: "probe-02", Label: "Dead Probe", URL: "http://127.0.0.1:1", Key: ""},
                },
        }

        cid := "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
        result := a.RunIPFSFleetProbe(context.Background(), cid)
        if result == nil {
                t.Fatal("expected non-nil result")
        }
        if result.Consensus.HealthyProbes != 1 {
                t.Errorf("expected 1 healthy probe, got %d", result.Consensus.HealthyProbes)
        }
        if result.Consensus.Persistence != persistenceUnproven {
                t.Errorf("should remain unproven with only 1 healthy probe, got %s", result.Consensus.Persistence)
        }

        var errorEntry *IPFSFleetProbeEntry
        for i := range result.Probes {
                if result.Probes[i].Status == "error" {
                        errorEntry = &result.Probes[i]
                        break
                }
        }
        if errorEntry == nil {
                t.Fatal("expected one probe entry with status=error")
        }
        if errorEntry.Error == "" {
                t.Error("expected error message on failed probe")
        }
}

func TestIPFSFleetProbe_AuthFailure(t *testing.T) {
        ts := makeIPFSProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusUnauthorized)
                w.Write([]byte(`{"error":"unauthorized"}`))
        })
        defer ts.Close()

        a := &Analyzer{
                IPFSProbeMode: "remote",
                Probes:        []ProbeEndpoint{{ID: "probe-01", Label: "Bad Auth", URL: ts.URL, Key: "wrong"}},
        }

        result := a.RunIPFSFleetProbe(context.Background(), "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")
        if result == nil {
                t.Fatal("expected non-nil result")
        }
        if result.Probes[0].Error != "authentication failed (401)" {
                t.Errorf("expected auth failure error, got %q", result.Probes[0].Error)
        }
}

func TestIPFSFleetProbe_RateLimited(t *testing.T) {
        ts := makeIPFSProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusTooManyRequests)
        })
        defer ts.Close()

        a := &Analyzer{
                IPFSProbeMode: "remote",
                Probes:        []ProbeEndpoint{{ID: "probe-01", Label: "Rate Limited", URL: ts.URL, Key: ""}},
        }

        result := a.RunIPFSFleetProbe(context.Background(), "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")
        if result.Probes[0].Error != "rate limited (429)" {
                t.Errorf("expected rate limit error, got %q", result.Probes[0].Error)
        }
}

func TestIPFSFleetProbe_ContextTimeout(t *testing.T) {
        ts := makeIPFSProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
                time.Sleep(5 * time.Second)
        })
        defer ts.Close()

        a := &Analyzer{
                IPFSProbeMode: "remote",
                Probes:        []ProbeEndpoint{{ID: "probe-01", Label: "Slow", URL: ts.URL, Key: ""}},
        }

        ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
        defer cancel()

        result := a.RunIPFSFleetProbe(ctx, "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")
        if result == nil {
                t.Fatal("expected non-nil result even on timeout")
        }
        if result.Probes[0].Status != "error" {
                t.Errorf("expected error status on timeout, got %s", result.Probes[0].Status)
        }
}

func TestIPFSFleetProbe_ParallelDispatch(t *testing.T) {
        var concurrentHits atomic.Int32
        var maxConcurrent atomic.Int32

        ts := makeIPFSProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
                cur := concurrentHits.Add(1)
                for {
                        old := maxConcurrent.Load()
                        if cur <= old || maxConcurrent.CompareAndSwap(old, cur) {
                                break
                        }
                }
                time.Sleep(50 * time.Millisecond)
                concurrentHits.Add(-1)

                var req IPFSFleetProbeRequest
                json.NewDecoder(r.Body).Decode(&req)
                json.NewEncoder(w).Encode(IPFSFleetProbeResponse{
                        ProbeHost: "parallel-host", Version: "test", ElapsedSeconds: 0.05, CID: req.CID,
                        Results: []IPFSFleetGatewayResult{{Gateway: "https://dweb.link", Reachable: true, StatusCode: 200, LatencyMs: 10}},
                })
        })
        defer ts.Close()

        a := &Analyzer{
                IPFSProbeMode: "remote",
                Probes: []ProbeEndpoint{
                        {ID: "p1", Label: "P1", URL: ts.URL, Key: ""},
                        {ID: "p2", Label: "P2", URL: ts.URL, Key: ""},
                        {ID: "p3", Label: "P3", URL: ts.URL, Key: ""},
                },
        }

        result := a.RunIPFSFleetProbe(context.Background(), "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")
        if result == nil {
                t.Fatal("expected non-nil result")
        }
        if len(result.Probes) != 3 {
                t.Errorf("expected 3 probe entries, got %d", len(result.Probes))
        }
        if maxConcurrent.Load() < 2 {
                t.Errorf("expected concurrent probe dispatch, max concurrent was %d", maxConcurrent.Load())
        }
}

func TestIPFSFleetProbe_RedirectDivergence(t *testing.T) {
        var callCount atomic.Int32

        ts := makeIPFSProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
                n := callCount.Add(1)
                var req IPFSFleetProbeRequest
                json.NewDecoder(r.Body).Decode(&req)

                finalURL := "https://cdn-a.example.com/ipfs/" + req.CID
                if n > 1 {
                        finalURL = "https://cdn-b.example.com/ipfs/" + req.CID
                }

                json.NewEncoder(w).Encode(IPFSFleetProbeResponse{
                        ProbeHost: "div-host", Version: "test", ElapsedSeconds: 0.1, CID: req.CID,
                        Results: []IPFSFleetGatewayResult{
                                {Gateway: "https://dweb.link", Reachable: true, StatusCode: 200, LatencyMs: 10, FinalURL: finalURL},
                        },
                })
        })
        defer ts.Close()

        a := &Analyzer{
                IPFSProbeMode: "remote",
                Probes: []ProbeEndpoint{
                        {ID: "p1", Label: "P1", URL: ts.URL, Key: ""},
                        {ID: "p2", Label: "P2", URL: ts.URL, Key: ""},
                },
        }

        result := a.RunIPFSFleetProbe(context.Background(), "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")
        if !result.Consensus.RedirectDivergence {
                t.Error("expected redirect divergence detected")
        }
}

func TestIPFSFleetProbe_InfrastructureFingerprint(t *testing.T) {
        ts := makeIPFSProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
                var req IPFSFleetProbeRequest
                json.NewDecoder(r.Body).Decode(&req)
                json.NewEncoder(w).Encode(IPFSFleetProbeResponse{
                        ProbeHost: "infra-host", Version: "test", ElapsedSeconds: 0.1, CID: req.CID,
                        Results: []IPFSFleetGatewayResult{
                                {Gateway: "https://dweb.link", Reachable: true, StatusCode: 200, LatencyMs: 10, ServerHeader: "cloudflare", TLSVersion: "TLS 1.3"},
                                {Gateway: "https://ipfs.io", Reachable: true, StatusCode: 200, LatencyMs: 20, ServerHeader: "nginx/1.24", TLSVersion: "TLS 1.2"},
                        },
                })
        })
        defer ts.Close()

        a := &Analyzer{
                IPFSProbeMode: "remote",
                Probes:        []ProbeEndpoint{{ID: "p1", Label: "P1", URL: ts.URL, Key: ""}},
        }

        result := a.RunIPFSFleetProbe(context.Background(), "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")
        if len(result.Consensus.Infrastructure) == 0 {
                t.Fatal("expected infrastructure fingerprints")
        }
        found := false
        for _, fp := range result.Consensus.Infrastructure {
                if fp.Gateway == "https://dweb.link" && len(fp.ServerValues) > 0 && fp.ServerValues[0] == "cloudflare" {
                        found = true
                }
        }
        if !found {
                t.Error("expected cloudflare fingerprint for dweb.link")
        }
}

func TestIPFSFleetProbe_ToMapRoundTrip(t *testing.T) {
        result := &IPFSFleetResult{
                Probes: []IPFSFleetProbeEntry{
                        {ProbeID: "p1", ProbeLabel: "Test", Status: "completed", ProbeHost: "host1", Elapsed: 0.5},
                },
                Consensus: IPFSFleetConsensus{
                        TotalProbes:   1,
                        HealthyProbes: 1,
                        TotalGateways: 4,
                        ReachableByAll: 2,
                        ReachableByAny: 4,
                        Persistence:   persistenceVerified,
                        GatewayMatrix: map[string]map[string]bool{
                                "https://dweb.link": {"p1": true},
                        },
                        Infrastructure: []GatewayInfraFingerprint{
                                {Gateway: "https://dweb.link", ServerValues: []string{"cloudflare"}, TLSVersions: []string{"TLS 1.3"}},
                        },
                },
        }

        m := result.ToMap()
        if m == nil {
                t.Fatal("ToMap returned nil")
        }

        consensus, ok := m["consensus"].(map[string]any)
        if !ok {
                t.Fatal("consensus key missing or wrong type")
        }
        if consensus["persistence"] != persistenceVerified {
                t.Errorf("expected persistence=%s, got %v", persistenceVerified, consensus["persistence"])
        }
        if consensus["total_probes"] != 1 {
                t.Errorf("expected total_probes=1, got %v", consensus["total_probes"])
        }

        data, err := json.Marshal(m)
        if err != nil {
                t.Fatalf("ToMap result should be JSON-serializable: %v", err)
        }
        if len(data) == 0 {
                t.Fatal("serialized output is empty")
        }
}

func TestIPFSFleetProbe_NilToMap(t *testing.T) {
        var result *IPFSFleetResult
        m := result.ToMap()
        if m != nil {
                t.Error("nil result.ToMap() should return nil")
        }
}

func TestIPFSConsensus_NoHealthyProbes(t *testing.T) {
        entries := []IPFSFleetProbeEntry{
                {ProbeID: "p1", Status: "error", Error: "timeout"},
                {ProbeID: "p2", Status: "error", Error: "refused"},
        }

        c := computeIPFSConsensus(entries, defaultIPFSGateways)
        if c.HealthyProbes != 0 {
                t.Errorf("expected 0 healthy probes, got %d", c.HealthyProbes)
        }
        if c.Persistence != persistenceUnproven {
                t.Errorf("expected unproven persistence, got %s", c.Persistence)
        }
}

func TestIPFSConsensus_PartialGatewayReachability(t *testing.T) {
        entries := []IPFSFleetProbeEntry{
                {ProbeID: "p1", Status: "completed", Gateways: []IPFSFleetGatewayResult{
                        {Gateway: "https://dweb.link", Reachable: true},
                        {Gateway: "https://ipfs.io", Reachable: false},
                }},
                {ProbeID: "p2", Status: "completed", Gateways: []IPFSFleetGatewayResult{
                        {Gateway: "https://dweb.link", Reachable: true},
                        {Gateway: "https://ipfs.io", Reachable: true},
                }},
        }

        c := computeIPFSConsensus(entries, []string{"https://dweb.link", "https://ipfs.io"})
        if c.ReachableByAll != 1 {
                t.Errorf("expected 1 gateway reachable by all, got %d", c.ReachableByAll)
        }
        if c.ReachableByAny != 2 {
                t.Errorf("expected 2 gateways reachable by any, got %d", c.ReachableByAny)
        }
        if c.Persistence != persistenceVerified {
                t.Errorf("2 probes + 2 reachable gateways should = verified, got %s", c.Persistence)
        }
}

func TestEnrichWeb3WithFleetProbe_SkipsWhenModeOff(t *testing.T) {
        a := &Analyzer{IPFSProbeMode: "off", Probes: []ProbeEndpoint{{ID: "p1", URL: "http://localhost:1"}}}
        web3 := map[string]any{"dnslink_cid": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"}
        a.enrichWeb3WithFleetProbe(context.Background(), "example.com", web3)
        if _, ok := web3["ipfs_fleet_probe"]; ok {
                t.Error("fleet probe should not run when mode=off")
        }
}

func TestEnrichWeb3WithFleetProbe_SkipsWhenNoCID(t *testing.T) {
        a := &Analyzer{IPFSProbeMode: "remote", Probes: []ProbeEndpoint{{ID: "p1", URL: "http://localhost:1"}}}
        web3 := map[string]any{"detected": true}
        a.enrichWeb3WithFleetProbe(context.Background(), "example.com", web3)
        if _, ok := web3["ipfs_fleet_probe"]; ok {
                t.Error("fleet probe should not run when no CID in web3 result")
        }
}

func TestEnrichWeb3WithFleetProbe_UpgradesPersistence(t *testing.T) {
        ts := makeIPFSProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
                var req IPFSFleetProbeRequest
                json.NewDecoder(r.Body).Decode(&req)
                results := make([]IPFSFleetGatewayResult, len(req.Gateways))
                for i, gw := range req.Gateways {
                        results[i] = IPFSFleetGatewayResult{Gateway: gw, Reachable: true, StatusCode: 200, LatencyMs: 10}
                }
                json.NewEncoder(w).Encode(IPFSFleetProbeResponse{
                        ProbeHost: "upgrade-host", Version: "test", ElapsedSeconds: 0.1, CID: req.CID, Results: results,
                })
        })
        defer ts.Close()

        a := &Analyzer{
                IPFSProbeMode: "remote",
                Probes: []ProbeEndpoint{
                        {ID: "p1", Label: "P1", URL: ts.URL, Key: ""},
                        {ID: "p2", Label: "P2", URL: ts.URL, Key: ""},
                },
        }

        web3 := map[string]any{
                "dnslink_cid": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
                "ipfs_probe": map[string]any{
                        "persistence_unproven": true,
                        "trust_mode":           "gateway_trusted",
                },
        }

        a.enrichWeb3WithFleetProbe(context.Background(), "example.com", web3)

        if _, ok := web3["ipfs_fleet_probe"]; !ok {
                t.Fatal("expected ipfs_fleet_probe in web3 result")
        }

        probe, ok := web3["ipfs_probe"].(map[string]any)
        if !ok {
                t.Fatal("ipfs_probe missing")
        }
        if probe["persistence_unproven"] != false {
                t.Error("expected persistence_unproven upgraded to false")
        }
        if probe["trust_mode"] != trustModeFleetVerified {
                t.Errorf("expected trust_mode=%s, got %v", trustModeFleetVerified, probe["trust_mode"])
        }
}

func TestIPFSFleetProbe_AuthHeaderForwarded(t *testing.T) {
        var receivedKey string
        ts := makeIPFSProbeServer(t, func(w http.ResponseWriter, r *http.Request) {
                receivedKey = r.Header.Get("X-Probe-Key")
                var req IPFSFleetProbeRequest
                json.NewDecoder(r.Body).Decode(&req)
                json.NewEncoder(w).Encode(IPFSFleetProbeResponse{
                        ProbeHost: "auth-host", Version: "test", ElapsedSeconds: 0.1, CID: req.CID,
                        Results: []IPFSFleetGatewayResult{{Gateway: "https://dweb.link", Reachable: true, StatusCode: 200, LatencyMs: 5}},
                })
        })
        defer ts.Close()

        secretKey := "super-secret-probe-key-42"
        a := &Analyzer{
                IPFSProbeMode: "remote",
                Probes:        []ProbeEndpoint{{ID: "p1", Label: "Auth Test", URL: ts.URL, Key: secretKey}},
        }

        result := a.RunIPFSFleetProbe(context.Background(), "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")
        if result == nil {
                t.Fatal("expected non-nil result")
        }
        if receivedKey != secretKey {
                t.Errorf("expected X-Probe-Key=%q forwarded, got %q", secretKey, receivedKey)
        }
}

func TestIPFSFleetProbe_HostileCID(t *testing.T) {
        a := &Analyzer{
                IPFSProbeMode: "remote",
                Probes:        []ProbeEndpoint{{ID: "p1", URL: "http://localhost:1", Key: "k"}},
        }
        hostileCIDs := []string{
                "../../../etc/passwd",
                "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG; rm -rf /",
                "<script>alert(1)</script>",
                "",
                "a",
        }
        for _, cid := range hostileCIDs {
                result := a.RunIPFSFleetProbe(context.Background(), cid)
                if result != nil {
                        t.Errorf("hostile CID %q should return nil, got result with %d probes", cid, len(result.Probes))
                }
        }
}

func TestClassifyFleetProbeError(t *testing.T) {
        tests := []struct {
                errMsg   string
                expected string
        }{
                {"context deadline exceeded", "probe timeout"},
                {"connection timeout after 10s", "probe timeout"},
                {"connection refused", "probe connection refused"},
                {"no such host", "probe DNS resolution failed"},
                {"unknown error xyz", "probe connection error"},
        }
        for _, tt := range tests {
                got := classifyFleetProbeError(fmt.Errorf("%s", tt.errMsg))
                if got != tt.expected {
                        t.Errorf("classifyFleetProbeError(%q) = %q, want %q", tt.errMsg, got, tt.expected)
                }
        }
}
