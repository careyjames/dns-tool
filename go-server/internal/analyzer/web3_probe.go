// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "bytes"
        "context"
        "encoding/json"
        "fmt"
        "io"
        "log/slog"
        "net/http"
        "strings"
        "sync"
        "time"
)

const (
        ipfsFleetProbeTimeout     = 15 * time.Second
        ipfsFleetPerProbeTimeout  = 10 * time.Second
        ipfsFleetResponseBodyMax  = 256 * 1024

        persistenceVerified = "persistence_verified"
        persistenceUnproven = "persistence_unproven"

        trustModeFleetVerified = "fleet_verified"
)

var defaultIPFSGateways = []string{
        "https://dweb.link",
        "https://ipfs.io",
        "https://w3s.link",
        "https://gateway.pinata.cloud",
}

type IPFSFleetProbeRequest struct {
        CID      string   `json:"cid"`
        Gateways []string `json:"gateways"`
}

type IPFSFleetGatewayResult struct {
        Gateway       string                   `json:"gateway"`
        Reachable     bool                     `json:"reachable"`
        StatusCode    int                      `json:"status_code,omitempty"`
        ContentType   string                   `json:"content_type,omitempty"`
        LatencyMs     int64                    `json:"latency_ms"`
        ServerHeader  string                   `json:"server_header,omitempty"`
        TLSVersion    string                   `json:"tls_version,omitempty"`
        RedirectChain []map[string]any         `json:"redirect_chain,omitempty"`
        FinalURL      string                   `json:"final_url,omitempty"`
        Error         string                   `json:"error,omitempty"`
}

type IPFSFleetProbeResponse struct {
        ProbeHost      string                   `json:"probe_host"`
        Version        string                   `json:"version"`
        ElapsedSeconds float64                  `json:"elapsed_seconds"`
        CID            string                   `json:"cid"`
        Results        []IPFSFleetGatewayResult `json:"results"`
}

type IPFSFleetProbeEntry struct {
        ProbeID    string                   `json:"probe_id"`
        ProbeLabel string                   `json:"probe_label"`
        ProbeHost  string                   `json:"probe_host"`
        Status     string                   `json:"status"`
        Elapsed    float64                  `json:"elapsed_seconds"`
        Error      string                   `json:"error,omitempty"`
        Gateways   []IPFSFleetGatewayResult `json:"gateways,omitempty"`
}

type IPFSFleetConsensus struct {
        TotalProbes      int                       `json:"total_probes"`
        HealthyProbes    int                       `json:"healthy_probes"`
        TotalGateways    int                       `json:"total_gateways"`
        ReachableByAll   int                       `json:"reachable_by_all"`
        ReachableByAny   int                       `json:"reachable_by_any"`
        Persistence      string                    `json:"persistence"`
        GatewayMatrix    map[string]map[string]bool `json:"gateway_matrix"`
        RedirectDivergence bool                    `json:"redirect_divergence"`
        Infrastructure   []GatewayInfraFingerprint `json:"infrastructure,omitempty"`
}

type GatewayInfraFingerprint struct {
        Gateway      string   `json:"gateway"`
        ServerValues []string `json:"server_values"`
        TLSVersions  []string `json:"tls_versions"`
}

type IPFSFleetResult struct {
        Probes    []IPFSFleetProbeEntry `json:"probes"`
        Consensus IPFSFleetConsensus    `json:"consensus"`
}

func (a *Analyzer) RunIPFSFleetProbe(ctx context.Context, cid string) *IPFSFleetResult {
        if len(a.Probes) == 0 || cid == "" || !IsValidCID(cid) {
                return nil
        }

        fleetCtx, cancel := context.WithTimeout(ctx, ipfsFleetProbeTimeout)
        defer cancel()

        gateways := defaultIPFSGateways

        type probeResult struct {
                entry IPFSFleetProbeEntry
        }

        var wg sync.WaitGroup
        ch := make(chan probeResult, len(a.Probes))

        for _, p := range a.Probes {
                wg.Add(1)
                go func(ep ProbeEndpoint) {
                        defer wg.Done()
                        entry := dispatchIPFSProbe(fleetCtx, ep, cid, gateways)
                        ch <- probeResult{entry: entry}
                }(p)
        }

        go func() {
                wg.Wait()
                close(ch)
        }()

        var entries []IPFSFleetProbeEntry
        for pr := range ch {
                entries = append(entries, pr.entry)
        }

        consensus := computeIPFSConsensus(entries, gateways)

        return &IPFSFleetResult{
                Probes:    entries,
                Consensus: consensus,
        }
}

func dispatchIPFSProbe(ctx context.Context, ep ProbeEndpoint, cid string, gateways []string) IPFSFleetProbeEntry {
        entry := IPFSFleetProbeEntry{
                ProbeID:    ep.ID,
                ProbeLabel: ep.Label,
                Status:     "error",
        }

        reqBody, err := json.Marshal(IPFSFleetProbeRequest{
                CID:      cid,
                Gateways: gateways,
        })
        if err != nil {
                entry.Error = "request encoding error"
                return entry
        }

        probeCtx, cancel := context.WithTimeout(ctx, ipfsFleetPerProbeTimeout)
        defer cancel()

        req, err := http.NewRequestWithContext(probeCtx, "POST", ep.URL+"/probe/ipfs", bytes.NewReader(reqBody))
        if err != nil {
                entry.Error = "request creation error"
                return entry
        }
        req.Header.Set("Content-Type", "application/json")
        if ep.Key != "" {
                req.Header.Set("X-Probe-Key", ep.Key)
        }

        resp, err := http.DefaultClient.Do(req)
        if err != nil {
                entry.Error = classifyFleetProbeError(err)
                slog.Warn("IPFS fleet probe failed", "probe_id", ep.ID, mapKeyError, err)
                return entry
        }
        defer func() {
                _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, ipfsFleetResponseBodyMax))
                resp.Body.Close()
        }()

        if resp.StatusCode == http.StatusUnauthorized {
                entry.Error = "authentication failed (401)"
                return entry
        }
        if resp.StatusCode == http.StatusTooManyRequests {
                entry.Error = "rate limited (429)"
                return entry
        }
        if resp.StatusCode != http.StatusOK {
                entry.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
                return entry
        }

        body, err := io.ReadAll(io.LimitReader(resp.Body, ipfsFleetResponseBodyMax))
        if err != nil {
                entry.Error = "response read error"
                return entry
        }

        var probeResp IPFSFleetProbeResponse
        if err := json.Unmarshal(body, &probeResp); err != nil {
                entry.Error = "response parse error"
                return entry
        }

        entry.Status = "completed"
        entry.ProbeHost = probeResp.ProbeHost
        entry.Elapsed = probeResp.ElapsedSeconds
        entry.Gateways = probeResp.Results

        return entry
}

func collectInfraAndURLs(healthyEntries []IPFSFleetProbeEntry, matrix map[string]map[string]bool) (map[string]*GatewayInfraFingerprint, map[string]map[string]bool) {
        infraMap := make(map[string]*GatewayInfraFingerprint)
        finalURLs := make(map[string]map[string]bool)

        for _, entry := range healthyEntries {
                for _, gwr := range entry.Gateways {
                        if _, ok := matrix[gwr.Gateway]; ok {
                                matrix[gwr.Gateway][entry.ProbeID] = gwr.Reachable
                        }
                        collectGatewayFingerprint(infraMap, &gwr)
                        collectFinalURL(finalURLs, &gwr)
                }
        }
        return infraMap, finalURLs
}

func collectGatewayFingerprint(infraMap map[string]*GatewayInfraFingerprint, gwr *IPFSFleetGatewayResult) {
        if infraMap[gwr.Gateway] == nil {
                infraMap[gwr.Gateway] = &GatewayInfraFingerprint{Gateway: gwr.Gateway}
        }
        fp := infraMap[gwr.Gateway]
        if gwr.ServerHeader != "" {
                fp.ServerValues = appendUniqueStr(fp.ServerValues, gwr.ServerHeader)
        }
        if gwr.TLSVersion != "" {
                fp.TLSVersions = appendUniqueStr(fp.TLSVersions, gwr.TLSVersion)
        }
}

func collectFinalURL(finalURLs map[string]map[string]bool, gwr *IPFSFleetGatewayResult) {
        if gwr.FinalURL == "" {
                return
        }
        if finalURLs[gwr.Gateway] == nil {
                finalURLs[gwr.Gateway] = make(map[string]bool)
        }
        finalURLs[gwr.Gateway][gwr.FinalURL] = true
}

func countGatewayReachability(matrix map[string]map[string]bool, healthyCount int) (int, int) {
        byAll, byAny := 0, 0
        for _, probeMap := range matrix {
                reachCount := 0
                for _, reachable := range probeMap {
                        if reachable {
                                reachCount++
                        }
                }
                if reachCount > 0 {
                        byAny++
                }
                if reachCount == healthyCount {
                        byAll++
                }
        }
        return byAll, byAny
}

func computeIPFSConsensus(entries []IPFSFleetProbeEntry, gateways []string) IPFSFleetConsensus {
        consensus := IPFSFleetConsensus{
                TotalProbes:   len(entries),
                TotalGateways: len(gateways),
                GatewayMatrix: make(map[string]map[string]bool),
                Persistence:   persistenceUnproven,
        }

        var healthyEntries []IPFSFleetProbeEntry
        for _, e := range entries {
                if e.Status == "completed" {
                        healthyEntries = append(healthyEntries, e)
                }
        }
        consensus.HealthyProbes = len(healthyEntries)

        if len(healthyEntries) == 0 {
                return consensus
        }

        for _, gw := range gateways {
                consensus.GatewayMatrix[gw] = make(map[string]bool)
        }

        infraMap, finalURLs := collectInfraAndURLs(healthyEntries, consensus.GatewayMatrix)

        consensus.ReachableByAll, consensus.ReachableByAny = countGatewayReachability(consensus.GatewayMatrix, len(healthyEntries))

        if len(healthyEntries) >= 2 && consensus.ReachableByAny >= 2 {
                consensus.Persistence = persistenceVerified
        }

        for _, urls := range finalURLs {
                if len(urls) > 1 {
                        consensus.RedirectDivergence = true
                        break
                }
        }

        var infra []GatewayInfraFingerprint
        for _, fp := range infraMap {
                infra = append(infra, *fp)
        }
        consensus.Infrastructure = infra

        return consensus
}

func classifyFleetProbeError(err error) string {
        s := err.Error()
        switch {
        case strings.Contains(s, "timeout"), strings.Contains(s, "deadline exceeded"):
                return "probe timeout"
        case strings.Contains(s, "refused"):
                return "probe connection refused"
        case strings.Contains(s, "no such host"):
                return "probe DNS resolution failed"
        default:
                return "probe connection error"
        }
}

func appendUniqueStr(slice []string, val string) []string {
        for _, s := range slice {
                if s == val {
                        return slice
                }
        }
        return append(slice, val)
}

func gatewayResultToMap(gw *IPFSFleetGatewayResult) map[string]any {
        gwm := map[string]any{
                "gateway":    gw.Gateway,
                "reachable":  gw.Reachable,
                "latency_ms": gw.LatencyMs,
        }
        if gw.StatusCode > 0 {
                gwm["status_code"] = gw.StatusCode
        }
        if gw.ContentType != "" {
                gwm["content_type"] = gw.ContentType
        }
        if gw.ServerHeader != "" {
                gwm["server_header"] = gw.ServerHeader
        }
        if gw.TLSVersion != "" {
                gwm["tls_version"] = gw.TLSVersion
        }
        if gw.FinalURL != "" {
                gwm["final_url"] = gw.FinalURL
        }
        if gw.Error != "" {
                gwm[mapKeyError] = gw.Error
        }
        if len(gw.RedirectChain) > 0 {
                gwm["redirect_chain"] = gw.RedirectChain
        }
        return gwm
}

func probeEntryToMap(p *IPFSFleetProbeEntry) map[string]any {
        entry := map[string]any{
                "probe_id":    p.ProbeID,
                "probe_label": p.ProbeLabel,
                "status":      p.Status,
        }
        if p.ProbeHost != "" {
                entry["probe_host"] = p.ProbeHost
        }
        if p.Elapsed > 0 {
                entry["elapsed_seconds"] = p.Elapsed
        }
        if p.Error != "" {
                entry[mapKeyError] = p.Error
        }
        if len(p.Gateways) > 0 {
                gws := make([]map[string]any, len(p.Gateways))
                for j, gw := range p.Gateways {
                        gws[j] = gatewayResultToMap(&gw)
                }
                entry["gateways"] = gws
        }
        return entry
}

func (f *IPFSFleetResult) ToMap() map[string]any {
        if f == nil {
                return nil
        }

        probes := make([]map[string]any, len(f.Probes))
        for i, p := range f.Probes {
                probes[i] = probeEntryToMap(&p)
        }

        gwMatrix := make(map[string]any)
        for gw, probeMap := range f.Consensus.GatewayMatrix {
                gwMatrix[gw] = probeMap
        }

        infra := make([]map[string]any, len(f.Consensus.Infrastructure))
        for i, fp := range f.Consensus.Infrastructure {
                infra[i] = map[string]any{
                        "gateway":       fp.Gateway,
                        "server_values": fp.ServerValues,
                        "tls_versions":  fp.TLSVersions,
                }
        }

        return map[string]any{
                "probes": probes,
                "consensus": map[string]any{
                        "total_probes":        f.Consensus.TotalProbes,
                        "healthy_probes":      f.Consensus.HealthyProbes,
                        "total_gateways":      f.Consensus.TotalGateways,
                        "reachable_by_all":    f.Consensus.ReachableByAll,
                        "reachable_by_any":    f.Consensus.ReachableByAny,
                        "persistence":         f.Consensus.Persistence,
                        "gateway_matrix":      gwMatrix,
                        "redirect_divergence": f.Consensus.RedirectDivergence,
                        "infrastructure":      infra,
                },
        }
}

func (a *Analyzer) enrichWeb3WithFleetProbe(ctx context.Context, domain string, web3Result map[string]any) {
        if a.IPFSProbeMode != "remote" || len(a.Probes) == 0 {
                return
        }

        cid, _ := web3Result["dnslink_cid"].(string)
        if cid == "" || !IsValidCID(cid) {
                return
        }

        fleetStart := time.Now()
        slog.Info("IPFS fleet probe starting", "domain", domain, "cid", truncateCID(cid), "probes", len(a.Probes))

        fleetResult := a.RunIPFSFleetProbe(ctx, cid)
        if fleetResult == nil {
                return
        }

        web3Result["ipfs_fleet_probe"] = fleetResult.ToMap()

        if fleetResult.Consensus.Persistence == persistenceVerified {
                if probe, ok := web3Result["ipfs_probe"].(map[string]any); ok {
                        probe["persistence_unproven"] = false
                        probe["trust_mode"] = trustModeFleetVerified
                }
        }

        if len(fleetResult.Consensus.Infrastructure) > 0 {
                infraMap := make(map[string]any)
                for _, fp := range fleetResult.Consensus.Infrastructure {
                        infraMap[fp.Gateway] = map[string]any{
                                "server_values": fp.ServerValues,
                                "tls_versions":  fp.TLSVersions,
                        }
                }
                web3Result["gateway_infrastructure"] = infraMap
        }

        slog.Info("IPFS fleet probe completed",
                "domain", domain,
                "healthy_probes", fleetResult.Consensus.HealthyProbes,
                "persistence", fleetResult.Consensus.Persistence,
                "redirect_divergence", fleetResult.Consensus.RedirectDivergence,
                "elapsed_ms", time.Since(fleetStart).Milliseconds(),
        )
}
