// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "bytes"
        "context"
        "crypto/tls"
        "encoding/json"
        "fmt"
        "io"
        "log/slog"
        "net"
        "net/http"
        "strings"
        "sync"
        "time"
)

const (
        mapKeyAgreement         = "agreement"
        mapKeyAllTls            = "all_tls"
        mapKeyCertDaysRemaining = "cert_days_remaining"
        mapKeyCertExpiry        = "cert_expiry"
        mapKeyCertIssuer        = "cert_issuer"
        mapKeyCertSubject       = "cert_subject"
        mapKeyCertValid         = "cert_valid"
        mapKeyCipher            = "cipher"
        mapKeyCipherBits        = "cipher_bits"
        mapKeyDane              = "dane"
        mapKeyEnforced          = "enforced"
        mapKeyExpiringSoon      = "expiring_soon"
        mapKeyMode              = "mode"
        mapKeyMonitored         = "monitored"
        mapKeyNoTls             = "no_tls"
        mapKeyObservations      = "observations"
        mapKeyObserved          = "observed"
        mapKeyOpportunistic     = "opportunistic"
        mapKeyPartialTls        = "partial_tls"
        mapKeyPresent           = "present"
        mapKeyProbeCount        = "probe_count"
        mapKeyProbeElapsed      = "probe_elapsed"
        mapKeyProbeHost         = "probe_host"
        mapKeyProbeMethod       = "probe_method"
        mapKeyProbeVerdict      = "probe_verdict"
        mapKeyReachable         = "reachable"
        mapKeyRemote            = "remote"
        mapKeyServers           = "servers"
        mapKeySignals           = "signals"
        mapKeySkipped           = "skipped"
        mapKeyStarttls          = "starttls"
        mapKeyStarttlsSupported = "starttls_supported"
        mapKeySummary           = "summary"
        mapKeyTlsVersion        = "tls_version"
        mapKeyTlsrptConfigured  = "tlsrpt_configured"
        mapKeyTls12             = "tls_1_2"
        mapKeyTls13             = "tls_1_3"
        mapKeyTotalServers      = "total_servers"
        mapKeyValidCerts        = "valid_certs"
        mapKeyVerdict           = "verdict"
        mapKeyVersion           = "version"

        smtpBannerPrefix = "220"
        verdictNone      = "none"
)

type smtpServerResult struct {
        Host              string  `json:"host"`
        Reachable         bool    `json:"reachable"`
        StartTLS          bool    `json:"starttls"`
        TLSVersion        *string `json:"tls_version"`
        Cipher            *string `json:"cipher"`
        CipherBits        *int    `json:"cipher_bits"`
        CertValid         bool    `json:"cert_valid"`
        CertExpiry        *string `json:"cert_expiry"`
        CertDaysRemaining *int    `json:"cert_days_remaining"`
        CertIssuer        *string `json:"cert_issuer"`
        CertSubject       *string `json:"cert_subject"`
        Error             *string `json:"error"`
}

type smtpSummary struct {
        TotalServers    int `json:"total_servers"`
        Reachable       int `json:"reachable"`
        StartTLSSupport int `json:"starttls_supported"`
        TLS13           int `json:"tls_1_3"`
        TLS12           int `json:"tls_1_2"`
        ValidCerts      int `json:"valid_certs"`
        ExpiringSoon    int `json:"expiring_soon"`
}

type AnalysisInputs struct {
        MTASTSResult map[string]any
        TLSRPTResult map[string]any
        DANEResult   map[string]any
}

func (a *Analyzer) AnalyzeSMTPTransport(ctx context.Context, domain string, mxRecords []string, inputs ...AnalysisInputs) map[string]any {
        var ai AnalysisInputs
        if len(inputs) > 0 {
                ai = inputs[0]
        }

        mxHosts := extractMXHosts(mxRecords)

        result := buildMailTransportResult(a, ctx, domain, mxHosts, ai)

        return result
}

func buildMailTransportResult(a *Analyzer, ctx context.Context, domain string, mxHosts []string, ai AnalysisInputs) map[string]any {
        result := map[string]any{
                mapKeyVersion: 2,
        }

        policy := buildPolicyAssessment(a, ctx, domain, mxHosts, ai)
        result["policy"] = policy

        telemetrySection := buildTelemetrySection(ai)
        result["telemetry"] = telemetrySection

        probe := buildProbeResult(a, ctx, domain, mxHosts)
        result["probe"] = probe

        result[mapKeyStatus] = derivePrimaryStatus(policy, probe)
        result["message"] = derivePrimaryMessage(policy, probe, mxHosts)

        result["dns_inferred"] = true
        result["inference_note"] = buildInferenceNote(probe)
        result["inference_signals"] = buildInferenceSignals(policy, telemetrySection)

        backfillLegacyFields(result, policy, probe)

        return result
}

func buildPolicyAssessment(a *Analyzer, ctx context.Context, domain string, mxHosts []string, ai AnalysisInputs) map[string]any {
        policy := map[string]any{
                mapKeyMtaSts:  map[string]any{mapKeyPresent: false, mapKeyMode: verdictNone},
                mapKeyDane:    map[string]any{mapKeyPresent: false},
                "tlsrpt":      map[string]any{mapKeyPresent: false},
                "provider":    map[string]any{"identified": false},
                mapKeyVerdict: verdictNone,
                mapKeySignals: []string{},
        }

        var signals []string

        signals = assessMTASTS(a, ctx, domain, ai, policy, signals)
        signals = assessDANE(a, ctx, mxHosts, ai, policy, signals)
        signals = assessTLSRPT(a, ctx, domain, ai, policy, signals)
        signals = assessProvider(mxHosts, policy, signals)

        policy[mapKeySignals] = signals
        policy[mapKeyVerdict] = computePolicyVerdict(policy, signals)

        return policy
}

func assessMTASTS(a *Analyzer, ctx context.Context, domain string, ai AnalysisInputs, policy map[string]any, signals []string) []string {
        mtaSts := ai.MTASTSResult
        if mtaSts == nil {
                mtaSts = a.AnalyzeMTASTS(ctx, domain)
        }
        if mode, ok := mtaSts["mode"].(string); ok && mode != "" && mode != verdictNone {
                policy[mapKeyMtaSts] = map[string]any{
                        mapKeyPresent: true,
                        mapKeyMode:    mode,
                        mapKeyStatus:  mapGetStrSafe(mtaSts, mapKeyStatus),
                }
                if mode == "enforce" {
                        signals = append(signals, "MTA-STS policy in enforce mode requires encrypted transport (RFC 8461)")
                } else if mode == "testing" {
                        signals = append(signals, "MTA-STS policy in testing mode — monitoring transport security (RFC 8461)")
                }
        }
        return signals
}

func assessDANE(a *Analyzer, ctx context.Context, mxHosts []string, ai AnalysisInputs, policy map[string]any, signals []string) []string {
        hasTLSA := false
        daneResult := ai.DANEResult
        if daneResult != nil {
                if hasDane, ok := daneResult["has_dane"].(bool); ok && hasDane {
                        hasTLSA = true
                }
        }
        if !hasTLSA {
                for _, host := range mxHosts {
                        tlsaName := fmt.Sprintf("_25._tcp.%s", host)
                        tlsaRecords := a.DNS.QueryDNS(ctx, "TLSA", tlsaName)
                        if len(tlsaRecords) > 0 {
                                hasTLSA = true
                                break
                        }
                }
        }
        if hasTLSA {
                policy[mapKeyDane] = map[string]any{mapKeyPresent: true}
                signals = append(signals, "DANE/TLSA records published — mail servers pin TLS certificates via DNSSEC (RFC 7672)")
        }
        return signals
}

func assessTLSRPT(a *Analyzer, ctx context.Context, domain string, ai AnalysisInputs, policy map[string]any, signals []string) []string {
        tlsrpt := ai.TLSRPTResult
        if tlsrpt == nil {
                tlsrpt = a.AnalyzeTLSRPT(ctx, domain)
        }
        if st, ok := tlsrpt[mapKeyStatus].(string); ok && st == mapKeySuccess {
                policy["tlsrpt"] = map[string]any{
                        mapKeyPresent: true,
                        mapKeyStatus:  st,
                }
                signals = append(signals, "TLS-RPT configured — domain monitors TLS delivery failures (RFC 8460)")
        }
        return signals
}

func assessProvider(mxHosts []string, policy map[string]any, signals []string) []string {
        providerSignal := inferFromProvider(mxHosts)
        if providerSignal != "" {
                providerName := identifyProviderName(mxHosts)
                policy["provider"] = map[string]any{
                        "identified": true,
                        "name":       providerName,
                }
                signals = append(signals, providerSignal)
        }
        return signals
}

func computePolicyVerdict(policy map[string]any, signals []string) string {
        mtaStsMeta, ok := policy[mapKeyMtaSts].(map[string]any)
        if !ok {
                mtaStsMeta = nil
        }
        mtaStsPresent, ok := mtaStsMeta[mapKeyPresent].(bool)
        if !ok {
                mtaStsPresent = false
        }
        mtaStsMode, ok := mtaStsMeta["mode"].(string)
        if !ok {
                mtaStsMode = ""
        }
        daneMeta, ok := policy[mapKeyDane].(map[string]any)
        if !ok {
                daneMeta = nil
        }
        danePresent, ok := daneMeta[mapKeyPresent].(bool)
        if !ok {
                danePresent = false
        }

        if mtaStsPresent && mtaStsMode == "enforce" {
                return mapKeyEnforced
        }
        if danePresent {
                return mapKeyEnforced
        }
        if mtaStsPresent && mtaStsMode == "testing" {
                return mapKeyMonitored
        }
        if len(signals) > 0 {
                return mapKeyOpportunistic
        }
        return verdictNone
}

func buildTelemetrySection(ai AnalysisInputs) map[string]any {
        section := map[string]any{
                mapKeyTlsrptConfigured: false,
                "reporting_uris":       []string{},
                "observability":        false,
        }

        tlsrpt := ai.TLSRPTResult
        if tlsrpt == nil {
                return section
        }

        if st, ok := tlsrpt[mapKeyStatus].(string); ok && st == mapKeySuccess {
                section[mapKeyTlsrptConfigured] = true
                section["observability"] = true

                if record, ok := tlsrpt["record"].(string); ok && record != "" {
                        uris := extractTLSRPTURIs(record)
                        if len(uris) > 0 {
                                section["reporting_uris"] = uris
                        }
                }
        }

        return section
}

func extractTLSRPTURIs(record string) []string {
        var uris []string
        parts := strings.Split(record, ";")
        for _, part := range parts {
                part = strings.TrimSpace(part)
                if strings.HasPrefix(part, "rua=") {
                        rua := strings.TrimPrefix(part, "rua=")
                        for _, uri := range strings.Split(rua, ",") {
                                uri = strings.TrimSpace(uri)
                                if uri != "" {
                                        uris = append(uris, uri)
                                }
                        }
                }
        }
        return uris
}

func buildProbeResult(a *Analyzer, ctx context.Context, domain string, mxHosts []string) map[string]any {
        probe := map[string]any{
                mapKeyStatus:       mapKeySkipped,
                mapKeyReason:       "",
                mapKeyObservations: []map[string]any{},
        }

        if len(mxHosts) == 0 {
                probe[mapKeyReason] = "No MX records found for this domain"
                probe[mapKeyProbeMethod] = verdictNone
                return probe
        }

        if a.SMTPProbeMode == "skip" || a.SMTPProbeMode == "" {
                probe[mapKeyReason] = "SMTP probe skipped — outbound TCP port 25 is blocked by cloud hosting provider. This is standard for all major cloud platforms (AWS, GCP, Azure, Replit) as an anti-spam measure. Transport security is assessed via DNS policy records above, which is the standards-aligned primary method per NIST SP 800-177 Rev. 1."
                probe[mapKeyProbeMethod] = "skip"
                slog.Info("SMTP probe skipped (mode=skip)", mapKeyDomain, domain)
                return probe
        }

        if a.SMTPProbeMode == mapKeyRemote && len(a.Probes) > 0 {
                probe[mapKeyProbeMethod] = mapKeyRemote
                probe[mapKeyProbeCount] = len(a.Probes)
                if len(a.Probes) == 1 {
                        return runRemoteProbe(ctx, a.Probes[0].URL, a.Probes[0].Key, mxHosts, probe)
                }
                return runMultiProbe(ctx, a.Probes, mxHosts, probe)
        }

        if a.SMTPProbeMode == mapKeyRemote && a.ProbeAPIURL != "" && len(a.Probes) == 0 {
                probe[mapKeyProbeMethod] = mapKeyRemote
                return runRemoteProbe(ctx, a.ProbeAPIURL, a.ProbeAPIKey, mxHosts, probe)
        }

        if a.SMTPProbeMode == mapKeyRemote && a.ProbeAPIURL == "" && len(a.Probes) == 0 {
                probe[mapKeyReason] = "Remote probe configured but PROBE_API_URL is not set — unable to reach external probe infrastructure."
                probe[mapKeyProbeMethod] = "remote_misconfigured"
                slog.Error("SMTP probe: mode=remote but PROBE_API_URL is empty", mapKeyDomain, domain)
                return probe
        }

        if a.SMTPProbeMode == "force" {
                probe[mapKeyProbeMethod] = "local"
                return runLiveProbe(ctx, mxHosts, probe)
        }

        probe[mapKeyProbeMethod] = "unknown"
        probe[mapKeyReason] = fmt.Sprintf("Unrecognized SMTP probe mode: %s", a.SMTPProbeMode)
        slog.Warn("SMTP probe: unrecognized mode", mapKeyMode, a.SMTPProbeMode, mapKeyDomain, domain)
        return probe
}

func remoteProbeFailover(ctx context.Context, mxHosts []string, probe map[string]any, remoteError string) map[string]any {
        slog.Warn("Remote probe failed, attempting local fallback", "remote_error", remoteError)
        probe["remote_attempted"] = true
        probe["remote_error"] = remoteError
        result := runLiveProbe(ctx, mxHosts, probe)
        if result[mapKeyStatus] == mapKeySkipped {
                result[mapKeyReason] = fmt.Sprintf("Remote probe failed (%s) and local port 25 is blocked. Transport security is assessed via DNS policy records per NIST SP 800-177 Rev. 1.", remoteError)
        } else {
                result[mapKeyProbeMethod] = "local_fallback"
        }
        return result
}

type remoteProbeAPIResp struct {
        ProbeHost      string           `json:"probe_host"`
        Version        string           `json:"version"`
        ElapsedSeconds float64          `json:"elapsed_seconds"`
        Servers        []map[string]any `json:"servers"`
        AllPorts       []map[string]any `json:"all_ports"`
}

func marshalRemoteProbeBody(mxHosts []string) ([]byte, string) {
        hostsToCheck := mxHosts
        if len(hostsToCheck) > 5 {
                hostsToCheck = hostsToCheck[:5]
        }

        reqBody, err := json.Marshal(map[string]any{
                "hosts": hostsToCheck,
                "ports": []int{25, 465, 587},
        })
        if err != nil {
                slog.Error("Remote probe: failed to marshal request", mapKeyError, err)
                return nil, "request encoding error"
        }
        return reqBody, ""
}

func executeRemoteProbeHTTP(req *http.Request) (*remoteProbeAPIResp, string) {
        resp, err := http.DefaultClient.Do(req)
        if err != nil {
                slog.Warn("Remote probe: request failed", mapKeyError, err)
                return nil, "connection failed — probe may be offline"
        }
        defer safeClose(resp.Body, "remote probe response body")

        if failMsg := classifyRemoteProbeStatus(resp.StatusCode); failMsg != "" {
                return nil, failMsg
        }

        return readRemoteProbeBody(resp)
}

func classifyRemoteProbeStatus(code int) string {
        switch code {
        case http.StatusOK:
                return ""
        case http.StatusUnauthorized:
                slog.Error("Remote probe: authentication failed (401) — check PROBE_API_KEY")
                return "authentication failed (401)"
        case http.StatusTooManyRequests:
                slog.Warn("Remote probe: rate limited (429)")
                return "rate limited (429)"
        default:
                slog.Warn("Remote probe: non-200 response", mapKeyStatus, code)
                return fmt.Sprintf("HTTP %d", code)
        }
}

func readRemoteProbeBody(resp *http.Response) (*remoteProbeAPIResp, string) {
        body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
        if err != nil {
                slog.Warn("Remote probe: failed to read response", mapKeyError, err)
                return nil, "response read error"
        }

        var apiResp remoteProbeAPIResp
        if err := json.Unmarshal(body, &apiResp); err != nil {
                slog.Warn("Remote probe: failed to parse response", mapKeyError, err)
                return nil, "response parse error"
        }

        if len(apiResp.Servers) == 0 {
                slog.Warn("Remote probe: no servers in response")
                return nil, "empty response from probe"
        }

        return &apiResp, ""
}

func applyRemoteProbeMetadata(probe map[string]any, apiResp *remoteProbeAPIResp) {
        probe[mapKeyProbeHost] = apiResp.ProbeHost
        probe[mapKeyProbeElapsed] = apiResp.ElapsedSeconds
        if len(apiResp.AllPorts) > 0 {
                probe["multi_port"] = apiResp.AllPorts
        }
}

func smtpProbeVerdictFromSummary(summary *smtpSummary) string {
        if summary.StartTLSSupport == summary.Reachable && summary.ValidCerts == summary.StartTLSSupport {
                return mapKeyAllTls
        }
        if summary.StartTLSSupport > 0 {
                return mapKeyPartialTls
        }
        return mapKeyNoTls
}

func runRemoteProbe(ctx context.Context, apiURL, apiKey string, mxHosts []string, probe map[string]any) map[string]any {
        reqBody, failMsg := marshalRemoteProbeBody(mxHosts)
        if reqBody == nil {
                return remoteProbeFailover(ctx, mxHosts, probe, failMsg)
        }

        probeCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
        defer cancel()

        req, err := http.NewRequestWithContext(probeCtx, "POST", apiURL+"/probe/smtp", bytes.NewReader(reqBody))
        if err != nil {
                slog.Error("Remote probe: failed to create request", mapKeyError, err)
                return remoteProbeFailover(ctx, mxHosts, probe, "request creation error")
        }
        req.Header.Set("Content-Type", "application/json")
        if apiKey != "" {
                req.Header.Set("X-Probe-Key", apiKey)
        }

        apiResp, failMsg := executeRemoteProbeHTTP(req)
        if apiResp == nil {
                return remoteProbeFailover(ctx, mxHosts, probe, failMsg)
        }

        summary := &smtpSummary{TotalServers: len(apiResp.Servers)}
        for _, srv := range apiResp.Servers {
                updateSummary(summary, srv)
        }

        applyRemoteProbeMetadata(probe, apiResp)

        if summary.Reachable == 0 {
                probe[mapKeyStatus] = mapKeySkipped
                probe[mapKeyReason] = "SMTP port 25 not reachable from probe host — all MX servers rejected or timed out on port 25. Transport security assessed via DNS policy records."
                return probe
        }

        probe[mapKeyStatus] = mapKeyObserved
        probe[mapKeyReason] = ""
        probe[mapKeyObservations] = apiResp.Servers
        probe[mapKeySummary] = summaryToMap(summary)
        probe[mapKeyProbeVerdict] = smtpProbeVerdictFromSummary(summary)

        slog.Info("Remote SMTP probe completed",
                mapKeyProbeHost, apiResp.ProbeHost,
                mapKeyVersion, apiResp.Version,
                mapKeyServers, len(apiResp.Servers),
                "all_ports", len(apiResp.AllPorts),
                mapKeyReachable, summary.Reachable,
                mapKeyStarttls, summary.StartTLSSupport,
                "elapsed", apiResp.ElapsedSeconds,
        )

        return probe
}

type smtpProbeResult struct {
        id    string
        label string
        data  map[string]any
}

func runMultiProbe(ctx context.Context, probes []ProbeEndpoint, mxHosts []string, probe map[string]any) map[string]any {
        results := make(chan smtpProbeResult, len(probes))
        for _, p := range probes {
                go func(ep ProbeEndpoint) {
                        single := make(map[string]any)
                        single = runRemoteProbe(ctx, ep.URL, ep.Key, mxHosts, single)
                        results <- smtpProbeResult{id: ep.ID, label: ep.Label, data: single}
                }(p)
        }

        multiResults, primaryResult := collectMultiProbeResults(probes, results)

        if primaryResult == nil {
                primaryResult = resolveMultiProbeFallback(ctx, probes, multiResults, mxHosts)
        }

        applyPrimaryResult(probe, primaryResult)

        probe["multi_probe"] = multiResults
        probe[mapKeyProbeMethod] = "multi_remote"
        probe[mapKeyProbeCount] = len(probes)

        consensus := computeProbeConsensus(multiResults)
        probe["probe_consensus"] = consensus

        slog.Info("Multi-probe SMTP completed",
                mapKeyProbeCount, len(probes),
                "results", len(multiResults),
                "consensus", consensus[mapKeyAgreement],
        )

        return probe
}

func buildMultiProbeEntry(r smtpProbeResult) map[string]any {
        entry := map[string]any{
                "probe_id":      r.id,
                "probe_label":   r.label,
                mapKeyStatus:    r.data[mapKeyStatus],
                mapKeyProbeHost: r.data[mapKeyProbeHost],
                "elapsed":       r.data[mapKeyProbeElapsed],
        }
        if obs, ok := r.data[mapKeyObservations]; ok {
                entry[mapKeyObservations] = obs
        }
        if s, ok := r.data[mapKeySummary]; ok {
                entry[mapKeySummary] = s
        }
        if v, ok := r.data[mapKeyProbeVerdict]; ok {
                entry[mapKeyProbeVerdict] = v
        }
        return entry
}

func collectMultiProbeResults(probes []ProbeEndpoint, results <-chan smtpProbeResult) ([]map[string]any, map[string]any) {
        var multiResults []map[string]any
        var primaryResult map[string]any
        for range probes {
                r := <-results
                entry := buildMultiProbeEntry(r)
                multiResults = append(multiResults, entry)
                if primaryResult == nil && r.data[mapKeyStatus] == mapKeyObserved {
                        primaryResult = r.data
                }
        }
        return multiResults, primaryResult
}

func resolveMultiProbeFallback(ctx context.Context, probes []ProbeEndpoint, multiResults []map[string]any, mxHosts []string) map[string]any {
        if len(multiResults) == 0 {
                return nil
        }
        for _, mr := range multiResults {
                if mr[mapKeyStatus] == mapKeyObserved {
                        return nil
                }
        }
        if len(probes) > 0 {
                first := make(map[string]any)
                first = runRemoteProbe(ctx, probes[0].URL, probes[0].Key, mxHosts, first)
                return first
        }
        return nil
}

func applyPrimaryResult(probe, primaryResult map[string]any) {
        if primaryResult == nil {
                return
        }
        for k, v := range primaryResult {
                probe[k] = v
        }
}

func computeProbeConsensus(results []map[string]any) map[string]any {
        consensus := map[string]any{
                "total_probes":  len(results),
                mapKeyAgreement: "unknown",
        }

        if len(results) == 0 {
                return consensus
        }

        observed := 0
        allTLS := 0
        partialTLS := 0
        noTLS := 0

        for _, r := range results {
                if r[mapKeyStatus] == mapKeyObserved {
                        observed++
                        switch r[mapKeyProbeVerdict] {
                        case mapKeyAllTls:
                                allTLS++
                        case mapKeyPartialTls:
                                partialTLS++
                        case mapKeyNoTls:
                                noTLS++
                        }
                }
        }

        consensus[mapKeyObserved] = observed
        consensus[mapKeyAllTls] = allTLS
        consensus[mapKeyPartialTls] = partialTLS
        consensus[mapKeyNoTls] = noTLS

        if observed == 0 {
                consensus[mapKeyAgreement] = "no_data"
        } else if allTLS == observed {
                consensus[mapKeyAgreement] = "unanimous_tls"
        } else if noTLS == observed {
                consensus[mapKeyAgreement] = "unanimous_no_tls"
        } else if allTLS > 0 && partialTLS == 0 && noTLS == 0 {
                consensus[mapKeyAgreement] = "unanimous_tls"
        } else {
                consensus[mapKeyAgreement] = "split"
        }

        return consensus
}

func runLiveProbe(ctx context.Context, mxHosts []string, probe map[string]any) map[string]any {
        hostsToCheck := mxHosts
        if len(hostsToCheck) > 3 {
                hostsToCheck = hostsToCheck[:3]
        }

        summary := &smtpSummary{TotalServers: len(hostsToCheck)}
        servers := probeSMTPServers(ctx, hostsToCheck, summary)

        if summary.Reachable == 0 {
                probe[mapKeyStatus] = mapKeySkipped
                probe[mapKeyReason] = "SMTP port 25 not reachable from this host — outbound port 25 is likely blocked by the hosting provider. Transport security is assessed via DNS policy records, which is the standards-aligned primary method per NIST SP 800-177 Rev. 1."
                return probe
        }

        probe[mapKeyStatus] = mapKeyObserved
        probe[mapKeyReason] = ""
        probe[mapKeyObservations] = servers
        probe[mapKeySummary] = summaryToMap(summary)

        if summary.StartTLSSupport == summary.Reachable && summary.ValidCerts == summary.StartTLSSupport {
                probe[mapKeyProbeVerdict] = mapKeyAllTls
        } else if summary.StartTLSSupport > 0 {
                probe[mapKeyProbeVerdict] = mapKeyPartialTls
        } else {
                probe[mapKeyProbeVerdict] = mapKeyNoTls
        }

        return probe
}

func derivePrimaryStatus(policy, probe map[string]any) string {
        verdict := mapGetStrSafe(policy, mapKeyVerdict)
        probeStatus := mapGetStrSafe(probe, mapKeyStatus)

        if probeStatus == mapKeyObserved {
                probeVerdict := mapGetStrSafe(probe, mapKeyProbeVerdict)
                if probeVerdict == mapKeyAllTls && (verdict == mapKeyEnforced || verdict == mapKeyMonitored) {
                        return mapKeySuccess
                }
                if probeVerdict == mapKeyAllTls {
                        return mapKeySuccess
                }
                if probeVerdict == mapKeyPartialTls {
                        return "warning"
                }
                return mapKeyError
        }

        switch verdict {
        case mapKeyEnforced:
                return mapKeySuccess
        case mapKeyMonitored:
                return "info"
        case mapKeyOpportunistic:
                return "inferred"
        default:
                return "info"
        }
}

func derivePrimaryMessage(policy, probe map[string]any, mxHosts []string) string {
        verdict := mapGetStrSafe(policy, mapKeyVerdict)
        probeStatus := mapGetStrSafe(probe, mapKeyStatus)
        signals, ok := policy[mapKeySignals].([]string)
        if !ok {
                signals = nil
        }

        if len(mxHosts) == 0 {
                return "No MX records found"
        }

        if probeStatus == mapKeyObserved {
                probeSummary, _ := probe[mapKeySummary].(map[string]any)
                if probeSummary != nil {
                        reachable := int(toFloat64Val(probeSummary[mapKeyReachable]))
                        starttls := int(toFloat64Val(probeSummary[mapKeyStarttlsSupported]))
                        if starttls == reachable && reachable > 0 {
                                return fmt.Sprintf("All %d server(s) verified: encrypted transport confirmed via direct SMTP probe and DNS policy", reachable)
                        }
                        return fmt.Sprintf("%d/%d servers support STARTTLS (direct probe)", starttls, reachable)
                }
        }

        switch verdict {
        case mapKeyEnforced:
                return fmt.Sprintf("Transport encryption enforced via DNS policy (%d signal(s))", len(signals))
        case mapKeyMonitored:
                return fmt.Sprintf("Transport security in monitoring mode (%d signal(s))", len(signals))
        case mapKeyOpportunistic:
                return fmt.Sprintf("Transport security inferred from %d signal(s) — no enforcement policy active", len(signals))
        default:
                return "No transport encryption policy detected — mail delivery relies on opportunistic TLS"
        }
}

func buildInferenceNote(probe map[string]any) string {
        probeStatus := mapGetStrSafe(probe, mapKeyStatus)
        if probeStatus == mapKeyObserved {
                return ""
        }
        return "Transport security assessed via DNS policy records (MTA-STS, DANE, TLS-RPT) — the standards-aligned primary method per NIST SP 800-177 Rev. 1 and RFC 8461. Direct SMTP probing is a supplementary verification step."
}

func buildInferenceSignals(policy, telemetrySection map[string]any) []string {
        signals, ok := policy[mapKeySignals].([]string)
        if !ok {
                signals = nil
        }
        result := make([]string, len(signals))
        copy(result, signals)

        if configured, ok := telemetrySection[mapKeyTlsrptConfigured].(bool); ok && configured {
                hasTLSRPTSignal := false
                for _, s := range result {
                        if strings.Contains(s, "TLS-RPT") {
                                hasTLSRPTSignal = true
                                break
                        }
                }
                if !hasTLSRPTSignal {
                        result = append(result, "TLS-RPT configured — domain monitors TLS delivery failures (RFC 8460)")
                }
        }

        return result
}

func backfillLegacyFields(result map[string]any, policy, probe map[string]any) {
        probeStatus := mapGetStrSafe(probe, mapKeyStatus)

        if probeStatus == mapKeyObserved {
                observations, ok := probe[mapKeyObservations].([]map[string]any)
                if !ok {
                        observations = nil
                }
                result[mapKeyServers] = observations
                if probeSummary, ok := probe[mapKeySummary].(map[string]any); ok {
                        result[mapKeySummary] = probeSummary
                } else {
                        result[mapKeySummary] = emptyLegacySummary()
                }
        } else {
                result[mapKeyServers] = []map[string]any{}
                result[mapKeySummary] = emptyLegacySummary()
        }

        result["issues"] = []string{}
}

func emptyLegacySummary() map[string]any {
        return map[string]any{
                mapKeyTotalServers:      0,
                mapKeyReachable:         0,
                mapKeyStarttlsSupported: 0,
                mapKeyTls13:             0,
                mapKeyTls12:             0,
                mapKeyValidCerts:        0,
                mapKeyExpiringSoon:      0,
        }
}

func identifyProviderName(mxHosts []string) string {
        providerNames := map[string]string{
                "google.com":         "Google Workspace",
                "googlemail.com":     "Google Workspace",
                "outlook.com":        "Microsoft 365",
                "protection.outlook": "Microsoft 365",
                "pphosted.com":       "Proofpoint",
                "mimecast.com":       "Mimecast",
                "messagelabs.com":    "Broadcom/Symantec",
                "fireeyecloud.com":   "Trellix",
                "iphmx.com":          "Cisco Email Security",
                "protonmail.ch":      "Proton Mail",
                "registrar-servers":  "Namecheap",
        }

        for _, host := range mxHosts {
                hostLower := strings.ToLower(host)
                for pattern, name := range providerNames {
                        if strings.Contains(hostLower, pattern) {
                                return name
                        }
                }
        }
        return ""
}

func mapGetStrSafe(m map[string]any, key string) string {
        if m == nil {
                return ""
        }
        v, ok := m[key].(string)
        if !ok {
                return ""
        }
        return v
}

func toFloat64Val(v any) float64 {
        switch n := v.(type) {
        case float64:
                return n
        case int:
                return float64(n)
        case int64:
                return float64(n)
        }
        return 0
}

func probeSMTPServers(ctx context.Context, hosts []string, summary *smtpSummary) []map[string]any {
        var (
                mu      sync.Mutex
                wg      sync.WaitGroup
                servers []map[string]any
        )

        for _, host := range hosts {
                wg.Add(1)
                go func(h string) {
                        defer wg.Done()
                        sr := probeSingleSMTPServer(ctx, h)
                        mu.Lock()
                        servers = append(servers, sr)
                        updateSummary(summary, sr)
                        mu.Unlock()
                }(host)
        }
        wg.Wait()
        return servers
}

func probeSingleSMTPServer(ctx context.Context, host string) map[string]any {
        result := map[string]any{
                "host":                  host,
                mapKeyReachable:         false,
                mapKeyStarttls:          false,
                mapKeyTlsVersion:        nil,
                mapKeyCipher:            nil,
                mapKeyCipherBits:        nil,
                mapKeyCertValid:         false,
                mapKeyCertExpiry:        nil,
                mapKeyCertDaysRemaining: nil,
                mapKeyCertIssuer:        nil,
                mapKeyCertSubject:       nil,
                mapKeyError:             nil,
        }

        probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
        defer cancel()

        conn, err := dialSMTP(probeCtx, host)
        if err != nil {
                result[mapKeyError] = classifySMTPError(err)
                return result
        }
        defer safeClose(conn, "smtp connection")

        result[mapKeyReachable] = true

        banner, err := readSMTPResponse(conn, 2*time.Second)
        if err != nil || !strings.HasPrefix(banner, smtpBannerPrefix) {
                result[mapKeyError] = "Unexpected SMTP banner"
                return result
        }

        _, err = fmt.Fprintf(conn, "EHLO dnstool.local\r\n")
        if err != nil {
                result[mapKeyError] = "EHLO failed"
                return result
        }

        ehloResp, err := readSMTPResponse(conn, 2*time.Second)
        if err != nil {
                result[mapKeyError] = "EHLO response timeout"
                return result
        }

        if !strings.Contains(strings.ToUpper(ehloResp), "STARTTLS") {
                result[mapKeyError] = "STARTTLS not supported"
                return result
        }

        result[mapKeyStarttls] = true

        _, err = fmt.Fprintf(conn, "STARTTLS\r\n")
        if err != nil {
                result[mapKeyError] = "STARTTLS command failed"
                return result
        }

        starttlsResp, err := readSMTPResponse(conn, 2*time.Second)
        if err != nil || !strings.HasPrefix(starttlsResp, smtpBannerPrefix) {
                result[mapKeyError] = fmt.Sprintf("STARTTLS rejected: %s", truncate(starttlsResp, 50))
                return result
        }

        negotiateTLS(probeCtx, conn, host, result)

        return result
}

func negotiateTLS(ctx context.Context, conn net.Conn, host string, result map[string]any) {
        tlsCfg := &tls.Config{ //nolint:gosec // Intentional: diagnostic tool must connect to servers with self-signed/expired/mismatched certs to inspect and report on their TLS configuration. Certificate validation is performed separately in verifyCert().
                ServerName:         host,
                InsecureSkipVerify: true, //NOSONAR — S4830/S5527: deliberate diagnostic probe; verifyCert() validates independently // SECINTENT-001
        }
        tlsConn := tls.Client(conn, tlsCfg)
        defer safeClose(tlsConn, "tls connection")

        if err := tlsConn.Handshake(); err != nil {
                result[mapKeyError] = fmt.Sprintf("TLS handshake failed: %s", truncate(err.Error(), 80))
                return
        }

        state := tlsConn.ConnectionState()
        result[mapKeyTlsVersion] = tlsVersionString(state.Version)
        result[mapKeyCipher] = tls.CipherSuiteName(state.CipherSuite)
        result[mapKeyCipherBits] = cipherBits(state.CipherSuite)

        verifyCert(ctx, host, result)
}

func verifyCert(ctx context.Context, host string, result map[string]any) {
        verifyCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
        defer cancel()

        dialer := &net.Dialer{Timeout: 2 * time.Second}
        verifyConn, err := dialSMTPWithDialer(verifyCtx, dialer, host)
        if err != nil {
                return
        }
        defer safeClose(verifyConn, "verify connection")

        banner, _ := readSMTPResponse(verifyConn, 1*time.Second)
        if !strings.HasPrefix(banner, smtpBannerPrefix) {
                return
        }
        fmt.Fprintf(verifyConn, "EHLO dnstool.local\r\n")
        readSMTPResponse(verifyConn, 1*time.Second)
        fmt.Fprintf(verifyConn, "STARTTLS\r\n")
        resp, _ := readSMTPResponse(verifyConn, 1*time.Second)
        if !strings.HasPrefix(resp, smtpBannerPrefix) {
                return
        }

        verifyCfg := &tls.Config{ServerName: host}
        verifyTLS := tls.Client(verifyConn, verifyCfg)
        defer safeClose(verifyTLS, "verify tls connection")

        if err := verifyTLS.Handshake(); err != nil {
                result[mapKeyCertValid] = false
                result[mapKeyError] = fmt.Sprintf("Certificate invalid: %s", truncate(err.Error(), 100))
                return
        }

        result[mapKeyCertValid] = true
        certs := verifyTLS.ConnectionState().PeerCertificates
        if len(certs) > 0 {
                leaf := certs[0]
                result[mapKeyCertExpiry] = leaf.NotAfter.Format("2006-01-02")
                result[mapKeyCertDaysRemaining] = int(time.Until(leaf.NotAfter).Hours() / 24)
                result[mapKeyCertSubject] = leaf.Subject.CommonName
                if leaf.Issuer.Organization != nil && len(leaf.Issuer.Organization) > 0 {
                        result[mapKeyCertIssuer] = leaf.Issuer.Organization[0]
                } else {
                        result[mapKeyCertIssuer] = leaf.Issuer.CommonName
                }
        }
}

func dialSMTP(ctx context.Context, host string) (net.Conn, error) {
        dialer := &net.Dialer{Timeout: 2 * time.Second}
        return dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "25"))
}

func dialSMTPWithDialer(ctx context.Context, dialer *net.Dialer, host string) (net.Conn, error) {
        return dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "25"))
}

func readSMTPResponse(conn net.Conn, timeout time.Duration) (string, error) {
        conn.SetReadDeadline(time.Now().Add(timeout))
        buf := make([]byte, 4096)
        var response strings.Builder
        for {
                n, err := conn.Read(buf)
                if n > 0 {
                        response.Write(buf[:n])
                        if smtpResponseComplete(response.String()) {
                                break
                        }
                }
                if err != nil {
                        return handlePartialResponse(response, err)
                }
        }
        return response.String(), nil
}

func smtpResponseComplete(data string) bool {
        lines := strings.Split(data, "\n")
        lastLine := strings.TrimSpace(lines[len(lines)-1])
        if lastLine == "" && len(lines) > 1 {
                lastLine = strings.TrimSpace(lines[len(lines)-2])
        }
        return len(lastLine) >= 4 && lastLine[3] == ' '
}

func handlePartialResponse(response strings.Builder, err error) (string, error) {
        if response.Len() > 0 {
                return response.String(), nil
        }
        return "", err
}

func classifySMTPError(err error) string {
        errStr := err.Error()
        if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
                return "Connection timeout"
        }
        if strings.Contains(errStr, "refused") {
                return "Connection refused"
        }
        if strings.Contains(errStr, "unreachable") {
                return "Network unreachable"
        }
        if strings.Contains(errStr, "no such host") {
                return "DNS resolution failed"
        }
        return truncate(errStr, 80)
}

func tlsVersionString(v uint16) string {
        switch v {
        case tls.VersionTLS13:
                return "TLSv1.3"
        case tls.VersionTLS12:
                return "TLSv1.2"
        case tls.VersionTLS11:
                return "TLSv1.1"
        case tls.VersionTLS10:
                return "TLSv1.0"
        default:
                return fmt.Sprintf("TLS 0x%04x", v)
        }
}

func cipherBits(suite uint16) int {
        name := tls.CipherSuiteName(suite)
        if strings.Contains(name, "256") || strings.Contains(name, "CHACHA20") {
                return 256
        }
        if strings.Contains(name, "128") {
                return 128
        }
        return 0
}

func truncate(s string, maxLen int) string {
        if len(s) <= maxLen {
                return s
        }
        return s[:maxLen]
}

func updateSummary(s *smtpSummary, sr map[string]any) {
        if sr[mapKeyReachable] == true {
                s.Reachable++
        }
        if sr[mapKeyStarttls] == true {
                s.StartTLSSupport++
        }
        if v, ok := sr[mapKeyTlsVersion].(string); ok {
                if v == "TLSv1.3" {
                        s.TLS13++
                } else if v == "TLSv1.2" {
                        s.TLS12++
                }
        }
        if sr[mapKeyCertValid] == true {
                s.ValidCerts++
        }
        if dr, ok := sr[mapKeyCertDaysRemaining].(int); ok && dr < 30 {
                s.ExpiringSoon++
        }
}

func summaryToMap(s *smtpSummary) map[string]any {
        return map[string]any{
                mapKeyTotalServers:      s.TotalServers,
                mapKeyReachable:         s.Reachable,
                mapKeyStarttlsSupported: s.StartTLSSupport,
                mapKeyTls13:             s.TLS13,
                mapKeyTls12:             s.TLS12,
                mapKeyValidCerts:        s.ValidCerts,
                mapKeyExpiringSoon:      s.ExpiringSoon,
        }
}

func inferFromProvider(mxHosts []string) string {
        providerMap := map[string]string{
                "google.com":         "Google Workspace enforces TLS 1.2+ with valid certificates on all inbound/outbound mail",
                "googlemail.com":     "Google Workspace enforces TLS 1.2+ with valid certificates on all inbound/outbound mail",
                "outlook.com":        "Microsoft 365 enforces TLS 1.2+ with DANE (GA Oct 2024) and valid certificates",
                "protection.outlook": "Microsoft 365 enforces TLS 1.2+ with DANE (GA Oct 2024) and valid certificates",
                "pphosted.com":       "Proofpoint enforces TLS on managed mail transport",
                "mimecast.com":       "Mimecast enforces TLS on managed mail transport",
                "messagelabs.com":    "Broadcom/Symantec Email Security enforces TLS",
                "fireeyecloud.com":   "Trellix Email Security enforces TLS",
                "iphmx.com":          "Cisco Email Security enforces TLS",
                "protonmail.ch":      "Proton Mail enforces TLS 1.2+ with DANE support",
                "registrar-servers":  "Namecheap mail service supports TLS",
        }

        for _, host := range mxHosts {
                hostLower := strings.ToLower(host)
                for pattern, description := range providerMap {
                        if strings.Contains(hostLower, pattern) {
                                return description
                        }
                }
        }
        return ""
}

func getIssuesList(result map[string]any) []string {
        if issues, ok := result["issues"].([]string); ok {
                return issues
        }
        return []string{}
}
