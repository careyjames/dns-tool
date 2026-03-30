// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "fmt"
        "log/slog"
        "strings"
        "sync"
        "time"

        "dnstool/go-server/internal/dnsclient"
        "dnstool/go-server/internal/icuae"
)

const (
        logTaskCompleted  = "Task completed"
        msgDomainNotExist = "Domain does not exist or is not delegated"
        msgDomainNoExist  = "Domain does not exist"

        mapKeyAiSurface             = "ai_surface"
        mapKeyAuthTtl               = "auth_ttl"
        mapKeyBasicRecords          = "basic_records"
        mapKeyCdsCdnskey            = "cds_cdnskey"
        mapKeyCtSubdomains          = "ct_subdomains"
        mapKeyDelegationConsistency = "delegation_consistency"
        mapKeyDkimAnalysis          = "dkim_analysis"
        mapKeyDmarc                 = "dmarc"
        mapKeyDnssecOps             = "dnssec_ops"
        mapKeyElapsedMs             = "elapsed_ms"
        mapKeyEmailHosting          = "email_hosting"
        mapKeyHasNullMx             = "has_null_mx"
        mapKeyHostingSummary        = "hosting_summary"
        mapKeyHttpsSvcb             = "https_svcb"
        mapKeyIsNoMailDomain        = "is_no_mail_domain"
        mapKeyMtaSts                = "mta_sts"
        mapKeyNmapDns               = "nmap_dns"
        mapKeyNsFleet               = "ns_fleet"
        mapKeyRegistrar             = "registrar"
        mapKeyResolverConsensus     = "resolver_consensus"
        mapKeyResolverTtl           = "resolver_ttl"
        mapKeySecretExposure        = "secret_exposure"
        mapKeySecurityTxt           = "security_txt"
        mapKeySmimeaOpenpgpkey      = "smimea_openpgpkey"
        mapKeySmtpTransport         = "smtp_transport"
        mapKeySubdomains            = "subdomains"
        mapKeyTlsrpt                = "tlsrpt"
        mapKeyWeb3                  = "web3_analysis"
        strNotChecked               = "Not checked"
        statusInfoOrch              = "info"
        mapKeyTaskOrch              = "task"
        mapKeyDaneOrch              = "dane"
        mapKeySpfOrch               = "spf"
        mapKeyDkimOrch              = "dkim"

        statusNA     = "n/a"
        displayNA    = "N/A"
        fmtElapsedMs = "%.0f"
        fmtSeconds   = "%.2f"
        mapKeyBimi   = "bimi"
)

type ProgressCallback func(phaseGroup, status string, durationMs int)

type AnalysisOptions struct {
        ExposureChecks   bool
        OnPhaseProgress  ProgressCallback
}

type namedResult struct {
        key         string
        result      any
        elapsed     time.Duration
        startOffset time.Duration
}

func (a *Analyzer) AnalyzeDomain(ctx context.Context, domain string, customDKIMSelectors []string, opts ...AnalysisOptions) map[string]any {
        var options AnalysisOptions
        if len(opts) > 0 {
                options = opts[0]
        }
        if rejected := a.acquireSlot(domain); rejected != nil {
                return rejected
        }
        defer func() { <-a.semaphore }()

        ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
        defer cancel()

        originalInput := domain
        inputKind := ClassifyInput(domain)
        web3Resolution, resolved, earlyReturn := a.resolveWeb3Input(ctx, domain, inputKind)
        if earlyReturn != nil {
                return earlyReturn
        }
        if resolved != "" {
                domain = resolved
        }

        domainStatus, domainStatusMessage, earlyReturn := a.checkExistence(ctx, domain, originalInput, inputKind, web3Resolution)
        if earlyReturn != nil {
                return earlyReturn
        }

        analysisStart := time.Now()
        scope := web3Resolution.AnalysisScope
        if scope == "" {
                scope = ScopeOwnedDNS
        }
        resultsMap, timings := a.runScopedAnalyses(ctx, domain, customDKIMSelectors, analysisStart, options.OnPhaseProgress, scope)

        parallelElapsed := time.Since(analysisStart).Seconds()
        slog.Info("Parallel lookups completed", mapKeyDomain, domain, "elapsed_s", fmt.Sprintf(fmtSeconds, parallelElapsed), "tasks", len(resultsMap), "scope", scope)

        engineStart := time.Now()
        if options.OnPhaseProgress != nil {
                options.OnPhaseProgress("analysis_engine", "running", 0)
        }

        results, seqTimings := a.assembleResults(ctx, domain, resultsMap, domainStatus, domainStatusMessage, options, analysisStart, scope)
        timings = append(timings, seqTimings...)

        annotateWeb3Results(results, web3Resolution, originalInput, inputKind)

        provenance := buildAnalysisProvenance(inputKind, scope, web3Resolution, results)
        results["_analysis_provenance"] = provenance
        results["_schema_version"] = 2

        totalElapsed := time.Since(analysisStart).Seconds()
        slog.Info("Analysis complete", mapKeyDomain, domain, "total_s", fmt.Sprintf(fmtSeconds, totalElapsed), "parallel_s", fmt.Sprintf(fmtSeconds, parallelElapsed))

        engineDurMs := int(time.Since(engineStart).Milliseconds())
        telemetry := NewScanTelemetry(timings, int(time.Since(analysisStart).Milliseconds()))
        results["_scan_telemetry"] = telemetry

        if options.OnPhaseProgress != nil {
                options.OnPhaseProgress("analysis_engine", "done", engineDurMs)
        }

        return results
}

func (a *Analyzer) acquireSlot(domain string) map[string]any {
        queueStart := time.Now()
        select {
        case a.semaphore <- struct{}{}:
                go func() {
                        if waited := time.Since(queueStart); waited > 500*time.Millisecond {
                                slog.Info("Analysis queued before slot opened", mapKeyDomain, domain, "waited_ms", waited.Milliseconds())
                        }
                }()
                return nil
        case <-time.After(30 * time.Second):
                a.backpressureRejections.Add(1)
                slog.Warn("Backpressure: rejected analysis after 30s queue", mapKeyDomain, domain)
                return map[string]any{
                        mapKeyDomain:       domain,
                        mapKeyError:        "System is currently at capacity. Please try again in a moment.",
                        "analysis_success": false,
                }
        }
}

func (a *Analyzer) resolveWeb3Input(ctx context.Context, domain string, inputKind InputKind) (Web3ResolutionResult, string, map[string]any) {
        var web3Resolution Web3ResolutionResult
        if inputKind == InputKindDNSDomain {
                return web3Resolution, "", nil
        }
        web3Resolution = a.ResolveWeb3Domain(ctx, domain)
        if web3Resolution.ResolvedDomain != "" && web3Resolution.Error == "" {
                slog.Info("Web3 input resolved", "original", domain, "resolved", web3Resolution.ResolvedDomain,
                        "type", web3Resolution.ResolutionType, "scope", web3Resolution.AnalysisScope,
                        "is_gateway", web3Resolution.IsGatewayDomain)
                return web3Resolution, web3Resolution.ResolvedDomain, nil
        }
        if web3Resolution.Error != "" {
                msg := fmt.Sprintf("Web3 domain resolution failed for %s: %s", domain, web3Resolution.Error)
                result := a.buildNonExistentResult(domain, "web3_unresolved", &msg)
                result["web3_resolution"] = web3Resolution.ToMap()
                result["input_kind"] = string(inputKind)
                result["_schema_version"] = 2
                result["_analysis_provenance"] = buildAnalysisProvenance(inputKind, web3Resolution.AnalysisScope, web3Resolution, result)
                return web3Resolution, "", result
        }
        return web3Resolution, "", nil
}

func (a *Analyzer) checkExistence(ctx context.Context, domain, originalInput string, inputKind InputKind, web3 Web3ResolutionResult) (string, *string, map[string]any) {
        if web3.IsWeb3Input && web3.ResolutionType == "hns" && web3.Error == "" {
                msg := "Handshake domain resolved via HNS resolver"
                return "hns_resolved", &msg, nil
        }
        exists, ds, dsm := a.checkDomainExists(ctx, domain)
        if exists {
                return ds, dsm, nil
        }
        result := a.buildNonExistentResult(domain, ds, dsm)
        if web3.IsWeb3Input {
                result["web3_resolution"] = web3.ToMap()
                result[mapKeyDomain] = originalInput
                result["input_kind"] = string(inputKind)
        }
        result["_schema_version"] = 2
        result["_analysis_provenance"] = buildAnalysisProvenance(inputKind, ScopeOwnedDNS, web3, result)
        return ds, dsm, result
}

func annotateWeb3Results(results map[string]any, web3 Web3ResolutionResult, originalInput string, inputKind InputKind) {
        if !web3.IsWeb3Input {
                return
        }
        results["web3_resolution"] = web3.ToMap()
        results["web3_original_input"] = originalInput
        results["input_kind"] = string(inputKind)
        if w3a, ok := results[mapKeyWeb3].(map[string]any); ok {
                w3a["resolution_info"] = web3.ToMap()
        }
        if web3.AttributionWarning != "" {
                results["attribution_warning"] = web3.AttributionWarning
        }
}

func (a *Analyzer) assembleResults(ctx context.Context, domain string, resultsMap map[string]any, domainStatus string, domainStatusMessage *string, options AnalysisOptions, analysisStart time.Time, scope ...AnalysisScope) (map[string]any, []PhaseTiming) {
        analysisScope := ScopeOwnedDNS
        if len(scope) > 0 && scope[0] != "" {
                analysisScope = scope[0]
        }
        basic := getMapResult(resultsMap, "basic")
        auth := getMapResult(resultsMap, "auth")

        resolverTTL := extractAndRemove(basic, "_ttl")
        authTTL := extractAndRemove(auth, "_ttl")
        authQueryStatus := extractAndRemove(auth, "_query_status")

        isTLD := dnsclient.IsTLDInput(domain)
        mxForDANE, _ := basic["MX"].([]string)

        postCtx, postCancel := context.WithTimeout(ctx, 15*time.Second)
        defer postCancel()

        progressCb := options.OnPhaseProgress
        var seqTimings []PhaseTiming

        daneStart := time.Now()
        if progressCb != nil {
                progressCb("dnssec_dane", "running", 0)
        }
        resultsMap[mapKeyDaneOrch] = a.AnalyzeDANE(postCtx, domain, mxForDANE)
        daneDur := time.Since(daneStart)
        daneDurMs := int(daneDur.Milliseconds())
        slog.Info(logTaskCompleted, mapKeyTaskOrch, mapKeyDaneOrch, mapKeyDomain, domain, mapKeyElapsedMs, fmt.Sprintf(fmtElapsedMs, float64(daneDurMs)))
        seqTimings = append(seqTimings, PhaseTiming{PhaseGroup: "dnssec_dane", PhaseTask: "dane", StartedAtMs: int(daneStart.Sub(analysisStart).Milliseconds()), DurationMs: daneDurMs})
        if progressCb != nil {
                progressCb("dnssec_dane", "done", daneDurMs)
        }

        smtpStart := time.Now()
        if progressCb != nil {
                progressCb("smtp_transport", "running", 0)
        }
        smtpResult := a.computeSMTPResult(postCtx, domain, isTLD, mxForDANE, resultsMap)
        smtpDur := time.Since(smtpStart)
        smtpDurMs := int(smtpDur.Milliseconds())
        seqTimings = append(seqTimings, PhaseTiming{PhaseGroup: "smtp_transport", PhaseTask: "smtp_transport", StartedAtMs: int(smtpStart.Sub(analysisStart).Milliseconds()), DurationMs: smtpDurMs})
        if progressCb != nil {
                progressCb("smtp_transport", "done", smtpDurMs)
        }

        enrichBasicRecords(basic, resultsMap)

        if !isTLD {
                enrichMisplacedDMARC(basic, resultsMap)
        }

        spfAnalysis := getMapResult(resultsMap, mapKeySpfOrch)

        results := buildCoreResults(domain, domainStatus, domainStatusMessage, basic, auth, resolverTTL, authTTL, authQueryStatus, resultsMap, spfAnalysis)
        results[mapKeySmtpTransport] = smtpResult

        engineStart := time.Now()
        a.enrichWithHostingAndSecurity(ctx, domain, results, resultsMap, spfAnalysis)
        populateExtendedResults(results, resultsMap)
        web3Timing := a.enrichWithPostAnalysis(ctx, domain, results, resultsMap, options, analysisStart)
        seqTimings = append(seqTimings, web3Timing)

        results["is_tld"] = isTLD
        results["analysis_scope"] = string(analysisScope)
        if analysisScope == ScopeGatewayDerived {
                results["posture"] = buildGatewayPosture(results)
                results["remediation"] = map[string]any{"status": "not_applicable", "reason": "gateway_derived", "items": []any{}}
                results["mail_posture"] = map[string]any{"status": "not_applicable", "reason": "gateway_derived"}
        } else {
                results["posture"] = a.CalculatePosture(results)
                results["remediation"] = a.GenerateRemediation(results)
                results["mail_posture"] = buildMailPosture(results)
        }

        populateTTLReports(results)
        engineDur := time.Since(engineStart)
        seqTimings = append(seqTimings, PhaseTiming{PhaseGroup: "analysis_engine", PhaseTask: "synthesis", StartedAtMs: int(engineStart.Sub(analysisStart).Milliseconds()), DurationMs: int(engineDur.Milliseconds())})

        return results, seqTimings
}

func buildCoreResults(domain, domainStatus string, domainStatusMessage *string, basic, auth map[string]any, resolverTTL, authTTL, authQueryStatus any, resultsMap map[string]any, spfAnalysis map[string]any) map[string]any {
        return map[string]any{
                mapKeyDomain:             domain,
                "domain_exists":          true,
                "domain_status":          domainStatus,
                "domain_status_message":  derefStr(domainStatusMessage),
                "section_status":         buildSectionStatus(resultsMap),
                mapKeyBasicRecords:       basic,
                "authoritative_records":  auth,
                "auth_query_status":      authQueryStatus,
                mapKeyResolverTtl:        resolverTTL,
                mapKeyAuthTtl:            authTTL,
                "propagation_status":     buildPropagationStatus(basic, auth),
                "spf_analysis":           getOrDefault(resultsMap, mapKeySpfOrch, map[string]any{mapKeyStatus: mapKeyError}),
                "dmarc_analysis":         getOrDefault(resultsMap, mapKeyDmarc, map[string]any{mapKeyStatus: mapKeyError}),
                mapKeyDkimAnalysis:       getOrDefault(resultsMap, mapKeyDkimOrch, map[string]any{mapKeyStatus: mapKeyError}),
                "mta_sts_analysis":       getOrDefault(resultsMap, mapKeyMtaSts, map[string]any{mapKeyStatus: mapKeyWarning}),
                "tlsrpt_analysis":        getOrDefault(resultsMap, mapKeyTlsrpt, map[string]any{mapKeyStatus: mapKeyWarning}),
                "bimi_analysis":          getOrDefault(resultsMap, mapKeyBimi, map[string]any{mapKeyStatus: mapKeyWarning}),
                "dane_analysis":          getOrDefault(resultsMap, mapKeyDaneOrch, map[string]any{mapKeyStatus: statusInfoOrch, "has_dane": false, "tlsa_records": []any{}, mapKeyIssues: []string{}}),
                "caa_analysis":           getOrDefault(resultsMap, "caa", map[string]any{mapKeyStatus: mapKeyWarning}),
                "dnssec_analysis":        getOrDefault(resultsMap, "dnssec", map[string]any{mapKeyStatus: mapKeyWarning}),
                "ns_delegation_analysis": getOrDefault(resultsMap, "ns_delegation", map[string]any{mapKeyStatus: mapKeyWarning}),
                "registrar_info":         getOrDefault(resultsMap, mapKeyRegistrar, map[string]any{mapKeyStatus: mapKeyError, mapKeyRegistrar: nil}),
                mapKeyResolverConsensus:  getOrDefault(resultsMap, mapKeyResolverConsensus, map[string]any{}),
                mapKeyCtSubdomains:       getOrDefault(resultsMap, mapKeyCtSubdomains, map[string]any{mapKeyStatus: mapKeyError, mapKeySubdomains: []any{}, "unique_subdomains": 0}),
                mapKeyHasNullMx:          detectNullMX(basic),
                mapKeyIsNoMailDomain:     spfAnalysis["no_mail_intent"] == true,
        }
}

func (a *Analyzer) enrichWithHostingAndSecurity(ctx context.Context, domain string, results, resultsMap, spfAnalysis map[string]any) {
        results[mapKeyHostingSummary] = a.GetHostingInfo(ctx, domain, results)
        adjustHostingSummary(results)
        results["dns_infrastructure"] = a.AnalyzeDNSInfrastructure(domain, results)
        results["email_security_mgmt"] = a.DetectEmailSecurityManagement(
                spfAnalysis,
                getMapResult(resultsMap, mapKeyDmarc),
                getMapResult(resultsMap, mapKeyTlsrpt),
                getMapResult(resultsMap, mapKeyMtaSts),
                domain,
                getMapResult(resultsMap, mapKeyDkimOrch),
        )
        authCtx, authCancel := context.WithTimeout(ctx, 10*time.Second)
        defer authCancel()
        results["dmarc_report_auth"] = a.ValidateDMARCExternalAuth(authCtx, domain, getMapResult(resultsMap, mapKeyDmarc))
}

func populateExtendedResults(results, resultsMap map[string]any) {
        results[mapKeyHttpsSvcb] = getOrDefault(resultsMap, mapKeyHttpsSvcb, map[string]any{mapKeyStatus: statusInfoOrch, "has_https": false, "has_svcb": false})
        results[mapKeyCdsCdnskey] = getOrDefault(resultsMap, mapKeyCdsCdnskey, map[string]any{mapKeyStatus: statusInfoOrch, "has_cds": false, "has_cdnskey": false})
        results[mapKeySmimeaOpenpgpkey] = getOrDefault(resultsMap, mapKeySmimeaOpenpgpkey, map[string]any{mapKeyStatus: statusInfoOrch, "has_smimea": false, "has_openpgpkey": false})
        results[mapKeySecurityTxt] = getOrDefault(resultsMap, mapKeySecurityTxt, map[string]any{mapKeyStatus: statusInfoOrch, mapKeyFound: false, mapKeyMessage: strNotChecked, "contacts": []string{}, mapKeyIssues: []string{}})
        results[mapKeyAiSurface] = getOrDefault(resultsMap, mapKeyAiSurface, map[string]any{mapKeyStatus: statusInfoOrch, mapKeyMessage: strNotChecked})
        results[mapKeySecretExposure] = getOrDefault(resultsMap, mapKeySecretExposure, map[string]any{mapKeyStatus: "clear", mapKeyMessage: strNotChecked, "finding_count": 0, "findings": []map[string]any{}, "scanned_urls": []string{}})
        results[mapKeyNmapDns] = getOrDefault(resultsMap, mapKeyNmapDns, map[string]any{mapKeyStatus: statusInfoOrch, mapKeyMessage: strNotChecked, mapKeyIssues: []string{}})
        results[mapKeyDelegationConsistency] = getOrDefault(resultsMap, mapKeyDelegationConsistency, map[string]any{mapKeyStatus: statusInfoOrch, mapKeyMessage: strNotChecked})
        results[mapKeyNsFleet] = getOrDefault(resultsMap, mapKeyNsFleet, map[string]any{mapKeyStatus: statusInfoOrch, mapKeyMessage: strNotChecked, "fleet": []map[string]any{}, mapKeyIssues: []string{}})
        results[mapKeyDnssecOps] = getOrDefault(resultsMap, mapKeyDnssecOps, map[string]any{mapKeyStatus: statusInfoOrch, mapKeyMessage: strNotChecked})
}

func (a *Analyzer) enrichWithPostAnalysis(ctx context.Context, domain string, results, resultsMap map[string]any, options AnalysisOptions, analysisStart time.Time) PhaseTiming {
        if options.ExposureChecks {
                exposureStart := time.Now()
                results["web_exposure"] = a.ScanWebExposure(ctx, domain)
                slog.Info(logTaskCompleted, mapKeyTaskOrch, "web_exposure", mapKeyDomain, domain, mapKeyElapsedMs, fmt.Sprintf(fmtElapsedMs, float64(time.Since(exposureStart).Milliseconds())))
        }

        results["saas_txt"] = ExtractSaaSTXTFootprint(results)

        progressCb := options.OnPhaseProgress

        web3Start := time.Now()
        if progressCb != nil {
                progressCb("web3_analysis", "running", 0)
        }
        basicForWeb3 := getMapResult(results, mapKeyBasicRecords)
        txtRecords := ExtractTXTFromBasicRecords(basicForWeb3)
        dnssecForWeb3 := getMapResult(results, "dnssec_analysis")
        web3Result := a.AnalyzeWeb3(ctx, domain, txtRecords, dnssecForWeb3)
        results[mapKeyWeb3] = web3Result
        web3Dur := time.Since(web3Start)
        web3DurMs := int(web3Dur.Milliseconds())
        slog.Info(logTaskCompleted, mapKeyTaskOrch, "web3_analysis", mapKeyDomain, domain, mapKeyElapsedMs, fmt.Sprintf(fmtElapsedMs, float64(web3DurMs)))
        if progressCb != nil {
                progressCb("web3_analysis", "done", web3DurMs)
        }

        a.enrichWeb3WithFleetProbe(ctx, domain, web3Result)

        results["asn_info"] = a.LookupASN(ctx, results)
        results["edge_cdn"] = DetectEdgeCDN(results)
        enrichHostingFromEdgeCDN(results)

        ctData := getMapResult(resultsMap, mapKeyCtSubdomains)
        ctSubdomains, _ := ctData[mapKeySubdomains].([]map[string]any)
        results["dangling_dns"] = a.DetectDanglingDNS(ctx, domain, ctSubdomains)

        return PhaseTiming{
                PhaseGroup:  "web3_analysis",
                PhaseTask:   "web3_analysis",
                StartedAtMs: int(web3Start.Sub(analysisStart).Milliseconds()),
                DurationMs:  web3DurMs,
        }
}

func populateTTLReports(results map[string]any) {
        resolverTTLMap, _ := results[mapKeyResolverTtl].(map[string]uint32)
        authTTLMap, _ := results[mapKeyAuthTtl].(map[string]uint32)
        if resolverTTLMap == nil {
                resolverTTLMap = map[string]uint32{}
        }
        if authTTLMap == nil {
                authTTLMap = map[string]uint32{}
        }
        results["freshness_matrix"] = BuildCurrencyMatrix(resolverTTLMap, authTTLMap)
        results["currency_report"] = buildICuAEReport(resolverTTLMap, authTTLMap, results)
}

func (a *Analyzer) computeSMTPResult(ctx context.Context, domain string, isTLD bool, mxForDANE []string, resultsMap map[string]any) map[string]any {
        if isTLD {
                for _, key := range []string{mapKeySpfOrch, mapKeyDmarc, mapKeyDkimOrch, mapKeyMtaSts, mapKeyTlsrpt, mapKeyBimi, mapKeyCtSubdomains, mapKeySmimeaOpenpgpkey, mapKeySecurityTxt, mapKeyAiSurface, mapKeySecretExposure} {
                        resultsMap[key] = map[string]any{mapKeyStatus: statusNA}
                }
                slog.Info("TLD analysis — skipped email/subdomain protocols", mapKeyDomain, domain)
                return map[string]any{mapKeyStatus: statusNA, "reason": "TLD — email transport not applicable"}
        }
        smtpStart := time.Now()
        smtpInputs := AnalysisInputs{
                MTASTSResult: getMapResult(resultsMap, mapKeyMtaSts),
                TLSRPTResult: getMapResult(resultsMap, mapKeyTlsrpt),
                DANEResult:   getMapResult(resultsMap, mapKeyDaneOrch),
        }
        result := a.AnalyzeSMTPTransport(ctx, domain, mxForDANE, smtpInputs)
        slog.Info(logTaskCompleted, mapKeyTaskOrch, mapKeySmtpTransport, mapKeyDomain, domain, mapKeyElapsedMs, fmt.Sprintf(fmtElapsedMs, float64(time.Since(smtpStart).Milliseconds())))
        return result
}

func enrichMisplacedDMARC(basic, resultsMap map[string]any) {
        rootTXT, _ := basic["TXT"].([]string)
        misplacedDMARC := DetectMisplacedDMARC(rootTXT)
        if misplacedDMARC["detected"] != true {
                return
        }
        dmarcResult, ok := resultsMap[mapKeyDmarc].(map[string]any)
        if !ok {
                return
        }
        dmarcResult["misplaced_dmarc"] = misplacedDMARC
        if msg, ok := misplacedDMARC[mapKeyMessage].(string); ok && msg != "" {
                existingIssues, _ := dmarcResult[mapKeyIssues].([]string)
                if existingIssues == nil {
                        existingIssues = []string{}
                }
                dmarcResult[mapKeyIssues] = append(existingIssues, msg)
        }
}

func (a *Analyzer) checkDomainExists(ctx context.Context, domain string) (bool, string, *string) {
        for _, rtype := range []string{"A", "TXT", "MX"} {
                if len(a.DNS.QueryDNS(ctx, rtype, domain)) > 0 {
                        return true, "active", nil
                }
        }

        if len(a.DNS.QueryDNS(ctx, "NS", domain)) > 0 {
                return true, "active", nil
        }

        msg := "Domain is not delegated or has no DNS records. This may be an unused subdomain or unregistered domain."
        return false, "undelegated", &msg
}

func timedTask(ch chan<- namedResult, key string, analysisStart time.Time, fn func() any) func() {
        return func() {
                start := time.Now()
                result := fn()
                ch <- namedResult{key, result, time.Since(start), start.Sub(analysisStart)}
        }
}

func timedTaskWithProgress(ch chan<- namedResult, key string, analysisStart time.Time, progressCb ProgressCallback, fn func() any) func() {
        return func() {
                group := LookupPhaseGroup(key)
                if progressCb != nil {
                        progressCb(group, "running", 0)
                }
                start := time.Now()
                result := fn()
                ch <- namedResult{key, result, time.Since(start), start.Sub(analysisStart)}
        }
}

func (a *Analyzer) buildCoreTasks(ctx context.Context, domain string, ch chan namedResult, t0 time.Time, progressCb ProgressCallback) []func() {
        tt := func(key string, fn func() any) func() {
                return timedTaskWithProgress(ch, key, t0, progressCb, fn)
        }
        return []func(){
                tt("basic", func() any { return a.GetBasicRecords(ctx, domain) }),
                tt("auth", func() any { return a.GetAuthoritativeRecords(ctx, domain) }),
                tt("caa", func() any { return a.AnalyzeCAA(ctx, domain) }),
                tt("dnssec", func() any { return a.AnalyzeDNSSEC(ctx, domain) }),
                tt("ns_delegation", func() any { return a.AnalyzeNSDelegation(ctx, domain) }),
                tt(mapKeyRegistrar, func() any { return a.GetRegistrarInfo(ctx, domain) }),
                tt(mapKeyResolverConsensus, func() any { return a.DNS.ValidateResolverConsensus(ctx, domain) }),
                tt(mapKeyHttpsSvcb, func() any { return a.AnalyzeHTTPSSVCB(ctx, domain) }),
                tt(mapKeyCdsCdnskey, func() any { return a.AnalyzeCDSCDNSKEY(ctx, domain) }),
                tt(mapKeyNmapDns, func() any { return a.AnalyzeNmapDNS(ctx, domain) }),
                tt(mapKeyDelegationConsistency, func() any { return a.AnalyzeDelegationConsistency(ctx, domain) }),
                tt(mapKeyNsFleet, func() any { return a.AnalyzeNSFleet(ctx, domain) }),
                tt(mapKeyDnssecOps, func() any { return a.AnalyzeDNSSECOps(ctx, domain) }),
        }
}

func (a *Analyzer) buildDomainTasks(ctx context.Context, domain string, customDKIMSelectors []string, ch chan namedResult, t0 time.Time, progressCb ProgressCallback) []func() {
        tt := func(key string, fn func() any) func() {
                return timedTaskWithProgress(ch, key, t0, progressCb, fn)
        }
        return []func(){
                tt(mapKeySpfOrch, func() any { return a.AnalyzeSPF(ctx, domain) }),
                tt(mapKeyDmarc, func() any { return a.AnalyzeDMARC(ctx, domain) }),
                tt(mapKeyDkimOrch, func() any { return a.AnalyzeDKIM(ctx, domain, nil, customDKIMSelectors) }),
                tt(mapKeyMtaSts, func() any { return a.AnalyzeMTASTS(ctx, domain) }),
                tt(mapKeyTlsrpt, func() any { return a.AnalyzeTLSRPT(ctx, domain) }),
                tt(mapKeyBimi, func() any { return a.AnalyzeBIMI(ctx, domain) }),
                tt(mapKeyCtSubdomains, func() any { return a.discoverSubdomainsWithBudget(ctx, domain) }),
                tt(mapKeySmimeaOpenpgpkey, func() any { return a.AnalyzeSMIMEA(ctx, domain) }),
                tt(mapKeySecurityTxt, func() any { return a.AnalyzeSecurityTxt(ctx, domain) }),
                tt(mapKeyAiSurface, func() any { return a.AnalyzeAISurface(ctx, domain) }),
                tt(mapKeySecretExposure, func() any { return a.ScanSecretExposure(ctx, domain) }),
        }
}

func (a *Analyzer) discoverSubdomainsWithBudget(parent context.Context, domain string) map[string]any {
        budget := 60 * time.Second
        if deadline, ok := parent.Deadline(); ok {
                if remaining := time.Until(deadline); remaining < budget {
                        budget = remaining
                }
        }
        if budget <= 0 {
                slog.Warn("CT subdomain budget exhausted by parent deadline", mapKeyDomain, domain)
                return map[string]any{"status": "deferred", "reason": "parent_deadline_exhausted"}
        }
        ctCtx, ctCancel := context.WithTimeout(parent, budget)
        defer ctCancel()
        return a.DiscoverSubdomains(ctCtx, domain)
}

func (a *Analyzer) runParallelAnalyses(ctx context.Context, domain string, customDKIMSelectors []string, analysisStart time.Time, progressCb ProgressCallback) (map[string]any, []PhaseTiming) {
        return a.runScopedAnalyses(ctx, domain, customDKIMSelectors, analysisStart, progressCb, ScopeOwnedDNS)
}

var emailProtocolKeys = map[string]bool{
        mapKeySpfOrch:        true,
        mapKeyDmarc:          true,
        mapKeyDkimOrch:       true,
        mapKeyMtaSts:         true,
        mapKeyTlsrpt:         true,
        mapKeyBimi:           true,
        mapKeySmimeaOpenpgpkey: true,
}

func (a *Analyzer) buildGatewaySkippedResults() map[string]any {
        results := make(map[string]any)
        for key := range emailProtocolKeys {
                results[key] = map[string]any{mapKeyStatus: "skipped", "reason": "gateway_attribution"}
        }
        return results
}

func (a *Analyzer) runScopedAnalyses(ctx context.Context, domain string, customDKIMSelectors []string, analysisStart time.Time, progressCb ProgressCallback, scope AnalysisScope) (map[string]any, []PhaseTiming) {
        resultsCh := make(chan namedResult, 28)
        var wg sync.WaitGroup

        tasks := a.buildCoreTasks(ctx, domain, resultsCh, analysisStart, progressCb)

        if !dnsclient.IsTLDInput(domain) {
                if scope == ScopeGatewayDerived {
                        gatewayTasks := a.buildGatewayDomainTasks(ctx, domain, resultsCh, analysisStart, progressCb)
                        tasks = append(tasks, gatewayTasks...)
                } else {
                        tasks = append(tasks, a.buildDomainTasks(ctx, domain, customDKIMSelectors, resultsCh, analysisStart, progressCb)...)
                }
        }

        for _, fn := range tasks {
                wg.Add(1)
                go func(f func()) {
                        defer wg.Done()
                        f()
                }(fn)
        }

        go func() {
                wg.Wait()
                close(resultsCh)
        }()

        resultsMap := make(map[string]any)
        if scope == ScopeGatewayDerived {
                for k, v := range a.buildGatewaySkippedResults() {
                        resultsMap[k] = v
                }
        }

        var timings []PhaseTiming
        for nr := range resultsCh {
                resultsMap[nr.key] = nr.result
                durMs := int(nr.elapsed.Milliseconds())
                group := LookupPhaseGroup(nr.key)
                slog.Info(logTaskCompleted, mapKeyTaskOrch, nr.key, mapKeyDomain, domain, mapKeyElapsedMs, fmt.Sprintf(fmtElapsedMs, float64(durMs)))
                pt := PhaseTiming{
                        PhaseGroup:  group,
                        PhaseTask:   nr.key,
                        StartedAtMs: int(nr.startOffset.Milliseconds()),
                        DurationMs:  durMs,
                }
                pt.RecordCount, pt.Error = extractResultMeta(nr.result)
                timings = append(timings, pt)
                if progressCb != nil {
                        progressCb(group, "done", durMs)
                }
        }
        return resultsMap, timings
}

func (a *Analyzer) buildGatewayDomainTasks(ctx context.Context, domain string, ch chan namedResult, t0 time.Time, progressCb ProgressCallback) []func() {
        tt := func(key string, fn func() any) func() {
                return timedTaskWithProgress(ch, key, t0, progressCb, fn)
        }
        return []func(){
                tt(mapKeyCtSubdomains, func() any { return a.discoverSubdomainsWithBudget(ctx, domain) }),
                tt(mapKeySecurityTxt, func() any { return a.AnalyzeSecurityTxt(ctx, domain) }),
                tt(mapKeyAiSurface, func() any { return a.AnalyzeAISurface(ctx, domain) }),
                tt(mapKeySecretExposure, func() any { return a.ScanSecretExposure(ctx, domain) }),
        }
}

func extractResultMeta(result any) (recordCount int, errMsg string) {
        m, ok := result.(map[string]any)
        if !ok {
                return 0, ""
        }
        if e, ok := m["error"]; ok {
                if s, ok := e.(string); ok && s != "" {
                        errMsg = s
                }
        }
        if records, ok := m["records"]; ok {
                recordCount = countSlice(records)
        }
        if recordCount == 0 {
                if cnt, ok := m["count"]; ok {
                        recordCount = toInt(cnt)
                }
        }
        return recordCount, errMsg
}

func countSlice(v any) int {
        switch s := v.(type) {
        case []any:
                return len(s)
        case []string:
                return len(s)
        case []map[string]any:
                return len(s)
        default:
                return 0
        }
}

func toInt(v any) int {
        switch n := v.(type) {
        case int:
                return n
        case int32:
                return int(n)
        case int64:
                return int(n)
        case float64:
                return int(n)
        default:
                return 0
        }
}

func buildRecordCurrencies(resolverTTLMap map[string]uint32) []icuae.RecordCurrency {
        var records []icuae.RecordCurrency
        for rt, ttl := range resolverTTLMap {
                records = append(records, icuae.RecordCurrency{
                        RecordType:  rt,
                        ObservedTTL: ttl,
                        TypicalTTL:  icuae.TypicalTTLFor(rt),
                        DataAgeS:    0,
                        TTLRatio:    0,
                })
        }
        return records
}

func buildObservedTypes(resolverTTLMap, authTTLMap map[string]uint32) map[string]bool {
        observedTypes := make(map[string]bool)
        for rt := range authTTLMap {
                observedTypes[rt] = true
        }
        for rt := range resolverTTLMap {
                observedTypes[rt] = true
        }
        return observedTypes
}

func extractResolverAgreements(consensus map[string]any) ([]icuae.ResolverAgreement, int) {
        resolverCount := 5
        if rq, ok := consensus["resolvers_queried"].(int); ok {
                resolverCount = rq
        }

        perRecord, ok := consensus["per_record_consensus"].(map[string]any)
        if !ok {
                return nil, resolverCount
        }

        var agreements []icuae.ResolverAgreement
        for rt, data := range perRecord {
                rd, ok := data.(map[string]any)
                if !ok {
                        continue
                }
                isConsensus, _ := rd["consensus"].(bool)
                rc, _ := rd["resolver_count"].(int)
                agreeCount := rc
                if !isConsensus {
                        agreeCount = rc - 1
                        if agreeCount < 0 {
                                agreeCount = 0
                        }
                }
                agreements = append(agreements, icuae.ResolverAgreement{
                        RecordType:     rt,
                        AgreeCount:     agreeCount,
                        TotalResolvers: rc,
                        Unanimous:      isConsensus,
                })
        }
        return agreements, resolverCount
}

func enrichCurrencyInput(input *icuae.CurrencyReportInput, results map[string]any) {
        if ns, ok := results["ns"].(map[string]any); ok {
                if providers, ok := ns["dns_providers"].([]string); ok {
                        input.DNSProviders = providers
                }
        }

        if br, ok := results[mapKeyBasicRecords].(map[string]any); ok {
                if nsSlice, ok := br["NS"].([]string); ok {
                        input.NSRecords = nsSlice
                }
                if soaSlice, ok := br["SOA"].([]string); ok && len(soaSlice) > 0 {
                        input.SOARaw = soaSlice[0]
                }
        }
}

func buildICuAEReport(resolverTTLMap, authTTLMap map[string]uint32, results map[string]any) icuae.CurrencyReport {
        var agreements []icuae.ResolverAgreement
        resolverCount := 5
        if consensus, ok := results[mapKeyResolverConsensus].(map[string]any); ok {
                agreements, resolverCount = extractResolverAgreements(consensus)
        }

        input := icuae.CurrencyReportInput{
                Records:       buildRecordCurrencies(resolverTTLMap),
                ResolverTTLs:  resolverTTLMap,
                AuthTTLs:      authTTLMap,
                ObservedTypes: buildObservedTypes(resolverTTLMap, authTTLMap),
                Agreements:    agreements,
                ResolverCount: resolverCount,
        }

        enrichCurrencyInput(&input, results)

        return icuae.BuildCurrencyReportWithProvider(input)
}

func adjustHostingSummary(results map[string]any) {
        hs, ok := results[mapKeyHostingSummary].(map[string]any)
        if !ok {
                return
        }
        emailUnknown := hs[mapKeyEmailHosting] == "Unknown" || hs[mapKeyEmailHosting] == ""
        isNoMail := results[mapKeyIsNoMailDomain] == true || results[mapKeyHasNullMx] == true
        if isNoMail && emailUnknown {
                hs[mapKeyEmailHosting] = "No Mail Domain"
                return
        }
        if !isNoMail && emailUnknown {
                inferEmailFromDKIM(hs, results)
        }
}

func inferEmailFromDKIM(hs, results map[string]any) {
        dkim, ok := results[mapKeyDkimAnalysis].(map[string]any)
        if !ok {
                return
        }
        pp, ok := dkim["primary_provider"].(string)
        if !ok || pp == "" || pp == "Unknown" {
                return
        }
        hs[mapKeyEmailHosting] = pp
        if ec, ecOK := hs["email_confidence"].(map[string]any); !ecOK || len(ec) == 0 {
                hs["email_confidence"] = map[string]any{
                        "level":  "inferred",
                        "label":  "Inferred",
                        "method": "MX record and SPF analysis",
                }
        }
}

func enrichBasicRecords(basic, resultsMap map[string]any) {
        dmarcData := getMapResult(resultsMap, mapKeyDmarc)
        mtaStsData := getMapResult(resultsMap, mapKeyMtaSts)
        tlsrptData := getMapResult(resultsMap, mapKeyTlsrpt)

        if dmarcData[mapKeyStatus] == mapKeySuccess || dmarcData[mapKeyStatus] == mapKeyWarning {
                if vr, ok := dmarcData["valid_records"].([]string); ok && len(vr) > 0 {
                        basic["DMARC"] = vr
                }
        }
        if rec, ok := mtaStsData["record"].(string); ok && rec != "" {
                basic["MTA-STS"] = []string{rec}
        }
        if rec, ok := tlsrptData["record"].(string); ok && rec != "" {
                basic["TLS-RPT"] = []string{rec}
        }
}

func buildSectionStatus(resultsMap map[string]any) map[string]any {
        sectionStatus := make(map[string]any)
        for key, result := range resultsMap {
                rm, ok := result.(map[string]any)
                if !ok {
                        sectionStatus[key] = map[string]any{mapKeyStatus: "ok"}
                        continue
                }
                status, _ := rm[mapKeyStatus].(string)
                switch status {
                case "timeout":
                        sectionStatus[key] = map[string]any{mapKeyStatus: "timeout", mapKeyMessage: "Query timed out"}
                case mapKeyError:
                        msg, _ := rm[mapKeyMessage].(string)
                        if msg == "" {
                                msg = "Lookup failed"
                        }
                        sectionStatus[key] = map[string]any{mapKeyStatus: mapKeyError, mapKeyMessage: msg}
                default:
                        sectionStatus[key] = map[string]any{mapKeyStatus: "ok"}
                }
        }
        return sectionStatus
}

func detectNullMX(basic map[string]any) bool {
        mxRecords, _ := basic["MX"].([]string)
        for _, r := range mxRecords {
                stripped := strings.TrimSpace(strings.TrimRight(r, "."))
                normalized := strings.ReplaceAll(stripped, " ", "")
                if normalized == "0." || normalized == "0" || stripped == "0 ." {
                        return true
                }
        }
        return false
}

func (a *Analyzer) buildNonExistentResult(domain, status string, statusMessage *string) map[string]any {
        return map[string]any{
                mapKeyDomain:                domain,
                "domain_exists":             false,
                "domain_status":             status,
                "domain_status_message":     derefStr(statusMessage),
                "section_status":            map[string]any{},
                mapKeyBasicRecords:          map[string]any{"A": []string{}, "AAAA": []string{}, "MX": []string{}, "NS": []string{}, "TXT": []string{}, "CNAME": []string{}, "SOA": []string{}},
                "authoritative_records":     map[string]any{},
                "auth_query_status":         nil,
                mapKeyResolverTtl:           nil,
                mapKeyAuthTtl:               nil,
                "propagation_status":        map[string]any{},
                mapKeyResolverConsensus:     map[string]any{},
                "spf_analysis":              map[string]any{mapKeyStatus: statusNA, mapKeyMessage: msgDomainNotExist},
                "dmarc_analysis":            map[string]any{mapKeyStatus: statusNA, mapKeyMessage: msgDomainNotExist},
                mapKeyDkimAnalysis:          map[string]any{mapKeyStatus: statusNA},
                "mta_sts_analysis":          map[string]any{mapKeyStatus: statusNA},
                "tlsrpt_analysis":           map[string]any{mapKeyStatus: statusNA},
                "bimi_analysis":             map[string]any{mapKeyStatus: statusNA},
                "dane_analysis":             map[string]any{mapKeyStatus: statusNA, "has_dane": false, "tlsa_records": []any{}, mapKeyIssues: []string{}},
                "caa_analysis":              map[string]any{mapKeyStatus: statusNA},
                "dnssec_analysis":           map[string]any{mapKeyStatus: statusNA},
                "ns_delegation_analysis":    map[string]any{mapKeyStatus: mapKeyError, "delegation_ok": false, mapKeyMessage: msgDomainNotExist},
                "registrar_info":            map[string]any{mapKeyStatus: statusNA, mapKeyRegistrar: nil},
                mapKeySmtpTransport:         map[string]any{mapKeyStatus: statusNA, mapKeyMessage: msgDomainNoExist},
                mapKeyCtSubdomains:          map[string]any{mapKeyStatus: mapKeySuccess, mapKeySubdomains: []any{}, "unique_subdomains": 0, "total_certs": 0},
                mapKeyHasNullMx:             false,
                mapKeyIsNoMailDomain:        false,
                mapKeyHostingSummary:        map[string]any{"hosting": displayNA, "dns_hosting": displayNA, mapKeyEmailHosting: displayNA},
                "dns_infrastructure":        map[string]any{"provider": displayNA, "tier": displayNA},
                "email_security_mgmt":       map[string]any{},
                "dmarc_report_auth":         map[string]any{mapKeyStatus: mapKeySuccess, "checked": false, "external_domains": []map[string]any{}, mapKeyIssues: []string{}},
                mapKeyHttpsSvcb:             map[string]any{mapKeyStatus: statusInfoOrch, "has_https": false, "has_svcb": false, "https_records": []map[string]any{}, "svcb_records": []map[string]any{}, "supports_http3": false, "supports_ech": false, mapKeyIssues: []string{}},
                mapKeyCdsCdnskey:            map[string]any{mapKeyStatus: statusInfoOrch, "has_cds": false, "has_cdnskey": false, "cds_records": []map[string]any{}, "cdnskey_records": []map[string]any{}, "automation": "none", mapKeyIssues: []string{}},
                mapKeySmimeaOpenpgpkey:      map[string]any{mapKeyStatus: statusInfoOrch, "has_smimea": false, "has_openpgpkey": false, "smimea_records": []map[string]any{}, "openpgpkey_records": []map[string]any{}, mapKeyIssues: []string{}},
                mapKeySecurityTxt:           map[string]any{mapKeyStatus: statusInfoOrch, mapKeyFound: false, mapKeyMessage: msgDomainNoExist, "contacts": []string{}, mapKeyIssues: []string{}},
                mapKeyAiSurface:             map[string]any{mapKeyStatus: statusInfoOrch, mapKeyMessage: msgDomainNoExist, "llms_txt": map[string]any{mapKeyFound: false}, "robots_txt": map[string]any{mapKeyFound: false}, "poisoning": map[string]any{"ioc_count": 0}, "hidden_prompts": map[string]any{"artifact_count": 0}, "evidence": []map[string]any{}, "summary": map[string]any{}},
                mapKeySecretExposure:        map[string]any{mapKeyStatus: "clear", mapKeyMessage: msgDomainNoExist, "finding_count": 0, "findings": []map[string]any{}, "scanned_urls": []string{}},
                "saas_txt":                  map[string]any{mapKeyStatus: mapKeySuccess, "services": []map[string]any{}, "service_count": 0, mapKeyIssues: []string{}},
                "asn_info":                  map[string]any{mapKeyStatus: statusInfoOrch, "ipv4_asn": []map[string]any{}, "ipv6_asn": []map[string]any{}, "unique_asns": []map[string]any{}, mapKeyIssues: []string{}},
                "edge_cdn":                  map[string]any{mapKeyStatus: mapKeySuccess, "is_behind_cdn": false, "cdn_provider": "", "cdn_indicators": []string{}, "origin_visible": true, mapKeyIssues: []string{}},
                "dangling_dns":              map[string]any{mapKeyStatus: mapKeySuccess, "checked": true, "dangling_count": 0, "dangling_records": []map[string]any{}, mapKeyIssues: []string{}},
                mapKeyWeb3:                  DefaultWeb3Analysis(),
                mapKeyDelegationConsistency: map[string]any{mapKeyStatus: statusInfoOrch, mapKeyMessage: msgDomainNoExist},
                mapKeyNsFleet:               map[string]any{mapKeyStatus: statusInfoOrch, mapKeyMessage: msgDomainNoExist, "fleet": []map[string]any{}, mapKeyIssues: []string{}},
                mapKeyDnssecOps:             map[string]any{mapKeyStatus: statusInfoOrch, mapKeyMessage: msgDomainNoExist},
                "posture":                   map[string]any{"score": 0, "grade": displayNA, "state": displayNA, "label": "Non-existent Domain", mapKeyMessage: msgDomainNotExist, "icon": "times-circle", mapKeyIssues: []string{msgDomainNotExist}, "monitoring": []string{}, "configured": []string{}, "absent": []string{}, "color": "secondary", "deliberate_monitoring": false, "deliberate_monitoring_note": ""},
                "remediation":               map[string]any{"top_fixes": []map[string]any{}, "posture_achievable": displayNA},
                "mail_posture":              map[string]any{"classification": "unknown"},
        }
}

func getMapResult(m map[string]any, key string) map[string]any {
        if v, ok := m[key]; ok {
                if vm, ok := v.(map[string]any); ok {
                        return vm
                }
        }
        return map[string]any{}
}

func getOrDefault(m map[string]any, key string, defaultVal map[string]any) any {
        if v, ok := m[key]; ok {
                return v
        }
        return defaultVal
}

func extractAndRemove(m map[string]any, key string) any {
        v := m[key]
        delete(m, key)
        return v
}

func buildPropagationStatus(basic, auth map[string]any) map[string]any {
        propagation := make(map[string]any)
        for rtype := range basic {
                if rtype == "_ttl" || rtype == "_query_status" {
                        continue
                }
                bRecords, _ := basic[rtype].([]string)
                aRecords, _ := auth[rtype].([]string)

                bSet := makeStringSet(bRecords)
                aSet := makeStringSet(aRecords)

                var status string
                if len(aSet) == 0 {
                        status = "unknown"
                } else if stringSetEqual(keysOf(bSet), keysOf(aSet)) {
                        status = "synchronized"
                } else {
                        status = "propagating"
                }

                propagation[rtype] = map[string]any{
                        mapKeyStatus: status,
                        "synced":     status == "synchronized",
                        "mismatch":   status == "propagating",
                }
        }
        return propagation
}

func makeStringSet(s []string) map[string]bool {
        m := make(map[string]bool, len(s))
        for _, v := range s {
                m[v] = true
        }
        return m
}

func keysOf(m map[string]bool) []string {
        keys := make([]string, 0, len(m))
        for k := range m {
                keys = append(keys, k)
        }
        return keys
}

func buildAnalysisProvenance(inputKind InputKind, scope AnalysisScope, web3 Web3ResolutionResult, results map[string]any) map[string]any {
        p := map[string]any{
                "input_kind":     string(inputKind),
                "analysis_scope": string(scope),
        }
        if web3.IsWeb3Input {
                p["resolution_type"] = web3.ResolutionType
                p["gateway_detected"] = web3.IsGatewayDomain
                p["attribution_warning_emitted"] = web3.AttributionWarning != ""
                if web3.Gateway != "" {
                        p["gateway"] = web3.Gateway
                }
        }
        if w3a, ok := results[mapKeyWeb3].(map[string]any); ok {
                if ds, ok := w3a["dnslink_source"].(string); ok && ds != "" {
                        p["dnslink_source"] = ds
                }
        }
        if skip, ok := results["skip_reason"].(string); ok && skip != "" {
                p["skip_reason"] = skip
        }
        return p
}

func buildGatewayPosture(results map[string]any) map[string]any {
        return map[string]any{
                "risk":             "attribution_limited",
                "risk_label":       "Gateway Derived",
                "score":            0,
                "grade":            "N/A",
                "reason":           "gateway_derived",
                "issues":           []string{},
                "recommendations":  []string{},
                "monitoring":       []string{},
                "configured":       []string{},
                "absent":           []string{},
                "provider_limited": []string{},
                "attribution_note": "Posture scoring is suppressed for gateway-derived analysis. DNS infrastructure results reflect the gateway operator, not the domain owner.",
        }
}
