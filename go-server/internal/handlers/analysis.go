// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "context"
        "encoding/hex"
        "encoding/json"
        "fmt"
        "log/slog"
        "net/http"
        "sort"
        "strconv"
        "strings"
        "sync"
        "time"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"
        "dnstool/go-server/internal/dnsclient"
        "dnstool/go-server/internal/icae"
        "dnstool/go-server/internal/icuae"
        "dnstool/go-server/internal/logging"
        "dnstool/go-server/internal/scanner"
        "dnstool/go-server/internal/unified"
        "dnstool/go-server/internal/wayback"

        "github.com/gin-gonic/gin"
        "golang.org/x/crypto/sha3"
)

const (
        templateIndex            = "index.html"
        headerContentDisposition = "Content-Disposition"

        mapKeyAuthenticated  = "authenticated"
        mapKeyCovert         = "covert"
        mapKeyCritical       = "critical"
        mapKeyCurrencyReport = "currency_report"
        mapKeyDanger         = "danger"
        mapKeyDkimAnalysis   = "dkim_analysis"
        mapKeyDmarcAnalysis  = "dmarc_analysis"
        mapKeyDomain         = "domain"
        mapKeyMessage        = "message"
        mapKeySpfAnalysis    = "spf_analysis"
        mapKeyStandard       = "standard"
        mapKeyStatus         = "status"
        mapKeyWarning        = "warning"
        strAnalysisNotFound  = "Analysis not found"
        strUtc               = "2006-01-02 15:04:05 UTC"
)

type AnalysisHandler struct {
        DB              *db.Database
        Config          *config.Config
        Analyzer        *analyzer.Analyzer
        DNSHistoryCache *analyzer.DNSHistoryCache
        Calibration     *icae.CalibrationEngine
        DimCharts       *icuae.DimensionCharts
        ProgressStore   *ProgressStore
        analysisStore   AnalysisStore
        statsExec       StatsExecer
}

func (h *AnalysisHandler) store() AnalysisStore {
        if h.analysisStore != nil {
                return h.analysisStore
        }
        if h.DB != nil {
                return h.DB.Queries
        }
        return nil
}

func (h *AnalysisHandler) execer() StatsExecer {
        if h.statsExec != nil {
                return h.statsExec
        }
        if h.DB != nil {
                return h.DB.Pool
        }
        return nil
}

func (h *AnalysisHandler) rawQueries() *dbq.Queries {
        if h.DB != nil {
                return h.DB.Queries
        }
        return nil
}

func NewAnalysisHandler(database *db.Database, cfg *config.Config, a *analyzer.Analyzer, historyCache *analyzer.DNSHistoryCache) *AnalysisHandler {
        return &AnalysisHandler{
                DB:              database,
                Config:          cfg,
                Analyzer:        a,
                DNSHistoryCache: historyCache,
                Calibration:     icae.NewCalibrationEngine(),
                DimCharts:       icuae.NewDimensionCharts(),
                ProgressStore:   NewProgressStore(),
        }
}

func (h *AnalysisHandler) Close() {
        if h.ProgressStore != nil {
                h.ProgressStore.Close()
        }
}

func (h *AnalysisHandler) checkPrivateAccess(c *gin.Context, analysisID int32, private bool) bool {
        if !private {
                return true
        }
        auth, exists := c.Get(mapKeyAuthenticated)
        if !exists || auth != true {
                return false
        }
        uid, ok := c.Get(mapKeyUserId)
        if !ok {
                return false
        }
        userID, ok := uid.(int32)
        if !ok {
                return false
        }
        isOwner, err := h.store().CheckAnalysisOwnership(c.Request.Context(), dbq.CheckAnalysisOwnershipParams{
                AnalysisID: analysisID,
                UserID:     userID,
        })
        return err == nil && isOwner
}

func resolveReportMode(c *gin.Context) string {
        if mode := c.Param("mode"); mode != "" {
                switch strings.ToUpper(mode) {
                case "C":
                        return "C"
                case "CZ":
                        return "CZ"
                case "Z":
                        return "Z"
                case "EC":
                        return "EC"
                case "B":
                        return "B"
                default:
                        return "E"
                }
        }
        if c.Query(mapKeyCovert) == "1" {
                return "C"
        }
        return "E"
}

func reportModeTemplate(mode string) string {
        switch mode {
        case "C", "CZ":
                return "results_covert.html"
        case "B":
                return "results_executive.html"
        default:
                return "results.html"
        }
}

func isCovertMode(mode string) bool {
        return mode == "C" || mode == "CZ" || mode == "EC"
}

func (h *AnalysisHandler) ViewAnalysisStatic(c *gin.Context) {
        h.viewAnalysisWithMode(c, resolveReportMode(c))
}

func (h *AnalysisHandler) ViewAnalysis(c *gin.Context) {
        h.viewAnalysisWithMode(c, resolveReportMode(c))
}

func (h *AnalysisHandler) ViewAnalysisExecutive(c *gin.Context) {
        h.viewAnalysisWithMode(c, "B")
}

func (h *AnalysisHandler) viewAnalysisWithMode(c *gin.Context, mode string) {
        nonce, ok := c.Get("csp_nonce")
        if !ok {
                nonce = ""
        }
        csrfToken, ok := c.Get("csrf_token")
        if !ok {
                csrfToken = ""
        }
        idStr := c.Param("id")
        analysisID, err := strconv.ParseInt(idStr, 10, 32)
        if err != nil {
                h.renderErrorPage(c, http.StatusBadRequest, nonce, csrfToken, mapKeyDanger, "Invalid analysis ID")
                return
        }

        ctx := c.Request.Context()
        analysis, err := h.store().GetAnalysisByID(ctx, int32(analysisID))
        if err != nil {
                h.renderErrorPage(c, http.StatusNotFound, nonce, csrfToken, mapKeyDanger, strAnalysisNotFound)
                return
        }

        if !h.checkPrivateAccess(c, analysis.ID, analysis.Private) {
                h.renderRestrictedAccess(c, nonce, csrfToken)
                return
        }

        if len(analysis.FullResults) == 0 || string(analysis.FullResults) == "null" {
                h.renderErrorPage(c, http.StatusGone, nonce, csrfToken, mapKeyWarning, "This report is no longer available. Please re-analyze the domain.")
                return
        }

        results := NormalizeResults(analysis.FullResults)
        if results == nil {
                h.renderErrorPage(c, http.StatusInternalServerError, nonce, csrfToken, mapKeyDanger, "Failed to parse results")
                return
        }

        if dnsclient.IsTLDInput(analysis.AsciiDomain) {
                if mode == "E" {
                        mode = "Z"
                } else if mode == "C" {
                        mode = "CZ"
                }
        }

        waitSeconds, err2 := strconv.Atoi(c.Query("wait_seconds"))
        if err2 != nil {
                waitSeconds = 0
        }
        waitReason := c.Query("wait_reason")

        timestamp := analysisTimestamp(analysis)
        dur := analysisDuration(analysis)
        toolVersion := extractToolVersion(results)
        verifyCommands := analyzer.GenerateVerificationCommands(analysis.AsciiDomain, results)
        integrityHash := computeIntegrityHash(analysis, timestamp, toolVersion, h.Config.AppVersion, results)
        rfcCount := analyzer.CountVerifiedStandards(results)
        currentHash := derefString(analysis.PostureHash)
        drift := h.detectHistoricalDrift(ctx, currentHash, analysis.Domain, analysis.ID, results)
        isSub, rootDom := extractRootDomain(analysis.AsciiDomain)
        emailScope := h.resolveEmailScope(ctx, isSub, rootDom, analysis.AsciiDomain, results)

        viewData := gin.H{
                strAppversion:          h.Config.AppVersion,
                strCspnonce:            nonce,
                strCsrftoken:           csrfToken,
                strActivepage:          "",
                "Domain":               analysis.Domain,
                "AsciiDomain":          analysis.AsciiDomain,
                "Results":              results,
                "AnalysisID":           analysis.ID,
                "AnalysisDuration":     dur,
                "AnalysisTimestamp":    timestamp,
                "FromHistory":          true,
                "WaitSeconds":          waitSeconds,
                "WaitReason":           waitReason,
                "DomainExists":         resultsDomainExists(results),
                "ToolVersion":          toolVersion,
                "VerificationCommands": verifyCommands,
                "IsSubdomain":          isSub,
                "RootDomain":           rootDom,
                "SecurityTrailsKey":    "",
                "IntegrityHash":        integrityHash,
                "RFCCount":             rfcCount,
                "MaintenanceNote":      h.Config.MaintenanceNote,
                "BetaPages":            h.Config.BetaPages,
                "SectionTuning":        h.Config.SectionTuning,
                "PostureHash":          currentHash,
                "DriftDetected":        drift.Detected,
                "DriftPrevHash":        drift.PrevHash,
                "DriftPrevTime":        drift.PrevTime,
                "DriftPrevID":          drift.PrevID,
                "DriftFields":          drift.Fields,
                "IsPublicSuffix":       isPublicSuffixDomain(analysis.AsciiDomain),
                "IsTLD":                dnsclient.IsTLDInput(analysis.AsciiDomain),
                "SubdomainEmailScope":  emailScope,
                "ReportMode":           mode,
                "WaybackURL":           derefString(analysis.WaybackUrl),
        }
        h.enrichViewDataMetrics(ctx, viewData, results, analysis.Domain, analysis.ID)
        viewData["CovertMode"] = isCovertMode(mode)

        mergeAuthData(c, h.Config, viewData)
        c.HTML(http.StatusOK, reportModeTemplate(mode), viewData)
}

func extractDomainInput(c *gin.Context) string {
        domain := strings.TrimSpace(c.PostForm(mapKeyDomain))
        if domain == "" {
                domain = strings.TrimSpace(c.Query(mapKeyDomain))
        }
        return domain
}

func isAnalysisFailure(results map[string]any) (bool, string) {
        success, ok := results["analysis_success"].(bool)
        if !ok || success {
                return false, ""
        }
        errMsg, ok := results[mapKeyError].(string)
        if !ok {
                return false, ""
        }
        return true, errMsg
}

func getContextValue(c *gin.Context, key string) any {
        v, ok := c.Get(key)
        if !ok {
                return ""
        }
        return v
}

func isAgentCacheEligible(c *gin.Context, customSelectors []string, exposureChecks bool) bool {
        return c.Request.Method == http.MethodGet && c.Query("src") == "agent" && len(customSelectors) == 0 && !exposureChecks
}

type analyzeInput struct {
        domain, asciiDomain              string
        customSelectors                  []string
        exposureChecks, devNull          bool
        isAuthenticated                  bool
        userID                           int32
        hasNovelSelectors, ephemeral     bool
}

func extractAnalyzeInput(c *gin.Context) (analyzeInput, bool) {
        domain := extractDomainInput(c)
        if domain == "" {
                return analyzeInput{}, false
        }
        if !dnsclient.ValidateDomain(domain) && !analyzer.IsWeb3Input(domain) {
                return analyzeInput{}, false
        }
        asciiDomain, err := dnsclient.DomainToASCII(domain)
        if err != nil {
                asciiDomain = domain
        }
        customSelectors := extractCustomSelectors(c)
        hasNovelSelectors := len(customSelectors) > 0 && !analyzer.AllSelectorsKnown(customSelectors)
        exposureChecks := c.PostForm("exposure_checks") == "1"
        devNull := c.PostForm("devnull") == "1"
        isAuthenticated, userID := extractAuthInfo(c)
        ephemeral := devNull || (hasNovelSelectors && !isAuthenticated)
        return analyzeInput{
                domain: domain, asciiDomain: asciiDomain,
                customSelectors: customSelectors, exposureChecks: exposureChecks,
                devNull: devNull, isAuthenticated: isAuthenticated, userID: userID,
                hasNovelSelectors: hasNovelSelectors, ephemeral: ephemeral,
        }, true
}

func (h *AnalysisHandler) tryServeFromCache(c *gin.Context, inp analyzeInput, nonce, csrfToken any) bool {
        if !isAgentCacheEligible(c, inp.customSelectors, inp.exposureChecks) {
                return false
        }
        if h.serveCachedAnalysis(c, inp.domain, inp.asciiDomain, nonce, csrfToken) {
                return true
        }
        return inp.domain != inp.asciiDomain && h.serveCachedAnalysis(c, inp.asciiDomain, inp.asciiDomain, nonce, csrfToken)
}

func (h *AnalysisHandler) Analyze(c *gin.Context) {
        nonce := getContextValue(c, "csp_nonce")
        csrfToken := getContextValue(c, "csrf_token")

        inp, valid := extractAnalyzeInput(c)
        if !valid {
                domain := extractDomainInput(c)
                msg := "Please enter a domain name."
                if domain != "" {
                        msg = fmt.Sprintf("Invalid domain name: %s", domain)
                }
                h.renderIndexFlash(c, nonce, csrfToken, mapKeyDanger, msg)
                return
        }

        wantsJSON := strings.Contains(c.GetHeader("Accept"), "application/json") && c.Request.Method == "POST"
        if wantsJSON {
                h.analyzeAsync(c, inp.domain, inp.asciiDomain, inp.customSelectors, inp.exposureChecks, inp.devNull, inp.isAuthenticated, inp.userID, inp.hasNovelSelectors, inp.ephemeral)
                return
        }

        if h.tryServeFromCache(c, inp, nonce, csrfToken) {
                return
        }

        startTime := time.Now()
        ctx := c.Request.Context()

        results := h.Analyzer.AnalyzeDomain(ctx, inp.asciiDomain, inp.customSelectors, analyzer.AnalysisOptions{
                ExposureChecks: inp.exposureChecks,
        })
        analysisDuration := time.Since(startTime).Seconds()

        h.applyConfidenceEngines(results)

        if failed, errMsg := isAnalysisFailure(results); failed {
                go h.recordDailyStats(false, analysisDuration)
                h.renderIndexFlash(c, nonce, csrfToken, mapKeyWarning, errMsg)
                return
        }

        h.enrichResultsNoHistory(c, inp.asciiDomain, results)

        domainExists := resultsDomainExists(results)
        clientIP := c.ClientIP()
        countryCode, countryName := lookupCountry(clientIP)
        scanClass := scanner.Classify(inp.asciiDomain, clientIP)
        postureHash := analyzer.CanonicalPostureHash(results)
        drift := h.detectDrift(ctx, inp.devNull, domainExists, inp.asciiDomain, postureHash, results)

        h.snapshotICAEMetrics(ctx, results)

        if c.Query("src") == "agent" {
                results["_request_source"] = "agent"
        }

        isPrivate := inp.hasNovelSelectors && inp.isAuthenticated
        analysisID, timestamp := h.persistOrLogEphemeral(c.Request.Context(), persistParams{
                domain:            inp.domain,
                asciiDomain:       inp.asciiDomain,
                results:           results,
                analysisDuration:  analysisDuration,
                countryCode:       countryCode,
                countryName:       countryName,
                isPrivate:         isPrivate,
                hasNovelSelectors: inp.hasNovelSelectors,
                scanClass:         scanClass,
                ephemeral:         inp.ephemeral,
                domainExists:      domainExists,
                devNull:           inp.devNull,
        })

        h.storeTelemetry(c.Request.Context(), analysisID, results, inp.ephemeral)

        analysisSuccess, _ := extractAnalysisError(results) //nolint:errcheck // error message not needed here
        h.handlePostAnalysisSideEffects(ctx, c, sideEffectsParams{
                asciiDomain:      inp.asciiDomain,
                analysisID:       analysisID,
                isAuthenticated:  inp.isAuthenticated,
                userID:           inp.userID,
                ephemeral:        inp.ephemeral,
                domainExists:     domainExists,
                drift:            drift,
                postureHash:      postureHash,
                analysisSuccess:  analysisSuccess,
                analysisDuration: analysisDuration,
                isPrivate:        isPrivate,
                isScanFlagged:    scanClass.IsScan,
        })

        h.recordCurrencyIfEligible(inp.ephemeral, domainExists, inp.asciiDomain, results)

        analyzeData := h.buildAnalyzeViewData(c, nonce, csrfToken, viewDataInput{
                domain:           inp.domain,
                asciiDomain:      inp.asciiDomain,
                results:          results,
                analysisID:       analysisID,
                analysisDuration: analysisDuration,
                timestamp:        timestamp,
                postureHash:      postureHash,
                drift:            drift,
                exposureChecks:   inp.exposureChecks,
                ephemeral:        inp.ephemeral,
                devNull:          inp.devNull,
                isPrivate:        isPrivate,
        })

        applyDevNullHeaders(c, inp.devNull)
        mode := resolveCovertMode(c, inp.asciiDomain)
        analyzeData["CovertMode"] = isCovertMode(mode)
        analyzeData["ReportMode"] = mode

        mergeAuthData(c, h.Config, analyzeData)
        c.HTML(http.StatusOK, reportModeTemplate(mode), analyzeData)
}

const cachedAnalysisMaxAge = 1 * time.Hour

func (h *AnalysisHandler) serveCachedAnalysis(c *gin.Context, domain, asciiDomain string, nonce, csrfToken any) bool {
        s := h.store()
        if s == nil {
                return false
        }
        analysis, err := s.GetRecentAnalysisByDomain(c.Request.Context(), domain)
        if err != nil || analysis.Private {
                return false
        }
        if analysis.AnalysisSuccess != nil && !*analysis.AnalysisSuccess {
                return false
        }
        if analysis.ScanFlag {
                return false
        }
        if !analysis.CreatedAt.Valid || time.Since(analysis.CreatedAt.Time) > cachedAnalysisMaxAge {
                return false
        }
        results := unmarshalResults(analysis.FullResults, "serveCachedAnalysis")
        if results == nil {
                return false
        }

        h.enrichResultsAsync(results)

        var analysisID int32 = analysis.ID
        var analysisDuration float64
        if analysis.AnalysisDuration != nil {
                analysisDuration = *analysis.AnalysisDuration
        }
        var timestamp string
        if analysis.CreatedAt.Valid {
                timestamp = analysis.CreatedAt.Time.UTC().Format(time.RFC3339)
        }
        var postureHash string
        if analysis.PostureHash != nil {
                postureHash = *analysis.PostureHash
        }

        analyzeData := h.buildAnalyzeViewData(c, nonce, csrfToken, viewDataInput{
                domain:       domain,
                asciiDomain:  asciiDomain,
                results:      results,
                analysisID:   analysisID,
                analysisDuration: analysisDuration,
                timestamp:    timestamp,
                postureHash:  postureHash,
                drift:        driftInfo{},
        })
        analyzeData["FromCache"] = true

        mode := resolveCovertMode(c, asciiDomain)
        analyzeData["CovertMode"] = isCovertMode(mode)
        analyzeData["ReportMode"] = mode

        mergeAuthData(c, h.Config, analyzeData)
        c.HTML(http.StatusOK, reportModeTemplate(mode), analyzeData)
        return true
}

func (h *AnalysisHandler) analyzeAsync(c *gin.Context, domain, asciiDomain string, customSelectors []string, exposureChecks, devNull, isAuthenticated bool, userID int32, hasNovelSelectors, ephemeral bool) {
        token, sp := h.ProgressStore.NewToken()

        clientIP := c.ClientIP()
        countryCode, countryName := lookupCountry(clientIP)

        traceID := token

        c.JSON(http.StatusAccepted, gin.H{
                "token":       token,
                "domain":      asciiDomain,
                "analysis_id": nil,
        })

        go func() {
                ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
                defer cancel()

                slog.LogAttrs(ctx, slog.LevelInfo, "scan started",
                        logging.ScanStarted(asciiDomain, traceID, 0)...)

                scanStart := time.Now()

                results := h.Analyzer.AnalyzeDomain(ctx, asciiDomain, customSelectors, analyzer.AnalysisOptions{
                        ExposureChecks:  exposureChecks,
                        OnPhaseProgress: sp.MakeInstrumentedProgressCallback(asciiDomain, traceID),
                })
                analysisDuration := time.Since(sp.startTime).Seconds()
                scanElapsedMs := time.Since(scanStart).Milliseconds()

                h.applyConfidenceEngines(results)
                h.enrichResultsAsync(results)

                if failed, _ := isAnalysisFailure(results); failed {
                        go h.recordDailyStats(false, analysisDuration)
                        slog.LogAttrs(ctx, slog.LevelError, "scan failed",
                                logging.ScanFailed(asciiDomain, traceID, "analysis returned failure")...)
                        sp.MarkFailed("analysis failed")
                        return
                }

                domainExists := resultsDomainExists(results)
                scanClass := scanner.Classify(asciiDomain, clientIP)
                postureHash := analyzer.CanonicalPostureHash(results)
                drift := h.detectDrift(ctx, devNull, domainExists, asciiDomain, postureHash, results)

                h.snapshotICAEMetrics(ctx, results)

                telRaw := results["_scan_telemetry"]
                delete(results, "_scan_telemetry")

                isPrivate := hasNovelSelectors && isAuthenticated
                analysisID, _ := h.persistOrLogEphemeral(ctx, persistParams{
                        domain:            domain,
                        asciiDomain:       asciiDomain,
                        results:           results,
                        analysisDuration:  analysisDuration,
                        countryCode:       countryCode,
                        countryName:       countryName,
                        isPrivate:         isPrivate,
                        hasNovelSelectors: hasNovelSelectors,
                        scanClass:         scanClass,
                        ephemeral:         ephemeral,
                        domainExists:      domainExists,
                        devNull:           devNull,
                })

                h.storeTelemetryFromRaw(ctx, analysisID, telRaw, ephemeral)

                analysisSuccess, _ := extractAnalysisError(results)
                h.handlePostAnalysisSideEffectsAsync(ctx, sideEffectsParams{
                        asciiDomain:      asciiDomain,
                        analysisID:       analysisID,
                        isAuthenticated:  isAuthenticated,
                        userID:           userID,
                        ephemeral:        ephemeral,
                        domainExists:     domainExists,
                        drift:            drift,
                        postureHash:      postureHash,
                        analysisSuccess:  analysisSuccess,
                        analysisDuration: analysisDuration,
                        isPrivate:        isPrivate,
                        isScanFlagged:    scanClass.IsScan,
                })

                h.recordCurrencyIfEligible(ephemeral, domainExists, asciiDomain, results)

                slog.LogAttrs(ctx, slog.LevelInfo, "scan completed",
                        logging.ScanCompleted(asciiDomain, traceID, int(analysisID), scanElapsedMs)...)

                if analysisID > 0 {
                        redirectURL := fmt.Sprintf("/analysis/%d", analysisID)
                        sp.MarkComplete(analysisID, redirectURL)
                } else {
                        sp.MarkComplete(0, "")
                }
        }()
}

func (h *AnalysisHandler) storeTelemetry(ctx context.Context, analysisID int32, results map[string]any, ephemeral bool) {
        if ephemeral || analysisID == 0 {
                return
        }
        telRaw, ok := results["_scan_telemetry"]
        if !ok {
                return
        }
        if _, valid := telRaw.(analyzer.ScanTelemetry); !valid {
                return
        }
        delete(results, "_scan_telemetry")
        h.storeTelemetryFromRaw(ctx, analysisID, telRaw, ephemeral)
}

func (h *AnalysisHandler) storeTelemetryFromRaw(_ context.Context, analysisID int32, telRaw any, ephemeral bool) {
        if ephemeral || analysisID == 0 || telRaw == nil {
                return
        }
        tel, ok := telRaw.(analyzer.ScanTelemetry)
        if !ok {
                return
        }

        go func() {
                bgCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
                defer cancel()
                for _, t := range tel.Timings {
                        var errPtr *string
                        if t.Error != "" {
                                errPtr = &t.Error
                        }
                        rc := int32(t.RecordCount)
                        if err := h.store().InsertPhaseTelemetry(bgCtx, dbq.InsertPhaseTelemetryParams{
                                AnalysisID:  analysisID,
                                PhaseGroup:  t.PhaseGroup,
                                PhaseTask:   t.PhaseTask,
                                StartedAtMs: int32(t.StartedAtMs),
                                DurationMs:  int32(t.DurationMs),
                                RecordCount: &rc,
                                Error:       errPtr,
                        }); err != nil {
                                slog.Warn("Failed to store phase telemetry", "analysis_id", analysisID, "task", t.PhaseTask, "error", err)
                        }
                }
                if err := h.store().InsertTelemetryHash(bgCtx, dbq.InsertTelemetryHashParams{
                        AnalysisID:      analysisID,
                        TotalDurationMs: int32(tel.TotalDurationMs),
                        PhaseCount:      int32(len(tel.Timings)),
                        Sha3512:         tel.SHA3Hash,
                }); err != nil {
                        slog.Warn("Failed to store telemetry hash", "analysis_id", analysisID, "error", err)
                }
        }()
}

func (h *AnalysisHandler) recordCurrencyIfEligible(ephemeral, domainExists bool, asciiDomain string, results map[string]any) {
        if ephemeral || !domainExists {
                return
        }
        cr, ok := results[mapKeyCurrencyReport]
        if !ok {
                return
        }
        if report, valid := cr.(icuae.CurrencyReport); valid {
                if q := h.rawQueries(); q != nil {
                        go icuae.RecordScanResult(context.Background(), q, asciiDomain, report, h.Config.AppVersion)
                }
        }
}

func applyDevNullHeaders(c *gin.Context, devNull bool) {
        if devNull {
                c.Header("X-Hacker", "MUST means MUST -- not kinda, maybe, should. // DNS Tool")
                c.Header("X-Persistence", "/dev/null")
        }
}

func resolveCovertMode(c *gin.Context, asciiDomain string) string {
        covert := c.PostForm(mapKeyCovert) == "1" || c.Query(mapKeyCovert) == "1"
        isTLD := dnsclient.IsTLDInput(asciiDomain)
        if covert && isTLD {
                return "CZ"
        }
        if covert {
                return "C"
        }
        if isTLD {
                return "Z"
        }
        return "E"
}

func (h *AnalysisHandler) enrichViewDataMetrics(ctx context.Context, data gin.H, results map[string]any, domain string, analysisID int32) {
        if snap, ok := results["_icae_snapshot"].(map[string]any); ok {
                h.enrichFromSnapshot(ctx, data, results, snap, domain, analysisID)
                return
        }

        var maturityLevel string
        if q := h.rawQueries(); q != nil {
                if icaeMetrics := icae.LoadReportMetrics(ctx, q); icaeMetrics != nil {
                        data["ICAEMetrics"] = icaeMetrics
                        maturityLevel = icaeMetrics.OverallMaturity
                }
        }
        var currencyScore float64
        if cr, ok := results[mapKeyCurrencyReport]; ok {
                if report, hydrated := icuae.HydrateCurrencyReport(cr); hydrated {
                        data["CurrencyReport"] = report
                        currencyScore = report.OverallScore
                }
        }

        calibrated, cOk := results["calibrated_confidence"].(map[string]float64)
        if cOk && calibrated != nil && maturityLevel != "" {
                uc := unified.ComputeUnifiedConfidence(unified.Input{
                        CalibratedConfidence: calibrated,
                        CurrencyScore:        currencyScore,
                        MaturityLevel:        maturityLevel,
                })
                data["UnifiedConfidence"] = uc
        }

        if analysisID > 0 {
                if q := h.rawQueries(); q != nil {
                        if sugConfig := buildSuggestedConfig(ctx, q, domain, analysisID); sugConfig != nil {
                                data["SuggestedConfig"] = sugConfig
                        }
                }
        }
}

func (h *AnalysisHandler) enrichFromSnapshot(ctx context.Context, data gin.H, results map[string]any, snap map[string]any, domain string, analysisID int32) {
        h.enrichICAEFromSnapshot(ctx, data, snap)
        enrichCurrencyReport(data, results)
        enrichUnifiedConfidence(data, snap)
        h.enrichSuggestedConfig(ctx, data, domain, analysisID)
}

func (h *AnalysisHandler) enrichICAEFromSnapshot(ctx context.Context, data gin.H, snap map[string]any) {
        q := h.rawQueries()
        if q == nil {
                return
        }
        icaeMetrics := icae.LoadReportMetrics(ctx, q)
        if icaeMetrics == nil {
                return
        }
        snappedMaturity, _ := snap["overall_maturity"].(string) //nolint:errcheck // zero-value fallback is intentional
        if snappedMaturity != "" {
                icaeMetrics.OverallMaturity = snappedMaturity
                icaeMetrics.OverallMaturityDisplay = snappedMaturity
        }
        data["ICAEMetrics"] = icaeMetrics
}

func enrichCurrencyReport(data gin.H, results map[string]any) {
        cr, ok := results[mapKeyCurrencyReport]
        if !ok {
                return
        }
        if report, hydrated := icuae.HydrateCurrencyReport(cr); hydrated {
                data["CurrencyReport"] = report
        }
}

func enrichUnifiedConfidence(data gin.H, snap map[string]any) {
        uc, ok := snap["unified_confidence"]
        if !ok {
                return
        }
        if ucMap, valid := uc.(map[string]any); valid {
                data["UnifiedConfidence"] = restoreUnifiedConfidence(ucMap)
        }
}

func (h *AnalysisHandler) enrichSuggestedConfig(ctx context.Context, data gin.H, domain string, analysisID int32) {
        if analysisID <= 0 {
                return
        }
        q := h.rawQueries()
        if q == nil {
                return
        }
        if sugConfig := buildSuggestedConfig(ctx, q, domain, analysisID); sugConfig != nil {
                data["SuggestedConfig"] = sugConfig
        }
}

func restoreUnifiedConfidence(m map[string]any) unified.UnifiedConfidence {
        uc := unified.UnifiedConfidence{}
        if v, ok := m["level"].(string); ok {
                uc.Level = v
        }
        if v, ok := m["score"].(float64); ok {
                uc.Score = v
        }
        if v, ok := m["accuracy_factor"].(float64); ok {
                uc.AccuracyFactor = v
        }
        if v, ok := m["currency_factor"].(float64); ok {
                uc.CurrencyFactor = v
        }
        if v, ok := m["maturity_ceiling"].(float64); ok {
                uc.MaturityCeiling = v
        }
        if v, ok := m["maturity_level"].(string); ok {
                uc.MaturityLevel = v
        }
        if v, ok := m["weakest_link"].(string); ok {
                uc.WeakestLink = v
        }
        if v, ok := m["weakest_detail"].(string); ok {
                uc.WeakestDetail = v
        }
        if v, ok := m["explanation"].(string); ok {
                uc.Explanation = v
        }
        if v, ok := m["protocol_count"].(float64); ok {
                uc.ProtocolCount = int(v)
        }
        return uc
}

func (h *AnalysisHandler) snapshotICAEMetrics(ctx context.Context, results map[string]any) {
        snapshot := map[string]any{}

        if q := h.rawQueries(); q != nil {
                if icaeMetrics := icae.LoadReportMetrics(ctx, q); icaeMetrics != nil {
                        snapshot["overall_maturity"] = icaeMetrics.OverallMaturity
                }
        }

        var currencyScore float64
        if cr, ok := results[mapKeyCurrencyReport]; ok {
                if report, hydrated := icuae.HydrateCurrencyReport(cr); hydrated {
                        currencyScore = report.OverallScore
                }
        }

        calibrated, calOk := results["calibrated_confidence"].(map[string]float64)
        maturityLevel, matOk := snapshot["overall_maturity"].(string)
        if calOk && calibrated != nil && matOk && maturityLevel != "" {
                uc := unified.ComputeUnifiedConfidence(unified.Input{
                        CalibratedConfidence: calibrated,
                        CurrencyScore:        currencyScore,
                        MaturityLevel:        maturityLevel,
                })
                snapshot["unified_confidence"] = map[string]any{
                        "level":            uc.Level,
                        "score":            uc.Score,
                        "accuracy_factor":  uc.AccuracyFactor,
                        "currency_factor":  uc.CurrencyFactor,
                        "maturity_ceiling": uc.MaturityCeiling,
                        "maturity_level":   uc.MaturityLevel,
                        "weakest_link":     uc.WeakestLink,
                        "weakest_detail":   uc.WeakestDetail,
                        "explanation":      uc.Explanation,
                        "protocol_count":   uc.ProtocolCount,
                }
        }

        results["_icae_snapshot"] = snapshot
}

func analysisTimestamp(analysis dbq.DomainAnalysis) string {
        ts := formatTimestamp(analysis.CreatedAt)
        if analysis.UpdatedAt.Valid {
                ts = formatTimestamp(analysis.UpdatedAt)
        }
        return ts
}

func analysisDuration(analysis dbq.DomainAnalysis) float64 {
        if analysis.AnalysisDuration != nil {
                return *analysis.AnalysisDuration
        }
        return 0.0
}

func computeIntegrityHash(analysis dbq.DomainAnalysis, timestamp, toolVersion, appVersion string, results map[string]any) string {
        hashVersion := toolVersion
        if hashVersion == "" {
                hashVersion = appVersion
        }
        return analyzer.ReportIntegrityHash(analysis.AsciiDomain, analysis.ID, timestamp, hashVersion, results)
}

func derefString(p *string) string {
        if p != nil {
                return *p
        }
        return ""
}

func (h *AnalysisHandler) detectHistoricalDrift(ctx context.Context, currentHash, domain string, analysisID int32, results map[string]any) driftInfo {
        if currentHash == "" {
                return driftInfo{}
        }
        prevRow, prevErr := h.store().GetPreviousAnalysisForDriftBefore(ctx, dbq.GetPreviousAnalysisForDriftBeforeParams{
                Domain: domain,
                ID:     analysisID,
        })
        if prevErr != nil {
                return driftInfo{}
        }
        return computeDriftFromPrev(currentHash, prevAnalysisSnapshot{
                Hash:           prevRow.PostureHash,
                ID:             prevRow.ID,
                CreatedAtValid: prevRow.CreatedAt.Valid,
                CreatedAt:      prevRow.CreatedAt.Time,
                FullResults:    prevRow.FullResults,
        }, results)
}

func (h *AnalysisHandler) resolveEmailScope(ctx context.Context, isSub bool, rootDom, asciiDomain string, results map[string]any) *subdomainEmailScope {
        if !isSub || rootDom == "" {
                return nil
        }
        es := computeSubdomainEmailScope(ctx, h.Analyzer.DNS, asciiDomain, rootDom, results)
        return &es
}

func extractAuthInfo(c *gin.Context) (bool, int32) {
        isAuthenticated := false
        var userID int32
        if auth, exists := c.Get(mapKeyAuthenticated); exists && auth == true {
                isAuthenticated = true
                if uid, ok := c.Get(mapKeyUserId); ok {
                        if id, idOk := uid.(int32); idOk {
                                userID = id
                        }
                }
        }
        return isAuthenticated, userID
}

func (h *AnalysisHandler) detectDrift(ctx context.Context, devNull, domainExists bool, asciiDomain, postureHash string, results map[string]any) driftInfo {
        drift := driftInfo{}
        if !devNull && domainExists {
                prevRow, prevErr := h.store().GetPreviousAnalysisForDrift(ctx, asciiDomain)
                if prevErr == nil {
                        drift = computeDriftFromPrev(postureHash, prevAnalysisSnapshot{
                                Hash:           prevRow.PostureHash,
                                ID:             prevRow.ID,
                                CreatedAtValid: prevRow.CreatedAt.Valid,
                                CreatedAt:      prevRow.CreatedAt.Time,
                                FullResults:    prevRow.FullResults,
                        }, results)
                        if drift.Detected {
                                slog.Info("Posture drift detected", mapKeyDomain, asciiDomain, "prev_hash", drift.PrevHash[:8], "new_hash", postureHash[:8], "changed_fields", len(drift.Fields))
                        }
                }
        }
        return drift
}

type persistParams struct {
        domain, asciiDomain      string
        results                  map[string]any
        analysisDuration         float64
        countryCode, countryName string
        isPrivate                bool
        hasNovelSelectors        bool
        scanClass                scanner.Classification
        ephemeral                bool
        domainExists             bool
        devNull                  bool
}

func (h *AnalysisHandler) persistOrLogEphemeral(ctx context.Context, p persistParams) (int32, string) {
        isSuccess, _ := extractAnalysisError(p.results) //nolint:errcheck // error message not needed here
        if persist, _ := shouldPersistResult(p.ephemeral, p.devNull, p.domainExists, isSuccess); !persist {
                logEphemeralReason(p.asciiDomain, p.devNull, p.domainExists)
                return 0, time.Now().UTC().Format(strUtc)
        }
        return h.saveAnalysis(ctx, saveAnalysisInput{
                domain:           p.domain,
                asciiDomain:      p.asciiDomain,
                results:          p.results,
                duration:         p.analysisDuration,
                countryCode:      p.countryCode,
                countryName:      p.countryName,
                private:          p.isPrivate,
                hasUserSelectors: p.hasNovelSelectors,
                scanClass:        p.scanClass,
        })
}

func logEphemeralReason(asciiDomain string, devNull, domainExists bool) {
        if devNull {
                slog.Info("/dev/null scan — full analysis, zero persistence", mapKeyDomain, asciiDomain)
        } else if !domainExists {
                slog.Info("Non-existent/undelegated domain — not persisted", mapKeyDomain, asciiDomain)
        } else {
                slog.Info("Ephemeral analysis (custom DKIM selectors, unauthenticated) — not persisted", mapKeyDomain, asciiDomain)
        }
}

type sideEffectsParams struct {
        asciiDomain      string
        analysisID       int32
        isAuthenticated  bool
        userID           int32
        ephemeral        bool
        domainExists     bool
        drift            driftInfo
        postureHash      string
        analysisSuccess  bool
        analysisDuration float64
        isPrivate        bool
        isScanFlagged    bool
}

func (h *AnalysisHandler) handlePostAnalysisSideEffects(ctx context.Context, c *gin.Context, p sideEffectsParams) {
        if p.analysisID > 0 {
                h.recordUserAnalysisAsync(p)
                if p.drift.Detected {
                        go h.persistDriftEvent(p.asciiDomain, p.analysisID, p.drift, p.postureHash)
                }
                if shouldArchiveToWayback(p.analysisID, p.analysisSuccess, p.ephemeral, p.isPrivate, p.isScanFlagged) {
                        go h.archiveToWayback(p.analysisID, p.asciiDomain)
                }
        }

        if shouldRunICAE(p.ephemeral, p.domainExists) {
                if q := h.rawQueries(); q != nil {
                        icae.EvaluateAndRecord(c.Request.Context(), q, h.Config.AppVersion)
                }
                recordAnalyticsCollector(c, p.asciiDomain)
        }

        go h.recordDailyStats(p.analysisSuccess, p.analysisDuration)
}

func (h *AnalysisHandler) handlePostAnalysisSideEffectsAsync(ctx context.Context, p sideEffectsParams) {
        if p.analysisID > 0 {
                h.recordUserAnalysisAsync(p)
                if p.drift.Detected {
                        go h.persistDriftEvent(p.asciiDomain, p.analysisID, p.drift, p.postureHash)
                }
                if shouldArchiveToWayback(p.analysisID, p.analysisSuccess, p.ephemeral, p.isPrivate, p.isScanFlagged) {
                        go h.archiveToWayback(p.analysisID, p.asciiDomain)
                }
        }

        if shouldRunICAE(p.ephemeral, p.domainExists) {
                if q := h.rawQueries(); q != nil {
                        icae.EvaluateAndRecord(ctx, q, h.Config.AppVersion)
                }
        }

        go h.recordDailyStats(p.analysisSuccess, p.analysisDuration)
}

func (h *AnalysisHandler) archiveToWayback(analysisID int32, domain string) {
        ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
        defer cancel()
        analysisURL := fmt.Sprintf("%s/analysis/%d/view/E", h.Config.BaseURL, analysisID)
        result := wayback.Archive(ctx, analysisURL)
        if result.Err != nil {
                slog.Warn("Wayback Machine archival failed", "analysis_id", analysisID, "domain", domain, mapKeyError, result.Err)
                return
        }
        err := h.store().UpdateWaybackURL(context.Background(), dbq.UpdateWaybackURLParams{
                ID:         analysisID,
                WaybackUrl: &result.URL,
        })
        if err != nil {
                slog.Error("Failed to store Wayback URL", "analysis_id", analysisID, "wayback_url", result.URL, mapKeyError, err)
        }
}

func (h *AnalysisHandler) recordUserAnalysisAsync(p sideEffectsParams) {
        if !shouldRecordUserAssociation(p.isAuthenticated, p.userID) {
                return
        }
        go func() {
                err := h.store().InsertUserAnalysis(context.Background(), dbq.InsertUserAnalysisParams{
                        UserID:     p.userID,
                        AnalysisID: p.analysisID,
                })
                if err != nil {
                        slog.Error("Failed to record user analysis association", mapKeyUserId, p.userID, "analysis_id", p.analysisID, mapKeyError, err)
                }
        }()
}

func (h *AnalysisHandler) recordDailyStats(success bool, duration float64) {
        exec := h.execer()
        if exec == nil {
                return
        }
        ctx := context.Background()
        today := time.Now().UTC().Truncate(24 * time.Hour)

        successInt := 0
        failedInt := 0
        if success {
                successInt = 1
        } else {
                failedInt = 1
        }

        _, err := exec.Exec(ctx,
                `INSERT INTO analysis_stats (date, total_analyses, successful_analyses, failed_analyses, unique_domains, avg_analysis_time, created_at, updated_at)
                 VALUES ($1, 1, $2, $3, 0, $4, NOW(), NOW())
                 ON CONFLICT (date) DO UPDATE SET
                     total_analyses = COALESCE(analysis_stats.total_analyses, 0) + 1,
                     successful_analyses = COALESCE(analysis_stats.successful_analyses, 0) + $2,
                     failed_analyses = COALESCE(analysis_stats.failed_analyses, 0) + $3,
                     avg_analysis_time = CASE
                         WHEN COALESCE(analysis_stats.total_analyses, 0) = 0 THEN $4
                         ELSE (COALESCE(analysis_stats.avg_analysis_time, 0) * COALESCE(analysis_stats.total_analyses, 0) + $4) / (COALESCE(analysis_stats.total_analyses, 0) + 1)
                     END,
                     updated_at = NOW()`,
                today, successInt, failedInt, duration)
        if err != nil {
                slog.Error("Failed to record daily stats", mapKeyError, err)
        }
}

func recordAnalyticsCollector(c *gin.Context, domain string) {
        ac, exists := c.Get("analytics_collector")
        if !exists {
                return
        }
        if collector, ok := ac.(interface{ RecordAnalysis(string) }); ok {
                collector.RecordAnalysis(domain)
        }
}

type viewDataInput struct {
        domain, asciiDomain string
        results             map[string]any
        analysisID          int32
        analysisDuration    float64
        timestamp           string
        postureHash         string
        drift               driftInfo
        exposureChecks      bool
        ephemeral           bool
        devNull             bool
        isPrivate           bool
}

func (h *AnalysisHandler) buildAnalyzeViewData(c *gin.Context, nonce, csrfToken any, v viewDataInput) gin.H {
        ctx := c.Request.Context()
        verifyCommands := analyzer.GenerateVerificationCommands(v.asciiDomain, v.results)
        integrityHash := analyzer.ReportIntegrityHash(v.asciiDomain, v.analysisID, v.timestamp, h.Config.AppVersion, v.results)
        rfcCount := analyzer.CountVerifiedStandards(v.results)

        isSub, rootDom := extractRootDomain(v.asciiDomain)
        emailScope := h.resolveEmailScope(ctx, isSub, rootDom, v.asciiDomain, v.results)

        analyzeData := gin.H{
                strAppversion:          h.Config.AppVersion,
                strCspnonce:            nonce,
                strCsrftoken:           csrfToken,
                strActivepage:          "",
                "Domain":               v.domain,
                "AsciiDomain":          v.asciiDomain,
                "Results":              v.results,
                "AnalysisID":           v.analysisID,
                "AnalysisDuration":     v.analysisDuration,
                "AnalysisTimestamp":    v.timestamp,
                "FromHistory":          false,
                "FromCache":            false,
                "DomainExists":         resultsDomainExists(v.results),
                "ToolVersion":          h.Config.AppVersion,
                "VerificationCommands": verifyCommands,
                "IsSubdomain":          isSub,
                "RootDomain":           rootDom,
                "SecurityTrailsKey":    "",
                "IntegrityHash":        integrityHash,
                "RFCCount":             rfcCount,
                "ExposureChecks":       v.exposureChecks,
                "MaintenanceNote":      h.Config.MaintenanceNote,
                "BetaPages":            h.Config.BetaPages,
                "SectionTuning":        h.Config.SectionTuning,
                "PostureHash":          v.postureHash,
                "DriftDetected":        v.drift.Detected,
                "DriftPrevHash":        v.drift.PrevHash,
                "DriftPrevTime":        v.drift.PrevTime,
                "DriftPrevID":          v.drift.PrevID,
                "DriftFields":          v.drift.Fields,
                "Ephemeral":            v.ephemeral,
                "DevNull":              v.devNull,
                "IsPrivateReport":      v.isPrivate,
                "IsPublicSuffix":       isPublicSuffixDomain(v.asciiDomain),
                "IsTLD":                dnsclient.IsTLDInput(v.asciiDomain),
                "SubdomainEmailScope":  emailScope,
                "WaybackURL":           "",
        }
        if q := h.rawQueries(); q != nil {
                if icaeMetrics := icae.LoadReportMetrics(ctx, q); icaeMetrics != nil {
                        analyzeData["ICAEMetrics"] = icaeMetrics
                }
        }
        if cr, ok := v.results[mapKeyCurrencyReport]; ok {
                if report, hydrated := icuae.HydrateCurrencyReport(cr); hydrated {
                        analyzeData["CurrencyReport"] = report
                }
        }
        return analyzeData
}

type driftInfo struct {
        Detected bool
        PrevHash string
        PrevTime string
        PrevID   int32
        Fields   []analyzer.PostureDiffField
}

type prevAnalysisSnapshot struct {
        Hash           *string
        ID             int32
        CreatedAtValid bool
        CreatedAt      time.Time
        FullResults    json.RawMessage
}

func computeDriftFromPrev(currentHash string, prev prevAnalysisSnapshot, currentResults map[string]any) driftInfo {
        if prev.Hash == nil || *prev.Hash == "" || *prev.Hash == currentHash {
                return driftInfo{}
        }
        di := driftInfo{
                Detected: true,
                PrevHash: *prev.Hash,
                PrevID:   prev.ID,
        }
        if prev.CreatedAtValid {
                di.PrevTime = prev.CreatedAt.Format("2 Jan 2006 15:04 UTC")
        }
        if prev.FullResults != nil {
                var prevResults map[string]any
                if json.Unmarshal(prev.FullResults, &prevResults) == nil {
                        di.Fields = analyzer.ComputePostureDiff(prevResults, currentResults)
                }
        }
        return di
}

func (h *AnalysisHandler) persistDriftEvent(domain string, analysisID int32, drift driftInfo, currentHash string) {
        diffJSON, err := json.Marshal(drift.Fields)
        if err != nil {
                slog.Error("Failed to marshal drift diff", mapKeyDomain, domain, mapKeyError, err)
                return
        }

        severity := computeDriftSeverity(drift.Fields)

        driftRow, insertErr := h.store().InsertDriftEvent(context.Background(), dbq.InsertDriftEventParams{
                Domain:         domain,
                AnalysisID:     analysisID,
                PrevAnalysisID: drift.PrevID,
                CurrentHash:    currentHash,
                PreviousHash:   drift.PrevHash,
                DiffSummary:    diffJSON,
                Severity:       severity,
        })
        if insertErr != nil {
                slog.Error("Failed to persist drift event", mapKeyDomain, domain, mapKeyError, insertErr)
                return
        }
        slog.Info("Drift event persisted", mapKeyDomain, domain, "severity", severity, "changed_fields", len(drift.Fields))

        h.queueDriftNotifications(domain, driftRow.ID)
}

func (h *AnalysisHandler) queueDriftNotifications(domain string, driftEventID int32) {
        ctx := context.Background()
        endpoints, err := h.store().ListEndpointsForWatchedDomain(ctx, domain)
        if err != nil {
                slog.Error("Failed to list endpoints for watched domain", mapKeyDomain, domain, mapKeyError, err)
                return
        }
        if len(endpoints) == 0 {
                return
        }
        for _, ep := range endpoints {
                _, qErr := h.store().InsertDriftNotification(ctx, dbq.InsertDriftNotificationParams{
                        DriftEventID: driftEventID,
                        EndpointID:   ep.EndpointID,
                        Status:       "pending",
                })
                if qErr != nil {
                        slog.Error("Failed to queue drift notification",
                                mapKeyDomain, domain,
                                "endpoint_id", ep.EndpointID,
                                "endpoint_type", ep.EndpointType,
                                mapKeyError, qErr,
                        )
                        continue
                }
                slog.Info("Drift notification queued",
                        mapKeyDomain, domain,
                        "endpoint_id", ep.EndpointID,
                        "endpoint_type", ep.EndpointType,
                )
        }
}

func (h *AnalysisHandler) indexFlashData(c *gin.Context, nonce, csrfToken any, category, message string) gin.H {
        data := gin.H{
                strAppversion:     h.Config.AppVersion,
                "BaseURL":         h.Config.BaseURL,
                strCspnonce:       nonce,
                strCsrftoken:      csrfToken,
                strActivepage:     "home",
                "MaintenanceNote": h.Config.MaintenanceNote,
                "BetaPages":       h.Config.BetaPages,
                "FlashMessages":   []FlashMessage{{Category: category, Message: message}},
        }
        mergeAuthData(c, h.Config, data)
        return data
}

func (h *AnalysisHandler) renderRestrictedAccess(c *gin.Context, nonce, csrfToken any) {
        auth, authExists := c.Get(mapKeyAuthenticated)
        if !authExists || auth != true {
                h.renderErrorPage(c, http.StatusNotFound, nonce, csrfToken, mapKeyDanger, strAnalysisNotFound)
                return
        }
        msg := "This report includes user-provided intelligence and is restricted to its owner. " +
                "Custom selectors can reveal internal mail infrastructure and vendor relationships — " +
                "responsible intelligence handling means sharing only with trusted parties. " +
                "If you should have access, request it from the report owner."
        c.HTML(http.StatusForbidden, templateIndex, h.indexFlashData(c, nonce, csrfToken, mapKeyWarning, msg))
}

func (h *AnalysisHandler) renderErrorPage(c *gin.Context, status int, nonce, csrfToken any, category, message string) {
        c.HTML(status, templateIndex, h.indexFlashData(c, nonce, csrfToken, category, message))
}

func extractToolVersion(results map[string]any) string {
        if tv, ok := results["_tool_version"].(string); ok {
                return tv
        }
        return ""
}

func (h *AnalysisHandler) renderIndexFlash(c *gin.Context, nonce, csrfToken any, category, message string) {
        c.HTML(http.StatusOK, templateIndex, h.indexFlashData(c, nonce, csrfToken, category, message))
}

func extractCustomSelectors(c *gin.Context) []string {
        var customSelectors []string
        for _, sel := range []string{c.PostForm("dkim_selector1"), c.PostForm("dkim_selector2")} {
                sel = strings.TrimSpace(sel)
                if sel != "" {
                        customSelectors = append(customSelectors, sel)
                }
        }
        return customSelectors
}

func (h *AnalysisHandler) APIDNSHistory(c *gin.Context) {
        domain := strings.TrimSpace(c.Query(mapKeyDomain))
        if domain == "" || !dnsclient.ValidateDomain(domain) {
                c.JSON(http.StatusBadRequest, gin.H{mapKeyStatus: mapKeyError, mapKeyMessage: "Invalid domain"})
                return
        }
        asciiDomain, err := dnsclient.DomainToASCII(domain)
        if err != nil {
                asciiDomain = domain
        }

        userAPIKey := strings.TrimSpace(c.GetHeader("X-SecurityTrails-Key"))

        if userAPIKey == "" {
                c.JSON(http.StatusOK, gin.H{mapKeyStatus: "no_key", mapKeyMessage: "SecurityTrails API key required"})
                return
        }

        result := analyzer.FetchDNSHistoryWithKey(c.Request.Context(), asciiDomain, userAPIKey, h.DNSHistoryCache)

        status, sOk := result[mapKeyStatus].(string)
        if !sOk || status == "rate_limited" || status == mapKeyError || status == "timeout" {
                c.JSON(http.StatusOK, gin.H{mapKeyStatus: "unavailable"})
                return
        }

        available, aOk := result["available"].(bool)
        if !aOk || !available {
                c.JSON(http.StatusOK, gin.H{mapKeyStatus: "unavailable"})
                return
        }

        c.JSON(http.StatusOK, result)
}

func (h *AnalysisHandler) enrichResultsNoHistory(_ *gin.Context, _ string, results map[string]any) {
        h.enrichResultsAsync(results)
}

func (h *AnalysisHandler) enrichResultsAsync(results map[string]any) {
        if rem, ok := results["remediation"].(map[string]any); ok {
                results["remediation"] = analyzer.EnrichRemediationWithRFCMeta(rem)
        }

        results["rfc_metadata"] = analyzer.GetAllRFCMetadata()
}

func shouldArchiveToWayback(analysisID int32, analysisSuccess, ephemeral, isPrivate, isScanFlagged bool) bool {
        return analysisID > 0 && analysisSuccess && !ephemeral && !isPrivate && !isScanFlagged
}

func computeDriftSeverity(fields []analyzer.PostureDiffField) string {
        severity := "info"
        for _, f := range fields {
                if f.Severity == mapKeyCritical {
                        return mapKeyCritical
                }
                if f.Severity == mapKeyWarning {
                        severity = mapKeyWarning
                }
        }
        return severity
}

func shouldPersistResult(ephemeral, devNull, domainExists, analysisSuccess bool) (persist bool, reason string) {
        if devNull {
                return false, "devnull"
        }
        if ephemeral {
                return false, "ephemeral"
        }
        if !domainExists && analysisSuccess {
                return false, "nonexistent_domain"
        }
        return true, ""
}

func shouldRunICAE(ephemeral, domainExists bool) bool {
        return !ephemeral && domainExists
}

func shouldRecordUserAssociation(isAuthenticated bool, userID int32) bool {
        return isAuthenticated && userID > 0
}

func resultsDomainExists(results map[string]any) bool {
        if v, ok := results["domain_exists"]; ok {
                if b, ok := v.(bool); ok {
                        return b
                }
        }
        return true
}

func (h *AnalysisHandler) APISubdomains(c *gin.Context) {
        domain := strings.TrimPrefix(c.Param(mapKeyDomain), "/")
        domain = strings.TrimSpace(strings.ToLower(domain))
        if domain == "" {
                c.JSON(http.StatusBadRequest, gin.H{mapKeyStatus: mapKeyError, mapKeyMessage: "Domain is required"})
                return
        }
        if !dnsclient.ValidateDomain(domain) {
                c.JSON(http.StatusBadRequest, gin.H{mapKeyStatus: mapKeyError, mapKeyMessage: "Invalid domain"})
                return
        }
        result := h.Analyzer.DiscoverSubdomains(c.Request.Context(), domain)
        c.JSON(http.StatusOK, result)
}

func (h *AnalysisHandler) ExportSubdomainsCSV(c *gin.Context) {
        domain := strings.TrimSpace(strings.ToLower(c.Query(mapKeyDomain)))
        if domain == "" {
                c.Redirect(http.StatusFound, "/")
                return
        }
        if !dnsclient.ValidateDomain(domain) {
                c.Redirect(http.StatusFound, "/")
                return
        }

        cached, ok := h.Analyzer.GetCTCache(domain)
        if !ok || len(cached) == 0 {
                c.Redirect(http.StatusFound, "/analyze?domain="+domain)
                return
        }

        timestamp := time.Now().UTC().Format("20060102_150405")
        filename := fmt.Sprintf("%s_subdomains_%s.csv", strings.ReplaceAll(domain, ".", "_"), timestamp)

        c.Header("Content-Type", "text/csv; charset=utf-8")
        c.Header(headerContentDisposition, fmt.Sprintf("attachment; filename=\"%s\"", filename))
        c.Status(http.StatusOK)

        w := c.Writer
        w.WriteString("Subdomain,Status,Source,CNAME Target,Provider,Certificates,First Seen,Issuers\n")

        for _, sd := range cached {
                name, _ := sd["name"].(string) //nolint:errcheck // type assertion with zero-value fallback
                sdStatus := "Expired"
                if isCur, ok := sd["is_current"].(bool); ok && isCur {
                        sdStatus = "Current"
                }
                source, _ := sd["source"].(string)            //nolint:errcheck // type assertion with zero-value fallback
                cnameTarget, _ := sd["cname_target"].(string) //nolint:errcheck // type assertion with zero-value fallback
                provider, _ := sd["provider"].(string)        //nolint:errcheck // type assertion with zero-value fallback
                certCount, _ := sd["cert_count"].(string)     //nolint:errcheck // type assertion with zero-value fallback
                firstSeen, _ := sd["first_seen"].(string)     //nolint:errcheck // type assertion with zero-value fallback

                var issuerStr string
                if issuers, ok := sd["issuers"].([]string); ok && len(issuers) > 0 {
                        issuerStr = strings.Join(issuers, "; ")
                }

                w.WriteString(csvEscape(name) + "," +
                        csvEscape(sdStatus) + "," +
                        csvEscape(source) + "," +
                        csvEscape(cnameTarget) + "," +
                        csvEscape(provider) + "," +
                        csvEscape(certCount) + "," +
                        csvEscape(firstSeen) + "," +
                        csvEscape(issuerStr) + "\n")
        }
        w.Flush()
}

func csvEscape(s string) string {
        if len(s) > 0 && (s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@' || s[0] == '\t' || s[0] == '\r') {
                s = "'" + s
        }
        if strings.ContainsAny(s, ",\"\n\r") {
                return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
        }
        return s
}

func unmarshalRawJSON(raw json.RawMessage, domain, label string) interface{} {
        if len(raw) == 0 {
                return nil
        }
        var result interface{}
        if err := json.Unmarshal(raw, &result); err != nil {
                slog.Warn("buildAnalysisJSON: failed to unmarshal "+label, "domain", domain, mapKeyError, err)
        }
        return result
}

func extractCurrencyFromResults(fullResults interface{}) interface{} {
        frMap, ok := fullResults.(map[string]interface{})
        if !ok {
                return nil
        }
        cr, exists := frMap[mapKeyCurrencyReport]
        if !exists {
                return nil
        }
        return cr
}

func (h *AnalysisHandler) buildAnalysisJSON(ctx context.Context, analysis dbq.DomainAnalysis) ([]byte, string) {
        fullResults := unmarshalRawJSON(analysis.FullResults, analysis.Domain, "full results")
        ctSubdomains := unmarshalRawJSON(analysis.CtSubdomains, analysis.Domain, "ct subdomains")
        currencyReport := extractCurrencyFromResults(fullResults)

        provenance := map[string]interface{}{
                "tool_version":       h.Config.AppVersion,
                "hash_algorithm":     "SHA-3-512",
                "hash_standard":      "NIST FIPS 202 (Keccak)",
                "export_timestamp":   time.Now().UTC().Format(time.RFC3339),
                "analysis_timestamp": formatTimestampISO(analysis.CreatedAt),
                "engines": map[string]interface{}{
                        "icae": map[string]string{
                                "name":         "Intelligence Confidence Audit Engine",
                                "purpose":      "Correctness verification via deterministic test cases",
                                mapKeyStandard: "ICD 203 Analytic Standards",
                        },
                        "icuae": map[string]string{
                                "name":         "Intelligence Currency Audit Engine",
                                "purpose":      "Data timeliness and validity measurement",
                                mapKeyStandard: "ICD 203, NIST SP 800-53 SI-7, ISO/IEC 25012, RFC 8767",
                        },
                },
        }
        if currencyReport != nil {
                provenance[mapKeyCurrencyReport] = currencyReport
        }
        if q := h.rawQueries(); q != nil {
                if icaeMetrics := icae.LoadReportMetrics(ctx, q); icaeMetrics != nil {
                        provenance["icae_summary"] = map[string]interface{}{
                                "maturity":        icaeMetrics.OverallMaturity,
                                "pass_rate":       icaeMetrics.PassRate,
                                "total_cases":     icaeMetrics.TotalAllCases,
                                "total_passes":    icaeMetrics.TotalPasses,
                                "total_runs":      icaeMetrics.TotalRuns,
                                "days_running":    icaeMetrics.DaysRunning,
                                "protocols_count": icaeMetrics.TotalProtocols,
                        }
                }
        }

        citationManifest := buildCitationManifestFromResults(analysis.FullResults)

        payload := map[string]interface{}{
                "analysis_duration":  analysis.AnalysisDuration,
                "analysis_success":   analysis.AnalysisSuccess,
                "ascii_domain":       analysis.AsciiDomain,
                "citation_manifest":  citationManifest,
                "country_code":       analysis.CountryCode,
                "country_name":       analysis.CountryName,
                "created_at":         formatTimestampISO(analysis.CreatedAt),
                "ct_subdomains":      ctSubdomains,
                "dkim_status":        analysis.DkimStatus,
                "dmarc_policy":       analysis.DmarcPolicy,
                "dmarc_status":       analysis.DmarcStatus,
                mapKeyDomain:         analysis.Domain,
                "error_message":      analysis.ErrorMessage,
                "full_results":       fullResults,
                "id":                 analysis.ID,
                "provenance":         provenance,
                "registrar_name":     analysis.RegistrarName,
                "registrar_source":   analysis.RegistrarSource,
                "spf_status":         analysis.SpfStatus,
                "updated_at":         formatTimestampISO(analysis.UpdatedAt),
        }

        keys := make([]string, 0, len(payload))
        for k := range payload {
                keys = append(keys, k)
        }
        sort.Strings(keys)

        orderedPayload := make([]orderedKV, len(keys))
        for i, k := range keys {
                orderedPayload[i] = orderedKV{Key: k, Value: payload[k]}
        }

        buf := marshalOrderedJSON(orderedPayload)
        buf = append(buf, '\n')

        hash := sha3.Sum512(buf)
        return buf, hex.EncodeToString(hash[:])
}

type orderedKV struct {
        Key   string
        Value interface{}
}

func marshalOrderedJSON(entries []orderedKV) []byte {
        buf := []byte("{")
        for i, kv := range entries {
                if i > 0 {
                        buf = append(buf, ',')
                }
                keyBytes, kErr := json.Marshal(kv.Key)
                if kErr != nil {
                        slog.Debug("marshal key error", "key", kv.Key, "error", kErr)
                        continue
                }
                valBytes, vErr := json.Marshal(kv.Value)
                if vErr != nil {
                        slog.Debug("marshal value error", "key", kv.Key, "error", vErr)
                        continue
                }
                buf = append(buf, keyBytes...)
                buf = append(buf, ':')
                buf = append(buf, valBytes...)
        }
        buf = append(buf, '}')
        return buf
}

func (h *AnalysisHandler) loadAnalysisForAPI(c *gin.Context) (dbq.DomainAnalysis, bool) {
        idStr := c.Param("id")
        analysisID, err := strconv.ParseInt(idStr, 10, 32)
        if err != nil {
                c.JSON(http.StatusBadRequest, gin.H{mapKeyError: "Invalid analysis ID"})
                return dbq.DomainAnalysis{}, false
        }

        ctx := c.Request.Context()
        analysis, err := h.store().GetAnalysisByID(ctx, int32(analysisID))
        if err != nil {
                c.JSON(http.StatusNotFound, gin.H{mapKeyError: strAnalysisNotFound})
                return dbq.DomainAnalysis{}, false
        }

        if !h.checkPrivateAccess(c, analysis.ID, analysis.Private) {
                auth, authOk := c.Get(mapKeyAuthenticated)
                if authOk && auth == true {
                        c.JSON(http.StatusForbidden, gin.H{
                                mapKeyError:   "restricted",
                                mapKeyMessage: "This report includes user-provided intelligence and is restricted to its owner. Custom selectors can reveal internal mail infrastructure and vendor relationships.",
                        })
                } else {
                        c.JSON(http.StatusNotFound, gin.H{mapKeyError: strAnalysisNotFound})
                }
                return dbq.DomainAnalysis{}, false
        }

        return analysis, true
}

func (h *AnalysisHandler) APIAnalysis(c *gin.Context) {
        analysis, ok := h.loadAnalysisForAPI(c)
        if !ok {
                return
        }

        jsonBytes, fileHash := h.buildAnalysisJSON(c.Request.Context(), analysis)
        filename := fmt.Sprintf("dns-intelligence-%s.json", analysis.AsciiDomain)

        if c.Query("download") == "1" || c.Request.Header.Get("Accept") == "application/octet-stream" {
                c.Header(headerContentDisposition, fmt.Sprintf(`attachment; filename="%s"`, filename))
        }
        c.Header("X-SHA3-512", fileHash)
        c.Data(http.StatusOK, "application/json; charset=utf-8", jsonBytes)
}

func (h *AnalysisHandler) APIAnalysisChecksum(c *gin.Context) {
        analysis, ok := h.loadAnalysisForAPI(c)
        if !ok {
                return
        }

        _, fileHash := h.buildAnalysisJSON(c.Request.Context(), analysis)
        filename := fmt.Sprintf("dns-intelligence-%s.json", analysis.AsciiDomain)

        format := c.Query("format")
        if format == "sha3" {
                sha3Filename := fmt.Sprintf("dns-intelligence-%s.json.sha3", analysis.AsciiDomain)
                c.Header(headerContentDisposition, fmt.Sprintf(`attachment; filename="%s"`, sha3Filename))
                var sb strings.Builder
                sb.WriteString("# DNS Tool — SHA-3-512 Integrity Checksum\n")
                sb.WriteString("#\n")
                sb.WriteString("# Cause I'm a hacker, baby, I'm gonna pwn you good,\n")
                sb.WriteString("# Diff your zone to the spec like you knew I would.\n")
                sb.WriteString("# Cite those RFCs, baby, so my argument stood,\n")
                sb.WriteString("# Standards over swagger — that's understood.\n")
                sb.WriteString("#\n")
                sb.WriteString("# — DNS Tool / If it's not in RFC 1034, it ain't understood.\n")
                sb.WriteString("#\n")
                sb.WriteString("# 'Hacker' per RFC 1392 (IETF Internet Users' Glossary, 1993):\n")
                sb.WriteString("# 'A person who delights in having an intimate understanding of the\n")
                sb.WriteString("#  internal workings of a system, computers and computer networks\n")
                sb.WriteString("#  in particular.' That's us. That's always been us.\n")
                sb.WriteString("#\n")
                sb.WriteString("# Algorithm: SHA-3-512 (Keccak, NIST FIPS 202)\n")
                sb.WriteString("# Verify:   openssl dgst -sha3-512 " + filename + "\n")
                sb.WriteString("#\n")
                sb.WriteString("# Provenance:\n")
                sb.WriteString(fmt.Sprintf("#   Analysis ID:   %d\n", analysis.ID))
                sb.WriteString(fmt.Sprintf("#   Report URL:    %s/analysis/%d/view\n", h.Config.BaseURL, analysis.ID))
                sb.WriteString(fmt.Sprintf("#   Tool Version:  %s\n", h.Config.AppVersion))
                sb.WriteString(fmt.Sprintf("#   Export Time:    %s\n", time.Now().UTC().Format(time.RFC3339)))
                sb.WriteString("#   Engines:        ICAE (Confidence) + ICuAE (Currency)\n")
                sb.WriteString("#   Standards:       ICD 203, NIST SP 800-53 SI-7, ISO/IEC 25012\n")
                sb.WriteString("#\n")
                sb.WriteString(fmt.Sprintf("%s  %s\n", fileHash, filename))
                c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(sb.String()))
                return
        }

        checksumResponse := gin.H{
                "algorithm":    "SHA-3-512",
                mapKeyStandard: "NIST FIPS 202 (Keccak)",
                "hash":         fileHash,
                "filename":     filename,
                "provenance": gin.H{
                        "analysis_id":      analysis.ID,
                        "report_url":       fmt.Sprintf("%s/analysis/%d/view", h.Config.BaseURL, analysis.ID),
                        "tool_version":     h.Config.AppVersion,
                        "export_timestamp": time.Now().UTC().Format(time.RFC3339),
                        "engines":          []string{"ICAE (Confidence)", "ICuAE (Currency)"},
                        "standards":        []string{"ICD 203", "NIST SP 800-53 SI-7", "ISO/IEC 25012", "RFC 8767"},
                },
                "verify_commands": map[string]string{
                        "openssl": fmt.Sprintf("openssl dgst -sha3-512 %s", filename),
                        "python":  fmt.Sprintf("python3 -c \"import hashlib; print(hashlib.sha3_512(open('%s','rb').read()).hexdigest())\"", filename),
                        "sha3sum": fmt.Sprintf("sha3sum -a 512 %s", filename),
                },
        }
        c.JSON(http.StatusOK, checksumResponse)
}

type saveAnalysisInput struct {
        domain           string
        asciiDomain      string
        results          map[string]any
        duration         float64
        countryCode      string
        countryName      string
        private          bool
        hasUserSelectors bool
        scanClass        scanner.Classification
}

func (h *AnalysisHandler) saveAnalysis(ctx context.Context, p saveAnalysisInput) (int32, string) {
        p.results["_tool_version"] = h.Config.AppVersion
        fullResultsJSON, marshalErr := json.Marshal(p.results)
        if marshalErr != nil {
                slog.Error("Failed to marshal results", mapKeyDomain, p.domain, mapKeyError, marshalErr)
                return 0, time.Now().UTC().Format(strUtc)
        }

        basicRecordsJSON := getJSONFromResults(p.results, "basic_records", "")
        authRecordsJSON := getJSONFromResults(p.results, "authoritative_records", "")

        spfStatus := getStringFromResults(p.results, mapKeySpfAnalysis, mapKeyStatus)
        dmarcStatus := getStringFromResults(p.results, mapKeyDmarcAnalysis, mapKeyStatus)
        dmarcPolicy := getStringFromResults(p.results, mapKeyDmarcAnalysis, "policy")
        dkimStatus := getStringFromResults(p.results, mapKeyDkimAnalysis, mapKeyStatus)
        registrarName := getStringFromResults(p.results, "registrar_info", "registrar")
        registrarSource := getStringFromResults(p.results, "registrar_info", "source")

        spfRecordsJSON := getJSONFromResults(p.results, mapKeySpfAnalysis, "records")
        dmarcRecordsJSON := getJSONFromResults(p.results, mapKeyDmarcAnalysis, "records")
        dkimSelectorsJSON := getJSONFromResults(p.results, mapKeyDkimAnalysis, "selectors")
        ctSubdomainsJSON := getJSONFromResults(p.results, "ct_subdomains", "")

        postureHash := analyzer.CanonicalPostureHash(p.results)

        success, errorMessage := extractAnalysisError(p.results)
        cc, cn := optionalStrings(p.countryCode, p.countryName)
        scanSource, scanIP := extractScanFields(p.scanClass)

        params := dbq.InsertAnalysisParams{
                Domain:               p.domain,
                AsciiDomain:          p.asciiDomain,
                BasicRecords:         basicRecordsJSON,
                AuthoritativeRecords: authRecordsJSON,
                SpfStatus:            spfStatus,
                SpfRecords:           spfRecordsJSON,
                DmarcStatus:          dmarcStatus,
                DmarcPolicy:          dmarcPolicy,
                DmarcRecords:         dmarcRecordsJSON,
                DkimStatus:           dkimStatus,
                DkimSelectors:        dkimSelectorsJSON,
                RegistrarName:        registrarName,
                RegistrarSource:      registrarSource,
                CtSubdomains:         ctSubdomainsJSON,
                FullResults:          fullResultsJSON,
                CountryCode:          cc,
                CountryName:          cn,
                AnalysisSuccess:      &success,
                ErrorMessage:         errorMessage,
                AnalysisDuration:     &p.duration,
                PostureHash:          &postureHash,
                Private:              p.private,
                HasUserSelectors:     p.hasUserSelectors,
                ScanFlag:             p.scanClass.IsScan,
                ScanSource:           scanSource,
                ScanIp:               scanIP,
        }

        row, err := h.store().InsertAnalysis(ctx, params)
        if err != nil {
                slog.Error("Failed to save analysis", mapKeyDomain, p.domain, mapKeyError, err)
                return 0, time.Now().UTC().Format(strUtc)
        }

        if success {
                go func() {
                        bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
                        defer cancel()
                        if err := h.store().UpsertDomainIndex(bgCtx, dbq.UpsertDomainIndexParams{
                                Domain:    p.domain,
                                HasDane:   analysisHasProtocol(p.results, "dane_analysis"),
                                HasDnssec: analysisHasProtocol(p.results, "dnssec_analysis"),
                                HasMtaSts: analysisHasProtocol(p.results, "mta_sts_analysis"),
                        }); err != nil {
                                slog.Warn("domain index upsert failed", "domain", p.domain, "error", err)
                        }
                }()
        }

        timestamp := "just now"
        if row.CreatedAt.Valid {
                timestamp = row.CreatedAt.Time.Format(strUtc)
        }
        return row.ID, timestamp
}

func (h *AnalysisHandler) SaveForAgent(ctx context.Context, domain, asciiDomain string, results map[string]any) int32 {
        id, _ := h.saveAnalysis(ctx, saveAnalysisInput{
                domain:      domain,
                asciiDomain: asciiDomain,
                results:     results,
        })
        return id
}

func analysisHasProtocol(results map[string]any, key string) bool {
        section, ok := results[key].(map[string]any)
        if !ok {
                return false
        }
        status, _ := section["status"].(string)
        return status == "success" || status == "warning"
}

func extractAnalysisError(results map[string]any) (bool, *string) {
        if errStr, ok := results[mapKeyError].(string); ok && errStr != "" {
                return false, &errStr
        }
        return true, nil
}

func optionalStrings(a, b string) (*string, *string) {
        var ap, bp *string
        if a != "" {
                ap = &a
        }
        if b != "" {
                bp = &b
        }
        return ap, bp
}

func extractScanFields(sc scanner.Classification) (*string, *string) {
        var scanSource, scanIP *string
        if sc.IsScan {
                scanSource = &sc.Source
        }
        if sc.IP != "" {
                scanIP = &sc.IP
        }
        return scanSource, scanIP
}

var countryCache sync.Map

type countryEntry struct {
        code, name string
        fetched    time.Time
}

var countryCacheEvictOnce sync.Once

func startCountryCacheEviction() {
        countryCacheEvictOnce.Do(func() {
                go func() {
                        ticker := time.NewTicker(1 * time.Hour)
                        defer ticker.Stop()
                        for range ticker.C {
                                now := time.Now()
                                countryCache.Range(func(key, value any) bool {
                                        if entry, ok := value.(countryEntry); ok {
                                                if now.Sub(entry.fetched) > 24*time.Hour {
                                                        countryCache.Delete(key)
                                                }
                                        }
                                        return true
                                })
                        }
                }()
        })
}

func lookupCountry(ip string) (string, string) {
        if ip == "" || ip == "127.0.0.1" || ip == "::1" { // S1313: loopback check — intentional
                return "", ""
        }

        startCountryCacheEviction()

        if cached, ok := countryCache.Load(ip); ok {
                entry, valid := cached.(countryEntry)
                if valid && time.Since(entry.fetched) < 24*time.Hour {
                        return entry.code, entry.name
                }
        }

        client := &http.Client{Timeout: 2 * time.Second}
        resp, err := client.Get(fmt.Sprintf("https://ip-api.com/json/%s?fields=status,countryCode,country", ip))
        if err != nil {
                return "", ""
        }
        defer safeClose(resp.Body, "openphish response body")

        if resp.StatusCode != 200 {
                return "", ""
        }

        var result struct {
                Status      string `json:"status"`
                CountryCode string `json:"countryCode"`
                Country     string `json:"country"`
        }
        if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || result.Status != "success" {
                return "", ""
        }

        countryCache.Store(ip, countryEntry{code: result.CountryCode, name: result.Country, fetched: time.Now()})
        return result.CountryCode, result.Country
}

func getStringFromResults(results map[string]any, section, key string) *string {
        if key == "" {
                if v, ok := results[section]; ok {
                        if s, ok := v.(string); ok {
                                return &s
                        }
                }
                return nil
        }
        sectionData, ok := results[section].(map[string]any)
        if !ok {
                return nil
        }
        v, ok := sectionData[key]
        if !ok {
                return nil
        }
        s, ok := v.(string)
        if !ok {
                return nil
        }
        return &s
}

func extractReportsAndDurations(analyses []dbq.DomainAnalysis) ([]icuae.CurrencyReport, []float64) {
        var reports []icuae.CurrencyReport
        var durations []float64
        for _, ha := range analyses {
                if len(ha.FullResults) == 0 {
                        continue
                }
                var fr map[string]any
                if json.Unmarshal(ha.FullResults, &fr) != nil {
                        continue
                }
                if cr, ok := fr[mapKeyCurrencyReport]; ok {
                        if report, hydrated := icuae.HydrateCurrencyReport(cr); hydrated {
                                reports = append(reports, report)
                        }
                }
                if ha.AnalysisDuration != nil {
                        durations = append(durations, *ha.AnalysisDuration*1000)
                }
        }
        return reports, durations
}

func buildSuggestedConfig(ctx context.Context, queries *dbq.Queries, domain string, currentID int32) *icuae.SuggestedConfig {
        historicalAnalyses, err := queries.ListAnalysesByDomain(ctx, dbq.ListAnalysesByDomainParams{
                Domain: domain,
                Limit:  20,
        })
        if err != nil || len(historicalAnalyses) < 3 {
                return nil
        }

        reports, durations := extractReportsAndDurations(historicalAnalyses)

        if len(reports) < 3 {
                return nil
        }

        stats := icuae.BuildRollingStats(reports, durations)
        config := icuae.GenerateSuggestedConfig(stats, icuae.DefaultProfile)
        config.BasedOn = len(reports)
        return &config
}

func getJSONFromResults(results map[string]any, section, key string) json.RawMessage {
        var data any
        if key == "" {
                data = results[section]
        } else {
                sectionData, ok := results[section].(map[string]any)
                if !ok {
                        return nil
                }
                data = sectionData[key]
        }
        if data == nil {
                return nil
        }
        b, err := json.Marshal(data)
        if err != nil {
                return nil
        }
        return b
}

var protocolResultKeys = map[string]string{
        "SPF":     mapKeySpfAnalysis,
        "DKIM":    mapKeyDkimAnalysis,
        "DMARC":   mapKeyDmarcAnalysis,
        "DANE":    "dane_analysis",
        "DNSSEC":  "dnssec_analysis",
        "BIMI":    "bimi_analysis",
        "MTA_STS": "mta_sts_analysis",
        "TLS_RPT": "tlsrpt_analysis",
        "CAA":     "caa_analysis",
}

var icuaeToDimChart = map[string]string{
        icuae.DimensionSourceCredibility: "SourceCredibility",
        icuae.DimensionCurrentness:       "TemporalValidity",
        icuae.DimensionCompleteness:      "ChainCompleteness",
        icuae.DimensionTTLCompliance:     "TTLCompliance",
        icuae.DimensionTTLRelevance:      "ResolverConsensus",
}

func (h *AnalysisHandler) applyConfidenceEngines(results map[string]any) {
        cr, ok := results[mapKeyCurrencyReport].(icuae.CurrencyReport)
        if !ok {
                return
        }

        calibrated := h.computeCalibratedConfidence(results, cr)
        results["calibrated_confidence"] = calibrated

        ewmaSnapshot := h.recordDimensionCharts(cr)
        results["ewma_drift"] = ewmaSnapshot

        slog.Info("Confidence engines applied",
                "protocols_calibrated", len(calibrated),
                "ewma_dimensions", len(ewmaSnapshot),
        )
}

func (h *AnalysisHandler) computeCalibratedConfidence(results map[string]any, cr icuae.CurrencyReport) map[string]float64 {
        totalAgree, totalResolvers := aggregateResolverAgreement(results)

        calibrated := make(map[string]float64, len(protocolResultKeys))
        for protocol, resultKey := range protocolResultKeys {
                rawConfidence := protocolRawConfidence(results, resultKey)
                cc := h.Calibration.CalibratedConfidence(protocol, rawConfidence, totalAgree, totalResolvers)
                calibrated[protocol] = cc
        }
        return calibrated
}

func protocolRawConfidence(results map[string]any, resultKey string) float64 {
        section, ok := results[resultKey].(map[string]any)
        if !ok {
                return 0.0
        }
        status, _ := section[mapKeyStatus].(string) //nolint:errcheck // zero-value fallback is intentional
        switch status {
        case "secure", "pass", "valid", "good":
                return 1.0
        case mapKeyWarning, "info", "partial":
                return 0.7
        case "fail", mapKeyDanger, mapKeyCritical:
                return 0.3
        case mapKeyError, "n/a", "":
                return 0.0
        default:
                return 0.5
        }
}

func aggregateResolverAgreement(results map[string]any) (int, int) {
        consensus, ok := results["resolver_consensus"].(map[string]any)
        if !ok {
                return 0, 0
        }
        perRecord, ok := consensus["per_record_consensus"].(map[string]any)
        if !ok {
                return 0, 0
        }
        totalAgree := 0
        totalResolvers := 0
        for _, data := range perRecord {
                rd, ok := data.(map[string]any)
                if !ok {
                        continue
                }
                rc, _ := rd["resolver_count"].(int)      //nolint:errcheck // zero-value fallback is intentional
                isConsensus, _ := rd["consensus"].(bool) //nolint:errcheck // zero-value fallback is intentional
                agreeCount := rc
                if !isConsensus {
                        agreeCount = rc - 1
                        if agreeCount < 0 {
                                agreeCount = 0
                        }
                }
                totalAgree += agreeCount
                totalResolvers += rc
        }
        return totalAgree, totalResolvers
}

func (h *AnalysisHandler) recordDimensionCharts(cr icuae.CurrencyReport) map[string]icuae.ChartSnapshot {
        scores := make(map[string]float64, len(cr.Dimensions))
        for _, dim := range cr.Dimensions {
                if chartKey, ok := icuaeToDimChart[dim.Dimension]; ok {
                        scores[chartKey] = dim.Score
                }
        }
        h.DimCharts.RecordDimensionScores(scores)
        return h.DimCharts.Summary()
}
