// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package main

import (
        "context"
        "fmt"
        "html/template"
        "log/slog"
        "mime"
        "net/http"
        "os"
        "os/exec"
        "os/signal"
        "path/filepath"
        "strings"
        "sync/atomic"
        "syscall"
        "time"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/citation"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/entitlements"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"
        "dnstool/go-server/internal/dnsclient"
        "dnstool/go-server/internal/handlers"
        "dnstool/go-server/internal/logging"
        "dnstool/go-server/internal/middleware"
        "dnstool/go-server/internal/notifier"
        "dnstool/go-server/internal/scanner"
        tmplFuncs "dnstool/go-server/internal/templates"

        "github.com/gin-contrib/gzip"
        "github.com/gin-gonic/gin"
)

const (
        mapKeyError = "error"
)

const headerCacheControl = "Cache-Control"

var staticMIME = map[string]string{
        ".mp4":   "video/mp4",
        ".webm":  "video/webm",
        ".ogg":   "video/ogg",
        ".m4a":   "audio/mp4",
        ".css":   "text/css; charset=utf-8",
        ".js":    "application/javascript",
        ".json":  "application/json",
        ".html":  "text/html; charset=utf-8",
        ".xml":   "application/xml",
        ".svg":   "image/svg+xml",
        ".png":   "image/png",
        ".jpg":   "image/jpeg",
        ".jpeg":  "image/jpeg",
        ".gif":   "image/gif",
        ".webp":  "image/webp",
        ".avif":  "image/avif",
        ".ico":   "image/x-icon",
        ".woff":  "font/woff",
        ".woff2": "font/woff2",
        ".ttf":   "font/ttf",
        ".pdf":   "application/pdf",
        ".txt":   "text/plain; charset=utf-8",
        ".map":   "application/json",
        ".zip":   "application/zip",
}

func init() {
        for ext, ct := range staticMIME {
                _ = mime.AddExtensionType(ext, ct)
        }
}

func main() {
        slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
                Level: slog.LevelInfo,
                ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
                        if a.Value.Kind() == slog.KindString {
                                v := a.Value.String()
                                if strings.Contains(v, "@") || strings.Contains(v, "webhook") || strings.Contains(v, "token=") {
                                        return slog.Attr{Key: a.Key, Value: slog.StringValue("[REDACTED_EARLY]")}
                                }
                        }
                        return a
                },
        })))

        earlyPort := os.Getenv("PORT")
        if earlyPort == "" {
                earlyPort = "5000"
        }
        earlyAddr := fmt.Sprintf("0.0.0.0:%s", earlyPort)

        var handler atomic.Value
        handler.Store(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                if r.URL.Path == "/" || r.URL.Path == "/healthz" {
                        w.Header().Set("Content-Type", "application/json")
                        w.WriteHeader(http.StatusOK)
                        w.Write([]byte(`{"status":"starting"}`))
                        return
                }
                w.Header().Set("Content-Type", "application/json")
                w.WriteHeader(http.StatusServiceUnavailable)
                w.Write([]byte(`{"status":"starting"}`))
        }))

        srv := &http.Server{
                Addr: earlyAddr,
                Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                        handler.Load().(http.Handler).ServeHTTP(w, r)
                }),
                ReadHeaderTimeout: 10 * time.Second,
                IdleTimeout:       120 * time.Second,
                MaxHeaderBytes:    1 << 20,
        }

        listenErr := make(chan error, 1)
        go func() {
                if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
                        listenErr <- err
                }
        }()

        select {
        case err := <-listenErr:
                slog.Error("Server failed to bind", mapKeyError, err)
                os.Exit(1)
        case <-time.After(100 * time.Millisecond):
        }
        slog.Info("Early listener started — accepting healthchecks", "address", earlyAddr)

        cfg, err := config.Load()
        if err != nil {
                slog.Error("Failed to load config", mapKeyError, err)
                os.Exit(1)
        }

        dnsclient.SetUserAgentVersion(cfg.AppVersion)

        database, err := db.Connect(cfg.DatabaseURL)
        if err != nil {
                slog.Error("Failed to connect to database", mapKeyError, err)
                handler.Store(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                        if r.URL.Path == "/healthz" {
                                w.Header().Set("Content-Type", "application/json")
                                w.WriteHeader(http.StatusOK)
                                w.Write([]byte(`{"status":"degraded","reason":"database_unavailable"}`))
                                return
                        }
                        w.Header().Set("Content-Type", "text/html; charset=utf-8")
                        w.Header().Set("Retry-After", "30")
                        w.WriteHeader(http.StatusServiceUnavailable)
                        w.Write([]byte(`<!DOCTYPE html><html><head><title>DNS Tool — Maintenance</title><meta http-equiv="refresh" content="30"><style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#0d1117;color:#c9d1d9}div{text-align:center;max-width:480px;padding:2rem}.icon{font-size:3rem;margin-bottom:1rem}h1{color:#58a6ff;margin:0 0 .5rem}p{color:#8b949e;line-height:1.6}</style></head><body><div><div class="icon">🦉</div><h1>DNS Tool</h1><p>The service is temporarily unavailable while the database connection is being restored. This page will automatically refresh.</p></div></body></html>`))
                }))
                slog.Warn("Running in DEGRADED mode — serving maintenance page, waiting for database")
                go func() {
                        for {
                                time.Sleep(15 * time.Second)
                                slog.Info("Retrying database connection in degraded mode...")
                                if retryDB, retryErr := db.Connect(cfg.DatabaseURL); retryErr == nil {
                                        slog.Info("Database reconnected in degraded mode — full restart required")
                                        retryDB.Close()
                                }
                        }
                }()
                quit := make(chan os.Signal, 1)
                signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
                <-quit
                slog.Info("Shutdown signal received in degraded mode")
                shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
                defer shutdownCancel()
                srv.Shutdown(shutdownCtx)
                return
        }
        defer database.Close()

        database.RunSeedMigrations("go-server/db/migrations")

        logger, err := logging.Setup(database.Pool, cfg.DiscordWebhookURL)
        if err != nil {
                slog.Warn("Structured logger setup failed, continuing with default", mapKeyError, err)
        } else {
                defer logger.Close()
                slog.Info("Structured logging initialized",
                        logging.AttrEvent, logging.EventStartup,
                        logging.AttrCategory, logging.CategorySystem,
                        "sinks", "stdout+jsonl+db+discord",
                )
        }

        gin.SetMode(gin.ReleaseMode)
        router := gin.New()
        router.SetTrustedProxies([]string{"127.0.0.1/8", "::1/128"})
        router.ForwardedByClientIP = true
        router.RemoteIPHeaders = []string{"X-Forwarded-For", "X-Real-Ip"}
        slog.Info("Trusted proxies configured — reading client IP from X-Forwarded-For via local proxy")

        if cfg.IsDevEnvironment {
                slog.Info("Security headers: dev mode — iframe embedding allowed for Replit preview")
        } else {
                slog.Info("Security headers: production mode — strict frame-ancestors, X-Frame-Options DENY")
        }

        router.Use(middleware.Recovery(cfg.AppVersion, map[string]any{
                "MaintenanceNote": cfg.MaintenanceNote,
                "BetaPages":       cfg.BetaPages,
        }))
        if !cfg.IsDevEnvironment {
                router.Use(middleware.CanonicalHostRedirect(cfg.BaseURL))
        }
        router.Use(gzip.Gzip(gzip.DefaultCompression))
        router.Use(middleware.RequestContext())
        router.Use(middleware.SecurityHeaders(cfg.IsDevEnvironment))

        csrf := middleware.NewCSRFMiddleware(cfg.SessionSecret)
        router.Use(csrf.Handler())

        router.Use(middleware.SessionLoader(database.Pool))

        analyticsCollector := middleware.NewAnalyticsCollector(database.Pool, cfg.BaseURL)
        router.Use(analyticsCollector.Middleware())

        rateLimiter := middleware.NewInMemoryRateLimiter()
        slog.Info("Rate limiter initialized", "backend", "in-memory", "max_requests", middleware.RateLimitMaxRequests, "window_seconds", middleware.RateLimitWindow)

        templatesDir := findTemplatesDir()
        slog.Info("Templates directory resolved", "path", templatesDir)
        globPattern := filepath.Join(templatesDir, "*.html")
        tmpl, err := template.New("").Funcs(tmplFuncs.FuncMap()).ParseGlob(globPattern)
        if err != nil {
                cwd, _ := os.Getwd()
                slog.Error("Failed to parse templates", "error", err, "glob", globPattern, "cwd", cwd)
                os.Exit(1)
        }
        router.SetHTMLTemplate(tmpl)

        staticDir := findStaticDir()
        slog.Info("Static directory resolved", "path", staticDir)
        tmplFuncs.InitSRI(staticDir)
        staticFS := http.Dir(staticDir)
        fileServer := http.StripPrefix("/static", http.FileServer(staticFS))
        serveStatic := func(c *gin.Context) {
                fp := c.Param("filepath")
                if isStaticAsset(fp) {
                        if strings.Contains(c.Request.URL.RawQuery, "v=") {
                                c.Header(headerCacheControl, "public, max-age=31536000, immutable")
                        } else {
                                c.Header(headerCacheControl, "public, max-age=86400")
                        }
                }
                fileServer.ServeHTTP(c.Writer, c.Request)
        }
        router.GET("/static/*filepath", serveStatic)
        router.HEAD("/static/*filepath", serveStatic)
        faviconHandler := func(c *gin.Context) {
                c.Header(headerCacheControl, "public, max-age=86400")
                c.File(filepath.Join(staticDir, "icons", "favicon-48x48.png"))
        }
        router.GET("/favicon.ico", faviconHandler)
        router.HEAD("/favicon.ico", faviconHandler)
        appleTouchHandler := func(c *gin.Context) {
                c.Header(headerCacheControl, "public, max-age=86400")
                c.File(filepath.Join(staticDir, "icons", "apple-touch-icon-180x180.png"))
        }
        router.GET("/apple-touch-icon.png", appleTouchHandler)
        router.HEAD("/apple-touch-icon.png", appleTouchHandler)
        router.GET("/apple-touch-icon-precomposed.png", appleTouchHandler)
        router.HEAD("/apple-touch-icon-precomposed.png", appleTouchHandler)
        imagesHandler := func(c *gin.Context) {
                fp := c.Param("filepath")
                if fp == "" || strings.Contains(fp, "..") {
                        c.Status(http.StatusNotFound)
                        return
                }
                c.Header(headerCacheControl, "public, max-age=86400")
                c.File(filepath.Join(staticDir, "images", fp))
        }
        router.GET("/images/*filepath", imagesHandler)
        router.HEAD("/images/*filepath", imagesHandler)

        ctStore := analyzer.NewPgCTStore(database.Queries)
        dnsAnalyzer := analyzer.New(analyzer.WithCTStore(ctStore))
        dnsAnalyzer.SMTPProbeMode = cfg.SMTPProbeMode
        dnsAnalyzer.IPFSProbeMode = cfg.IPFSProbeMode
        dnsAnalyzer.ProbeAPIURL = cfg.ProbeAPIURL
        dnsAnalyzer.ProbeAPIKey = cfg.ProbeAPIKey
        for _, p := range cfg.Probes {
                dnsAnalyzer.Probes = append(dnsAnalyzer.Probes, analyzer.ProbeEndpoint{
                        ID:    p.ID,
                        Label: p.Label,
                        URL:   p.URL,
                        Key:   p.Key,
                })
        }
        slog.Info("DNS analyzer initialized with telemetry", "smtp_probe_mode", cfg.SMTPProbeMode, "ipfs_probe_mode", cfg.IPFSProbeMode, "probe_count", len(cfg.Probes))

        analyzer.InitIETFMetadata()
        analyzer.ScheduleRFCRefresh()

        scanner.StartCISARefresh()

        dnsHistoryCache := analyzer.NewDNSHistoryCache(24 * time.Hour)
        slog.Info("DNS history cache initialized", "ttl", "24h")

        homeHandler := handlers.NewHomeHandler(cfg, database)
        healthHandler := handlers.NewHealthHandler(database, dnsAnalyzer)
        historyHandler := handlers.NewHistoryHandler(database, cfg)
        analysisHandler := handlers.NewAnalysisHandler(database, cfg, dnsAnalyzer, dnsHistoryCache)
        statsHandler := handlers.NewStatsHandler(database, cfg)
        compareHandler := handlers.NewCompareHandler(database, cfg)
        exportHandler := handlers.NewExportHandler(database)
        snapshotHandler := handlers.NewSnapshotHandler(database, cfg)
        staticHandler := handlers.NewStaticHandler(staticDir, cfg.AppVersion, cfg.BaseURL)
        proxyHandler := handlers.NewProxyHandler()

        router.GET("/", homeHandler.Index)
        router.HEAD("/", homeHandler.Index)
        router.GET("/healthz", healthHandler.Healthz)
        router.HEAD("/healthz", healthHandler.Healthz)
        router.GET("/api/capacity", healthHandler.Capacity)
        router.GET("/go/health", middleware.RequireAdmin(), healthHandler.HealthCheck)

        router.GET("/.well-known/security.txt", staticHandler.SecurityTxt)
        router.GET("/security.txt", staticHandler.SecurityTxt)
        router.GET("/robots.txt", staticHandler.RobotsTxt)
        router.GET("/sitemap.xml", staticHandler.SitemapXML)
        router.GET("/bimi-logo.svg", staticHandler.BIMILogoSVG)
        router.GET("/llms.txt", staticHandler.LLMsTxt)
        router.GET("/llms-full.txt", staticHandler.LLMsFullTxt)
        router.GET("/.well-known/llms.txt", staticHandler.LLMsTxt)
        router.GET("/.well-known/llms-full.txt", staticHandler.LLMsFullTxt)
        router.GET("/manifest.json", staticHandler.ManifestJSON)
        router.GET("/sw.js", staticHandler.ServiceWorker)

        router.GET("/analyze", analysisHandler.Analyze)
        router.POST("/analyze", middleware.AnalyzeRateLimit(rateLimiter), analysisHandler.Analyze)
        router.GET("/api/scan/progress/:token", handlers.ScanProgressHandler(analysisHandler.ProgressStore))

        router.GET("/history", historyHandler.History)

        dossierHandler := handlers.NewDossierHandler(database, cfg)
        router.GET("/dossier", middleware.RequireFeature(entitlements.FeatureDossier), dossierHandler.Dossier)

        driftHandler := handlers.NewDriftHandler(database, cfg)
        router.GET("/drift", driftHandler.Timeline)

        watchlistHandler := handlers.NewWatchlistHandler(database, cfg)
        router.GET("/watchlist", middleware.RequireFeature(entitlements.FeatureWatchlist), watchlistHandler.Watchlist)
        router.POST("/watchlist/add", middleware.RequireFeature(entitlements.FeatureWatchlist), watchlistHandler.AddDomain)
        router.POST("/watchlist/:id/delete", middleware.RequireFeature(entitlements.FeatureWatchlist), watchlistHandler.RemoveDomain)
        router.POST("/watchlist/:id/toggle", middleware.RequireFeature(entitlements.FeatureWatchlist), watchlistHandler.ToggleDomain)
        router.POST("/watchlist/endpoint/add", middleware.RequireFeature(entitlements.FeatureWatchlist), watchlistHandler.AddEndpoint)
        router.POST("/watchlist/endpoint/:id/delete", middleware.RequireFeature(entitlements.FeatureWatchlist), watchlistHandler.RemoveEndpoint)
        router.POST("/watchlist/endpoint/:id/toggle", middleware.RequireFeature(entitlements.FeatureWatchlist), watchlistHandler.ToggleEndpoint)
        router.POST("/watchlist/webhook/test", middleware.RequireAdmin(), watchlistHandler.TestWebhook)

        router.GET("/analysis/:id", analysisHandler.ViewAnalysis)
        router.GET("/analysis/:id/view", analysisHandler.ViewAnalysisStatic)
        router.GET("/analysis/:id/view/:mode", analysisHandler.ViewAnalysisStatic)
        router.GET("/analysis/:id/executive", analysisHandler.ViewAnalysisExecutive)

        router.GET("/stats", statsHandler.Stats)
        router.GET("/statistics", statsHandler.StatisticsRedirect)

        failuresHandler := handlers.NewFailuresHandler(database, cfg)
        router.GET("/failures", failuresHandler.Failures)

        router.GET("/compare", compareHandler.Compare)

        adminHandler := handlers.NewAdminHandler(database, cfg, dnsAnalyzer.BackpressureRejections)
        router.GET("/ops", middleware.RequireAdmin(), adminHandler.Dashboard)
        router.POST("/ops/user/:id/delete", middleware.RequireAdmin(), adminHandler.DeleteUser)
        router.POST("/ops/user/:id/reset-sessions", middleware.RequireAdmin(), adminHandler.ResetUserSessions)
        router.POST("/ops/sessions/purge-expired", middleware.RequireAdmin(), adminHandler.PurgeExpiredSessions)
        router.GET("/ops/operations", middleware.RequireAdmin(), adminHandler.OperationsPage)
        router.POST("/ops/run/:task", middleware.RequireAdmin(), adminHandler.RunOperation)

        probeAdminHandler := handlers.NewProbeAdminHandler(database, cfg)
        router.GET("/ops/probes", middleware.RequireAdmin(), probeAdminHandler.ProbeDashboard)
        router.POST("/ops/probes/:id/:action", middleware.RequireAdmin(), probeAdminHandler.RunProbeAction)

        analyticsHandler := handlers.NewAnalyticsHandler(database, cfg)
        router.GET("/ops/analytics", middleware.RequireAdmin(), analyticsHandler.Dashboard)

        telemetryHandler := handlers.NewTelemetryHandler(database, cfg)
        router.GET("/ops/telemetry", middleware.RequireAdmin(), telemetryHandler.Dashboard)
        router.GET("/admin/telemetry", middleware.RequireAdmin(), telemetryHandler.Dashboard)
        router.GET("/api/telemetry/verify/:id", middleware.RequireAdmin(), telemetryHandler.VerifyHash)

        logsHandler := handlers.NewLogsHandler(database, cfg)
        router.GET("/ops/logs", middleware.RequireAdmin(), logsHandler.Dashboard)
        router.GET("/admin/logs", middleware.RequireAdmin(), logsHandler.Dashboard)
        router.GET("/admin/logs/export", middleware.RequireAdmin(), logsHandler.ExportJSONL)

        pipelineHandler := handlers.NewPipelineHandler(database, cfg)
        router.GET("/ops/pipeline", middleware.RequireAdmin(), pipelineHandler.Observatory)

        router.GET("/snapshot/:domain", snapshotHandler.Snapshot)

        router.GET("/export/json", middleware.RequireAdmin(), exportHandler.ExportJSON)
        router.GET("/export/subdomains", analysisHandler.ExportSubdomainsCSV)

        router.GET("/api/analysis/:id", analysisHandler.APIAnalysis)
        router.GET("/api/analysis/:id/checksum", analysisHandler.APIAnalysisChecksum)
        router.GET("/api/subdomains/*domain", analysisHandler.APISubdomains)
        router.GET("/api/dns-history", analysisHandler.APIDNSHistory)
        router.GET("/api/health", middleware.RequireAdmin(), healthHandler.HealthCheck)

        router.GET("/proxy/bimi-logo", proxyHandler.BIMILogo)
        router.GET("/proxy/sonar-badge/:key", proxyHandler.SonarBadge)

        toolkitHandler := handlers.NewToolkitHandler(cfg)
        router.GET("/toolkit", toolkitHandler.ToolkitPage)
        router.POST("/toolkit/myip", toolkitHandler.MyIP)
        router.POST("/toolkit/portcheck", middleware.AnalyzeRateLimit(rateLimiter), toolkitHandler.PortCheck)

        ttlTunerHandler := handlers.NewTTLTunerHandler(cfg, dnsAnalyzer)
        router.GET("/ttl-tuner", ttlTunerHandler.TTLTunerPage)
        router.GET("/ttl-tuner/analyze", func(c *gin.Context) { c.Redirect(http.StatusMovedPermanently, "/ttl-tuner") })
        router.POST("/ttl-tuner/analyze", middleware.AnalyzeRateLimit(rateLimiter), ttlTunerHandler.AnalyzeTTL)

        remediationHandler := handlers.NewRemediationHandler(database, cfg)
        router.GET("/remediation", remediationHandler.RemediationPage)
        router.POST("/remediation", remediationHandler.RemediationSubmit)

        investigateHandler := handlers.NewInvestigateHandler(cfg, dnsAnalyzer)
        router.GET("/investigate", investigateHandler.InvestigatePage)
        router.POST("/investigate", middleware.AnalyzeRateLimit(rateLimiter), investigateHandler.Investigate)

        emailHeaderHandler := handlers.NewEmailHeaderHandler(cfg)
        router.GET("/email-header", emailHeaderHandler.EmailHeaderPage)
        router.POST("/email-header", middleware.AnalyzeRateLimit(rateLimiter), emailHeaderHandler.AnalyzeEmailHeader)

        sourcesHandler := handlers.NewSourcesHandler(cfg)
        router.GET("/sources", sourcesHandler.Sources)

        citationReg := citation.Global()
        citationHandler := handlers.NewCitationHandler(cfg, citationReg, database)
        router.GET("/api/authorities", citationHandler.Authorities)
        router.GET("/api/research", citationHandler.ResearchAPI)
        router.GET("/cite", citationHandler.CitePage)
        router.GET("/cite/software", citationHandler.SoftwareCitation)
        router.GET("/analysis/:id/cite", citationHandler.AnalysisCitation)

        architectureHandler := handlers.NewArchitectureHandler(cfg)
        router.GET("/architecture", architectureHandler.Architecture)

        signatureHandler := handlers.NewSignatureHandler(cfg)
        router.GET("/signature", signatureHandler.SignaturePage)

        topologyHandler := handlers.NewTopologyHandler(cfg)
        router.GET("/topology", topologyHandler.Topology)

        changelogHandler := handlers.NewChangelogHandler(cfg)
        router.GET("/changelog", changelogHandler.Changelog)

        faqHandler := handlers.NewFAQHandler(cfg)
        router.GET("/faq/subdomains", faqHandler.SubdomainDiscovery)

        confidenceHandler := handlers.NewConfidenceHandler(cfg, database)
        router.GET("/confidence", confidenceHandler.Confidence)
        router.GET("/confidence/audit-log", confidenceHandler.AuditLog)

        securityPolicyHandler := handlers.NewSecurityPolicyHandler(cfg)
        router.GET("/security-policy", securityPolicyHandler.SecurityPolicy)

        privacyHandler := handlers.NewPrivacyHandler(cfg)
        router.GET("/privacy", privacyHandler.Privacy)

        aboutHandler := handlers.NewAboutHandler(cfg)
        router.GET("/about", aboutHandler.About)

        contactHandler := handlers.NewContactHandler(cfg)
        router.GET("/contact", contactHandler.Contact)

        refLibHandler := handlers.NewReferenceLibraryHandler(cfg)
        router.GET("/reference-library", refLibHandler.ReferenceLibrary)

        roadmapHandler := handlers.NewRoadmapHandler(cfg)
        router.GET("/roadmap", roadmapHandler.Roadmap)

        approachHandler := handlers.NewApproachHandler(cfg)
        router.GET("/approach", approachHandler.Approach)

        edeHandler := handlers.NewEDEHandler(database, cfg)
        router.GET("/ede", edeHandler.EDE)

        manifestoHandler := handlers.NewManifestoHandler(cfg)
        router.GET("/manifesto", manifestoHandler.Manifesto)

        owlSemaphoreHandler := handlers.NewOwlSemaphoreHandler(cfg)
        router.GET("/owl-semaphore", owlSemaphoreHandler.OwlSemaphore)
        router.GET("/owl-layers", owlSemaphoreHandler.OwlLayers)

        commStdsHandler := handlers.NewCommunicationStandardsHandler(cfg)
        router.GET("/communication-standards", commStdsHandler.CommunicationStandards)

        router.GET("/methodology", staticHandler.MethodologyPDF)
        router.GET("/docs/dns-tool-methodology.pdf", staticHandler.MethodologyPDF)
        router.GET("/foundations", staticHandler.FoundationsPDF)
        router.GET("/docs/philosophical-foundations.pdf", staticHandler.FoundationsPDF)
        router.GET("/manifesto-pdf", staticHandler.ManifestoPDF)
        router.GET("/docs/founders-manifesto.pdf", staticHandler.ManifestoPDF)
        router.GET("/communication-standards-pdf", staticHandler.CommStandardsPDF)
        router.GET("/docs/communication-standards.pdf", staticHandler.CommStandardsPDF)

        corpusHandler := handlers.NewCorpusHandler(cfg)
        router.GET("/corpus", corpusHandler.Corpus)

        videoHandler := handlers.NewVideoHandler(cfg)
        router.GET("/publications", videoHandler.Publications)
        router.GET("/video/forgotten-domain", videoHandler.ForgottenDomain)
        router.GET("/case-study/", videoHandler.CaseStudyIndex)
        router.GET("/case-study/intelligence-dmarc", videoHandler.IntelligenceDMARC)

        roeHandler := handlers.NewROEHandler(cfg)
        router.GET("/roe", roeHandler.ROE)

        blackSiteHandler := handlers.NewBlackSiteHandler(database, cfg)
        router.GET("/black-site", blackSiteHandler.BlackSite)

        brandColorsHandler := handlers.NewBrandColorsHandler(cfg)
        router.GET("/brand-colors", brandColorsHandler.BrandColors)

        colorScienceHandler := handlers.NewColorScienceHandler(cfg)
        router.GET("/color-science", colorScienceHandler.ColorScience)

        badgeHandler := handlers.NewBadgeHandler(database, cfg)
        router.GET("/badge", badgeHandler.Badge)
        router.GET("/badge/shields", badgeHandler.BadgeShieldsIO)
        router.GET("/badge/embed", badgeHandler.BadgeEmbed)
        router.GET("/badge/animated", badgeHandler.BadgeAnimated)

        agentHandler := handlers.NewAgentHandler(cfg, dnsAnalyzer, database.Queries)
        agentHandler.SaveFn = analysisHandler.SaveForAgent
        router.GET("/agent/search", middleware.AgentRateLimit(rateLimiter), agentHandler.AgentSearch)
        router.GET("/agent/api", middleware.AgentRateLimit(rateLimiter), agentHandler.AgentAPI)
        router.GET("/agent/badge-view", agentHandler.BadgeView)
        router.GET("/agent/wayback", agentHandler.WaybackView)
        router.GET("/agent/report", agentHandler.ReportView)
        router.GET("/agent/opensearch.xml", agentHandler.OpenSearchXML)
        router.GET("/agent/plugin", agentHandler.PluginPage)

        zoneHandler := handlers.NewZoneHandler(database, cfg)
        router.GET("/zone", middleware.RequireFeature(entitlements.FeatureZoneUpload), zoneHandler.UploadForm)
        router.POST("/zone/upload", middleware.RequireFeature(entitlements.FeatureZoneUpload), zoneHandler.ProcessUpload)

        authHandler := handlers.NewAuthHandler(cfg, database.Pool)
        if cfg.GoogleClientID != "" {
                authRL := middleware.AuthRateLimit(rateLimiter)
                router.GET("/auth/login", authRL, authHandler.Login)
                router.GET("/auth/callback", authRL, authHandler.Callback)
                router.POST("/auth/logout", authHandler.Logout)
        }

        router.NoRoute(func(c *gin.Context) {
                nonce, _ := c.Get("csp_nonce")
                csrfToken, _ := c.Get("csrf_token")
                data := gin.H{
                        "AppVersion":      cfg.AppVersion,
                        "MaintenanceNote": cfg.MaintenanceNote,
                        "BetaPages":       cfg.BetaPages,
                        "CspNonce":        nonce,
                        "CsrfToken":       csrfToken,
                        "ActivePage":      "home",
                }
                for k, v := range middleware.GetAuthTemplateData(c) {
                        data[k] = v
                }
                if cfg.GoogleClientID != "" {
                        data["GoogleAuthEnabled"] = true
                }
                c.HTML(http.StatusNotFound, "index.html", data)
        })

        handler.Store(http.HandlerFunc(router.Handler().ServeHTTP))
        slog.Info("Full router ready — handler swapped",
                "address", earlyAddr,
                "version", cfg.AppVersion,
                "commit", config.GitCommit,
                "built", config.BuildTime,
        )

        syncCtx, syncCancel := context.WithCancel(context.Background())
        defer syncCancel()
        startScheduledSync(syncCtx)

        ctEnrichment := analyzer.NewCTEnrichmentJob(database.Queries, ctStore)
        ctEnrichment.Start(syncCtx)

        driftNotifier := notifier.New(dbq.New(database.Pool))
        startNotificationDelivery(syncCtx, driftNotifier)

        quit := make(chan os.Signal, 1)
        signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

        <-quit
        slog.Info("Shutdown signal received, draining connections…")

        syncCancel()
        analyticsCollector.Flush()
        slog.Info("Analytics flushed on shutdown")

        shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
        defer shutdownCancel()

        if err := srv.Shutdown(shutdownCtx); err != nil {
                slog.Error("Server forced to shutdown", mapKeyError, err)
                os.Exit(1)
        }

        slog.Info("Server exited cleanly")
}

func findTemplatesDir() string {
        candidates := []string{
                "go-server/templates",
                "templates",
                "../templates",
        }
        for _, c := range candidates {
                if info, err := os.Stat(c); err == nil && info.IsDir() {
                        return c
                }
        }
        slog.Warn("Templates directory not found, using default")
        return "templates"
}

var cacheableExts = map[string]bool{
        ".css": true, ".js": true, ".woff": true, ".woff2": true, ".ttf": true,
        ".png": true, ".ico": true, ".svg": true, ".jpg": true, ".jpeg": true,
        ".gif": true, ".webp": true, ".avif": true,
        ".mp4": true, ".webm": true, ".ogg": true, ".m4a": true,
        ".pdf": true, ".zip": true, ".map": true,
}

func isStaticAsset(fp string) bool {
        return cacheableExts[filepath.Ext(fp)]
}

func findStaticDir() string {
        candidates := []string{
                "static",
                "go-server/static",
                "../static",
        }
        for _, c := range candidates {
                if info, err := os.Stat(c); err == nil && info.IsDir() {
                        return c
                }
        }
        slog.Warn("Static directory not found, using default")
        return "static"
}

func startScheduledSync(ctx context.Context) {
        loc, err := time.LoadLocation("America/New_York")
        if err != nil {
                slog.Warn("Could not load ET timezone, using UTC-5 offset")
                loc = time.FixedZone("ET", -5*60*60)
        }

        go func() {
                for {
                        now := time.Now().In(loc)
                        next := time.Date(now.Year(), now.Month(), now.Day(), 4, 0, 0, 0, loc)
                        if now.After(next) {
                                next = next.Add(24 * time.Hour)
                        }
                        wait := time.Until(next)
                        slog.Info("Notion sync scheduled", "next_run", next.Format("2006-01-02 15:04 MST"), "wait", wait.Round(time.Minute))

                        select {
                        case <-time.After(wait):
                                runNotionSync()
                        case <-ctx.Done():
                                slog.Info("Scheduled sync shutting down")
                                return
                        }
                }
        }()
}

func startNotificationDelivery(ctx context.Context, n *notifier.Notifier) {
        go func() {
                const interval = 30 * time.Second
                const batchSize int32 = 50
                slog.Info("Notification delivery loop started", "interval", interval, "batch_size", batchSize)
                ticker := time.NewTicker(interval)
                defer ticker.Stop()
                for {
                        select {
                        case <-ticker.C:
                                delivered, err := n.DeliverPending(ctx, batchSize)
                                if err != nil {
                                        slog.Error("Notification delivery error", mapKeyError, err)
                                } else if delivered > 0 {
                                        slog.Info("Notifications delivered", "count", delivered)
                                }
                        case <-ctx.Done():
                                slog.Info("Notification delivery loop shutting down")
                                return
                        }
                }
        }()
}

func runNotionSync() {
        slog.Info("Starting scheduled Notion roadmap sync")

        scriptPath := "scripts/notion-roadmap-sync.mjs"
        if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
                slog.Warn("Notion sync script not found", "path", scriptPath)
                return
        }

        ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
        defer cancel()

        cmd := exec.CommandContext(ctx, "node", scriptPath)
        output, err := cmd.CombinedOutput()
        if err != nil {
                slog.Error("Notion sync failed", mapKeyError, err, "output", string(output))
                return
        }
        slog.Info("Notion sync completed", "output", string(output))
}
