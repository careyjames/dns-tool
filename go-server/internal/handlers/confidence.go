// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "encoding/hex"
        "fmt"
        "net/http"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/icae"
        "dnstool/go-server/internal/icuae"

        "github.com/gin-gonic/gin"
        "golang.org/x/crypto/sha3"
)

type ConfidenceHandler struct {
        Config     *config.Config
        DB         *db.Database
        auditStore AuditStore
}

func (h *ConfidenceHandler) auditQ() AuditStore {
        if h.auditStore != nil {
                return h.auditStore
        }
        if h.DB != nil {
                return h.DB.Queries
        }
        return nil
}

func NewConfidenceHandler(cfg *config.Config, database *db.Database) *ConfidenceHandler {
        return &ConfidenceHandler{Config: cfg, DB: database}
}

func (h *ConfidenceHandler) Confidence(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")
        data := gin.H{
                keyAppVersion:      h.Config.AppVersion,
                keyMaintenanceNote: h.Config.MaintenanceNote,
                keyBetaPages:       h.Config.BetaPages,
                keyCspNonce:        nonce,
                "CsrfToken":       csrfToken,
                keyActivePage:      "confidence",
        }

        isDev := h.Config.IsDevEnvironment
        data["IsDev"] = isDev

        if h.DB != nil {
                if metrics := icae.LoadReportMetrics(c.Request.Context(), h.DB.Queries); metrics != nil {
                        metrics.HashAudit = icae.AuditHashIntegrity(c.Request.Context(), h.DB.Queries, 100)
                        if metrics.HashAudit != nil {
                                if totalHashed, err := h.DB.Queries.CountHashedAnalyses(c.Request.Context()); err == nil {
                                        metrics.HashAudit.TotalHashedInDB = int(totalHashed)
                                }
                        }
                        ce := icae.NewCalibrationEngine()
                        calResult := icae.RunDegradedCalibration(ce)
                        metrics.Calibration = &calResult
                        data["ICAEMetrics"] = metrics
                }
        }

        if h.DB != nil {
                if runtimeMetrics := icuae.LoadRuntimeMetrics(c.Request.Context(), h.DB.Queries); runtimeMetrics != nil {
                        data["ICuAERuntimeMetrics"] = runtimeMetrics
                }
        }

        mergeAuthData(c, h.Config, data)
        data["ICuAEInventory"] = icuae.GetTestInventory()

        now := time.Now().UTC()
        data["PageRenderedUTC"] = now.Format("2006-01-02T15:04:05Z")
        data["PageRenderedDisplay"] = now.Format("2 Jan 2006 15:04:05 UTC")
        data["PageStateHash"] = confidenceStateHash(data, now)

        c.HTML(http.StatusOK, "confidence.html", data)
}

func confidenceStateHash(data gin.H, ts time.Time) string {
        var canonical string
        canonical += ts.Format(time.RFC3339)
        if m, ok := data["ICAEMetrics"].(*icae.ReportMetrics); ok && m != nil {
                canonical += fmt.Sprintf("|passes=%d|col=%d|runs=%d|evaluated=%d/%d|maturity=%s|passrate=%s|days=%d|regressions=%d",
                        m.TotalPasses, m.CollectionPasses, m.TotalRuns,
                        m.EvaluatedCount, m.TotalProtocols,
                        m.OverallMaturity, m.PassRate, m.DaysRunning, len(m.Regressions))
                if m.HashAudit != nil {
                        canonical += fmt.Sprintf("|hash_audited=%d|hash_verified=%d|hash_failed=%d|integrity=%d",
                                m.HashAudit.TotalAudited, m.HashAudit.TotalVerified,
                                m.HashAudit.TotalFailed, m.HashAudit.IntegrityPct)
                }
                if m.Calibration != nil {
                        canonical += fmt.Sprintf("|brier=%s|ece=%s|cal_cases=%d",
                                m.Calibration.BrierDisplay, m.Calibration.ECEDisplay, m.Calibration.TotalCases)
                }
                for _, p := range m.Protocols {
                        canonical += fmt.Sprintf("|%s:%s:%d:%d",
                                p.Protocol, p.EffectiveLevel, p.AnalysisPasses, p.CollectionPasses)
                }
        }
        if v, ok := data[keyAppVersion].(string); ok {
                canonical += "|version=" + v
        }
        hash := sha3.Sum256([]byte(canonical))
        return hex.EncodeToString(hash[:])
}
