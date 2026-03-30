package handlers

// dns-tool:scrutiny design

import (
        "net/http"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"

        "github.com/gin-gonic/gin"
)

type PipelineHandler struct {
        DB            *db.Database
        Config        *config.Config
        pipelineStore PipelineStore
}

func (h *PipelineHandler) store() PipelineStore {
        if h.pipelineStore != nil {
                return h.pipelineStore
        }
        if h.DB != nil {
                return h.DB.Queries
        }
        return nil
}

func NewPipelineHandler(database *db.Database, cfg *config.Config) *PipelineHandler {
        return &PipelineHandler{DB: database, Config: cfg}
}

func toInt64(v interface{}) int64 {
        switch n := v.(type) {
        case int32:
                return int64(n)
        case int64:
                return n
        case int:
                return int64(n)
        case float64:
                return int64(n)
        default:
                return 0
        }
}

type pipelineStageView struct {
        Key         string
        Label       string
        ScanCount   int64
        AvgMs       int32
        P50Ms       int32
        P95Ms       int32
        P99Ms       int32
        MinMs       int64
        MaxMs       int64
        Records     int64
        ErrorCount  int32
        ErrorRate   float64
        HealthClass string
}

func (h *PipelineHandler) Observatory(c *gin.Context) {
        ctx := c.Request.Context()

        stageStats, err := h.store().GetPipelineStageStats(ctx)
        if err != nil {
                stageStats = nil
        }

        endToEnd, err := h.store().GetPipelineEndToEndStats(ctx)
        if err != nil {
                endToEnd.TotalScans = 0
        }

        distribution, err := h.store().GetPipelineDurationDistribution(ctx)
        if err != nil {
                distribution = nil
        }

        driftDist, err := h.store().GetDriftSeverityDistribution(ctx)
        if err != nil {
                driftDist = nil
        }

        slowest, err := h.store().GetSlowestPhases(ctx, 15)
        if err != nil {
                slowest = nil
        }

        trends, err := h.store().GetTelemetryTrends(ctx)
        if err != nil {
                trends = nil
        }

        stages := make([]pipelineStageView, 0, len(stageStats))
        for _, s := range stageStats {
                label := s.PhaseGroup
                if l, ok := analyzer.PhaseGroupLabels[s.PhaseGroup]; ok {
                        label = l
                }
                var errorRate float64
                if s.ScanCount > 0 {
                        errorRate = float64(s.ErrorCount) / float64(s.ScanCount) * 100
                }
                health := "success"
                if errorRate > 10 {
                        health = "danger"
                } else if errorRate > 5 {
                        health = "warning"
                }
                stages = append(stages, pipelineStageView{
                        Key:         s.PhaseGroup,
                        Label:       label,
                        ScanCount:   s.ScanCount,
                        AvgMs:       s.AvgMs,
                        P50Ms:       s.P50Ms,
                        P95Ms:       s.P95Ms,
                        P99Ms:       s.P99Ms,
                        MinMs:       toInt64(s.MinMs),
                        MaxMs:       toInt64(s.MaxMs),
                        Records:     s.TotalRecords,
                        ErrorCount:  s.ErrorCount,
                        ErrorRate:   errorRate,
                        HealthClass: health,
                })
        }

        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")

        data := gin.H{
                "Title":            "Pipeline Observatory",
                keyActivePage:       "pipeline",
                keyAppVersion:       h.Config.AppVersion,
                keyMaintenanceNote:  h.Config.MaintenanceNote,
                keyBetaPages:        h.Config.BetaPages,
                keyCspNonce:         nonce,
                "CsrfToken":        csrfToken,
                "Stages":           stages,
                "EndToEnd":         endToEnd,
                "Distribution":     distribution,
                "DriftDistribution": driftDist,
                "Slowest":          slowest,
                "Trends":           trends,
                "PhaseGroupLabels": analyzer.PhaseGroupLabels,
                "PhaseGroupOrder":  analyzer.PhaseGroupOrder,
        }

        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, "admin_pipeline.html", data)
}
