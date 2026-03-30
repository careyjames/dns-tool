// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "context"
        "encoding/json"
        "log/slog"
        "net/http"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
)

type EDEHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewEDEHandler(database *db.Database, cfg *config.Config) *EDEHandler {
        return &EDEHandler{DB: database, Config: cfg}
}

func (h *EDEHandler) EDE(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")

        integrityData := h.resolveIntegrityData(c.Request.Context())

        data := gin.H{
                keyAppVersion:      h.Config.AppVersion,
                keyMaintenanceNote: h.Config.MaintenanceNote,
                keyBetaPages:       h.Config.BetaPages,
                keyCspNonce:        nonce,
                keyActivePage:      "ede",
                "IntegrityData":   integrityData,
        }
        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, "ede.html", data)
}

func (h *EDEHandler) resolveIntegrityData(ctx context.Context) IntegrityData {
        if h.DB == nil || h.DB.Queries == nil {
                return loadIntegrityData()
        }

        dbEvents, err := h.DB.Queries.ListEDEEvents(ctx)
        if err != nil {
                slog.Warn("ede: db query failed, falling back to JSON", "error", err)
                return loadIntegrityData()
        }
        if len(dbEvents) == 0 {
                return loadIntegrityData()
        }

        return h.buildFromDB(ctx, dbEvents)
}

func (h *EDEHandler) buildFromDB(ctx context.Context, dbEvents []dbq.EdeEvent) IntegrityData {
        counts, cErr := h.DB.Queries.CountEDEEvents(ctx)
        if cErr != nil {
                slog.Warn("ede: count query failed", "error", cErr)
        }

        amendmentMap := h.loadAmendmentMap(ctx)
        events, allProtocols := mapDBEvents(dbEvents, amendmentMap)

        lastDate := ""
        if len(events) > 0 {
                lastDate = events[0].Date
        }

        result := IntegrityData{
                Summary: IntegritySummary{
                        TotalEvents:              int(counts.Total),
                        Open:                     int(counts.Open),
                        Closed:                   int(counts.Closed),
                        ConfidenceRecalibrations: int(counts.Recalibrations),
                        LastEventDate:            lastDate,
                        ProtocolsAffected:        allProtocols,
                },
                Events:                 events,
                Taxonomy:               edeTaxonomy(),
                TamperResistancePolicy: edeTamperPolicy(),
        }

        fileData := loadIntegrityData()
        result.SHA3Hash = fileData.SHA3Hash

        return result
}

func (h *EDEHandler) loadAmendmentMap(ctx context.Context) map[string][]EDEAmendment {
        amendments, aErr := h.DB.Queries.ListEDEAmendments(ctx)
        if aErr != nil {
                slog.Warn("ede: amendment query failed", "error", aErr)
                return map[string][]EDEAmendment{}
        }

        out := map[string][]EDEAmendment{}
        for _, a := range amendments {
                am := EDEAmendment{
                        Ground:        a.Ground,
                        FieldChanged:  a.FieldChanged,
                        OriginalValue: a.OriginalValue,
                        CorrectedTo:   a.CorrectedTo,
                        Justification: a.Justification,
                }
                if a.Evidence != nil {
                        am.Evidence = *a.Evidence
                }
                if a.Rationale != nil {
                        am.Rationale = *a.Rationale
                }
                if a.AmendmentDate.Valid {
                        am.Date = a.AmendmentDate.Time.Format("2006-01-02")
                }
                out[a.EdeID] = append(out[a.EdeID], am)
        }
        return out
}

func mapDBEvents(dbEvents []dbq.EdeEvent, amendmentMap map[string][]EDEAmendment) ([]IntegrityEvent, []string) {
        events := make([]IntegrityEvent, 0, len(dbEvents))
        protocolSet := map[string]bool{}

        for _, e := range dbEvents {
                ev := mapSingleEvent(e)
                ev.ProtocolsAffected = unmarshalProtocols(e)
                for _, p := range ev.ProtocolsAffected {
                        protocolSet[p] = true
                }
                if ams, ok := amendmentMap[e.EdeID]; ok {
                        ev.Amendments = ams
                }
                redactDignityAmendments(&ev)
                hashEvent(&ev)
                events = append(events, ev)
        }

        allProtocols := make([]string, 0, len(protocolSet))
        for p := range protocolSet {
                allProtocols = append(allProtocols, p)
        }
        return events, allProtocols
}

func mapSingleEvent(e dbq.EdeEvent) IntegrityEvent {
        ev := IntegrityEvent{
                ID:          e.EdeID,
                Category:    e.Category,
                Severity:    e.Severity,
                Title:       e.Title,
                Status:      e.Status,
                Attribution: e.Attribution,
                Commit:      e.CommitRef,
        }
        if e.EventDate.Valid {
                ev.Date = e.EventDate.Time.Format("2006-01-02")
        }
        if e.ConfidenceImpact != nil {
                ev.ConfidenceImpact = *e.ConfidenceImpact
        }
        if e.Resolution != nil {
                ev.Resolution = *e.Resolution
        }
        if e.BayesianNote != nil {
                ev.BayesianNote = *e.BayesianNote
        }
        if e.CorrectionAction != nil {
                ev.CorrectionAction = *e.CorrectionAction
        }
        if e.PreventionRule != nil {
                ev.PreventionRule = *e.PreventionRule
        }
        if e.AuthoritativeSource != nil {
                ev.AuthoritativeSource = *e.AuthoritativeSource
        }
        return ev
}

func unmarshalProtocols(e dbq.EdeEvent) []string {
        if len(e.ProtocolsAffected) == 0 {
                return nil
        }
        var protocols []string
        if err := json.Unmarshal(e.ProtocolsAffected, &protocols); err != nil {
                slog.Warn("ede: failed to unmarshal protocols_affected", "ede_id", e.EdeID, "error", err)
                return nil
        }
        return protocols
}

func edeTaxonomy() map[string]string {
        return map[string]string{
                "scoring_calibration":       "Scoring Calibration",
                "evidence_reinterpretation": "Evidence Reinterpretation",
                "drift_detection":           "Drift Detection",
                "resolver_trust":            "Resolver Trust",
                "false_positive":            "False Positive",
                "confidence_decay":          "Confidence Decay",
                "governance_correction":     "Governance Correction",
                "citation_error":            "Citation Error",
                "overclaim":                 "Overclaim",
                "standards_misattribution":  "Standards Misattribution",
        }
}

func edeTamperPolicy() TamperResistancePolicy {
        return TamperResistancePolicy{
                Enabled:       true,
                Effective:     "2026-03-07",
                Standard:      "SHA-3-512 per-event hashing",
                AmendmentRule: "FACTUAL_ERROR or DIGNITY_OF_EXPRESSION only",
        }
}
