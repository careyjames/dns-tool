// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "encoding/json"
        "log/slog"
        "time"

        "dnstool/go-server/internal/dbq"
)

const (
        stEnrichmentDelay    = 60 * time.Second
        stEnrichmentInterval = 24 * time.Hour
        stTopDomainLimit     = 50
)

type STBudgetDB interface {
        GetSTBudget(ctx context.Context, monthKey string) (dbq.GetSTBudgetRow, error)
        UpsertSTBudget(ctx context.Context, arg dbq.UpsertSTBudgetParams) error
        GetTopAnalyzedDomains(ctx context.Context, limit int32) ([]dbq.GetTopAnalyzedDomainsRow, error)
        ListPriorityDomains(ctx context.Context) ([]dbq.ListPriorityDomainsRow, error)
}

type CTEnrichmentJob struct {
        budgetDB STBudgetDB
        ctStore  CTStore
}

func NewCTEnrichmentJob(budgetDB STBudgetDB, ctStore CTStore) *CTEnrichmentJob {
        return &CTEnrichmentJob{
                budgetDB: budgetDB,
                ctStore:  ctStore,
        }
}

func (j *CTEnrichmentJob) Start(ctx context.Context) {
        initSecurityTrails()
        if !securityTrailsEnabled {
                slog.Info("CT enrichment: SecurityTrails not configured, skipping background enrichment")
                return
        }

        go func() {
                select {
                case <-time.After(stEnrichmentDelay):
                case <-ctx.Done():
                        return
                }

                j.run(ctx)

                ticker := time.NewTicker(stEnrichmentInterval)
                defer ticker.Stop()
                for {
                        select {
                        case <-ticker.C:
                                j.run(ctx)
                        case <-ctx.Done():
                                return
                        }
                }
        }()

        slog.Info("CT enrichment: scheduled", "initial_delay", stEnrichmentDelay, "interval", stEnrichmentInterval)
}

func (j *CTEnrichmentJob) run(ctx context.Context) {
        monthKey := time.Now().Format("2006-01")

        budget, err := j.budgetDB.GetSTBudget(ctx, monthKey)
        if err != nil {
                budget = dbq.GetSTBudgetRow{
                        MonthKey:  monthKey,
                        CallsUsed: 0,
                }
        }

        remaining := int(stMonthlyBudget) - int(budget.CallsUsed) - stBudgetReserve
        if remaining <= 0 {
                slog.Info("CT enrichment: monthly SecurityTrails budget exhausted",
                        "month", monthKey,
                        "used", budget.CallsUsed,
                        "limit", stMonthlyBudget,
                )
                return
        }

        enrichmentTargets := j.buildEnrichmentList(ctx)

        var enrichedDomains []string
        if len(budget.DomainsEnriched) > 0 {
                if err := json.Unmarshal(budget.DomainsEnriched, &enrichedDomains); err != nil {
                        slog.Warn("CT enrichment: failed to unmarshal enriched domains", "error", err)
                }
        }
        enrichedSet := make(map[string]bool, len(enrichedDomains))
        for _, d := range enrichedDomains {
                enrichedSet[d] = true
        }

        enriched, remaining := j.enrichTargets(ctx, enrichmentTargets, enrichedSet, enrichedDomains, &budget, monthKey, remaining)

        slog.Info("CT enrichment: cycle complete",
                "month", monthKey,
                "enriched_this_run", enriched,
                "total_used", budget.CallsUsed,
                "remaining", remaining,
        )
}

func (j *CTEnrichmentJob) enrichTargets(ctx context.Context, targets []enrichmentTarget, enrichedSet map[string]bool, enrichedDomains []string, budget *dbq.GetSTBudgetRow, monthKey string, remaining int) (int, int) {
        enriched := 0
        for _, td := range targets {
                if remaining <= 0 {
                        break
                }
                if enrichedSet[td.Domain] {
                        continue
                }

                budget.CallsUsed++
                remaining--

                ok := j.enrichSingleTarget(ctx, td, &enrichedDomains, enrichedSet)
                if !ok {
                        break
                }
                if enrichedSet[td.Domain] {
                        enriched++
                        domainsJSON, _ := json.Marshal(enrichedDomains)
                        if err := j.budgetDB.UpsertSTBudget(ctx, dbq.UpsertSTBudgetParams{
                                MonthKey:        monthKey,
                                CallsUsed:       budget.CallsUsed,
                                DomainsEnriched: domainsJSON,
                        }); err != nil {
                                slog.Warn("CT enrichment: failed to persist budget after success, aborting", mapKeyError, err)
                                break
                        }
                }
        }
        return enriched, remaining
}

func (j *CTEnrichmentJob) enrichSingleTarget(ctx context.Context, td enrichmentTarget, enrichedDomains *[]string, enrichedSet map[string]bool) bool {
        subs, status, fetchErr := FetchSubdomains(ctx, td.Domain)
        if fetchErr != nil || (status != nil && (status.RateLimited || status.Errored)) {
                slog.Warn("CT enrichment: SecurityTrails fetch failed",
                        mapKeyDomain, td.Domain,
                        "rate_limited", status != nil && status.RateLimited,
                )
                return !(status != nil && status.RateLimited)
        }

        if len(subs) > 0 {
                j.mergeST(ctx, td.Domain, subs)
        }

        *enrichedDomains = append(*enrichedDomains, td.Domain)
        enrichedSet[td.Domain] = true
        return true
}

type enrichmentTarget struct {
        Domain   string
        Priority bool
}

func (j *CTEnrichmentJob) buildEnrichmentList(ctx context.Context) []enrichmentTarget {
        var targets []enrichmentTarget
        seen := make(map[string]bool)

        targets = j.loadPriorityDomains(ctx, targets, seen)
        targets = j.loadTopDomains(ctx, targets, seen)
        return targets
}

func (j *CTEnrichmentJob) loadPriorityDomains(ctx context.Context, targets []enrichmentTarget, seen map[string]bool) []enrichmentTarget {
        priorityDomains, err := j.budgetDB.ListPriorityDomains(ctx)
        if err != nil {
                slog.Warn("CT enrichment: failed to load priority domains", mapKeyError, err)
                return targets
        }
        for _, pd := range priorityDomains {
                targets = append(targets, enrichmentTarget{Domain: pd.Domain, Priority: true})
                seen[pd.Domain] = true
        }
        slog.Info("CT enrichment: priority domains loaded", mapKeyCount, len(priorityDomains))
        return targets
}

func (j *CTEnrichmentJob) loadTopDomains(ctx context.Context, targets []enrichmentTarget, seen map[string]bool) []enrichmentTarget {
        remaining := stTopDomainLimit - len(targets)
        if remaining <= 0 {
                return targets
        }
        topDomains, err := j.budgetDB.GetTopAnalyzedDomains(ctx, int32(stTopDomainLimit))
        if err != nil {
                slog.Warn("CT enrichment: failed to get top analyzed domains", mapKeyError, err)
                return targets
        }
        for _, td := range topDomains {
                if seen[td.Domain] {
                        continue
                }
                targets = append(targets, enrichmentTarget{Domain: td.Domain, Priority: false})
                seen[td.Domain] = true
                remaining--
                if remaining <= 0 {
                        break
                }
        }
        return targets
}

func (j *CTEnrichmentJob) mergeST(ctx context.Context, domain string, stSubdomains []string) {
        existing, ok := j.ctStore.Get(ctx, domain)
        if !ok {
                existing = []map[string]any{}
        }

        existingNames := make(map[string]bool, len(existing))
        for _, sd := range existing {
                if name, ok := sd[mapKeyName].(string); ok {
                        existingNames[name] = true
                }
        }

        added := 0
        for _, fqdn := range stSubdomains {
                if existingNames[fqdn] {
                        continue
                }
                existing = append(existing, map[string]any{
                        mapKeyName:      fqdn,
                        mapKeyIsCurrent: false,
                        mapKeySource:    "securitytrails",
                        mapKeyFirstSeen: time.Now().Format("2006-01-02"),
                })
                added++
        }

        if added > 0 {
                j.ctStore.Set(ctx, domain, existing, "crt.sh+securitytrails")
                slog.Info("CT enrichment: SecurityTrails subdomains merged",
                        mapKeyDomain, domain,
                        "new_subdomains", added,
                        "total", len(existing),
                )
        }
}
