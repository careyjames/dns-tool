package handlers

// dns-tool:scrutiny design

import (
        "context"

        "dnstool/go-server/internal/dbq"

        "github.com/jackc/pgx/v5/pgconn"
)

type AnalysisStore interface {
        InsertAnalysis(ctx context.Context, arg dbq.InsertAnalysisParams) (dbq.InsertAnalysisRow, error)
        UpsertDomainIndex(ctx context.Context, arg dbq.UpsertDomainIndexParams) error
        GetPreviousAnalysisForDrift(ctx context.Context, domain string) (dbq.GetPreviousAnalysisForDriftRow, error)
        GetPreviousAnalysisForDriftBefore(ctx context.Context, arg dbq.GetPreviousAnalysisForDriftBeforeParams) (dbq.GetPreviousAnalysisForDriftBeforeRow, error)
        InsertDriftEvent(ctx context.Context, arg dbq.InsertDriftEventParams) (dbq.InsertDriftEventRow, error)
        ListEndpointsForWatchedDomain(ctx context.Context, domain string) ([]dbq.ListEndpointsForWatchedDomainRow, error)
        InsertDriftNotification(ctx context.Context, arg dbq.InsertDriftNotificationParams) (int32, error)
        InsertPhaseTelemetry(ctx context.Context, arg dbq.InsertPhaseTelemetryParams) error
        InsertTelemetryHash(ctx context.Context, arg dbq.InsertTelemetryHashParams) error
        InsertUserAnalysis(ctx context.Context, arg dbq.InsertUserAnalysisParams) error
        UpdateWaybackURL(ctx context.Context, arg dbq.UpdateWaybackURLParams) error
        CountHashedAnalyses(ctx context.Context) (int64, error)
        ListHashedAnalyses(ctx context.Context, arg dbq.ListHashedAnalysesParams) ([]dbq.ListHashedAnalysesRow, error)
        GetAnalysisByID(ctx context.Context, id int32) (dbq.DomainAnalysis, error)
        CheckAnalysisOwnership(ctx context.Context, arg dbq.CheckAnalysisOwnershipParams) (bool, error)
        GetRecentAnalysisByDomain(ctx context.Context, domain string) (dbq.DomainAnalysis, error)
}

type AuthStore interface {
        UpsertUser(ctx context.Context, arg dbq.UpsertUserParams) (dbq.User, error)
        PromoteUserToAdmin(ctx context.Context, id int32) error
        CountAdminUsers(ctx context.Context) (int64, error)
        CreateSession(ctx context.Context, arg dbq.CreateSessionParams) error
        DeleteSession(ctx context.Context, id string) error
        ListWatchlistByUser(ctx context.Context, userID int32) ([]dbq.DomainWatchlist, error)
        InsertWatchlistEntry(ctx context.Context, arg dbq.InsertWatchlistEntryParams) (dbq.InsertWatchlistEntryRow, error)
        ListNotificationEndpointsByUser(ctx context.Context, userID int32) ([]dbq.NotificationEndpoint, error)
        InsertNotificationEndpoint(ctx context.Context, arg dbq.InsertNotificationEndpointParams) (dbq.InsertNotificationEndpointRow, error)
}

type PipelineStore interface {
        GetPipelineStageStats(ctx context.Context) ([]dbq.GetPipelineStageStatsRow, error)
        GetPipelineEndToEndStats(ctx context.Context) (dbq.GetPipelineEndToEndStatsRow, error)
        GetPipelineDurationDistribution(ctx context.Context) ([]dbq.GetPipelineDurationDistributionRow, error)
        GetDriftSeverityDistribution(ctx context.Context) ([]dbq.GetDriftSeverityDistributionRow, error)
        GetSlowestPhases(ctx context.Context, limit int32) ([]dbq.GetSlowestPhasesRow, error)
        GetTelemetryTrends(ctx context.Context) ([]dbq.GetTelemetryTrendsRow, error)
}

type LookupStore interface {
        GetAnalysisByID(ctx context.Context, id int32) (dbq.DomainAnalysis, error)
        CheckAnalysisOwnership(ctx context.Context, arg dbq.CheckAnalysisOwnershipParams) (bool, error)
        GetRecentAnalysisByDomain(ctx context.Context, domain string) (dbq.DomainAnalysis, error)
}

type AuditStore interface {
        CountHashedAnalyses(ctx context.Context) (int64, error)
        ListHashedAnalyses(ctx context.Context, arg dbq.ListHashedAnalysesParams) ([]dbq.ListHashedAnalysesRow, error)
}

type StatsExecer interface {
        Exec(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error)
}
