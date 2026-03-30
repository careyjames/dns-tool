// dns-tool:scrutiny plumbing
package logging

import (
	"log/slog"
)

const (
	CategoryScan        = "scan"
	CategorySecurity    = "security"
	CategoryPerformance = "performance"
	CategorySystem      = "system"
	CategoryExternalAPI = "external_api"

	EventScanStarted     = "scan_started"
	EventScanCompleted   = "scan_completed"
	EventScanFailed      = "scan_failed"
	EventPhaseStarted    = "phase_started"
	EventPhaseFinished   = "phase_finished"
	EventAuthFailure     = "auth_failure"
	EventCSRFReject      = "csrf_reject"
	EventRateLimitHit    = "rate_limit_hit"
	EventPanic           = "panic_recovered"
	EventSlowPhase       = "slow_phase"
	EventExternalCall    = "external_call"
	EventCacheHit        = "cache_hit"
	EventCacheMiss       = "cache_miss"
	EventStartup         = "startup"
	EventShutdown        = "shutdown"
	EventDBError         = "db_error"
	EventResolverFailure = "resolver_failure"

	AttrEvent           = "event"
	AttrCategory        = "category"
	AttrTraceID         = "trace_id"
	AttrAnalysisID      = "analysis_id"
	AttrScanToken       = "scan_token"
	AttrDomain          = "domain"
	AttrPhaseGroup      = "phase_group"
	AttrPhaseTask       = "phase_task"
	AttrElapsedMs       = "elapsed_ms"
	AttrOutcome         = "outcome"
	AttrErrorClass      = "error_class"
	AttrErrorChain      = "error_chain"
	AttrExternalService = "external_service"
	AttrHTTPStatus      = "http_status"
	AttrCacheHit        = "cache_hit"
	AttrRemoteAddr      = "remote_addr"
)

func ScanStarted(domain, traceID string, analysisID int) []slog.Attr {
	return []slog.Attr{
		slog.String(AttrEvent, EventScanStarted),
		slog.String(AttrCategory, CategoryScan),
		slog.String(AttrDomain, domain),
		slog.String(AttrTraceID, traceID),
		slog.Int(AttrAnalysisID, analysisID),
	}
}

func ScanCompleted(domain, traceID string, analysisID int, elapsedMs int64) []slog.Attr {
	return []slog.Attr{
		slog.String(AttrEvent, EventScanCompleted),
		slog.String(AttrCategory, CategoryScan),
		slog.String(AttrDomain, domain),
		slog.String(AttrTraceID, traceID),
		slog.Int(AttrAnalysisID, analysisID),
		slog.Int64(AttrElapsedMs, elapsedMs),
		slog.String(AttrOutcome, "success"),
	}
}

func ScanFailed(domain, traceID, errChain string) []slog.Attr {
	return []slog.Attr{
		slog.String(AttrEvent, EventScanFailed),
		slog.String(AttrCategory, CategoryScan),
		slog.String(AttrDomain, domain),
		slog.String(AttrTraceID, traceID),
		slog.String(AttrOutcome, "failure"),
		slog.String(AttrErrorChain, errChain),
	}
}

func PhaseStarted(domain, traceID, group, task string) []slog.Attr {
	return []slog.Attr{
		slog.String(AttrEvent, EventPhaseStarted),
		slog.String(AttrCategory, CategoryScan),
		slog.String(AttrDomain, domain),
		slog.String(AttrTraceID, traceID),
		slog.String(AttrPhaseGroup, group),
		slog.String(AttrPhaseTask, task),
	}
}

func PhaseFinished(domain, traceID, group, task string, elapsedMs int64, outcome string) []slog.Attr {
	return []slog.Attr{
		slog.String(AttrEvent, EventPhaseFinished),
		slog.String(AttrCategory, CategoryScan),
		slog.String(AttrDomain, domain),
		slog.String(AttrTraceID, traceID),
		slog.String(AttrPhaseGroup, group),
		slog.String(AttrPhaseTask, task),
		slog.Int64(AttrElapsedMs, elapsedMs),
		slog.String(AttrOutcome, outcome),
	}
}

func SecurityEvent(event, traceID, remoteAddr string, extra ...slog.Attr) []slog.Attr {
	attrs := []slog.Attr{
		slog.String(AttrEvent, event),
		slog.String(AttrCategory, CategorySecurity),
		slog.String(AttrTraceID, traceID),
		slog.String(AttrRemoteAddr, remoteAddr),
	}
	return append(attrs, extra...)
}

func ExternalCall(service, traceID string, httpStatus int, elapsedMs int64, outcome string) []slog.Attr {
	return []slog.Attr{
		slog.String(AttrEvent, EventExternalCall),
		slog.String(AttrCategory, CategoryExternalAPI),
		slog.String(AttrExternalService, service),
		slog.String(AttrTraceID, traceID),
		slog.Int(AttrHTTPStatus, httpStatus),
		slog.Int64(AttrElapsedMs, elapsedMs),
		slog.String(AttrOutcome, outcome),
	}
}

func AttrsToAny(attrs []slog.Attr) []any {
	result := make([]any, 0, len(attrs)*2)
	for _, a := range attrs {
		result = append(result, a.Key, a.Value)
	}
	return result
}
