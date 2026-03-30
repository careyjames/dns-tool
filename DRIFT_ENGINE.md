# Drift Engine — Longitudinal Security Posture Monitoring

## Status

The drift engine extends DNS Tool's observation-based analysis from point-in-time reports into longitudinal monitoring. Every scan generates a canonical posture hash (SHA-3-512) that fingerprints the domain's security posture at the time of analysis. When a domain is re-analyzed, the current hash is compared against the previous observation to detect posture drift.

### Implemented (Phase 1–2): Core Detection

- **Canonical posture hashing** (`posture_hash.go`): Deterministic SHA-3-512 of normalized security posture vector (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, DANE, CAA, DNSSEC, mail posture, MX, NS). Order-independent — sorted before hashing to prevent false drift from DNS provider record reordering.
- **Database persistence**: `posture_hash VARCHAR(64)` column on `domain_analyses`. Every successful analysis stores its posture hash.
- **Drift comparison**: Live analysis and history views compare current vs. previous posture hash. Drift detected when hashes differ.
- **Drift alert UI**: "Posture Drift Detected" banner on results page when drift is found, with hash previews and link to previous report.
- **Posture diff engine** (`posture_diff.go` / `posture_diff_oss.go`): Field-level comparison of previous vs. current security posture across 12 status fields and 6 sorted record sets. Severity classification (danger/warning/success/info) per field using policy-aware ranking (DMARC policy regression = danger, DNSSEC loss = danger, etc.).

### Implemented (Phase 3): Timeline & Visualization

- **Drift timeline** (`drift.go`, `drift.html`): `/drift?domain=` route renders full posture change history for a domain with field-level diffs, severity badges, and timestamps.
- **Drift events table** (`drift_events`): Normalized storage of individual field changes with severity, previous/current values, and analysis linkage.
- **Timeline navigation**: Chart-line icons in results.html, dossier.html, and history.html link to the drift timeline for any analyzed domain.

### Implemented (Phase 4): Watchlist & Alerting

- **Domain watchlist** (`watchlist.go`, `watchlist.html`): `/watchlist` route with full CRUD for monitored domains. Max 25 domains per user. Configurable cadence (hourly/daily/weekly) with enable/disable toggle.
- **Notification endpoints**: Webhook URL management with optional HMAC-SHA-256 secret for payload verification. Enable/disable toggle per endpoint.
- **Database schema**: `domain_watchlist`, `notification_endpoints`, `drift_notifications` tables with proper indexes and foreign key constraints.
- **Routes**: 7 watchlist endpoints — GET `/watchlist`, POST `/watchlist/add`, POST `/watchlist/:id/delete`, POST `/watchlist/:id/toggle`, POST `/watchlist/endpoint/add`, POST `/watchlist/endpoint/:id/delete`, POST `/watchlist/endpoint/:id/toggle`.

### Implemented (Phase 5): Third-Party Evidence Archival

- **Wayback Machine integration** (`internal/wayback/client.go`): Every successful, non-private, non-scan-flagged analysis is automatically submitted to the Internet Archive via `web.archive.org/save/` in a background goroutine. Snapshot URL stored in `domain_analyses.wayback_url`.
- **Three-layer evidence chain**: SHA-3-512 integrity hash (report-level) + posture hash (drift detection) + Wayback Machine archive (independent third-party verification). Legally defensible, independently verifiable, tamper-proof.
- **Privacy guards**: Private analyses and scanner-flagged analyses are never archived.
- **Results display**: Green "Archived" badge in header + "Internet Archive — Permanent Record" card on Engineer's and Executive's reports with View/Copy buttons.

### Architecture Principles

1. **Live results are sacred.** The analysis path is never altered by drift detection. Snapshots are a side effect.
2. **Conservative storage.** Lean posture hashes for comparison, not redundant copies of full results.
3. **Canonical hashing.** DNS records normalized (sorted, lowercased, whitespace-stripped) before hashing. Cosmetic differences don't trigger false drift.
4. **No false alarms.** Presentation changes (record ordering) don't register as drift.
5. **Severity is policy-aware.** DMARC policy regression (reject→none) is danger. Status loss (pass→fail) is danger. Record changes are warning. Unknown changes are info.
6. **Watchlist is user-scoped.** Each authenticated user manages their own monitored domains and notification preferences.
7. **Third-party evidence is privacy-gated.** Only non-private, non-scan-flagged analyses are submitted to external archives. The Wayback Machine URL is validated before storage.

### Build Tag Boundary

The `posture_diff` boundary follows the open-core pattern:
- `posture_diff.go` — Framework file (compiles unconditionally). Contains `ComputePostureDiff()` and extraction helpers.
- `posture_diff_oss.go` — OSS stub (`//go:build !intel`). Contains `classifyDriftSeverity()`, `classifyPolicyChange()`, `classifyStatusChange()`.
- `posture_diff_intel.go` — Private intel (requires -tags intel build). Enhanced severity classification with threat intelligence correlation.

### Roadmap

- **Background scheduler**: Automated re-analysis at watchlist cadence intervals.
- **Webhook dispatch**: HTTP POST delivery of drift notifications with HMAC-SHA-256 signed payloads.
- **Drift scoring**: Aggregate drift velocity metric for domains over time windows.

---

*Full roadmap and design documentation maintained in the private repository.*
