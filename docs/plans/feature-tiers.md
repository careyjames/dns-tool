# DNS Tool — Feature Tier Design

**Status**: Approved  
**Version**: 26.35.17+  
**Date**: 2026-03-08  
**Author**: Carey James Balboa / Architect Review  

## Philosophy

DNS Tool is open-core (BUSL-1.1). The product serves multiple archetypes — engineers, executives, hackers, researchers — and the symbiosis between them is foundational. Nothing that enables cross-archetype collaboration (like the Executive Report) gets locked behind a paywall.

"Free" is not the right word. Open source isn't "free source." Tier 2 is **Registered** — it means you chose to log in. That's it.

## Tier Definitions

### Tier 1 — Open (Anonymous)

No login required. Hacker-friendly. The core product.

| Feature | Route(s) |
|---------|----------|
| Full domain scan (all 9 protocols) | `POST /analyze`, `GET /analysis/:id` |
| Engineer's Report (view + download) | `GET /analysis/:id` |
| Executive Report | `GET /analysis/:id/executive` |
| Covert Recon Report | `GET /analysis/:id` (covert mode toggle) |
| Confidence scoring | embedded in analysis |
| Badge embed | `GET /badge`, `/badge/shields`, `/badge/embed` |
| Compare (public analyses) | `GET /compare` |
| Drift timeline (public analyses) | `GET /drift` |
| Topology | `GET /topology` |
| TTL Tuner | `GET /ttl-tuner`, `POST /ttl-tuner/analyze` |
| Email header analyzer | `GET /headers`, `POST /headers/analyze` |
| Toolkit (MyIP, PortCheck) | `GET /toolkit`, `POST /toolkit/*` |
| Subdomain CSV export (per-scan) | `GET /api/subdomains/*` |
| Snapshot view | `GET /snapshot/:id` |
| Public results history | `GET /history` |
| Stats | `GET /stats` |
| All docs pages | `/about`, `/approach`, `/faq`, etc. |
| Changelog, Roadmap | `GET /changelog`, `GET /roadmap` |

### Tier 2 — Registered (Google OAuth login)

Everything in Tier 1, plus personal state features:

| Feature | Route(s) |
|---------|----------|
| Personal scan history ("My History") | future (not yet built) |
| Watchlist (CRUD + endpoints) | `GET/POST /watchlist/*` |
| Personal dossier | `GET /dossier` |
| Zone file upload/analysis | `GET /zone`, `POST /zone/upload` |
| Analysis ownership (scans saved to account) | implicit |

### Tier 3 — Premium (Paid subscription via Stripe)

Everything in Tier 2, plus scale/programmatic features:

| Feature | Route(s) |
|---------|----------|
| Bulk scanning (multiple domains) | `POST /api/bulk-scan` (new) |
| API keys + higher rate limits | `GET /api/keys` (new) |
| Bulk/programmatic data export (account-scope NDJSON/CSV) | `GET /api/export/*` (new) |
| Priority scan queue | scan infrastructure flag |
| Webhook notification scale | watchlist webhook config |
| Team/org controls | future |

**Clarification**: "Export JSON" in Premium means bulk/programmatic export at account scope — NOT the per-scan Engineer's Report download, which stays in Tier 1.

## Data Model

### Existing (unchanged)

- `users.role` — RBAC only (`user`, `admin`). Not for tier gating.
- `RequireAuth()` — checks session existence.
- `RequireAdmin()` — checks `role = admin`.

### New

```sql
ALTER TABLE users ADD COLUMN plan VARCHAR(20) NOT NULL DEFAULT 'registered';

CREATE TABLE subscriptions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stripe_customer_id VARCHAR(255),
    stripe_subscription_id VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'inactive',
    current_period_start TIMESTAMP,
    current_period_end TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(user_id)
);
```

Plan resolution:
- No session → `anonymous` (Tier 1)
- Valid session, no active subscription → `registered` (Tier 2)
- Valid session + active subscription → `premium` (Tier 3)
- Admin bypasses all tier checks

## Implementation Architecture

### 1. Entitlements Package (`internal/entitlements/`)

```go
type Plan string
const (
    PlanAnonymous  Plan = "anonymous"
    PlanRegistered Plan = "registered"
    PlanPremium    Plan = "premium"
)

type Feature string
const (
    FeatureHistory       Feature = "history"
    FeatureWatchlist     Feature = "watchlist"
    FeatureDossier       Feature = "dossier"
    FeatureZoneUpload    Feature = "zone_upload"
    FeatureBulkScan      Feature = "bulk_scan"
    FeatureAPIKeys       Feature = "api_keys"
    FeatureBulkExport    Feature = "bulk_export"
    FeaturePriorityQueue Feature = "priority_queue"
    FeatureWebhookScale  Feature = "webhook_scale"
)

var Registry = map[Feature]Plan{
    FeatureHistory:       PlanRegistered,
    FeatureWatchlist:     PlanRegistered,
    FeatureDossier:       PlanRegistered,
    FeatureZoneUpload:    PlanRegistered,
    FeatureBulkScan:      PlanPremium,
    FeatureAPIKeys:       PlanPremium,
    FeatureBulkExport:    PlanPremium,
    FeaturePriorityQueue: PlanPremium,
    FeatureWebhookScale:  PlanPremium,
}
```

### 2. Middleware (`RequireFeature`)

```go
func RequireFeature(feature entitlements.Feature) gin.HandlerFunc
func HasFeature(c *gin.Context, feature entitlements.Feature) bool
```

- Resolves user's plan from session context
- Compares against registry
- Returns 401 (not authenticated) or 403 (insufficient plan)
- Admin always passes

### 3. Template Gating

- Add `Plan` and `HasFeature` func to template context
- Show/hide UI elements and upgrade CTAs
- Server-side route checks remain authoritative

### 4. Build Tag Interaction

- `//go:build intel` / `//go:build !intel` — code boundaries (public vs private repo)
- Feature tiers — runtime access control
- They are orthogonal. If intel-only code provides a capability, it requires BOTH compiled code AND premium entitlement.

## Phase Plan

1. **Design doc** ← this document
2. **Entitlements package** — feature registry, plan types, resolution
3. **RequireFeature middleware** — route gating
4. **Gate existing routes** — history, dossier, watchlist confirm RequireAuth; compare/drift/topology stay open
5. **Template helpers** — `hasFeature` func, upgrade CTAs
6. **Subscription schema + Stripe** — later phase (Premium tier activation)
