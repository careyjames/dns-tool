# DNS Tool — AI Change Interrogation Protocol (ACIP)

**Status:** Active
**Version:** 2.0
**Applies to:** All AI-assisted code changes in `dns-tool`

---

## Purpose

ACIP is a lightweight governance protocol for interrogating AI-generated code changes before they enter the codebase. It exists because AI assistants optimize for plausibility, not correctness — and plausible-but-wrong changes are the most dangerous kind.

This protocol ensures that every AI-assisted change is subjected to the same epistemic discipline that DNS Tool applies to DNS intelligence: multi-source verification, confidence classification, and independent reproducibility.

---

## The Three Questions

Every AI-generated change must answer three questions before merge:

### 1. What changed and why?

- Diff must be human-reviewable (no bulk reformats mixed with logic changes)
- The change rationale must reference a concrete requirement, bug, or task ID
- If the AI invented a requirement, the change is rejected

### 2. What could this break?

- Boundary integrity: Does this change cross the public/intel boundary?
- Stub contracts: Do OSS stubs still compile and return safe defaults?
- Test coverage: Do existing tests still pass? Are new paths covered?
- RFC compliance: Does this change alter how any RFC-defined protocol is parsed or evaluated?

### 3. How do we verify it?

- Unit tests must cover the changed logic
- Boundary integrity tests (`boundary_integrity_test.go`) must pass
- Golden fixture tests must not regress
- Build must succeed with both default and `intel` build tags

---

## Protected Invariants — Non-Negotiable Quality Gates

These are HARD STOPS. No change ships unless ALL pass. No exceptions. No "we'll fix it later."

| Gate | Target | Verification Command | Failure = STOP |
|------|--------|---------------------|----------------|
| **SonarCloud** | A rating, all categories, 100% | SonarCloud dashboard | Yes |
| **Lighthouse** | 100, all categories | `lighthouse` or Chrome DevTools | Yes |
| **Mozilla Observatory** | 145+ score | observatory.mozilla.org | Yes |
| **SRI** | All CSS/JS assets have SHA-384 integrity + crossorigin | `curl` + grep for `integrity=` | Yes |
| **Go Tests** | All pass, zero failures | `go test ./go-server/... -count=1` | Yes |
| **R009 CSS Cohesion** | PASS | `node scripts/audit-css-cohesion.js` | Yes |
| **R010 Scientific Colors** | PASS | `node scripts/validate-scientific-colors.js` | Yes |
| **R011 Feature Inventory** | PASS, 0 failures | `node scripts/feature-inventory.js` | Yes |
| **Preview** | User can see and interact with the site | Replit Preview pane | Yes |
| **Git** | Clean, synced, merged, healthy, pushed to correct repos | `git status` + branch checks | Yes |
| **Build** | Both `go build` (OSS) and `go build -tags intel` succeed | `bash build.sh` | Yes |

### Git Discipline

- Branches must be synced before any push
- NEVER expose proprietary logic, hacker Easter eggs, or IP in public commit messages
- ALWAYS verify which repo/branch a push targets (public vs intel)
- Privacy and intellectual property awareness is mandatory, not optional

### Version Separation — Development vs Citation

**Development version** (`config.go`, `sonar-project.properties`, UI badge):
- Tracks the current development state
- Changes with every meaningful code change

**Citation version** (`CITATION.cff`, `codemeta.json`):
- Tracks the last DOI-backed Zenodo release
- Changes ONLY when a new GitHub Release triggers Zenodo archival
- Must match the version the DOI (`10.5281/zenodo.18854899`) resolves to
- Changing this without a Zenodo release creates a falsified citation state
- This breaks ORCID linking, OpenAlex ingestion, and scholarly reproducibility

**Rule**: CITATION.cff and codemeta.json are ORCID-linked research artifacts. They are NOT dev tracking files. Never bump them during routine development.

**Two-Track Version Bump Law**:
- **Dev bump** (routine): Edit ONLY `go-server/internal/config/config.go` → rebuild → publish. No other versioned file is touched. The concept DOI (`10.5281/zenodo.18854899`) NEVER changes.
- **Release bump** (tag time only): `scripts/release-gate.sh X.Y.Z` bumps ALL versioned artifacts (config.go, CITATION.cff, codemeta.json, sonar-project.properties, methodology docs). Only run when a git tag is being created. The concept DOI still does not change — only `version:` fields update.

---

## Change Classification

| Category | Risk | Required Verification |
|----------|------|-----------------------|
| **Template/CSS** | Low | Visual review, mobile check |
| **Handler logic** | Medium | Unit tests, integration test |
| **Analyzer logic** | High | Unit tests, golden fixtures, ICAE cases |
| **Stub/boundary files** | Critical | Boundary integrity tests, dual-tag build |
| **Database schema** | Critical | Migration review, rollback plan |
| **DNS client** | Critical | Multi-resolver tests, live integration test |
| **Citation metadata** | Critical | Must match last Zenodo release; ORCID/DOI verification |
| **Version bump** | Medium | Dev files only; never CITATION.cff/codemeta.json without release |

---

## Boundary-Sensitive Changes

Changes to files in the public/intel boundary require additional scrutiny:

1. **OSS stub files** (`*_oss.go`): Must compile independently, return safe defaults, never import intel-only packages
2. **Framework files** (e.g., `edge_cdn.go`, `confidence.go`): Must not embed proprietary logic — classification algorithms, provider databases, and methodology belong in the intel repo
3. **Build tags**: `//go:build !intel` on stubs, `//go:build intel` on intel implementations — never omitted, never inverted
4. **Stubs directory** (`stubs/`): Reference copies must stay synchronized with their corresponding OSS files

---

## AI-Specific Failure Modes

These are patterns where AI assistants commonly introduce errors in this codebase:

| Failure Mode | Detection | Prevention |
|---|---|---|
| **Hallucinated RFC citations** | Cross-reference against IETF datatracker | Never trust AI-generated RFC numbers without verification |
| **Stub contract violation** | `boundary_integrity_test.go` fails | Run boundary tests before any merge |
| **Silent behavior change** | Golden fixture diff | Compare analyzer output against golden fixtures |
| **Dependency injection** | `go.mod` diff review | No new dependencies without explicit approval |
| **Hard-coded test data** | Code review | Test data must come from golden fixtures or deterministic generators |
| **Confidence inflation** | ICAE score regression | ICAE audit scores must not decrease after a change |
| **Citation metadata drift** | CITATION.cff version ≠ Zenodo release | Never bump CITATION.cff/codemeta.json during dev; only on Zenodo release |
| **Quality gate regression** | Lighthouse/Observatory/Sonar score drops | Run ALL quality gates before and after every change |
| **IP leak in commit messages** | Public git log review | Never reference proprietary logic, Easter eggs, or intel details in public commits |

---

## Protocol Enforcement

ACIP is enforced through existing automated checks:

- **Build**: `go build` (OSS) and `go build -tags intel` (full) must both succeed
- **Boundary tests**: `go test ./internal/analyzer/ -run TestBoundary` must pass
- **ICAE**: Protocol confidence scores must not regress
- **Golden fixtures**: Structural confidence bridge must maintain ≥90% match

Manual enforcement:

- Reviewer must confirm the change answers the Three Questions
- Changes touching `*_oss.go` or `*_intel.go` files require explicit boundary review
- RFC-affecting changes require citation verification against the actual RFC text

---

## Relationship to Other Governance

- **BOUNDARY_MANIFEST.md**: Documents which subsystems are stubbed and where the public/intel boundary lies
- **MISSION.md**: Defines the epistemic principles that ACIP enforces procedurally
- **ICAE**: Provides quantitative confidence scoring that ACIP references for regression detection
- **ICuAE**: Ensures data currency standards are maintained through changes

---

**© 2024–2026 IT Help San Diego Inc. — DNS Security Intelligence**
