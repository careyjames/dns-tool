# DNS Tool — Boundary Manifest

**Status:** Active
**Version:** 1.0
**Architecture:** Single-repo open-core with Go build tags (`_oss.go` default + `_intel.go` via `-tags intel`)

---

## Purpose

This document inventories every stubbed subsystem in the public repository and defines the boundary between public framework code and private intelligence modules. It exists so that contributors, auditors, and AI assistants can understand what is implemented in the open-core public build versus what requires the `intel` build tag.

---

## Build Tag Convention

- **Default build** (`go build`): Compiles all framework code plus OSS stubs. Produces a functional application with safe defaults where intelligence modules would otherwise operate.
- **Intel build** (`go build -tags intel`): Compiles framework code plus full intelligence implementations from the private repo. Stubs are excluded via `//go:build !intel`.

Every stubbed subsystem follows this file pattern:

| File | Build Tag | Role |
|------|-----------|------|
| `feature.go` | None (always compiled) | Framework interface — defines types, constants, function signatures used by handlers and other packages |
| `feature_oss.go` | `//go:build !intel` | OSS stub — compiles in default build, returns safe empty/default values |
| `feature_intel.go` | `//go:build intel` | Intel implementation — lives in private repo, provides full capability |

---

## Stubbed Subsystems — Analyzer Package

### `internal/analyzer/`

| Subsystem | Framework File | OSS Stub | Description |
|-----------|---------------|----------|-------------|
| **Edge/CDN Detection** | `edge_cdn.go` | `edge_cdn_oss.go` | Detects CDN and edge providers from ASN, CNAME, and header patterns |
| **Infrastructure Detection** | `infrastructure.go` | `infrastructure_oss.go` | Identifies hosting, DNS, and email infrastructure providers |
| **Provider Classification** | `providers.go` | `providers_oss.go` | ESP detection, DKIM provider maps, SPF flattening service identification |
| **IP Investigation** | `ip_investigation.go` | `ip_investigation_oss.go` | Deep IP intelligence — geolocation, ASN enrichment, threat correlation |
| **Posture Diff** | `posture_diff.go` | `posture_diff_oss.go` | Compares security posture between scans to detect drift |
| **Manifest** | `manifest.go` | `manifest_oss.go` | Intelligence manifest — tracks what sources contributed to each finding |
| **SaaS TXT** | `saas_txt.go` | `saas_txt_oss.go` | Detects SaaS domain verification TXT records and classifies services |
| **Remediation** | `remediation.go` | (inline stubs) | RFC-aligned remediation engine with priority fixes |
| **Confidence** | `confidence.go` | (inline stubs) | Confidence classification — Observed, Inferred, Third-party attribution |
| **Commands** | `commands.go` | (inline stubs) | "Verify It Yourself" terminal command generation |

### `internal/analyzer/ai_surface/`

| Subsystem | Framework File | OSS Stub | Description |
|-----------|---------------|----------|-------------|
| **AI HTTP Surface** | `http.go` | `http_oss.go` | Detects AI-relevant HTTP headers and configurations |
| **LLMs.txt** | `llms_txt.go` | `llms_txt_oss.go` | Parses and validates llms.txt files for AI crawler guidance |
| **Poisoning Detection** | `poisoning.go` | `poisoning_oss.go` | Detects DNS and content poisoning indicators relevant to AI training |
| **Robots.txt AI** | `robots_txt.go` | `robots_txt_oss.go` | Analyzes robots.txt for AI-specific crawler directives |
| **AI Surface Scanner** | `scanner.go` | `scanner_oss.go` | Orchestrates AI surface analysis across all sub-modules |

---

## Stubs Reference Directory

The `stubs/` directory at the repository root contains reference copies of stubbed files:

```
stubs/go-server/internal/analyzer/
├── ai_surface/
│   ├── http.go
│   ├── http_oss.go
│   ├── llms_txt.go
│   ├── llms_txt_oss.go
│   ├── poisoning.go
│   ├── poisoning_oss.go
│   ├── robots_txt.go
│   ├── robots_txt_oss.go
│   └── scanner.go
├── analyzer_test.go
├── commands.go
├── confidence.go
├── confidence_test.go
├── dkim_state.go
├── dkim_state_test.go
├── edge_cdn.go
├── golden_rules_test.go
├── infrastructure.go
├── ip_investigation.go
├── manifest.go
├── manifest_test.go
├── orchestrator_test.go
├── posture.go
├── providers.go
├── remediation.go
└── saas_txt.go
```

These reference copies serve as documentation of the public API surface. The canonical implementations live in `go-server/internal/analyzer/` (OSS stubs) and the private intel repo (full implementations).

---

## Boundary Integrity Tests

Automated boundary tests verify that the public/intel boundary is never violated:

- **`go-server/internal/analyzer/boundary_integrity_test.go`**: Verifies that every framework file has a corresponding OSS stub, that stubs compile independently, and that function signatures match between stub and framework.
- **`go-server/internal/analyzer/ai_surface/boundary_integrity_test.go`**: Same verification for the AI surface analysis sub-package.

These tests run in CI on every commit and prevent:

1. OSS stubs that fail to compile
2. Missing stubs for new framework functions
3. Signature mismatches between stub and intel implementations
4. Accidental import of intel-only packages in OSS stubs

---

## What Stays Public

The following subsystems are fully implemented in the public repository with no intel-gated components:

- **SPF Analysis** (`spf.go`) — RFC 7208 compliant
- **DMARC Analysis** (`dmarc.go`) — RFC 7489 compliant
- **DKIM Discovery** (`dkim.go`) — RFC 6376, 81+ known selectors
- **DNSSEC Validation** (`dnssec.go`) — RFC 4033-4035
- **DANE/TLSA** (`dane.go`) — RFC 6698
- **MTA-STS** (`mta_sts.go`) — RFC 8461
- **TLS-RPT** (`tlsrpt.go`) — RFC 8460
- **BIMI** (`bimi.go`) — RFC 9495
- **CAA** (`caa.go`) — RFC 8659
- **DNS Client** (`dnsclient/`) — Multi-resolver queries
- **ICAE** (`icae/`) — Intelligence Confidence Audit Engine
- **ICuAE** (`icuae/`) — Intelligence Currency Audit Engine
- **All handlers** (`handlers/`) — Request handling, auth, export
- **All templates** (`templates/`) — HTML rendering
- **All middleware** (`middleware/`) — CSP, rate limiting, analytics

---

## Design Principles

1. **OSS build must be fully functional**: The default build produces a working application. Stubs return empty results, not errors. Users see "no data available" rather than crashes.

2. **No proprietary logic in framework files**: Framework files define interfaces and types. Classification algorithms, provider databases, and detection heuristics live exclusively in intel implementations.

3. **Stubs are contracts**: The function signatures in OSS stubs are the public API contract. Intel implementations must satisfy the same signatures. Boundary integrity tests enforce this.

4. **One-way dependency**: Intel code imports and extends framework code. Framework code never imports intel code. Build tags ensure compile-time separation.

---

**© 2024–2026 IT Help San Diego Inc. — DNS Security Intelligence**
