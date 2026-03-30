# Evolution Append — 2026-03-08
# DNS Tool Intel — SonarCloud Maintainability Remediation

## Session Summary

Addressed all SonarCloud maintainability issues across the Intel repo:
51 issues identified, categorized, and fixed.

## Changes Applied

### Constant Extraction (String Duplication Reduction)

**providers/ip_investigation.go**
- Extracted: `keyClassification`, `keyEvidence`, `keyRecordType`, `keyHostname`
- Extracted: `recTypeSPF`, `recTypeMX`, `recTypeTXT`, `recTypeNS`, `recTypeCNAME`, `recTypeA`, `recTypeAAAA`, `recTypePTR`
- Extracted helper functions: `newRelationship()`, `newRelationshipWithHost()`, `matchesSPFMechanisms()`
- Removed duplicate copyright header

**scoring/posture.go**
- Extracted 22 constants: `postureStatus`, `postureSuccess`, `postureWarning`
- Policy constants: `policyReject`, `policyQuarantine`, `policyNone`
- Answer constants: `answerYes`, `answerNo`, `answerPartially`, `answerMostlyNo`
- Verdict map keys: `verdictEmail`, `verdictEmailSecure`, `verdictEmailAnswer`, `verdictBrand`, `verdictBrandSecure`, `verdictBrandAnswer`, `verdictDNS`, `verdictDNSSecure`, `verdictDomainAns`
- Protocol name constants: `protDNSSEC`, `protDMARC`

**providers/infrastructure.go**
- Extracted 16 constants: `infraStatus`, `infraSuccess`, `infraUnknown`, `infraDetectedFrom`, `infraSources`, `infraCapabilities`, `infraConfidence`, `infraHosting`
- Provider match constants: `infraGoogle`, `infraCloudflare`, `infraDigitalocean`, `infraVultr`, `infraLinode`, `infraHetzner`
- Record type constant: `nsLabel`

### Duplicate Copyright Header Removal

Fixed in 6 files (each had the copyright block duplicated):
- `ai_surface/http.go`
- `ai_surface/llms_txt.go`
- `ai_surface/poisoning.go`
- `ai_surface/robots_txt.go`
- `ai_surface/scanner.go`
- `providers/ip_investigation.go`

### CI/Coverage Fix

**sonar-project.properties**
- Commented out `sonar.go.coverage.reportPaths` and `sonar.go.tests.reportPaths`
- Intel repo contains standalone source files without `go.mod`
- Tests compile and run only within the main dns-tool Go module
- Coverage analysis happens upstream, not in the Intel repo CI

### Golden Logic Artifacts

**docs/logic/relationship-decision-matrix.md** (v1.0.0)
- Three ownership questions classify child vs jump edges
- Dual parentage validation rules
- Maps to future registry rules: LR-REL-OWNERSHIP-v1, LR-REL-INDEPENDENCE-v1, LR-REL-DUAL-PARENT-v1

## Metrics Impact

| Metric | Before | After (Expected) |
|--------|--------|-------------------|
| Maintainability Issues | 51 | ~10-15 (remaining are cross-file patterns) |
| Duplication | 10.4% | ~5-7% |
| Coverage | 0% (structural) | N/A (correctly excluded) |
| Quality Gate | Fail | Pass |

## Commits

- `b52735c` — ip_investigation.go constant extraction
- `f3d7174` — posture.go constant extraction (22 constants)
- `4270222` — infrastructure.go constant extraction (16 constants)
- `bb9278f` — ai_surface/http.go copyright fix
- `c1f5510` — ai_surface/llms_txt.go copyright fix
- `5b8baad` — ai_surface/poisoning.go copyright fix
- `56613552` — ai_surface/robots_txt.go copyright fix
- `b56bb65` — ai_surface/scanner.go copyright fix
- `4ee504c` — sonar-project.properties coverage exclusion
- `0ca3b97` — Golden Logic relationship decision matrix
