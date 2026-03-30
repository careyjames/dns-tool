# DNS Tool — Testing Patterns

## Test Frameworks
| Framework | Language | Location | Purpose |
|-----------|----------|----------|---------|
| Go `testing` | Go | `*_test.go` in-package | Unit/integration tests |
| Playwright | TypeScript | `tests/e2e/` | End-to-end browser tests |
| Quality Gate Scripts | Node.js | `scripts/` | Static analysis, CSS/color validation |

## Go Test Patterns

### Standard Tests (`*_test.go`)
- Use standard `testing` package — no third-party assertion libraries
- Subtests via `t.Run("name", func(t *testing.T) {...})`
- Error formatting: `t.Errorf("expected %v, got %v", expected, actual)`

### Bridge Tests (`*_bridge_test.go`)
- Validate mock-based analysis output against golden fixture reference data
- Primary file: `go-server/internal/analyzer/confidence_bridge_test.go`
- Loads fixtures from `tests/golden_fixtures/*.json`
- Requires minimum 90% confidence score match

### Pure Tests (`*_pure_test.go`)
- Unit tests without external dependencies (no network, no DB)
- Test internal helpers and utility functions in isolation

### Coverage Boost Tests (`coverage_boost*_test.go`)
- 27 files across handlers/ and analyzer/
- Targeted tests added to improve code coverage metrics
- Test specific edge cases and internal helpers

## Golden Fixtures
- **Location**: `tests/golden_fixtures/*.json`
- **Content**: Real domain analysis snapshots (google_com.json, etc.)
- **Refresh**: `scripts/refresh-golden-fixtures.sh` — calls production API
- **Usage**: ICAE cases (`go-server/internal/icae/cases_fixture.go`)
- **Rule**: Never fabricate fixture data — always from real DNS queries

## Quality Gate Scripts
| Script | Rule ID | What It Validates |
|--------|---------|-------------------|
| `audit-css-cohesion.js` | R009 | CSS semantic colors, glass opacity, RGB ranges |
| `validate-scientific-colors.js` | R010 | Status color spectrum (success/warning/danger) |
| `feature-inventory.js` | R011 | Feature consistency, 72 features tracked |

### Running Quality Gates
```bash
node scripts/audit-css-cohesion.js      # R009
node scripts/validate-scientific-colors.js  # R010
node scripts/feature-inventory.js       # R011
```

## Test Commands
```bash
# All Go tests
go test ./go-server/... -count=1 -timeout 120s

# Core packages only (faster)
go test ./go-server/internal/config/ ./go-server/internal/templates/ \
       ./go-server/internal/middleware/ ./go-server/cmd/server/ -count=1

# Specific package
go test ./go-server/internal/analyzer/ -count=1 -timeout 90s

# With verbose output
go test ./go-server/... -count=1 -v

# Quality gates
node scripts/feature-inventory.js  # Must show 0 failures
```

## Dependency Injection for Testing
- `Analyzer` struct uses `DNSQuerier` and `HTTPClient` interfaces
- Tests inject mock implementations for deterministic results
- No real DNS queries in unit tests — only in golden fixture refresh

## E2E Testing
- Playwright with TypeScript
- Tests in `tests/e2e/homepage.spec.ts`
- Runs against the live dev server on port 5000
- Same development database — don't assume specific data counts
