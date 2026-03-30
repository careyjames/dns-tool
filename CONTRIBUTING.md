# Contributing to DNS Tool

Thank you for your interest in DNS Tool. We welcome contributions that improve the scientific accuracy, security, and usability of this platform.

## License

DNS Tool is licensed under [BUSL-1.1](LICENSE) (Business Source License 1.1). By submitting a contribution, you agree that your work is subject to this license. If you have questions about what this means for your contribution, please ask before submitting.

## How to Contribute

### Reporting Issues

We use [GitHub Issues](https://github.com/IT-Help-San-Diego/dns-tool/issues/new/choose) with structured templates. Blank issues are disabled — please choose the appropriate template:

| Template | When to Use | Priority |
|----------|------------|----------|
| **Research Mission Critical** | Wrong RFC citation, flawed methodology, incorrect confidence logic, broken detection vectors | P0 — Immediate investigation |
| **Cosmetic / UX / UI** | Visual bugs, layout issues, accessibility problems, user experience improvements | Normal cadence |
| **Security Vulnerability** | Security issues — **redirects to private reporting** | Private channel only |

**Questions and discussions** should go to [GitHub Discussions](https://github.com/IT-Help-San-Diego/dns-tool/discussions), not the issue tracker.

### Research Mission Critical Issues

These are the most important class of issue. If you find that DNS Tool misinterprets an RFC, produces incorrect confidence scores, or has a flawed detection vector, we want to know immediately. The template requires:

- The specific RFC section with normative text
- Expected vs. observed behavior with concrete examples
- Confidence impact assessment (false positives, false negatives, severity errors)
- Reproduction steps with a specific domain
- Confirmation that you have verified your interpretation against the RFC

This rigor is not bureaucracy — it is how we maintain scientific accuracy. A vague "something seems wrong" report cannot be investigated. A precise "RFC 7489 §6.3 says X, but DNS Tool reports Y for domain Z" report can be fixed within hours.

### Security Vulnerabilities

**Never post security vulnerability details in a public issue.** Use one of these private channels:

- [GitHub Security Advisory](https://github.com/IT-Help-San-Diego/dns-tool/security/advisories/new)
- Email: [security@it-help.tech](mailto:security@it-help.tech)
- [security.txt](https://dnstool.it-help.tech/.well-known/security.txt)

Our [Security Policy](https://dnstool.it-help.tech/security-policy) includes safe harbor provisions for good-faith research.

## Issue Triage State Machine

Every issue follows a lifecycle tracked by labels. This process is partially automated by GitHub Actions:

```
New Issue
    |
    v
[needs-triage]  <-- Auto-applied on creation
    |
    +-- Bot validates content (Research: checks RFC ref, expected/observed, confidence)
    |
    +---> Substantive? -----> [triage/accepted]  --> needs-triage removed
    |                              |
    |                              +--> Work begins --> PR with "Fixes #N"
    |                              |
    |                              +--> Merged --> Issue auto-closed
    |
    +---> Incomplete? -----> [triage/needs-information]  --> awaiting reporter
    |                              |
    |                              +--> Reporter updates --> Re-evaluated on edit
    |
    +---> Security content? -> [needs-security-review]  --> maintainer review
    |
    +---> Security template? -> Auto-closed + locked --> Private channel redirect
```

**Label taxonomy:**

| Label | Meaning |
|-------|---------|
| `needs-triage` | New issue, not yet validated |
| `triage/accepted` | Validated and queued for work |
| `triage/needs-information` | Missing required detail from reporter |
| `needs-security-review` | Possible security content in a non-security issue |
| `triage:research` | Research Mission Critical (P0) |
| `triage:ux` | Cosmetic / UX / UI |
| `triage:security-redirect` | Security template — auto-closed |
| `priority:P0` | Immediate investigation required |

**Who clears `needs-triage`:** The automated workflow clears it when content validation passes. Maintainers can also manually transition by adding `triage/accepted` and removing `needs-triage`.

## Development Setup

### Prerequisites

- Go 1.23+
- PostgreSQL (provided by Replit in development)
- Node.js (for asset minification and quality gate scripts)

### Running Tests

```bash
go test ./go-server/... -cover -count=1
```

### Pre-Push Checklist

1. **Go tests pass with coverage:**
   ```bash
   go test ./go-server/... -cover -count=1
   ```

2. **Minify JS after changes:**
   ```bash
   npx terser static/js/main.js -o static/js/main.min.js --compress --mangle
   ```

3. **Minify CSS after changes:**
   ```bash
   npx csso static/css/custom.css -o static/css/custom.min.css
   ```

4. **Run quality gate scripts:**
   ```bash
   node scripts/audit-css-cohesion.js
   node scripts/feature-inventory.js
   node scripts/validate-scientific-colors.js
   ```

5. **Build the binary:**
   ```bash
   bash build.sh
   ```

## SonarCloud Quality Gate Standards

All contributions must meet the following quality standards enforced by SonarCloud.

### Test Coverage

- All new code must have **80%+ test coverage**.
- Use table-driven tests with descriptive names.
- Cover edge cases: empty strings, nil inputs, boundary values, malformed data.

### Code Smells

- No new code smells rated **CRITICAL** or above.
- No new duplicated string literals — extract to constants.
- Keep functions focused and under reasonable complexity thresholds.

### Security Hotspots

- All security hotspots must be reviewed before merge.
- Never hard-code secrets, API keys, or credentials.
- Use environment variables for sensitive configuration.

### Duplication

- No new duplicated blocks or string literals.
- Extract repeated strings into package-level constants.
- Reuse existing utility functions rather than duplicating logic.

## Code Style

- Follow existing patterns and conventions in the codebase.
- Use Go standard formatting (`gofmt`).
- No inline `onclick`, `onchange`, or `style=""` in templates — use `addEventListener` in nonce'd script blocks.
- Every CSS/template change must be verified at 375px viewport width.
- All domain/IP input fields must include `autocapitalize="none" spellcheck="false" autocomplete="off"`.

## Version Bump Protocol

1. Bump `Version` in `go-server/internal/config/config.go`.
2. Run `bash build.sh` to compile the new version into the binary.
3. Restart the application workflow.

The version is compiled at build time via `-ldflags` in `build.sh`. The `Version` variable in `config.go` is the single source of truth.

## SonarCloud Coverage Targets by Package

| Package | Minimum Target |
|---------|---------------|
| New packages | 80%+ |
| `analyzer` | 80%+ |
| `dnsclient` | 80%+ |
| `middleware` | 65%+ |
| `notifier` | 80%+ |
| `scanner` | 80%+ |
| `icae` | 80%+ |
| `handlers` | Improve from baseline |
| `cmd/probe` | 45%+ |

## Traceability

Every pull request should reference the issue it addresses using `Fixes #NNN` or `Closes #NNN` in the PR description. This creates a traceable chain from issue to code change to deployment.
