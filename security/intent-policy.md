# SECINTENT Exception Policy

## Overview

The SECINTENT system provides auditable, narrowly-scoped exceptions for intentional
security decisions in the DNS Tool codebase. Every exception must be:

1. **Inline-tagged** in source code with a `SECINTENT-NNN` comment
2. **Registered** in `security/security-intents.yaml` with full justification
3. **Time-bounded** with an expiration date and review interval
4. **Narrowly scoped** to specific files and patterns

## Tag Format

```
// SECINTENT-NNN: <brief description>
```

Examples:
```go
// SECINTENT-001: TLS skip-verify for SMTP diagnostic probe
tlsCfg := &tls.Config{InsecureSkipVerify: true}
```

## YAML Registry Schema

Each entry in `security/security-intents.yaml` must include:

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier `SECINTENT-NNN` |
| `title` | Yes | Human-readable title |
| `file` | Yes | File path or glob pattern |
| `pattern` | Yes | Regex pattern matching the code construct |
| `category` | Yes | One of: `accepted-risk`, `intentional-behavior`, `test-fixture`, `easter-egg` |
| `severity` | Yes | One of: `critical`, `high`, `medium`, `low`, `info` |
| `justification` | Yes | Detailed explanation of why this is intentional |
| `sonar_rules` | No | SonarQube rule IDs this exception covers |
| `owner` | Yes | Team or individual responsible |
| `approved_by` | Yes | Who approved this exception |
| `approved_date` | Yes | Date of approval (YYYY-MM-DD) |
| `expires` | Yes | Expiration date (YYYY-MM-DD) |
| `review_interval_days` | Yes | How often this must be re-reviewed |

## Categories

- **accepted-risk**: Known security pattern that is intentional and mitigated
- **intentional-behavior**: Design decision that triggers scanner false positives
- **test-fixture**: Test data that resembles secrets or vulnerabilities
- **easter-egg**: Intentional hidden feature with security implications

## Reconciliation Rules

The `secintent-check.py` script enforces:

1. **No orphaned YAML entries**: Every registry entry must have at least one
   matching `SECINTENT-NNN` tag in source code within the specified file scope
2. **No unregistered tags**: Every `SECINTENT-NNN` tag in code must have a
   matching entry in the YAML registry
3. **No expired exceptions**: Entries past their `expires` date cause failures
4. **No overly-broad scope**: File patterns must not use `**/*` (too broad)

## Severity-Based Pass/Fail

| Severity | Action |
|----------|--------|
| Critical | **BLOCK** — pipeline fails |
| High | **BLOCK** — pipeline fails |
| Medium | **WARN** — logged, does not block |
| Low | **TRACK** — recorded in report |
| Info | **TRACK** — recorded in report |

## Workflows

### Adding a New Exception

1. Add inline comment in code: `// SECINTENT-NNN: description`
2. Add entry to `security/security-intents.yaml`
3. Run `python security/secintent-check.py` to validate
4. Get approval from security team lead

### Reviewing Expiring Exceptions

1. Run `python security/secintent-check.py` — it warns on exceptions
   expiring within 30 days
2. Review the justification — is the exception still needed?
3. If yes: update `expires` and `approved_date`, get re-approval
4. If no: remove the YAML entry and inline tag, fix the underlying issue

### Removing an Exception

1. Remove the inline `SECINTENT-NNN` tag from source code
2. Remove the corresponding entry from `security/security-intents.yaml`
3. Run `python security/secintent-check.py` to verify clean reconciliation

## Integration with Scanners

The SECINTENT system complements (does not replace) scanner-specific suppression:

- **SonarQube**: `//NOSONAR` and `sonar-project.properties` multicriteria
- **Semgrep**: `// nosemgrep` inline annotations
- **Gitleaks**: `.gitleaks.toml` allowlists
- **gosec**: `//nolint:gosec` annotations

SECINTENT provides a unified, auditable layer on top of these tool-specific mechanisms.
