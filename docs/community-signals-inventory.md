# Community Signals — Full Inventory

> **Classification**: Private / Intel Repo Only
> **Last Updated**: 2026-02-20
> **Version**: 26.21.16

This document contains the complete inventory of community signals (Easter eggs) deployed in DNS Tool. This file lives exclusively in the Intel repo — NEVER commit to the public webapp repo.

## Legal Framework

All community signals cite **RFC 1392** (IETF Internet Users' Glossary, 1993) definition of "hacker" as a person who delights in having an intimate understanding of systems. Legal disclaimers are embedded in each signal.

## Implementation Infrastructure

### htmlComment() Template Function
- **File**: `go-server/internal/templates/funcs.go`
- **Purpose**: Go's `html/template` silently strips all HTML comments for security. `htmlComment()` returns `template.HTML` type, bypassing the stripping.
- **Security**: Sanitizes `--` sequences to em dashes to prevent comment injection. Used ONLY with static compile-time strings, never user input.
- **CSP**: All signals are CSP-compliant. No inline scripts or styles.

## Signal Inventory

### 1. HTML Comments (Visible via `curl` or View Source)

| Template | Content | Discovery Method |
|---|---|---|
| `index.html` | Zone-diff verse | View Source / curl |
| `results.html` | NSEC-chain verse | View Source / curl |
| `architecture.html` | Discovery breadcrumb | View Source / curl |

### 2. HTTP Response Headers (devNull Mode Only)

| Header | Value | Compliance |
|---|---|---|
| `X-Hacker` | Hacker culture message | RFC 7230 compliant ASCII |
| `X-Persistence` | `/dev/null` | RFC 7230 compliant |

These headers are only set on ephemeral/devNull scan results.

### 3. Browser Console Log (devNull Mode Only)

- Styled hacker verse output in browser DevTools console
- Delivered via nonce'd `<script>` block (CSP-compliant)
- Only triggers on devNull scan results

### 4. Architecture Page — Opacity Hint

- **File**: `go-server/templates/architecture.html`
- **Element**: Text at 50% opacity encouraging source code exploration
- **Design**: Intentionally reduced visibility — a community signal, not a bug
- **Protection**: Go template comment (`{{/* INTENTIONAL... */}}`) guards against AI "fixing" it

## Scanner Gap Note (2026-02-20)

The AI surface scanner (`scanForHiddenPrompts()` in `ai_surface/scanner.go`) checks for:
- `display:none`
- `visibility:hidden`
- `position:absolute;left:-9999`
- `aria-hidden="true"`

It does **NOT** check for opacity-based hiding techniques:
- `opacity:0` through `opacity:0.49` (text effectively invisible)
- `font-size:0`
- `color:transparent` / same-color-on-background
- `text-indent:-9999` (only `left:-9999` is checked)
- `clip-path` / `clip:rect(0,0,0,0)`

This is an architectural enhancement opportunity — bad actors could use these techniques to hide prompt injection content that our scanner wouldn't catch. Our own 50% opacity hint is benign but demonstrates the gap.

## /dev/null Response Details

- **Template**: Dark terminal-themed banner with `> ./dns-tool --output /dev/null` code block
- **Response headers**: RFC 7230 compliant custom headers on ephemeral results
- **Behavior**: Full analysis runs, but `saveAnalysis()`, `InsertUserAnalysis()`, `icae.EvaluateAndRecord()`, `RecordAnalysis()` analytics, and drift lookup are all skipped

## Discovery Design Philosophy

The signals are layered for different skill levels:
1. **Noob-friendly**: The architecture page hint at 50% opacity — visible if you're paying attention
2. **Intermediate**: View Source on any page reveals HTML comments
3. **Advanced**: DevTools console output and HTTP headers only appear in devNull mode
4. **Expert**: Understanding the `htmlComment()` function and why it exists

Public documentation contains enough hints ("discoverable content for security researchers", "curious engineers are encouraged to explore") to get anyone started, but never reveals specific locations or content.
