# Definition of Done

Every change must satisfy this checklist before it ships.

---

## Code Quality

- [ ] Format passes (`gofmt`)
- [ ] Lint passes (`go vet`)
- [ ] Typecheck passes (compiles cleanly)
- [ ] All tests pass (`go test ./...`)
- [ ] Golden rules pass (`go test -run TestGoldenRule ./internal/analyzer/ -v`)
- [ ] No new high/critical findings from code quality scanners
- [ ] Diffs are minimal — smallest change that solves the problem

## Security

- [ ] No secrets in code, logs, or docs
- [ ] No debug endpoints or test backdoors
- [ ] No silent failures — errors are structured and surfaced
- [ ] SSRF, injection, and authz boundaries reviewed for any change touching external input
- [ ] Secrets managed through environment variables only, never hardcoded

## Testing

- [ ] Add or adjust tests for every behavior change
- [ ] Golden rule test added if change affects detection logic or scoring
- [ ] Edge cases covered — not just the happy path

## Documentation

- [ ] replit.md updated if architecture or features changed
- [ ] DOCS.md updated if user-facing behavior changed
- [ ] No proprietary intelligence exposed in public-facing docs
- [ ] Observation-based language used (never definitive claims)

## Mobile UI Verification — MANDATORY for CSS/Template Changes

Any change to CSS or HTML templates MUST be verified at narrow viewport (375px, iPhone SE). Mobile regressions are recurring and expensive.

- [ ] Action bars and button rows: labels don't wrap or overlap at 375px width
- [ ] All buttons have `white-space: nowrap` — text never breaks inside a button
- [ ] Flex rows with 3+ items use `flex-wrap: wrap` so items flow to next row instead of squishing
- [ ] No `flex: 1` + `min-width: 0` on buttons without `white-space: nowrap`
- [ ] No `pointer-events: none` on `body` or `html` (kills Chrome scroll — use targeted selectors)
- [ ] No global `overflow: hidden` on `body` or `html` for vertical axis (blocks scroll)
- [ ] Headings, badges, and metadata don't overflow or get clipped on narrow screens
- [ ] Touch targets meet 44px minimum (Apple HIG / WCAG 2.5.5)

**Known failure patterns** (all have caused real production bugs):
1. `flex: 1` + `min-width: 0` squishes button labels into multi-line wrapping
2. `pointer-events: none` on body blocks wheel/trackpad scroll in Chrome
3. Desktop-only tested CSS that collapses action bars on mobile
4. `btn-sm` with tight padding + long labels without `nowrap`

## Build and Deploy

- [ ] CSS minified if changed (`npx csso`)
- [ ] JS minified if changed (`npx terser`)
- [ ] Version bumped if static assets changed (`AppVersion` in config.go)
- [ ] Go binary rebuilt and tested
- [ ] Workflow restarted and running without errors

## Quality Gates — Lighthouse, Observatory & SonarCloud (MANDATORY)

Every change must maintain or improve these scores. **Never ship a regression.**

| Tool | Category | Target | Acceptable |
|------|----------|--------|------------|
| Lighthouse | Performance | 100 | 100 (all categories) |
| Lighthouse | Best Practices | 100 | 100 (errors = broken UX) |
| Lighthouse | Accessibility | 100 | 100 (no excuses) |
| Lighthouse | SEO | 100 | 100 (no excuses) |
| Mozilla Observatory | Security | 145 | 145 (never go backwards) |
| SonarCloud | Reliability | A | A (zero new bugs) |
| SonarCloud | Security | A | A (zero new vulnerabilities) |
| SonarCloud | Maintainability | A | A (zero new code smells) |

- [ ] Lighthouse Performance = 100 (all categories)
- [ ] Lighthouse Best Practices = 100
- [ ] Lighthouse Accessibility = 100
- [ ] Lighthouse SEO = 100
- [ ] Mozilla Observatory ≥ 145
- [ ] SonarCloud Quality Gate passes (Reliability A, Security A, Maintainability A)
- [ ] No new bugs, vulnerabilities, or code smells introduced
- [ ] Security hotspots reviewed (not left unreviewed)

**Rules:**
1. Best Practices < 100 means a real error exists that affects user experience — fix it.
2. Accessibility < 100 means broken markup — missing labels, contrast, ARIA — fix it.
3. SEO < 100 means missing metadata, structural issues — fix it.
4. Performance 98–100 is acceptable due to network variance; consistent 100 is the goal.
5. Observatory score must never decrease. Security posture only moves forward.
6. SonarCloud A-rating is non-negotiable. Code quality is foundational, not retroactive.
7. **Test URL**: `https://pagespeed.web.dev/` against `https://dnstool.it-help.tech`
8. **Observatory URL**: `https://observatory.mozilla.org/` against `dnstool.it-help.tech`
9. **SonarCloud**: Enforced via CI on GitHub (`sonarcloud.yml`). Quality Gate must pass before merge.

## Development Process — Research First, Build Correctly

The anti-pattern is: build fast, get an idea working, then clean up. The correct process is:

- [ ] **Research before coding** — find the best-practices path, cite RFCs or authority sources
- [ ] **Design before implementing** — identify boundaries, error paths, data flows
- [ ] **Let tests guide** — write or update tests first, then implement to pass them
- [ ] **Quality gates are guardrails, not afterthoughts** — check them during development, not after
- [ ] **Smallest correct change** — not the fastest change, not the most impressive change

**The tests, quality gates, and documentation exist to prevent rework. Use them.**

## Standards (see AUTHORITIES.md)

- [ ] Every conclusion is RFC-cited or authority-backed (verify in AUTHORITIES.md)
- [ ] Drafts labeled as drafts — never use IETF status terms for non-IETF documents
- [ ] Every detection is independently verifiable with standard commands
- [ ] No clever tricks — boring, explicit, testable code
- [ ] No new dependencies without justification
- [ ] If something is an assumption, it is labeled as such

### DTIC / MIL-STD Citations — Covert Mode Scotopic Lighting

The Covert Recon Mode UI references three authoritative military/defense sources for its scotopic (red-spectrum) lighting discipline. All three are cited in the covert mode disclosure banner (`go-server/templates/results_covert.html`).

| Identifier | Title | URL | Our Use |
|------------|-------|-----|---------|
| AD0639176 | Scotopic Adaptation Research (DTIC Technical Report) | https://apps.dtic.mil/sti/citations/tr/AD0639176 | Authoritative citation for red-spectrum preservation of dark-adapted (scotopic) vision |
| ADA148883 | MIL-STD-3009 — Lighting, Aircraft, Night Vision Imaging System Compatible | https://apps.dtic.mil/sti/tr/pdf/ADA148883.pdf | Military standard for NVG-compatible tactical lighting; Class B minimum luminance reference for submarine environment preset |
| MIL-STD-1472G | Human Engineering (Dept. of Defense Design Criteria Standard) | https://cvgstrategy.com/wp-content/uploads/2023/04/MIL-STD-1472G.pdf | DoD human factors standard governing display lighting, color usage, and operator interface design for tactical environments |

## Public Repo Safety

- [ ] No analyzer logic details in public docs
- [ ] No provider database contents exposed
- [ ] No scoring algorithms or remediation text revealed
- [ ] No schema keys or internal data structures listed
- [ ] Legacy source code not present in tracked files
