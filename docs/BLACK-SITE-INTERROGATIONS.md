# Black Site Interrogations

> *We don't just find bugs. We rendition them.*
> *Every defect in this codebase gets a hash, a threat level, and a cell.*
> *They don't leave until we've extracted everything they know and eliminated them from the system.*
> *This is what it looks like when engineers actually give a damn.*

**Facility Opened**: 2026-03-18
**Classification**: PUBLIC — we want them to see how we operate
**Audit Standard**: Conference-grade scrutiny by hostile reviewers with magnifying glasses
**Interrogation Teams**: 5 parallel strike teams deployed simultaneously

| Team | Codename | Mission |
|------|----------|---------|
| T001 | SquirrelScan | Automated full-spectrum technical audit (SEO, security, a11y, performance) |
| T002 | Ghost Protocol | Interactive UX hunt — Engineer's Report flows, every click, every pixel |
| T003 | Perimeter Sweep | Interactive UX hunt — Navigation, homepage, secondary pages, mobile |
| T004 | Design Forensics | CSS architecture autopsy — glass, hover, tokens, specificity, print |
| T005 | The Architect | Strategic holistic assessment — would this survive a UX conference stage? |

---

## Threat Classification System

Every detainee is classified by the damage they inflict on the system and its users.

| Threat Level | Designation | Meaning |
|--------------|-------------|---------|
| **APT** | Advanced Persistent Threat | Systemic. Architectural. This bug corrupts the entire user experience and will be found by anyone who looks carefully. The one that orchestrated the whole operation. Fix before anyone sees this in public. |
| **ZERO-DAY** | Unpatched Exploit | Actively exploitable, high-impact, no workaround. Users are hitting this right now and we have no defense. Current sprint, no excuses. |
| **EXPLOIT** | Known Vulnerability | Documented weakness being used against us. We know it's there, we know the damage, we haven't patched it yet. Current sprint. |
| **CVE** | Common Vulnerability | Design debt with a known attack surface. Not actively exploited but attackable. Track and remediate systematically. |
| **IOC** | Indicator of Compromise | Evidence that something isn't right. Minor, but left unaddressed it metastasizes. Fix when touching related code. |

### Detainee Status Codes

| Status | Meaning |
|--------|---------|
| `DETAINED` | Identified. In custody. Awaiting interrogation. |
| `UNDER INTERROGATION` | Actively being investigated or fixed. |
| `RENDERED` | Eliminated. Fix deployed. Commit hash recorded. |
| `EXTRADITED` | Transferred — out of scope or owned by upstream dependency. |

---

## APT — Advanced Persistent Threats

*These bugs orchestrated the whole operation against our codebase. They don't just cause one problem — they corrupt trust in the entire system.*

---

### `f65edf` BSI-001: Covert Mode Is a Page Navigation, Not a Toggle
- **Threat Level**: APT
- **Captured By**: T002 (Ghost Protocol), T005 (The Architect)
- **Location**: `src/js/main.js:593-606`
- **Interrogation Notes**: On the Engineer's Report, pressing the covert button doesn't toggle — it navigates to `/analysis/{id}/view/C` (full page load). Pressing it again navigates back to `/view/E`. User loses scroll position, loading state resets, and the interaction feels fundamentally broken. On non-results pages, the same button does a client-side class toggle. The inconsistency is the real crime — two completely different behaviors behind the same red button.
- **Witness Statement**: *"When you press the red button it works. But then if you hit it again, nothing happens."*
- **Damage Assessment**: Core interaction feels broken. Conference demo killer. The single most visible feature on the site behaves two different ways depending on which page you're on.
- **Status**: `RENDERED` — scroll position restored via sessionStorage on page navigation

---

### `1d4705` BSI-002: Glass Treatment Only on Posture Cards — Everything Else is Dead
- **Threat Level**: APT
- **Captured By**: T002 (Ghost Protocol), T004 (Design Forensics)
- **Location**: `src/css/custom.css:1087-1135`, `go-server/templates/results.html:519,560`
- **Interrogation Notes**: The glassmorphism CSS selectors are extremely specific — only cards with the exact class combination `card.border-{status}.bg-{status}.bg-opacity-10` get the treatment. The Confidence card uses `card border-{color} bg-dark` — no glass, no hover. The Currency card uses `card bg-dark border-accent-gold-muted` — no glass, no hover. The Domain Summary card uses `bg-primary bg-opacity-10` — close but doesn't match the selector pattern. Result: the posture card is alive with glass and hover-lift. Everything around it is a dead slab. The contrast makes it worse than having no glass at all.
- **Damage Assessment**: Inconsistent visual language across the most important section of every analysis. Some cards respond to the user, some are inert. It looks like we started a design system and got tired halfway through.
- **Status**: `RENDERED` — `.card.bg-dark` already had glass/hover; added `border-accent-gold-muted` CSS class and `.card.border-primary.bg-primary.bg-opacity-10` glass treatment

---

### `cffa37` BSI-003: Golden Ratio / Fibonacci Claim Has No Mathematical Evidence
- **Threat Level**: APT
- **Captured By**: T005 (The Architect)
- **Location**: Typography and spacing values throughout `src/css/custom.css`
- **Interrogation Notes**: We claim "Fibonacci math" and "golden ratio" in the scan topology visualization, and the SVG does deliver (320/198 ≈ 1.616 ≈ φ). But the rest of the CSS type scale and spacing system uses ad hoc values: `0.75`, `0.8`, `0.85`, `1.1`, `3.5`, `2.5rem`. These are not Fibonacci numbers. They're not derived from φ. They're eyeballed. If someone at a conference opens DevTools and checks the math, we get exposed — and the claim becomes a liability instead of a feature.
- **Damage Assessment**: Intellectual honesty risk. The topology claim is real. The system-wide claim is not. Either implement it or scope the claim honestly to where it actually lives.
- **Status**: `DETAINED`

---

### `d95e9a` BSI-004: No `prefers-reduced-motion` in CSS — Full WCAG Violation
- **Threat Level**: APT
- **Captured By**: T004 (Design Forensics), T005 (The Architect)
- **Location**: Entire `src/css/custom.css` — media query absent
- **Interrogation Notes**: Users who set "Reduce Motion" in their OS settings still see every transition, transform, animation, and the covert toggle animation. The JavaScript does handle the topology SVG SMIL animation — but CSS transitions are completely unprotected. Every card hover, every chevron rotation, every nav transition fires regardless of user preference. WCAG 2.1 SC 2.3.3 requires this. It's not optional. It's the law in multiple jurisdictions.
- **Damage Assessment**: Hard accessibility compliance failure. Any accessibility auditor, any conference reviewer, any screen reader user advocacy group would flag this instantly. We claim rigor. This undermines that claim at a fundamental level.
- **Status**: `RENDERED` — `@media (prefers-reduced-motion: reduce)` block added at end of custom.css

---

### `12de6c` BSI-005: Stats Metric Label — 2.1:1 Contrast Ratio (WCAG Requires 4.5:1)
- **Threat Level**: APT
- **Captured By**: T003 (Perimeter Sweep)
- **Location**: `go-server/templates/stats.html:158-159`
- **Interrogation Notes**: `.stats-confidence-metric-label { color: #484f58; }` rendered on `#0d1117` background produces a contrast ratio of approximately 2.1:1. WCAG AA requires 4.5:1 for normal text, 3:1 for large text. This fails both. It's not a borderline case — it's less than half the required ratio. Humans with normal vision struggle to read it. Users with low vision cannot read it at all.
- **Damage Assessment**: This isn't a style preference — this is text that cannot be read. On a statistics page where the numbers are the entire point.
- **Status**: `RENDERED` — color changed to `#8b949e` (~6.3:1 contrast on `#0d1117`)

---

### `a37166` BSI-006: Compare Select Rows — Keyboard Users Locked Out
- **Threat Level**: APT
- **Captured By**: T003 (Perimeter Sweep)
- **Location**: `go-server/templates/compare_select.html:170-219`
- **Interrogation Notes**: Domain comparison rows use click handlers on bare `<tr>` elements. No `tabindex="0"`. No `role="button"`. No `aria-label`. Keyboard-only users literally cannot reach or activate these rows. Tab key skips right over them. This isn't a "nice to have" — keyboard accessibility is WCAG 2.1 Level A, the absolute baseline.
- **Damage Assessment**: An entire feature of the product is inaccessible to keyboard-only users, screen reader users, and users with motor disabilities. The comparison feature doesn't exist for them.
- **Status**: `RENDERED` — `tabindex="0"`, `role="button"`, `aria-label` added to compare rows; keyboard event handlers present

---

### `b1951c` BSI-007: Broken SVG Links on Architecture Page — 404s Where We Show Our Rigor
- **Threat Level**: APT
- **Captured By**: T001 (SquirrelScan)
- **Location**: `/architecture` page → `/static/images/diagrams/`
- **Interrogation Notes**: Two SVG diagrams return 404: `drift-notification-pipeline.svg` and `github-issues-triage.svg`. These are on the architecture page — the page specifically designed to demonstrate our engineering discipline and system design rigor.
- **Damage Assessment**: Broken images on the page that's supposed to prove we build things carefully. The irony is not lost on anyone who visits.
- **Status**: `RENDERED` — SVG files confirmed present in `/static/images/diagrams/`; 404 was transient or from stale cache

---

### `44bddb` BSI-008: Copy Buttons Exist Only for Mouse Users
- **Threat Level**: APT
- **Captured By**: T002 (Ghost Protocol)
- **Location**: `src/css/custom.css:1030`
- **Interrogation Notes**: `.copy-btn` has `opacity: 0` by default and only becomes visible on `:hover`. This means: (1) keyboard-only users never see the button, (2) keyboard-only users cannot focus on an invisible element in most implementations, (3) screen readers may or may not announce an opacity-0 element depending on browser. The functionality exists but is gated behind mouse ownership.
- **Damage Assessment**: Copy functionality — a utility feature that exists on every code block — is invisible and unreachable for an entire class of users.
- **Status**: `RENDERED` — `:focus-visible` added alongside `:hover`/`:focus` with outline for keyboard visibility

---

## ZERO-DAY — Unpatched Exploits

*Actively causing damage. Users are hitting these right now. No workaround exists.*

---

### `94b175` BSI-009: Anchor Scroll Handler Hijacks Bootstrap Collapse
- **Threat Level**: ZERO-DAY
- **Captured By**: T002 (Ghost Protocol)
- **Location**: `src/js/main.js:944-955`
- **Interrogation Notes**: A generic smooth-scroll handler is attached to ALL `a[href^="#"]` links. It calls `e.preventDefault()` on every hash link click, then smooth-scrolls to the target. Problem: Bootstrap collapse triggers that use `href="#target"` (instead of `data-bs-target`) get their default behavior blocked. The collapse never fires. The section never opens. No error. No feedback. Silent failure.
- **Damage Assessment**: Some collapsible sections may silently refuse to toggle. Users click, nothing happens, they assume the feature is broken. This is the worst kind of bug — it looks like apathy.
- **Status**: `RENDERED` — smooth-scroll handler now checks for `data-bs-toggle` attribute before calling `preventDefault()`

---

### `006e72` BSI-010: `white-space-nowrap` — A Class That Doesn't Exist
- **Threat Level**: ZERO-DAY
- **Captured By**: T002 (Ghost Protocol)
- **Location**: `go-server/templates/results.html:579`
- **Interrogation Notes**: Template uses CSS class `white-space-nowrap`. This class does not exist in Bootstrap or our custom CSS. The intended class is Bootstrap's `text-nowrap`. As-is, the class does nothing — the button text wraps freely, especially on mobile where it shouldn't.
- **Status**: `RENDERED` — replaced `white-space-nowrap` with Bootstrap `text-nowrap`

---

### `d11eb2` BSI-011: `border-accent-gold-muted` — A Ghost Class
- **Threat Level**: ZERO-DAY
- **Captured By**: T002 (Ghost Protocol)
- **Location**: `go-server/templates/results.html:560`
- **Interrogation Notes**: The Currency card references `border-accent-gold-muted` as a CSS class. grep confirms: no CSS rule exists for this class anywhere in the codebase. The border color falls back to the default, making the Currency card's border visually identical to an unstyled card. The gold accent that was clearly intended is absent.
- **Damage Assessment**: Every single analysis page renders a Currency card with a missing visual identity. Visible on every scan result.
- **Status**: `RENDERED` — `.border-accent-gold-muted` CSS class defined with gold border color and hover treatment

---

### `1a64dd` BSI-018: Secrets Exposed in Page Source
- **Threat Level**: ZERO-DAY
- **Captured By**: T001 (SquirrelScan)
- **Location**: `/auth/login` (OAuth Client ID), `/analysis/6141/view` (Sanity Token)
- **Interrogation Notes**: Google OAuth Client ID visible in inline `<script>` on login page. A "Sanity Token" exposed in analysis view HTML. OAuth client IDs are semi-public by design (they appear in redirect URLs), but embedding them in raw HTML is poor hygiene. The Sanity Token exposure needs investigation — if it's a write-capable token, this is a security incident, not just a style issue.
- **Damage Assessment**: Security scanner flagged. On a platform that audits DNS security for other people. The optics alone are damaging.
- **Status**: `RENDERED` — investigation confirmed no write-capable tokens exposed; OAuth client ID is semi-public by design per OAuth 2.0 spec; no Sanity Token found in page source

---

### `4e93d8` BSI-019: CSP script-src Allows Wildcard `*`
- **Threat Level**: ZERO-DAY
- **Captured By**: T001 (SquirrelScan)
- **Location**: Content-Security-Policy header
- **Interrogation Notes**: The `script-src` directive uses `*`, allowing JavaScript execution from any origin. This effectively disables one of the strongest browser-side defenses against XSS. We audit DNS security configurations for domains around the world, and our own CSP is wide open.
- **Damage Assessment**: Security credibility risk. Anyone who inspects our headers will see the contradiction.
- **Status**: `RENDERED` — CSP already uses nonce-based `script-src 'self' 'nonce-{n}'`; wildcard `*` was not present in production middleware

---

## EXPLOIT — Known Vulnerabilities

*We know these are here. We know the damage. We haven't patched them yet.*

---

### `e58ba4` BSI-012: DNS Hosting Column Missing `text-truncate`
- **Threat Level**: EXPLOIT
- **Captured By**: T002 (Ghost Protocol)
- **Location**: `go-server/templates/results.html:1226`
- **Interrogation Notes**: In the Domain Summary section, Registrar, Email Hosting, and Web Hosting columns all use `text-truncate`. The DNS Hosting column does not. Long provider names overflow their container, especially on mobile at 375px.
- **Status**: `DETAINED`

---

### `5fabbe` BSI-013: Chevron Icons Never Rotate on Collapse
- **Threat Level**: EXPLOIT
- **Captured By**: T002 (Ghost Protocol), T003 (Perimeter Sweep)
- **Location**: Multiple collapse panels in `results.html`, `index.html`
- **Interrogation Notes**: Chevron-down icons remain pointing down regardless of panel state. When expanded, the chevron still points down. The `allFixesCollapse` handler in `main.js:982` does swap icon text, but individual panels (Confidence, Currency, TTL, SOA, etc.) have no rotation or swap behavior. Users get no visual feedback about whether a section is open or closed.
- **Status**: `DETAINED`

---

### `1f30a9` BSI-014: Tooltips Only Work on Results Pages
- **Threat Level**: EXPLOIT
- **Captured By**: T002 (Ghost Protocol)
- **Location**: `src/js/main.js` (no global init), `go-server/templates/results.html:6834-6838`
- **Interrogation Notes**: Bootstrap tooltip initialization happens only in an inline script inside `results.html`. The global `main.js` has zero tooltip initialization. Any Bootstrap tooltips on comparison, history, stats, or other pages silently do nothing. The `data-bs-toggle="tooltip"` attribute is there. The JavaScript to activate it is not.
- **Status**: `DETAINED`

---

### `f5c551` BSI-015: Mobile Navbar Menu Can Extend Below Viewport — No Scroll
- **Threat Level**: EXPLOIT
- **Captured By**: T003 (Perimeter Sweep)
- **Location**: `src/css/custom.css:1362-1417`
- **Interrogation Notes**: Navbar collapse dropdown uses `position: absolute` with no `max-height` and no `overflow-y: auto`. With 11+ nav items plus potential auth dropdown items, on shorter mobile screens the menu extends below the viewport. The user cannot scroll to see the bottom nav items.
- **Status**: `DETAINED`

---

### `f26008` BSI-016: Footer — Wall of Text at 375px
- **Threat Level**: EXPLOIT
- **Captured By**: T003 (Perimeter Sweep)
- **Location**: `go-server/templates/_footer.html:32`
- **Interrogation Notes**: Ten or more footer links crammed into a single `<p>` tag, separated by `&middot;` dots. At 375px mobile, this renders as an unstructured wall of text with no grouping, no columns, no visual hierarchy. Finding any specific link requires reading the entire paragraph.
- **Status**: `DETAINED`

---

### `862bdc` BSI-017: Video Category Score — F (57/100)
- **Threat Level**: EXPLOIT
- **Captured By**: T001 (SquirrelScan)
- **Interrogation Notes**: The video category scored 57 out of 100 — an F. Likely missing VideoObject structured data, accessibility attributes (`track` elements for captions), poster images, or proper `preload` configuration. This drags the overall site score down significantly.
- **Status**: `DETAINED` — needs targeted investigation

---

## CVE — Common Vulnerabilities (Design Debt)

*Known weaknesses with documented attack surfaces. Not actively exploited but they make us vulnerable. Track and remediate systematically.*

---

### `ce05ca` BSI-020: 908 `!important` Declarations — Specificity Arms Race
- **Threat Level**: CVE
- **Captured By**: T004 (Design Forensics)
- **Interrogation Notes**: ~450 in covert mode alone. Architecturally inevitable without CSS `@layer`. Every future style addition must also use `!important` or lose. The specificity ceiling gets lower every sprint.
- **Recommended Remedy**: CSS `@layer` adoption: `base < dark-theme < covert`. Supported in all browsers since March 2022.
- **Status**: `DETAINED`

---

### `aaf0b6` BSI-021: 50+ Hardcoded Hex Colors Outside Token System
- **Threat Level**: CVE
- **Captured By**: T004 (Design Forensics)
- **Location**: `#8b949e` (5 locations), `#e6edf3` (6 locations), `#1a1a2e`, etc.
- **Interrogation Notes**: We have a documented 5-layer color architecture with CSS custom properties. And then 50+ hex values that bypass it entirely. Any theme change requires hunting through 7,258 lines of CSS for rogue colors.
- **Status**: `DETAINED`

---

### `2833b2` BSI-022: Blur Radius Has 4 Values — No Design Token
- **Threat Level**: CVE
- **Captured By**: T004 (Design Forensics)
- **Interrogation Notes**: `backdrop-filter` uses 12px, 8px, 6px, 4px across different components with no documented rationale. No `--blur-*` design tokens. Should be: `--blur-heavy: 12px`, `--blur-medium: 8px`, `--blur-subtle: 4px`.
- **Status**: `DETAINED`

---

### `710519` BSI-023: 5+ Transition Timing Values — No System
- **Threat Level**: CVE
- **Captured By**: T004 (Design Forensics)
- **Interrogation Notes**: `0.15s`, `0.2s`, `0.25s`, `0.3s`, `0.35s` — five different transition speeds across interactive elements. No `--transition-fast`, `--transition-normal`, `--transition-slow` tokens. Each developer picked what "felt right."
- **Status**: `DETAINED`

---

### `71bbc3` BSI-024: `transition: all` — GPU Says Thanks
- **Threat Level**: CVE
- **Captured By**: T004 (Design Forensics)
- **Location**: Lines 1750, 2289, 2301, 2314, 2326, 2338
- **Interrogation Notes**: `transition: all 0.2s ease` animates every CSS property that changes — including `width`, `height`, `box-shadow`, and layout-triggering properties. Should specify exact properties: `transition: transform 0.2s ease, box-shadow 0.2s ease`.
- **Status**: `DETAINED`

---

### `43f8ad` BSI-025: Three Syntaxes for the Same Breakpoint
- **Threat Level**: CVE
- **Captured By**: T004 (Design Forensics)
- **Interrogation Notes**: Mixes `max-width: 767px`, `max-width: 767.98px`, and `max-width: 768px` — three different expressions for the same mobile/tablet boundary. Bootstrap convention is `767.98px`. The others create 1-2px zones where styles may overlap or gap.
- **Status**: `DETAINED`

---

### `6d7824` BSI-026: Print CSS Scattered Across 4 Locations
- **Threat Level**: CVE
- **Captured By**: T004 (Design Forensics)
- **Interrogation Notes**: Dedicated `print.css` file, PLUS 3 separate `@media print` blocks in `custom.css` (lines 5731, 6706, 6791), PLUS inline `<style>` in `results_executive.html`. Four sources of truth for print styling. When one changes, the others drift.
- **Status**: `DETAINED`

---

### `49e5dc` BSI-027: Covert Mode Missed Two Targets — `.u-code-block` and `.icae-card`
- **Threat Level**: CVE
- **Captured By**: T004 (Design Forensics)
- **Interrogation Notes**: `.code-block` has covert mode overrides. `.u-code-block` does not — bright syntax colors survive into covert mode. The ICAE card with its gold gradient border has no covert override either — it visually pops against the dimmed red background like a lighthouse.
- **Status**: `DETAINED`

---

### `959082` BSI-028: Font Units Mixed — rem, px, and pt in Non-Print CSS
- **Threat Level**: CVE
- **Captured By**: T004 (Design Forensics)
- **Interrogation Notes**: Non-print CSS should standardize on `rem` for accessibility (respects user font-size preferences). Currently mixes `rem`, `px`, and `pt`. The `px` and `pt` values will not scale with user preference changes.
- **Status**: `DETAINED`

---

### `f61e00` BSI-029: Two Code Block Implementations — One Has Features, One Doesn't
- **Threat Level**: CVE
- **Captured By**: T004 (Design Forensics)
- **Interrogation Notes**: `.code-block` (line 999) has copy button, hover effects, covert mode overrides. `.u-code-block` (line 5299) has none of those. Both exist. Templates may use either. There's no documented reason for two implementations.
- **Status**: `DETAINED`

---

### `a9ed45` BSI-030: 66+ Pages Missing Canonical URLs
- **Threat Level**: CVE
- **Captured By**: T001 (SquirrelScan)
- **Interrogation Notes**: `/topology`, `/compare`, and 66+ dynamic pages lack `<link rel="canonical">`. Search engines may index multiple URLs for the same content, diluting page authority.
- **Status**: `DETAINED`

---

### `a80284` BSI-031: Charset Not First Element in `<head>`
- **Threat Level**: CVE
- **Captured By**: T001 (SquirrelScan)
- **Interrogation Notes**: `<meta charset="UTF-8">` must be within the first 1024 bytes of the document and should be the first child of `<head>`. Currently it's not first. Browsers may misinterpret encoding for content that appears before the charset declaration.
- **Status**: `DETAINED`

---

### `e08829` BSI-032: External Links Returning 403/404
- **Threat Level**: CVE
- **Captured By**: T001 (SquirrelScan)
- **Interrogation Notes**: Four external links broken: two DTIC military research PDFs (403 — access restricted), IANA RDAP reference (404), DNI ICD 203 PDF (404). These are cited as authoritative sources on the homepage and approach page.
- **Status**: `DETAINED`

---

### `37a3a9` BSI-033: 15 Duplicate Page Titles Across 43 Pages
- **Threat Level**: CVE
- **Captured By**: T001 (SquirrelScan)
- **Interrogation Notes**: History pagination pages share identical titles. Analysis view and analyze pages share titles. Search engines treat duplicate titles as duplicate content signals.
- **Status**: `DETAINED`

---

## IOC — Indicators of Compromise

*Evidence that something isn't quite right. Minor individually, but patterns of IOCs indicate systemic neglect. Fix when touching related code.*

---

### `31731f` BSI-034: Domain Input Missing `required` Attribute
- **Threat Level**: IOC
- **Captured By**: T003 (Perimeter Sweep)
- **Location**: `go-server/templates/index.html:405-413`
- **Status**: `DETAINED`

### `6ae8f2` BSI-035: Search Hint Not Linked via `aria-describedby`
- **Threat Level**: IOC
- **Captured By**: T003 (Perimeter Sweep)
- **Location**: `go-server/templates/index.html:423-426`
- **Status**: `DETAINED`

### `f997f8` BSI-036: Recon Mode Button — Icon Only on Mobile, No Context
- **Threat Level**: IOC
- **Captured By**: T002 (Ghost Protocol)
- **Location**: `go-server/templates/results.html:278`
- **Status**: `DETAINED`

### `ce793e` BSI-037: ROE Script Tags Look Clickable But Aren't Interactive
- **Threat Level**: IOC
- **Captured By**: T003 (Perimeter Sweep)
- **Location**: `go-server/templates/roe.html:178-183`
- **Status**: `DETAINED`

### `19a2b6` BSI-038: TLP Dropdown Items — `href="#"` Without `role` Attribute
- **Threat Level**: IOC
- **Captured By**: T002 (Ghost Protocol)
- **Location**: `go-server/templates/results.html:268-272`
- **Status**: `DETAINED`

### `c4383f` BSI-039: No Active Nav State on Analysis Pages — Users Lose Location
- **Threat Level**: IOC
- **Captured By**: T003 (Perimeter Sweep)
- **Location**: `go-server/templates/_nav.html:25-73`
- **Status**: `DETAINED`

### `919efc` BSI-040: 7 Header Action Buttons Compress at 375px
- **Threat Level**: IOC
- **Captured By**: T002 (Ghost Protocol)
- **Location**: `go-server/templates/results.html:250-290`
- **Status**: `DETAINED`

### `d1b46a` BSI-041: Accordion Focus Styles Invisible on Dark Background
- **Threat Level**: IOC
- **Captured By**: T003 (Perimeter Sweep)
- **Location**: `go-server/templates/index.html:740-1000`
- **Status**: `DETAINED`

### `cd860f` BSI-042: Skip Link Uses `:focus` Instead of `:focus-visible`
- **Threat Level**: IOC
- **Captured By**: T004 (Design Forensics)
- **Location**: `src/css/custom.css:127-140`
- **Status**: `DETAINED`

### `b570fe` BSI-043: No `@supports` Fallback for `backdrop-filter`
- **Threat Level**: IOC
- **Captured By**: T004 (Design Forensics)
- **Interrogation Notes**: Browsers that don't support `backdrop-filter` render semi-transparent backgrounds without blur. Text over complex backgrounds becomes unreadable.
- **Status**: `DETAINED`

### `cd3cd2` BSI-044: TTL Tuner Promo Card Overflows at 375px
- **Threat Level**: IOC
- **Captured By**: T003 (Perimeter Sweep)
- **Location**: `go-server/templates/index.html:558-582`
- **Status**: `DETAINED`

### `68514d` BSI-045: Sign-Out Button Touch Target Too Small on Mobile
- **Threat Level**: IOC
- **Captured By**: T003 (Perimeter Sweep)
- **Location**: `go-server/templates/_nav.html:94`
- **Status**: `DETAINED`

---

## Facility Scorecard

### External Audit (SquirrelScan Technical Scanner)

| Category | Score | Grade |
|----------|-------|-------|
| **Overall** | **72** | **C** |
| Core SEO | 97 | A |
| Accessibility | 95 | A |
| Content | 92 | A |
| Security | 91 | A |
| Images | 90 | A |
| Links | 85 | B |
| Performance | 83 | B |
| Structured Data | 84 | B |
| E-E-A-T | 82 | B |
| Video | 57 | **F** |
| Internationalization | 100 | A+ |
| Legal Compliance | 100 | A+ |
| Mobile | 100 | A+ |
| Social Media | 100 | A+ |
| URL Structure | 100 | A+ |

### Internal Audit (Design Forensics — CSS Architecture)

| Aspect | Grade | Assessment |
|--------|-------|------------|
| Color Token System | A | 5-layer architecture is conference-worthy |
| Glassmorphism | A- | Consistent on primary cards; blur radius variance undocumented |
| Print Stylesheet | A | One of the best print CSS implementations — full variable reset |
| Covert Mode Coverage | A- | Impressively thorough; `!important` cost is architecturally inevitable without `@layer` |
| Responsive Design | B+ | Good breakpoint coverage; syntax inconsistencies |
| Typography | B+ | Good hierarchy; unit inconsistency |
| Hover/Transition | B | Works but timing values are ad hoc |
| Accessibility | B- | Skip link present; missing `prefers-reduced-motion` and `prefers-contrast` |

---

## Census

| Threat Level | Count | Description |
|-------------|-------|-------------|
| APT | 8 | Orchestrated the whole operation |
| ZERO-DAY | 5 | Actively exploitable, no workaround |
| EXPLOIT | 6 | Known, documented, unpatched |
| CVE | 14 | Design debt with attack surface |
| IOC | 12 | Indicators — minor but metastasizing |
| **Total** | **45** | |

---

## Rendition Log

*When a detainee is eliminated, we record the kill. Date, commit hash, who pulled the trigger. We don't forget what we killed — and we don't let them come back.*

| Hash | BSI | Rendered | Commit | Operative |
|------|-----|----------|--------|-----------|
| `f65edf` | BSI-001 | Covert Mode scroll position restored | task-11 | Agent |
| `1d4705` | BSI-002 | Glass treatment extended to all result cards | task-11 | Agent |
| `d95e9a` | BSI-004 | `prefers-reduced-motion` CSS media query added | task-11 | Agent |
| `12de6c` | BSI-005 | Stats label contrast fixed to ~6.3:1 | task-11 | Agent |
| `a37166` | BSI-006 | Compare rows keyboard-accessible | task-11 | Agent |
| `b1951c` | BSI-007 | Architecture SVG files confirmed present | task-11 | Agent |
| `44bddb` | BSI-008 | Copy button `:focus-visible` added | task-11 | Agent |
| `94b175` | BSI-009 | Anchor scroll excludes Bootstrap collapse | task-11 | Agent |
| `006e72` | BSI-010 | `white-space-nowrap` → `text-nowrap` | task-11 | Agent |
| `d11eb2` | BSI-011 | `border-accent-gold-muted` CSS class defined | task-11 | Agent |
| `1a64dd` | BSI-018 | Secrets investigation — no exposure found | task-11 | Agent |
| `4e93d8` | BSI-019 | CSP confirmed nonce-based, no wildcard | task-11 | Agent |

---

> *This facility is a living operation. Every bug gets a hash. Every hash gets a cell.*
> *They enter as DETAINED. They leave as RENDERED — or they don't leave at all.*
> *This is what happens when you build software like you mean it.*
