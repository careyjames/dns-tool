# Communication Standards

**DNS Tool — Clarity and Vision Quality Gate**

Version 26.38.35 · Effective 2026-03-18

*This document defines the measurable standards that all user-facing copy and interface elements must pass before publication. These standards are enforceable: a page that fails any MUST-level requirement is not ready for production.*

---

## 1. Dual-Gate Requirement

Every piece of user-facing text must pass **both** gates simultaneously. Passing one gate but failing the other is a failure.

### Gate 1: Clarity

The words chosen must be clear, communicative, and logical to the reader. Text should educate, not obscure.

| Requirement | Level | Measurement |
|-------------|-------|-------------|
| **Jargon with first use** | MUST | Every acronym (DMARC, DNSSEC, ICAE, EDE) must be expanded on first use per page, or linked to a definition |
| **Active voice** | SHOULD | Prefer "The SPF record authorizes..." over "Authorization is provided by the SPF record..." |
| **Sentence length** | SHOULD | Body copy sentences should not exceed 35 words. Technical explanations may exceed this when precision requires it |
| **One idea per paragraph** | SHOULD | Each paragraph should advance one concept. Dense paragraphs should be split |
| **Action-oriented findings** | MUST | Security findings must state what was observed, why it matters, and what the reader can do about it |
| **RFC citation** | MUST | Any claim about protocol behavior must cite the specific RFC section. A claim without a citation is an opinion |
| **Transformative language** | SHOULD | Prefer language that teaches the reader something they didn't know, rather than restating what they already understand |

### Gate 2: Vision

The visual presentation must not cause strain or impede comprehension. The reader's eyes matter.

| Requirement | Level | Measurement |
|-------------|-------|-------------|
| **Minimum font size** | MUST | No rendered text below 0.75rem (12px) in standard mode. Print mode may use pt-based sizes for density |
| **Body text minimum** | SHOULD | Primary reading text should be at least 0.875rem (14px) |
| **Contrast ratio (normal text)** | MUST | WCAG 2.1 AA: minimum 4.5:1 contrast ratio against background |
| **Contrast ratio (large text)** | MUST | WCAG 2.1 AA: minimum 3:1 for text 18px+ or 14px+ bold |
| **Text overflow** | MUST | No text may extend beyond its container boundary. All containers must handle long content (domain names, hash values) with `overflow-wrap`, `text-overflow`, or responsive layout |
| **Line length** | SHOULD | Body text should not exceed 80 characters per line (approximately 640px at 1rem). Use `max-width` constraints |
| **Line height** | SHOULD | Body text should use at least 1.5 line-height for readability |
| **Scotopic mode** | MUST | All text in covert/scotopic mode must achieve minimum 4.5:1 contrast ratio against the covert background (`#0a0c10`). Test: enable covert mode, run Chrome DevTools accessibility audit, zero contrast failures |
| **Focus indicators** | MUST | All interactive elements must have visible focus indicators for keyboard navigation |

---

## 2. Audience Calibration

DNS Tool serves three primary audiences with different reading contexts:

### The Engineer

- **Context**: Analyzing a domain at a terminal, possibly at 2 AM, possibly under incident pressure
- **Needs**: Precision, RFC references, verification commands, machine-parseable output
- **Vision concern**: Extended reading sessions on dark backgrounds. Font size and contrast directly affect error rate
- **Clarity concern**: Ambiguous language under pressure leads to wrong remediation decisions

### The Executive

- **Context**: Reading a brief before a board meeting or vendor assessment
- **Needs**: Risk posture in business terms, remediation cost/complexity, decision points
- **Vision concern**: May be reading on a phone, tablet, or printed page. Layout must be responsive
- **Clarity concern**: Jargon without context makes the report useless to a non-technical decision-maker

### The Older Professional

- **Context**: 20+ years in infosec, may have age-related vision changes (presbyopia, reduced contrast sensitivity)
- **Needs**: Everything both audiences need, plus accommodation for reduced visual acuity
- **Vision concern**: This is the primary reason the font-size floor exists. 10px text that "looks fine" to a 25-year-old developer may be unreadable to the 55-year-old CISO who most needs the information
- **Clarity concern**: Experienced professionals detect vague or hedging language immediately. Be precise or be dismissed

---

## 3. Enforcement

### Automated Checks

| Check | Tool | Threshold |
|-------|------|-----------|
| Font size floor | CSS audit (`grep` for sub-0.75rem values in `src/css/custom.css`) | Zero violations |
| Contrast ratio | squirrelscan `a11y/color-contrast` rule | Zero errors, warnings reviewed |
| Text overflow | squirrelscan + manual viewport testing at 375px, 768px, 1024px, 1440px | No horizontal scrollbar on body content |
| Heading hierarchy | squirrelscan `content/heading-hierarchy` rule | No skipped levels |
| Lighthouse accessibility | Chrome Lighthouse | Score >= 95 |

### Manual Review Checklist

Before any page is published or significantly modified, review against this checklist:

- [ ] **Clarity Gate**: Can a non-technical executive understand the main finding within 10 seconds of reading?
- [ ] **Clarity Gate**: Does every acronym have a first-use expansion or link?
- [ ] **Clarity Gate**: Does every security finding include a "what to do" action?
- [ ] **Vision Gate**: At standard viewing distance (50cm / 20"), can all text be read on a 13" laptop display at 100% zoom?
- [ ] **Vision Gate**: In scotopic/covert mode, does all text pass WCAG AA contrast (4.5:1) against the covert-mode background color?
- [ ] **Vision Gate**: On a 375px mobile viewport, does all content fit without horizontal scroll?
- [ ] **Vision Gate**: Are interactive elements large enough for touch targets (minimum 44x44px)?
- [ ] **Combined**: Does the page pass both gates simultaneously?

---

## 4. CSS Reference Values

These are the enforced values as of v26.37.35:

| Property | Value | Contrast Ratio | Standard |
|----------|-------|----------------|----------|
| Font size floor | `0.75rem` (12px) | — | All `.u-fs-*` utility classes enforce this minimum |
| `.text-muted` | `#9ca3af` on `#0d1117` | ~7.45:1 | WCAG AA (requires 4.5:1) |
| `.card.bg-dark .text-muted` | `#adb5bd` on `#21262d` | ~8.8:1 | WCAG AA |
| Secondary text minimum | `#8b949e` on `#0d1117` | ~6.15:1 | WCAG AA (replaces prior `#6c757d` at ~4.04:1) |

**Verification command:**
```bash
grep -nE 'font-size:\s*0\.[0-6]\d*(rem|em)' src/css/custom.css | grep -v '@media print'
# Expected output: zero matches (all sub-0.75 values have been raised)
```

---

## 5. Connection to Project Philosophy

These standards are not aesthetic preferences. They are implementations of the project's core principles:

- **Accountability** (`[ACCOUNTABILITY]`): If the text is unreadable, the finding is unaccountable — it exists but cannot be acted upon
- **Zero Waste** (`[ZERO_WASTE]`): Text that cannot be read is wasted — it consumes space without delivering value
- **Verbose Context** (`[VERBOSE+++++]`): Clarity does not mean brevity. It means *every word earns its place* by advancing the reader's understanding
- **Vision as Ethics**: Causing eye strain to a reader who came for security intelligence is a design failure with real consequences. The scotopic mode is the most visible implementation, but the standard-mode contrast and font-size requirements serve the same principle

---

*"A score without a citation is an opinion. A finding without readability is invisible."*

**© 2024–2026 IT Help San Diego Inc. — DNS Security Intelligence**
