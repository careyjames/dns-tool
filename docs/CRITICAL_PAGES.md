# Critical Pages Registry

Per-page issue tracking for DNS Tool. When fixing one page breaks another, this registry surfaces the cross-page dependency so it can be caught before delivery.

## How to Use

1. When a bug is found on a page, add it to the **Known Issues** column with a date.
2. When a fix is deployed, move it to **Resolved** with the version and date.
3. When a fix on one page causes a regression on another, add a **Cross-Page Regression** entry linking the two.
4. Before any CSS, JS, or template change, check the **Sensitive Areas** column for the affected page.

---

## Page Registry

### Homepage (`/`)
| Attribute | Value |
|-----------|-------|
| Template | `index.html` |
| Sensitive Areas | Hero section layout, domain input field (mobile autocapitalize), DKIM selector inputs (mobile autocapitalize), SecurityTrails API key input, scan overlay animation (Safari fetch pattern), privacy banner |
| Known Issues | None |
| Resolved | DKIM selector inputs missing `autocapitalize="none"` and `spellcheck="false"` — fixed v26.36.02 (Mar 2026); SecurityTrails API key input missing `autocapitalize="none"` — fixed v26.36.02 (Mar 2026) |

### Engineer's DNS Intelligence Report (`/analysis/:id/view/E`)
| Attribute | Value |
|-----------|-------|
| Template | `results.html` |
| Sensitive Areas | Recon Mode button (toggles to covert red theme + Morse code beep with audio permissions graceful fallback), Wayback archive badge/card, integrity hash header preview, posture drift alert banner, TLP classification header, copy-to-clipboard buttons, collapsible RFC & Security Context panels, print stylesheet |
| Known Issues | Recon Mode button: toggles red theme and plays Morse code beep but beep stops after ~1 minute (Mar 2026) |
| Resolved | — |

### Executive's DNS Intelligence Brief (`/analysis/:id/view/X`)
| Attribute | Value |
|-----------|-------|
| Template | `results_executive.html` |
| Sensitive Areas | Wayback archive badge/card, security scorecard, risk posture summary, TLP header |
| Known Issues | None |
| Resolved | — |

### Recon Report (Covert Mode) (`/analysis/:id/view/C`)
| Attribute | Value |
|-----------|-------|
| Template | `results_covert.html` |
| Sensitive Areas | Scotopic red-spectrum palette (#cc2020), exit covert mode button, Focus Mode button (Fullscreen API + webkit fallback, inline SVG `expand`/`compress-arrows-alt` icon swap via `window._icons`), dynamic `meta[name="theme-color"]` per covert environment, dark background consistency, all text must pass WCAG contrast against dark bg, no light-theme color leaks, iPhone graceful degradation (Focus button hidden when Fullscreen API unavailable) |
| Known Issues | None |
| Resolved | — |

### Analysis History (`/history`)
| Attribute | Value |
|-----------|-------|
| Template | `history.html` |
| Sensitive Areas | Search/filter, scan overlay (Safari fetch pattern), drift timeline links, pagination |
| Known Issues | None |
| Resolved | — |

### Statistics Dashboard (`/stats`)
| Attribute | Value |
|-----------|-------|
| Template | `stats.html` |
| Sensitive Areas | Chart rendering, temporal trend data, confidence engine preview card, success rate display |
| Known Issues | None |
| Resolved | — |

### Intelligence Topology (`/topology`)
| Attribute | Value |
|-----------|-------|
| Template | `topology.html` |
| Sensitive Areas | Canvas 2D rendering, hybrid solver layout integration, FR fallback path, orthographic globe projection, signal arc convergence, PoP label crowding, legend accuracy |
| Known Issues | Tablet/mobile viewports have residual overlaps (5/4 respectively) due to tight zone bounds — desktop is zero-overlap (Mar 2026) |
| Resolved | Hybrid constrained layered-stress solver replaces FR as primary layout (v26.34.40, Mar 2026); Signal arcs now target HUB live position (v26.34.40, Mar 2026); Internet Archive node added (v26.34.40); PoP labels show city-only with resolver tag on hover (v26.34.40); globe initial rotation shifted to -58° (v26.34.39) |

### Domain Dossier (`/dossier/:domain`)
| Attribute | Value |
|-----------|-------|
| Template | `dossier.html` |
| Sensitive Areas | Drift timeline links, infrastructure summary, scan overlay |
| Known Issues | None |
| Resolved | — |

### Domain Comparison (`/compare`)
| Attribute | Value |
|-----------|-------|
| Template | `compare.html`, `compare_select.html` |
| Sensitive Areas | Side-by-side layout, domain input fields (mobile autocapitalize) |
| Known Issues | None |
| Resolved | — |

### Email Header Analyzer (`/email-header`)
| Attribute | Value |
|-----------|-------|
| Template | `email_header.html` |
| Sensitive Areas | Multi-format upload (paste, .eml, JSON, .mbox, .txt), SPF/DKIM/DMARC verification display, spoofing detection, scam analysis |
| Known Issues | None |
| Resolved | — |

### Approach & Methodology (`/approach`)
| Attribute | Value |
|-----------|-------|
| Template | `approach.html` |
| Sensitive Areas | Embedded video styling, KaTeX math rendering, methodology content, five archetypes section |
| Known Issues | None |
| Resolved | — |

### Architecture (`/architecture`)
| Attribute | Value |
|-----------|-------|
| Template | `architecture.html` |
| Sensitive Areas | Pure HTML/CSS diagrams (no JS), redacted content bars, TLP:GREEN classification |
| Known Issues | None |
| Resolved | — |

### Color Science (`/color-science`)
| Attribute | Value |
|-----------|-------|
| Template | `color_science.html` |
| Sensitive Areas | CIE scotopic/photopic calculations, WCAG contrast display, MIL-STD compliance badges |
| Known Issues | None |
| Resolved | — |

### Changelog (`/changelog`)
| Attribute | Value |
|-----------|-------|
| Template | `changelog.html` |
| Sensitive Areas | Changelog entry rendering, icon display, category badges |
| Known Issues | None |
| Resolved | — |

### TTL Tuner (`/ttl-tuner`)
| Attribute | Value |
|-----------|-------|
| Template | `ttl_tuner.html` |
| Sensitive Areas | Auto-scroll, profile selection, loading state, mobile responsive table, CSRF token |
| Known Issues | None |
| Resolved | — |

### Drift Timeline (`/drift`)
| Attribute | Value |
|-----------|-------|
| Template | `drift.html` |
| Sensitive Areas | Field-level diff display, severity badges, timestamp formatting |
| Known Issues | None |
| Resolved | — |

### Watchlist (`/watchlist`)
| Attribute | Value |
|-----------|-------|
| Template | `watchlist.html` |
| Sensitive Areas | CRUD operations, webhook management, cadence toggle, CSRF tokens |
| Known Issues | None |
| Resolved | — |

### Admin Analytics (`/ops/analytics`)
| Attribute | Value |
|-----------|-------|
| Template | `admin_analytics.html` |
| Sensitive Areas | 30-day trend chart, top pages/referrers, admin-only access |
| Known Issues | None |
| Resolved | — |

### Field Tech Toolkit (`/toolkit`)
| Attribute | Value |
|-----------|-------|
| Template | `toolkit.html` |
| Sensitive Areas | Guided wizard flow, triage matrix, port check, IP detection, command preflight |
| Known Issues | None |
| Resolved | — |

### Zone File Upload (`/zone`)
| Attribute | Value |
|-----------|-------|
| Template | `zone.html` |
| Sensitive Areas | File upload, auth-aware size limits (1MB/2MB), domain input (mobile autocapitalize) |
| Known Issues | None |
| Resolved | — |

---

## Safari / Mobile Compatibility Audit Log

| Date | Version | Audit Scope | Findings |
|------|---------|-------------|----------|
| 2026-03-11 | v26.36.02 | All critical pages: Safari fetch pattern, Fullscreen API, autocapitalize, PWA manifest, icon system, theme-color | Scan overlay uses fetch()+DOMParser+document.replaceChild() (Safari-safe). Fullscreen API has webkit fallbacks. Focus Mode button hidden when API unavailable. PWA manifest complete. Icon system uses inline SVGs from Go registry (icons.go), not CSS subsets. theme-color meta tag dynamically updated per covert env. Fixed: 6 inputs missing autocapitalize=none (DKIM selectors, API keys). audit_icons.py references obsolete fontawesome-subset.min.css path. |

## Cross-Page Regression Log

Track when fixing one page breaks another.

| Date | Fix Applied To | Regression Found On | Description | Resolution |
|------|---------------|-------------------|-------------|------------|
| — | — | — | — | — |

---

## Sensitive Shared Resources

Changes to these files affect multiple pages simultaneously. Extra caution required.

| Resource | Pages Affected | Risk |
|----------|---------------|------|
| `_nav.html` | All pages | Navbar, maintenance badge, covert mode toggle, version display |
| `_head.html` | All pages | CSS loading, inline SVG icon system (via `go-server/internal/icons/icons.go`), CSP nonce, SRI hashes, PWA manifest/splash screens |
| `_footer.html` | All pages | Footer links, copyright |
| `static/css/custom.min.css` | All pages | Global styling, color tokens, glass effects |
| `static/js/main.js` | Pages with scan overlay, covert mode pages | Safari fetch pattern, overlay animation, Focus Mode (Fullscreen API), dynamic theme-color, Morse audio easter egg |
| `static/js/foundation.js` | All pages | Lightweight Bootstrap supplement |
| `static/sw.js` | All pages (PWA) | Service worker caching, offline fallback |
| `middleware/analytics.go` | All pages | Request counting, exclusion logic |
| `middleware/security.go` | All pages | CSP headers, security headers |
| `templates/funcs.go` | All pages | Template functions, SRI, static path helper |
