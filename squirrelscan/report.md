# SquirrelScan Audit Report — dnstool.it-help.tech

**Date**: 2026-03-18
**Tool**: SquirrelScan v0.0.38
**Coverage**: Quick (18 pages from sitemap) + targeted analysis page audits
**Previous Score**: 50 (Grade F) — 2026-03-07 (100 pages crawled)
**Current Score**: 72 (Grade C) — significant improvement from prior audit

---

## Score Summary

| Category | Score | Grade |
|---|---|---|
| **Overall** | **72** | **C** |
| Performance | 83 | B |
| Accessibility | 95 | A |
| Images | 90 | A |
| Content | 92 | A |
| Core SEO | 97 | A |
| Links | 85 | B |
| Security | 91 | A |
| Video | 57 | F |
| E-E-A-T | 82 | B |
| Crawlability | 94 | A |
| Structured Data | 84 | B |
| Internationalization | 100 | A+ |
| Legal Compliance | 100 | A+ |
| Mobile | 100 | A+ |
| Social Media | 100 | A+ |
| URL Structure | 100 | A+ |

**Totals**: 1,779 passed | 199 warnings | 2 failed

---

## Findings by Category

### 1. SECURITY (Score: 91)

#### ERROR: Leaked Secrets (from full-crawl baseline)
- **Rule**: `security/leaked-secrets`
- **Severity**: ERROR
- **Details**:
  - Google OAuth Client ID exposed in inline script on `/auth/login`
  - Sanity Token exposed in HTML on `/analysis/6141/view`
- **Impact**: High — credentials visible in page source
- **Fix**: Move OAuth client ID to server-side config; sanitize analysis view output to not leak tokens

#### WARNING: CSP script-src allows wildcard (*)
- **Rule**: `security/csp`
- **Severity**: WARNING
- **Pages**: All pages
- **Details**: Content-Security-Policy script-src directive uses wildcard `*`, allowing scripts from any origin
- **Fix**: Restrict CSP script-src to specific trusted domains (e.g., `'self'`, specific CDN hosts)

#### WARNING: Form without CAPTCHA
- **Rule**: `security/form-captcha`
- **Pages**: `/email-header`
- **Details**: `#emailHeaderForm` is a public form without CAPTCHA protection
- **Fix**: Add reCAPTCHA or similar bot protection

#### WARNING: HTTP-to-HTTPS redirects
- **Rule**: `security/http-to-https`
- **Details**: 18 HTTP URLs redirect to HTTPS (301). All HTTP variants properly redirect, but internal links should use HTTPS directly.
- **Fix**: Ensure all internal hrefs use `https://` scheme

#### WARNING: External links missing rel="noopener" (from full-crawl baseline)
- **Rule**: `security/new-tab`
- **Pages**: `/auth/login` (Google OAuth error page)
- **Details**: 4 external links missing `rel="noopener"` on the auth/login redirect page
- **Fix**: Add `rel="noopener noreferrer"` to external links opening in new tabs

---

### 2. CORE SEO (Score: 97)

#### WARNING: Title too long / too short
- **Rule**: `core/meta-title`
- **Severity**: ERROR (downgraded to warning — no pages fully missing titles)
- **Affected Pages**:
  - `/toolkit` — "Network Troubleshooting Toolkit for Field Engineer" (62 chars) — too long
  - `/about` — "Origin Story - DNS Tool" (23 chars) — too short
  - `/stats` — "Statistics - DNS Tool" (21 chars) — too short
  - `/topology` — "Protocol Topology — DNS Tool" (28 chars) — too short
  - `/ttl-tuner` — "TTL Tuner - DNS Tool" (20 chars) — too short
  - `/changelog` — too short
  - `/security-policy` — too short
- **Fix**: Titles should be 30-60 characters. Expand short titles with descriptive keywords.

#### WARNING: Missing canonical URL
- **Rule**: `core/canonical`
- **Pages**: `/topology`, `/compare`, and 66+ dynamic pages (analysis, analyze, drift, history)
- **Fix**: Add `<link rel="canonical" href="...">` to all pages

#### WARNING: Charset not at start of head
- **Rule**: `core/charset`
- **Pages**: All main pages (/, /investigate, /email-header, /toolkit, /sources, etc.)
- **Details**: UTF-8 charset is declared but not as the first element in `<head>`
- **Fix**: Move `<meta charset="UTF-8">` to be the first child of `<head>`

#### WARNING: Page set to noindex and nofollow
- **Rule**: `core/robots-meta`
- **Pages**: `/topology`, `/compare`, and 67 dynamic pages
- **Details**: These pages have noindex+nofollow but are allowed in robots.txt

#### WARNING: Duplicate titles
- **Rule**: `core/title-unique`
- **Details**: 15 duplicate titles affecting 43 pages
  - "Analysis History - DNS Tool" duplicated across 8 history pagination pages
  - Analysis/view pages share identical titles with analyze pages
- **Fix**: Append page number for paginated pages; ensure unique titles per analysis

#### WARNING: Meta description issues
- **Rule**: `core/meta-description`
- **Pages**: `/approach` (161 chars — too long), `/changelog` (115 chars — too short), `/topology` (missing), `/compare` (119 chars — too short)
- **Fix**: Descriptions should be 120-160 characters

#### WARNING: No H1 on /topology
- **Rule**: `core/h1`
- **Pages**: `/topology`
- **Fix**: Add an H1 heading to the topology page

---

### 3. LINKS (Score: 85)

#### ERROR: Broken internal links (from full-crawl baseline)
- **Rule**: `links/broken-links`
- **Details**:
  - `/static/images/diagrams/drift-notification-pipeline.svg` → 404 (linked from `/architecture`)
  - `/static/images/diagrams/github-issues-triage.svg` → 404 (linked from `/architecture`)
- **Fix**: Add the missing SVG files or update the links

#### WARNING: Broken external links
- **Rule**: `links/broken-external-links`
- **Details**:
  - `https://apps.dtic.mil/sti/citations/tr/AD0639176` → 403 (from `/`, `/approach`)
  - `https://apps.dtic.mil/sti/tr/pdf/ADA148883.pdf` → 403 (from `/`, `/approach`)
  - `https://www.iana.org/domains/rdap` → 404 (from `/sources`)
  - `https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf` → 404 (from `/approach`)
- **Fix**: Update or remove broken external links; DTIC links may be access-restricted

#### WARNING: Orphan pages
- **Rule**: `links/orphan-pages`
- **Pages**: `/roadmap`, `/analysis/155/view/R`
- **Fix**: Add internal links from other pages to these orphans

#### WARNING: Too many internal links on history pages
- **Rule**: `links/internal-links`
- **Pages**: `/history`, `/history?page=2`, etc. (193-198 links each, max recommended: 100)
- **Fix**: Reduce link density on history pages, possibly with pagination controls that don't link every page

#### WARNING: Weak internal linking
- **Rule**: `links/weak-internal-links`
- **Pages**: `/roadmap` (only 1 incoming link)
- **Fix**: Link to roadmap from footer or navigation

---

### 4. ACCESSIBILITY (Score: 95)

#### WARNING: Color contrast issues
- **Rule**: `a11y/color-contrast`
- **Pages**: All pages (modal headers, `.text-muted` elements, `.small` text)
- **Specific Elements**:
  - `div.modal-header.border-bottom` — low contrast
  - `p.small.text-muted.mb-0` — low contrast
  - `h6.text-uppercase.small.fw-semibold` — low contrast
  - `div.modal-footer.border-top` — low contrast
  - `p.text-muted.mx-auto.mb-4` — low contrast
- **Fix**: Increase contrast ratios for `.text-muted` elements in dark theme; WCAG AA requires 4.5:1 for normal text

#### WARNING: Links in text blocks may lack underlines
- **Rule**: `a11y/link-in-text-block`
- **Pages**: `/approach`, `/confidence`, `/roe`, `/sources`, `/stats`
- **Details**: Links like "Intelligence Confidence Audit", "architecture", "confidence", "Philosophical Foundations" may not be visually distinguishable from surrounding text
- **Fix**: Add underlines or other visual indicators to inline links

#### WARNING: Generic link text
- **Rule**: `a11y/link-text`
- **Pages**: All pages (nav "sign in"), plus specific pages
- **Details**: Links with text "sign in", "View", "next" are too generic for screen readers
- **Fix**: Use descriptive link text (e.g., "Sign in to your account", "View analysis results")

#### WARNING: Tables without accessible names
- **Rule**: `a11y/table-duplicate-name`
- **Pages**: `/sources` (4 tables), `/confidence` (6 tables)
- **Fix**: Add `aria-label` or `<caption>` to each table

#### WARNING: Buttons without accessible names
- **Rule**: `a11y/button-name`
- **Pages**: `/compare`
- **Details**: `btn-close` button lacks accessible name
- **Fix**: Add `aria-label="Close"` to close buttons

#### WARNING: Heading order skip
- **Rule**: `a11y/heading-order`
- **Pages**: `/compare` (H5 after H1)
- **Fix**: Use proper heading hierarchy (H1 → H2 → H3, etc.)

---

### 5. CONTENT (Score: 92)

#### WARNING: Duplicate titles across 43 pages
- **Rule**: `content/duplicate-title`
- **Details**: 15 distinct title strings shared across multiple pages (history pagination, analysis duplicates)
- **Fix**: Unique titles per page

#### WARNING: Duplicate descriptions across 56 pages
- **Rule**: `content/duplicate-description`
- **Details**: 16 duplicate description strings (history pages, drift pages, analysis pages)
- **Fix**: Generate unique meta descriptions per page

#### WARNING: Heading hierarchy violations
- **Rule**: `content/heading-hierarchy`
- **Pages**: 87 pages affected
- **Specific Skips**: H3→H5, H1→H3, H1→H5, H2→H5, H1→H4
- **Fix**: Follow sequential heading hierarchy on all pages

#### WARNING: Keyword stuffing
- **Rule**: `content/keyword-stuffing`
- **Pages**: Analysis/analyze pages
- **Details**: "dns" (3.2%), "spf" (5.4%), "dmarc" (5.4%), "dkim" (5.4%) density too high
- **Note**: These are domain-specific technical terms and may be acceptable for this tool

#### WARNING: Thin content
- **Rule**: `content/word-count`
- **Pages**: `/auth/login` (92 words, min 300)
- **Note**: Login pages typically have minimal content; acceptable

---

### 6. PERFORMANCE (Score: 83)

#### WARNING: Large HTML pages (from full-crawl baseline)
- **Rule**: `crawl/html-size`
- **Details**: Some analysis pages approach Googlebot's 2MB limit:
  - `/analyze?domain=google.com` — 1,440KB
  - `/analyze?domain=dpsg-radolfzell.de` — 1,433KB
  - `/analysis/6155/view` — 1,123KB
  - `/analyze?domain=tesla.com` — 1,080KB
- **Fix**: Lazy-load sections, paginate long reports, or defer non-critical content

#### WARNING: No caching headers
- **Rule**: `perf/no-cache`
- **Pages**: `/`, `/email-header`, `/investigate`, `/toolkit`
- **Fix**: Add `Cache-Control` headers for static-ish pages

#### WARNING: Unminified inline CSS
- **Rule**: `perf/unminified-css`
- **Pages**: All pages
- **Details**: Inline style blocks (~4.0KB) contain newlines suggesting they are not minified
- **Fix**: Minify inline CSS

---

### 7. E-E-A-T (Score: 82)

#### WARNING: No Contact page found
- **Rule**: `eeat/contact-page`
- **Fix**: Create a contact page or add contact information to the about page

#### WARNING: No Privacy Policy page found
- **Rule**: `eeat/privacy-policy`
- **Fix**: Create a privacy policy page

#### WARNING: No author attribution on content pages
- **Rule**: `eeat/author-byline`
- **Fix**: Add author bylines to content-heavy pages

#### WARNING: No datePublished on content pages
- **Rule**: `eeat/content-dates`
- **Fix**: Add publication dates to analysis and content pages

---

### 8. VIDEO (Score: 57)

#### WARNING: Video without VideoObject schema
- **Rule**: `video/video-schema`
- **Pages**: `/approach`
- **Fix**: Add VideoObject JSON-LD structured data for the video on the approach page

#### WARNING: No caption tracks on videos
- **Rule**: `video/video-accessible`
- **Pages**: `/approach`
- **Fix**: Add WebVTT caption tracks to the video element

---

### 9. CRAWLABILITY (Score: 94)

#### WARNING: Noindexed page in sitemap
- **Rule**: `crawl/noindex-in-sitemap`
- **Pages**: `/topology`
- **Fix**: Either remove `/topology` from sitemap or remove the noindex directive

#### WARNING: Indexability conflicts
- **Rule**: `crawl/indexability-conflicts`
- **Details**: Pages allowed in robots.txt but have noindex meta tag
- **Fix**: Align robots.txt and meta robots directives

#### WARNING: Sitemap coverage gaps (from full-crawl baseline)
- **Rule**: `crawl/sitemap-coverage`
- **Details**: 72 indexable pages (77%) not in sitemap
- **Fix**: Add all indexable pages to sitemap.xml

---

### 10. STRUCTURED DATA (Score: 84)

#### WARNING: Missing VideoObject schema
- **Rule**: `schema/video`
- **Pages**: `/approach`
- **Fix**: Add VideoObject JSON-LD

---

### 11. IMAGES (Score: 90)

#### WARNING: Missing alt text
- **Rule**: `images/alt-text`
- **Pages**: All pages (90 pages affected)
- **Details**: `/static/icons/icon-48x48.webp?v=26.35.04` missing alt text (likely the navbar/manifest icon)
- **Fix**: Add alt text to the icon image

#### WARNING: Oversized images for display size
- **Rule**: `images/responsive-size`
- **Pages**: All pages
- **Fix**: Serve appropriately sized images using srcset or resize

---

## Page-Specific Findings

### /compare
- Score: 67 (Grade D)
- Missing canonical URL
- noindex + nofollow set
- Meta description too short (119 chars)
- Heading skip: H5 after H1
- Button without accessible name (btn-close)
- Not in sitemap

### /analysis/155/view/E (Engineer's Report)
- Score: 75 (Grade C)
- CSP wildcard issue
- Color contrast issues in modal elements
- No caching headers
- Inline CSS not minified
- No author attribution or dates

### /analysis/155/view/R (Recon Report)
- Score: 73 (Grade C)
- Orphan page (< 2 incoming links)
- Broken external links to dtic.mil (403)
- CSP wildcard issue
- No caching headers

### / (Homepage)
- Color contrast issues
- "sign in" link has generic text
- Heading hierarchy skips

### /approach
- Video lacks VideoObject schema
- Video lacks caption tracks
- Broken external links (dtic.mil 403, dni.gov 404)
- Links in text may lack underlines

---

## Priority Recommendations

### Critical (Fix Immediately)
1. **Remove leaked secrets** from `/auth/login` (OAuth Client ID) and analysis pages (Sanity Token)
2. **Fix broken internal links** on `/architecture` (missing SVG diagrams)
3. **Tighten CSP** — remove wildcard `*` from script-src

### High Priority
4. **Fix broken external links** — update dtic.mil, iana.org, dni.gov links
5. **Add caching headers** to all pages
6. **Move charset declaration** to first element in `<head>`
7. **Fix heading hierarchy** across all pages
8. **Add canonical URLs** to all pages

### Medium Priority
9. **Fix meta title lengths** — expand short titles, shorten long ones
10. **Add video accessibility** — VideoObject schema + caption tracks on `/approach`
11. **Improve link text** — replace "sign in", "View", "next" with descriptive text
12. **Add table captions** on `/confidence` and `/sources`
13. **Improve color contrast** for `.text-muted` elements in dark theme
14. **Add privacy policy** and **contact page**
15. **Add alt text** to icon-48x48.webp
16. **Reduce HTML size** of analysis pages (approaching 2MB limit)

### Low Priority
17. **Add CAPTCHA** to email header form
18. **Add author bylines** and publication dates
19. **Deduplicate titles/descriptions** across paginated and analysis pages
20. **Improve sitemap coverage** — add missing indexable pages
21. **Resolve noindex/sitemap conflicts** for `/topology`
22. **Add underlines** to inline text links for accessibility
23. **Add internal links** to orphan pages (`/roadmap`, analysis views)

---

## Score Comparison: Previous vs Current

| Category | Previous (Mar 7) | Current (Mar 18) | Delta |
|---|---|---|---|
| Overall | 50 (F) | 72 (C) | +22 |
| Performance | 73 | 83 | +10 |
| Accessibility | 90 | 95 | +5 |
| Images | 82 | 90 | +8 |
| Content | 76 | 92 | +16 |
| Core SEO | 80 | 97 | +17 |
| Links | 64 | 85 | +21 |
| Security | 81 | 91 | +10 |
| Video | 57 | 57 | 0 |
| E-E-A-T | 82 | 82 | 0 |
| Crawlability | 88 | 94 | +6 |
| Structured Data | 84 | 84 | 0 |

Significant improvements across the board. The remaining drag on the overall score comes primarily from Video (57) and E-E-A-T (82).
