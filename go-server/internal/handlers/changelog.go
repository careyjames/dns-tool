// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
//
// CHANGELOG DATE POLICY
// =====================
// Each entry's Date field must reflect the ACTUAL date the feature shipped or
// the incident occurred — NOT the version number prefix, NOT "today", and NOT
// the date the changelog entry was written. Version numbers (26.14.x, 26.13.x)
// are feature-level counters and do NOT encode dates.
//
// When adding a new entry:
//  1. Determine the real ship/event date.
//  2. Use (or create) a named date constant below.
//  3. Reference the constant — never inline a date string.
//
// HISTORICAL EDIT AUDIT
// =====================
// 2026-03-05 (commit 751fe32f): Corrected SPDX license identifier in the
//
//      dateFeb17 changelog entry from "BSL 1.1" (not a valid SPDX identifier;
//      could be confused with Boost Software License) to "BUSL-1.1" (the
//      correct SPDX identifier for Business Source License 1.1). This was an
//      intentional, targeted correction — NOT a mass version rewrite. Only 3
//      lines changed: the date-mapping comment, the entry Title, and the entry
//      Description. No version strings were altered. The same commit also
//      corrected the identifier across 14 other project files (README, CITATION,
//      architecture docs, methodology PDF, etc.) as part of a project-wide
//      SPDX compliance sweep. Investigated and confirmed clean on 2026-03-05
//      by cross-referencing git diff, version string diversity (26 distinct
//      versions intact), and release script analysis.
//
// Canonical date mapping (verified Feb 28, 2026):
//
//      dateFeb28 — Schema.org Intelligence Pipeline Mapping,
//                  Intelligence Pipeline Topology Visualization
//      dateFeb26 — Safari Covert Mode Fix, Stats Success Rate Fix,
//                  Daily Analysis Stats Tracking, Admin IP Audit Trail,
//                  CSRF Form Fix (TTL Tuner & Watchlist),
//                  TTL Tuner UX Overhaul, DNS Provider Detection Expansion (5→15),
//                  NS Provider-Locked Display, Mobile Homepage Scroll Fix,
//                  Navbar Dropdown Refinement, HTTP Observatory A+ Infrastructure,
//                  Secure Cookie Infrastructure, TTL Tuner Mobile Responsive Table,
//                  SonarCloud Quality Gate Fixes
//      dateFeb23 — Architecture Page TLP:GREEN Redesign, Currency Level Hero Card Label,
//                  PWA Icon Edge Cleanup
//      dateFeb21 — Misplaced DMARC Record Detection, Covert Mode Recon Report UI,
//                  High-DPI PWA Icon Regeneration, Origin Story Page,
//                  ASCII Art Homepage Hero
//      dateFeb19 — Architecture Diagrams, miekg/dns v2 Migration, CT Resilience,
//                  History Table Cleanup, Brand Verdict Overhaul, DKIM Selector Expansion,
//                  Privacy-Preserving Analytics, Admin Analytics Dashboard,
//                  Admin Dashboard + JSON Export, Admin Bootstrap Fix,
//                  UNLIKELY Badge Color Unification
//      dateFeb18 — Google OAuth 2.0 + PKCE, Security Redaction & Mission Statement
//      dateFeb17 — BUSL-1.1 License Migration, Boundary Integrity Test Suite
//      dateFeb15 — Dual Intelligence Products (Engineer's DNS Intelligence Report & Executive's DNS Intelligence Brief), OpenPhish Threat
//                  Intelligence Attribution, Email Header Analyzer Homepage Promotion
//      dateFeb14 — High-Speed Subdomain Discovery
//      dateFeb13 — DNS History Cache, Verify It Yourself, Confidence Indicators,
//                  SMTP Transport Verification, AI Surface Scanner, DNS History
//                  Timeline, Enhanced Remediation Engine, Email Security Mgmt
//      dateFeb12 — Intelligence Sources Inventory, PTR-Based Hosting Detection,
//                  IP-to-ASN Attribution, DANE/TLSA, Go Rewrite, IP Investigation,
//                  Email Header Analyzer, Enterprise DNS Detection
//      dateFeb11 — Incident Disclosure, Honest Data Reporting
// dns-tool:scrutiny design
package handlers

const (
        dateMar25 = "Mar 25, 2026"
        dateMar24 = "Mar 24, 2026"
        dateMar20 = "Mar 20, 2026"
        dateMar19 = "Mar 19, 2026"
        dateMar18 = "Mar 18, 2026"
        dateMar14 = "Mar 14, 2026"
        dateMar12 = "Mar 12, 2026"
        dateMar10 = "Mar 10, 2026"
        dateMar08 = "Mar 8, 2026"
        dateMar06 = "Mar 6, 2026"
        dateFeb28 = "Feb 28, 2026"
        dateFeb26 = "Feb 26, 2026"
        dateFeb23 = "Feb 23, 2026"
        dateFeb21 = "Feb 21, 2026"
        dateFeb19 = "Feb 19, 2026"
        dateFeb18 = "Feb 18, 2026"
        dateFeb17 = "Feb 17, 2026"
        dateFeb15 = "Feb 15, 2026"
        dateFeb14 = "Feb 14, 2026"
        dateFeb13 = "Feb 13, 2026"
        dateFeb12 = "Feb 12, 2026"
        dateFeb11 = "Feb 11, 2026"
        dateJan22 = "Jan 22, 2026"
        dateNov05 = "Nov 5, 2025"
        dateJun05 = "Jun 5, 2025"
        dateMay24 = "May 24, 2025"
        dateMay18 = "May 18, 2025"
        dateNov23 = "Nov 5, 2023"
        date2019  = "2019"

        ver263832 = "26.38.32"
        ver263830 = "26.38.30"
        ver263802 = "26.38.02"
        ver263732 = "26.37.32"
        ver263716 = "26.37.16"
        ver263611 = "26.36.11"
        ver263609 = "26.36.09"
        ver263535 = "26.35.35"
        ver263534 = "26.35.34"
        ver263440 = "26.34.40"
        ver263439 = "26.34.39"
        ver263438 = "26.34.38"
        ver262823 = "26.28.23"
        ver262822 = "26.28.22"
        ver262821 = "26.28.21"
        ver262820 = "26.28.20"
        ver262704 = "26.27.04"
        ver262703 = "26.27.03"
        ver262701 = "26.27.01"
        ver262525 = "26.25.25"
        ver262225 = "26.22.25"
        ver262088 = "26.20.88"
        ver262076 = "26.20.76"

        iconShieldAlt  = "shield-alt"
        iconMobileAlt  = "mobile-alt"
        iconSatDish    = "satellite-dish"

        catIntelligence = "Intelligence"
        catSecurity     = "Security"
        catTransparency = "Transparency"
        catBrand        = "Brand"
        catOrigins      = "Origins"
        catCore         = "Core"
        catUX           = "UX"
)

type ChangelogEntry struct {
        Version     string
        Date        string
        Category    string
        Title       string
        Description string
        Icon        string
        IsIncident  bool
        IsLegacy    bool
}

func GetRecentChangelog(n int) []ChangelogEntry {
        all := GetChangelog()
        if len(all) <= n {
                return all
        }
        return all[:n]
}

func GetChangelog() []ChangelogEntry {
        return []ChangelogEntry{
                {
                        Version:     ver263832,
                        Date:        dateMar25,
                        Category:    catBrand,
                        Title:       "Footer Organizational Topology Tree",
                        Description: "Footer redesigned with a visual corporate hierarchy tree showing IT Help San Diego Inc. at the root, Delaware and California state registrations branching left and right with OpenCorporates links, a T-junction connecting the Research Department and Professional Consulting divisions, and DNS Tool descending from Research. Per-link contextual icons across all 21 footer links. Grid cards reorganized into four categories: Research (Publications, Case Studies, Sources, References, Corpus, Cite), Platform (Approach, Architecture, Confidence, Topology, Roadmap, Changelog), Governance (Owl Semaphore, Manifesto, Standards, ROE), and Company (Origin Story, Contact, Security, Privacy).",
                        Icon:        "sitemap",
                },
                {
                        Version:     ver263830,
                        Date:        dateMar25,
                        Category:    catUX,
                        Title:       "ICAE Progress Bar Color Science Overhaul",
                        Description: "Replaced harsh electric cyan (#4fd2ff) and saturated violet (#7c5cff) Collection/Analysis bar colors with scotopic-safe warm amber-gold (#C9A15A) and muted copper/terracotta (#B07A5A). Color selection informed by rod-cell sensitivity research (scotopic peak ~507nm), WCAG contrast analysis on dark backgrounds, and color-blind distinguishability. Updated across CSS, SVG diagrams, and architecture page.",
                        Icon:        "palette",
                },
                {
                        Version:     ver263830,
                        Date:        dateMar25,
                        Category:    catSecurity,
                        Title:       "SAST False-Positive Suppression (17 HIGH Findings)",
                        Description: "Resolved all 17 HIGH-severity SAST false positives in test files with comprehensive five-scanner suppression tags (gosec, nosec, gitleaks, semgrep, SonarQube) and human-readable justifications. Added dns-eval/Inputs/ to .semgrepignore for JSON fixture data. Every suppression is traceable and defensible for third-party security auditors.",
                        Icon:        iconShieldAlt,
                },
                {
                        Version:     ver263830,
                        Date:        dateMar24,
                        Category:    catSecurity,
                        Title:       "Off-Site Backup Automation",
                        Description: "Added daily cron schedule (06:15 UTC) to the off-site backup workflow for the IT-Help-San-Diego/off-site-backup repository. Previously backup was only triggered manually. Disabled orphaned mirror-codeberg.yml workflow (221 consecutive failures) via GitHub API.",
                        Icon:        "database",
                },
                {
                        Version:     ver263830,
                        Date:        dateMar25,
                        Category:    catTransparency,
                        Title:       "Pre-Release Science Audit",
                        Description: "Full repository audit ahead of science documentation release: verified all 35+ public page routes, all static assets, all hosted PDFs, robots.txt, llms.txt, sitemap.xml, and navigation links. Updated roadmap with March 2026 accomplishments. Footer enriched with Roadmap and Corpus links.",
                        Icon:        "clipboard-check",
                },
                {
                        Version:     ver263802,
                        Date:        dateMar20,
                        Category:    catIntelligence,
                        Title:       "Publications & Research Index",
                        Description: "New /publications page consolidating all scientific papers, case studies, governance documents, and technical documentation in a single, citable index. Includes format badges (PDF/HTML/Video), metadata, and DOI citation link. Footer redesigned with glassmorphism grid cards organized into Research, Platform, Governance, and Company categories.",
                        Icon:        "book-open",
                },
                {
                        Version:     ver263802,
                        Date:        dateMar19,
                        Category:    catIntelligence,
                        Title:       "Domain Confessions #2 — Intelligence DMARC Case Study",
                        Description: "Published case study analyzing DMARC postures across 13 U.S. intelligence and federal agencies. The CIA and ODNI are the only agencies in the survey that have not upgraded to DMARC reject eight years after BOD 18-01. Analysis of forensic reporting (ruf=) configurations, strict alignment adoption, and the deliberate monitoring posture hypothesis. Includes accessible agency comparison table, SPF technical explanation, and nuanced treatment of the ruf= specification status (DMARCbis removal vs. government system support).",
                        Icon:        "eye",
                },
                {
                        Version:     ver263802,
                        Date:        dateMar19,
                        Category:    catIntelligence,
                        Title:       "Case Study Index & Cross-Linking",
                        Description: "New /case-study/ index page listing all Domain Confessions entries. Cross-links between Confessions #1 (Forgotten Domain) and #2 (Intelligence DMARC). Case study section added to the Approach page. Service worker updated to skip /case-study/ and /video/ paths to prevent stale cache interference.",
                        Icon:        "list",
                },
                {
                        Version:     ver263732,
                        Date:        dateMar18,
                        Category:    catIntelligence,
                        Title:       "Founder's Manifesto & Communication Standards",
                        Description: "Two new governance documents published as both HTML pages and downloadable PDFs. The Founder's Manifesto declares aspirational design philosophy (non-normative). The Communication Standards document defines the measurable quality gate for all DNS Tool output — clarity requirements, vision accessibility standards (WCAG AA), acronym expansion rules, and the manual review checklist.",
                        Icon:        "scroll",
                },
                {
                        Version:     ver263716,
                        Date:        dateMar14,
                        Category:    catIntelligence,
                        Title:       "ICSAE Standards Evaluation Engine",
                        Description: "DNS analysis results now include mapping against formal security standards: INCITS/ISO/IEC 27001, INCITS/ISO/IEC 27002, INCITS 585-2025, and DoD DI-IPSC-81427B. Each finding maps to specific control clauses with compliance context. Standards reference documentation added to the project.",
                        Icon:        iconShieldAlt,
                },
                {
                        Version:     ver263611,
                        Date:        dateMar12,
                        Category:    catUX,
                        Title:       "UX Clarity & Vision Audit",
                        Description: "Comprehensive warm-shift of the accent palette from cool blue to gold/amber tones across all templates. Icon consistency sweep replacing generic icons with domain-specific choices. Glassmorphism treatment applied to protocol badges and scan topology nodes. Font-size floor raised to 0.75rem for WCAG AA compliance. LCP preload hints added. Heading hierarchy corrected across all pages.",
                        Icon:        "palette",
                },
                {
                        Version:     ver263611,
                        Date:        dateMar12,
                        Category:    catSecurity,
                        Title:       "CSP Deep Audit",
                        Description: "Eliminated all remaining unsafe-inline directives from Content Security Policy. All inline scripts and styles now use nonce-based CSP. Static asset serving hardened with Subresource Integrity (SRI) hashes. Image source directive tightened. Complete CSP compliance across all page templates.",
                        Icon:        "lock",
                },
                {
                        Version:     ver263609,
                        Date:        dateMar10,
                        Category:    catIntelligence,
                        Title:       "Web3 Analysis Node & Topology Globe",
                        Description: "Added Web3 domain analysis phase to the scan pipeline — detects ENS/HNS names, IPFS/DNSLink CIDs, gateway infrastructure, and decentralized web indicators in DNS records. Scan topology visualization updated with Web3 node, golden-ratio layout, animated Earth globe with continent outlines, and concentric glass ring node design.",
                        Icon:        "globe",
                },
                {
                        Version:     ver263535,
                        Date:        dateMar08,
                        Category:    catIntelligence,
                        Title:       "Black Site — Adversarial Testing Framework",
                        Description: "New /black-site page implementing a bug tracking system styled as a detainee interrogation facility. Findings (BSI entries) are tracked with severity classification, rendition status, and resolution tracking. Integrated with PostgreSQL for persistent storage. EDE (Extended DNS Errors) data seeded on startup with auto-applied findings.",
                        Icon:        iconSatDish,
                },
                {
                        Version:     ver263534,
                        Date:        dateMar08,
                        Category:    catUX,
                        Title:       "Domain Confessions Video Platform",
                        Description: "Video content system with YouTube embed support, privacy-preserving nocookie player, structured data (Schema.org VideoObject), WebVTT captions, share buttons (Copy Link, Post, Share, Email), and Watch on YouTube integration. Approach page updated with clickable video thumbnails. CSP frame-src configured for youtube-nocookie.com.",
                        Icon:        "play-circle",
                },
                {
                        Version:     ver263440,
                        Date:        dateMar06,
                        Category:    catIntelligence,
                        Title:       "Hybrid Topology Layout Engine",
                        Description: "Replaced the Fruchterman-Reingold force-directed layout with a hybrid constrained layered-stress topology solver. The solver pipeline uses longest-path rank assignment with barycenter crossing reduction, zone-aware constraint compilation, constrained stress refinement with anchor terms, and a deterministic seeded PRNG (mulberry32). Pre-computed layouts for desktop, tablet, and mobile viewports are embedded at server startup. Falls back to the original FR engine if solver output is missing or malformed. Zero node overlaps and zero flow x-monotonicity violations on desktop.",
                        Icon:        "project-diagram",
                },
                {
                        Version:     ver263439,
                        Date:        dateMar06,
                        Category:    catIntelligence,
                        Title:       "Wayback Machine Automatic Archival",
                        Description: "Every successful, non-private, non-scan-flagged analysis is now automatically submitted to the Internet Archive via web.archive.org/save/ in a background goroutine. The returned snapshot URL is stored in domain_analyses.wayback_url and displayed as a green \"Archived\" badge in the results header, plus an \"Internet Archive — Permanent Record\" card on Engineer's and Executive's reports with View Archived Snapshot and Copy URL buttons. Privacy guards ensure private analyses and scanner-flagged analyses are never archived. Completes a three-layer evidence chain: SHA-3-512 integrity hash + posture hash for drift detection + third-party Wayback Machine archive for independent verification.",
                        Icon:        "landmark",
                },
                {
                        Version:     ver263438,
                        Date:        dateMar06,
                        Category:    catUX,
                        Title:       "Font Awesome CSS Direct Loading Fix",
                        Description: "Fixed Font Awesome CSS loading to use direct <link rel=\"stylesheet\"> instead of the media=\"print\" progressive loading trick, which caused icon flicker on initial page load across all templates.",
                        Icon:        "paint-brush",
                },
                {
                        Version:     ver263438,
                        Date:        dateMar06,
                        Category:    catUX,
                        Title:       "ROE Modal iOS Compatibility Fix",
                        Description: "Fixed the Rules of Engagement modal on iOS devices by adding touchend event listeners alongside click, setting aria-hidden=\"true\" for accessibility, implementing roeHandled debounce flag to prevent double-fire, and using modal-fullscreen-sm-down modal-dialog-scrollable classes for proper mobile display.",
                        Icon:        iconMobileAlt,
                },
                {
                        Version:     ver262823,
                        Date:        dateFeb28,
                        Category:    catTransparency,
                        Title:       "Privacy Banner — Straight Talk About Your Data",
                        Description: "Added a fixed-position privacy banner that appears once on first visit regardless of entry page. Lists the exact two cookies used (_csrf for security, _dns_session only if you sign in), explains IP logging for rate limiting and security, and geo checks for DNS analysis accuracy. States plainly: no tracking cookies, no analytics cookies, no ad networks, no data brokers. Links to open-core codebase for verification and Privacy Pledge for full details. Describes account deletion process. Banner is permanently dismissed via localStorage on acknowledgment, compatible with fetch-based navigation, and accessible (role=region, aria-label). Covert mode compatible with red spectrum overrides.",
                        Icon:        "shield-halved",
                },
                {
                        Version:     ver262823,
                        Date:        dateFeb28,
                        Category:    catIntelligence,
                        Title:       "DMARC Quarantine Monitoring Posture Note",
                        Description: "Added a contextual note to the DMARC RFC & Security Context panel when p=quarantine is detected. Notes that quarantine sequesters authentication failures while preserving full DMARC forensic telemetry (RFC 7489 §7), and that some organizations maintain quarantine rather than reject as a deliberate monitoring strategy. Cites NIST SP 800-177 Rev. 1 for enforcement tradeoffs. Appears universally for all domains with p=quarantine — no special treatment based on domain owner. Applied to both Engineer's Report and Covert Recon Report templates.",
                        Icon:        iconSatDish,
                },
                {
                        Version:     ver262822,
                        Date:        dateFeb28,
                        Category:    catUX,
                        Title:       "Covert Recon Mode — Mobile ASCII Art, Exit Sign, Toggle Fix",
                        Description: "Three fixes to Covert Recon Mode: ASCII art hero now displays on mobile Safari (was gated behind 768px media query, now global with 0.32rem mobile scaling). Exit button restyled as scotopic-correct emergency exit sign — solid #cc3030 with red glow, uppercase, fa-sign-out-alt icon, hover brightens to #ff4040. Toggle button on results page now navigates to standard view instead of just removing CSS class (prevented users getting stuck on covert template with standard styling). Hardened toggle logic to redirect whenever analysis ID is present regardless of report mode value. Added x-public-suffix meta tag to results_covert.html for correct exit routing.",
                        Icon:        "sign-out-alt",
                },
                {
                        Version:     ver262821,
                        Date:        dateFeb28,
                        Category:    catTransparency,
                        Title:       "IC Framing Defense — Addressing the Criticism",
                        Description: "Expanded the Addressing the Criticism section on /approach with a dedicated IC framing defense. ICD 203 applies because the problem matches (high-stakes decisions on incomplete data). ICAE/ICuAE naming enforces subsystem separation between correctness and currency with IC-precise terminology. Scotopic vision science citations added. Marketing voice directive applied: removed comparative language.",
                        Icon:        "crosshairs",
                },
                {
                        Version:     ver262820,
                        Date:        dateFeb28,
                        Category:    catIntelligence,
                        Title:       "Schema.org Intelligence Pipeline Mapping",
                        Description: "Rich JSON-LD structured data on indexed pages now maps the full intelligence pipeline to Google's knowledge graph. Index page WebApplication schema includes featureList (18 protocol analyzers with RFC citations), hasPart (ICIE/ICAE/ICuAE as named SoftwareApplication entities with @id identifiers), isBasedOn (10 RFC/draft references as CreativeWork), and additionalProperty (intelligence sources, protocol coverage, output formats, risk classification, CVE coverage). Approach page Article schema maps methodology components with isBasedOn RFC references. Live version injection via template variables.",
                        Icon:        "project-diagram",
                },
                {
                        Version:     ver262820,
                        Date:        dateFeb28,
                        Category:    catIntelligence,
                        Title:       "Intelligence Pipeline Topology Visualization",
                        Description: "System architecture visualization showing the full intelligence pipeline: source nodes, engine processing, confidence auditors, protocol analysis modules with RFC-based dependency edges, storage layers, and output formats. Animated data flow illustrates movement from sources through engine to outputs.",
                        Icon:        "network-wired",
                },
                {
                        Version:     ver262704,
                        Date:        dateFeb26,
                        Category:    catUX,
                        Title:       "Safari Covert Mode Fix",
                        Description: "Fixed operator environment buttons (Submarine, Tactical, Operator) not responding to clicks in Safari. Replaced CSS pseudo-element overlay with a real DOM element to resolve WebKit mix-blend-mode pointer-events bug.",
                        Icon:        "safari",
                },
                {
                        Version:     ver262703,
                        Date:        dateFeb26,
                        Category:    catTransparency,
                        Title:       "Stats Page Success Rate Fix",
                        Description: "Fixed success rate calculation that reported 100% by counting all stored analyses as successful. Now uses actual analysis_success field from domain_analyses for accurate success/failure counts.",
                        Icon:        "chart-pie",
                },
                {
                        Version:     ver262703,
                        Date:        dateFeb26,
                        Category:    catCore,
                        Title:       "Daily Analysis Stats Tracking",
                        Description: "Wired up daily_stats recording for every completed analysis. Each scan now increments the analysis_stats table with success/failure status and duration, enabling accurate per-day trend reporting.",
                        Icon:        "database",
                },
                {
                        Version:     ver262703,
                        Date:        dateFeb26,
                        Category:    catSecurity,
                        Title:       "Admin IP Audit Trail",
                        Description: "Added scan_ip and country origin column to admin dashboard recent analyses table, enabling traffic pattern investigation and external scan source identification.",
                        Icon:        "map-marker-alt",
                },
                {
                        Version:     ver262701,
                        Date:        dateFeb26,
                        Category:    catSecurity,
                        Title:       "HTTP Observatory A+ Score — Infrastructure Hardening",
                        Description: "Achieved a perfect A+ score (140/100, 10/10 tests passed) on Mozilla HTTP Observatory. Secure cookie flag now enforced in production via Replit infrastructure. Combined with existing Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy headers for comprehensive HTTP security posture.",
                        Icon:        iconShieldAlt,
                },
                {
                        Version:     ver262701,
                        Date:        dateFeb26,
                        Category:    catSecurity,
                        Title:       "CSRF Form Field Fix — TTL Tuner & Watchlist",
                        Description: "Corrected CSRF token field name from '_csrf' to 'csrf_token' in TTL Tuner analysis, re-scan, and Watchlist forms. The mismatch caused silent form submission failures — POST requests were rejected by the CSRF middleware and redirected to the homepage without any user-visible error. All form submissions on these pages now work correctly.",
                        Icon:        "bug",
                },
                {
                        Version:     ver262701,
                        Date:        dateFeb26,
                        Category:    catUX,
                        Title:       "TTL Tuner UX Overhaul",
                        Description: "Added loading overlay with spinner during TTL analysis to prevent double-submission and provide visual feedback. Results auto-scroll into view on completion. Profile card selection now shows a checkmark with opacity and scale transition for clear visual confirmation. GET requests to /ttl-tuner/analyze now redirect to the TTL Tuner page instead of returning a 404. Mobile-responsive table hides Current TTL and Impact columns on small screens to prevent horizontal scrolling.",
                        Icon:        "sliders-h",
                },
                {
                        Version:     ver262701,
                        Date:        dateFeb26,
                        Category:    catIntelligence,
                        Title:       "DNS Provider Detection Expansion — 5 to 15 Providers",
                        Description: "Expanded DNS provider detection from 5 providers (Cloudflare, AWS Route 53, GoDaddy, Namecheap, Hostinger) to 15 by adding Gandi, Porkbun, Hetzner, DigitalOcean, Linode (Akamai), OVH, Dyn, NS1 (IBM), DNS Made Easy, and Google Cloud DNS. Each provider includes nameserver pattern matching and minimum TTL constraints where applicable. NS records for all detected providers are now marked as 'Provider-Locked' with an explanation that NS TTL control requires DNS delegation migration.",
                        Icon:        "network-wired",
                },
                {
                        Version:     ver262701,
                        Date:        dateFeb26,
                        Category:    catUX,
                        Title:       "Mobile Homepage Scroll Fix",
                        Description: "Removed HTML autofocus attribute from the domain input field to prevent iOS Safari from scrolling the viewport to the input and opening the keyboard on page load. Desktop browsers now receive focus via JavaScript only when the viewport is 768px or wider and the device is non-touch.",
                        Icon:        iconMobileAlt,
                },
                {
                        Version:     ver262701,
                        Date:        dateFeb26,
                        Category:    catUX,
                        Title:       "Navbar Dropdown Refinement",
                        Description: "Unified the navbar dropdown background color with the navbar itself using rgba(28, 35, 51, 0.97) with backdrop-filter blur. Removed the top border so the dropdown extends seamlessly from the navbar. History page 'New Analysis' button now uses the glass-style btn-analyze treatment consistent with the homepage.",
                        Icon:        "bars",
                },
                {
                        Version:     ver262701,
                        Date:        dateFeb26,
                        Category:    catCore,
                        Title:       "SonarCloud Quality Gate Fixes",
                        Description: "Fixed unchecked error returns across multiple source files. All ignored errors now have proper handling with logging and graceful degradation.",
                        Icon:        "code",
                },
                {
                        Version:     ver262525,
                        Date:        dateFeb23,
                        Category:    "Architecture",
                        Title:       "Architecture Page — TLP:GREEN Public Release",
                        Description: "Complete redesign of the /architecture page: replaced 2.9MB Mermaid.js dependency with static HTML/CSS diagrams for zero-JavaScript rendering and Lighthouse-optimal performance. Page now carries FIRST TLP:GREEN classification with six curated public-safe sections — Intelligence Pipeline, Dual-Engine Confidence Framework (ICAE/ICuAE), Protocol Coverage (9 RFCs), Open-Core Architecture boundary, Intelligence Products, and Standards Foundation (ICD 203, NIST SI-18, ISO 25012, FIPS 202). Redacted content bars protect proprietary methodology. Full Mermaid source retained in docs/architecture/ for GitHub rendering.",
                        Icon:        "sitemap",
                },
                {
                        Version:     ver262525,
                        Date:        dateFeb23,
                        Category:    catUX,
                        Title:       "Currency Level Hero Card Label",
                        Description: "Added \"Currency Level:\" label to the homepage ICAE hero card, paralleling the existing \"Confidence Level:\" label. This surfaces ICuAE's data timeliness assessment alongside ICAE's correctness assessment, completing the dual-engine confidence display at the first point of user contact.",
                        Icon:        "clock",
                },
                {
                        Version:     ver262525,
                        Date:        dateFeb23,
                        Category:    "PWA",
                        Title:       "PWA Icon Edge Cleanup",
                        Description: "Regenerated all Progressive Web App icons, favicons, and Apple touch icons with the owl artwork scaled to 88% of canvas size, creating a clean dark buffer zone around the Greek key border ring. Prevents anti-aliasing edge bleed when browsers crop icons to circles (Chrome tabs, PWA app icons, Safari favicons). Maskable icons use 72% scale to fit within the mandatory 80% safe zone.",
                        Icon:        iconMobileAlt,
                },
                {
                        Version:     ver262225,
                        Date:        dateFeb21,
                        Category:    catIntelligence,
                        Title:       "Misplaced DMARC Record Detection",
                        Description: "New post-analysis enrichment detects DMARC records incorrectly published at the root domain instead of the required _dmarc subdomain (RFC 7489 §6.1). DetectMisplacedDMARC scans root TXT records for v=DMARC1 patterns with case-insensitive matching, extracts the policy, and surfaces the misconfiguration in the report with specific remediation guidance. Four deterministic golden test cases validate detection accuracy.",
                        Icon:        "crosshairs",
                },
                {
                        Version:     ver262225,
                        Date:        dateFeb21,
                        Category:    catUX,
                        Title:       "Covert Mode Recon Report UI",
                        Description: "Fixed Recon Report buttons in Covert Mode to use proper red-themed styling consistent with the tactical red-light aesthetic. Buttons now use the covert accent palette instead of default blue, maintaining the adversarial perspective throughout the report view.",
                        Icon:        "user-secret",
                },
                {
                        Version:     ver262225,
                        Date:        dateFeb21,
                        Category:    "PWA",
                        Title:       "High-DPI PWA Icon Regeneration",
                        Description: "Regenerated all Progressive Web App icons at proper high-DPI resolution with maskable variants for Android adaptive icons. Icons now render crisply on high-resolution displays and correctly fill the safe zone on devices that apply circular or shaped masks.",
                        Icon:        iconMobileAlt,
                },
                {
                        Version:     ver262225,
                        Date:        dateFeb21,
                        Category:    catBrand,
                        Title:       "Origin Story Page",
                        Description: "New /about page documenting the project's origin story, from early CLI development through defensive security work and the evolution to the current Go-based intelligence platform. Includes acknowledgments section crediting early collaborators and linked verifiable references.",
                        Icon:        "book-open",
                },
                {
                        Version:     ver262225,
                        Date:        dateFeb21,
                        Category:    catUX,
                        Title:       "ASCII Art Homepage Hero",
                        Description: "Desktop homepage hero title rendered as a Unicode block-character ASCII art banner for visual impact. Responsive design with automatic mobile text fallback below 768px width. The art uses CSS monospace rendering with careful line-height tuning for consistent cross-browser display.",
                        Icon:        "terminal",
                },
                {
                        Version:     ver262088,
                        Date:        dateFeb19,
                        Category:    catSecurity,
                        Title:       "Authenticated Multi-Port SMTP Probe API",
                        Description: "Remote probe infrastructure upgraded to API v2 with shared-secret authentication, rate limiting, and multi-port mail transport probing across ports 25 (SMTP), 465 (SMTPS), and 587 (submission). Banner capture provides additional server intelligence fingerprinting. Graceful fallback on authentication or rate limit responses.",
                        Icon:        iconSatDish,
                },
                {
                        Version:     ver262088,
                        Date:        dateFeb19,
                        Category:    "Analytics",
                        Title:       "Privacy-Preserving Analytics Middleware",
                        Description: "Cookie-free, GDPR-friendly analytics pipeline collecting pageviews, unique visitors, analyses run, and unique domains analyzed. Daily-rotating random salt hashes visitor IPs into pseudonymous IDs — no cookies, no fingerprinting, no PII stored. Referrer origin and top page tracking with automatic self-referral filtering. In-memory aggregation flushed to database periodically. Static assets, health checks, and bot paths excluded.",
                        Icon:        "chart-line",
                },
                {
                        Version:     ver262088,
                        Date:        dateFeb19,
                        Category:    "Admin",
                        Title:       "Admin Analytics Dashboard",
                        Description: "Administrative monitoring dashboard with 30-day daily analytics view showing pageviews, unique visitors, analyses run, and unique domains. Summary cards with totals, averages, top referrers, and most-visited pages. Built on the privacy-preserving analytics middleware — no third-party tracking scripts.",
                        Icon:        "chart-bar",
                },
                {
                        Version:     "26.20.85",
                        Date:        dateFeb19,
                        Category:    "Admin",
                        Title:       "Admin Dashboard & JSON Export",
                        Description: "Administrative monitoring dashboard with stats cards for total users, analyses, unique domains, and session metrics. Users table with role badges, recent analyses table with domain links and status. JSON export streams NDJSON with paginated batches and proper Content-Disposition header.",
                        Icon:        "tachometer-alt",
                },
                {
                        Version:     "26.20.85",
                        Date:        dateFeb19,
                        Category:    catSecurity,
                        Title:       "Admin Bootstrap Fix",
                        Description: "Fixed admin bootstrap for existing users. When initial admin email matches an already-registered user and zero admins exist, the system now correctly upgrades their role. Previously, the existing role was preserved, silently skipping the bootstrap. Audit-logged with reason and email.",
                        Icon:        "user-shield",
                },
                {
                        Version:     ver262076,
                        Date:        dateFeb19,
                        Category:    catUX,
                        Title:       "UNLIKELY Badge Color Unification",
                        Description: "Unified the UNLIKELY verdict color to green/success across both email spoofing and brand impersonation assessments. Email spoofing with DMARC quarantine at 100% now shows success (green) instead of warning (amber). Brand impersonation with quarantine + BIMI + CAA also uses success (green). Consistent visual language: UNLIKELY = green across all verdict types.",
                        Icon:        "palette",
                },
                {
                        Version:     "26.20.87",
                        Date:        dateFeb19,
                        Category:    catIntelligence,
                        Title:       "Remote SMTP Probe Infrastructure",
                        Description: "Deployed external probe infrastructure for live SMTP transport verification. Cloud platforms block outbound port 25 — the probe infrastructure provides direct STARTTLS handshakes, certificate chain validation, and cipher suite inspection. Falls back gracefully when probe is unavailable.",
                        Icon:        "server",
                },
                {
                        Version:     "26.20.83",
                        Date:        dateFeb19,
                        Category:    "Architecture",
                        Title:       "Interactive System Architecture Diagrams",
                        Description: "New /architecture page with interactive Mermaid diagrams visualizing the full system: high-level overview of the intelligence pipeline, ICIE pipeline, ICAE confidence engine, and Privacy Gate decision tree. Color-coded nodes with CSP-compliant rendering. Dark background with thin blue connector lines.",
                        Icon:        "sitemap",
                },
                {
                        Version:     ver262076,
                        Date:        dateFeb19,
                        Category:    catCore,
                        Title:       "DNS Library v2 Migration (miekg/dns)",
                        Description: "Migrated from miekg/dns v1 to v2. The v1 library is archived; v2 is actively maintained with improved performance and modern API. Updated with new Exchange, RR data access, and EDNS0 patterns.",
                        Icon:        "bolt",
                },
                {
                        Version:     ver262076,
                        Date:        dateFeb19,
                        Category:    "Reliability",
                        Title:       "CT Log Resilience (Certspotter Fallback)",
                        Description: "Added Certspotter API as a fallback Certificate Transparency source when crt.sh is unavailable (502/timeout). Expanded DNS subdomain probe list from ~130 to ~280 common subdomains. Probe concurrency increased from 20 to 30 workers with a 25-second timeout.",
                        Icon:        iconShieldAlt,
                },
                {
                        Version:     "26.20.74",
                        Date:        dateFeb19,
                        Category:    catUX,
                        Title:       "History Table Cleanup",
                        Description: "Removed the redundant status column from the analysis history table. Failed analyses are already excluded from history (they appear in statistics only). The green checkmark column was wasting horizontal space without adding information.",
                        Icon:        "list",
                },
                {
                        Version:     "26.20.71",
                        Date:        dateFeb19,
                        Category:    catIntelligence,
                        Title:       "Brand Security Verdict Matrix Overhaul",
                        Description: "Corrected the brand impersonation verdict logic. DMARC reject alone blocks email spoofing (RFC 7489 §6.3) but not visual impersonation via lookalike domains or unrestricted certificate issuance. New 8-branch verdict matrix considers DMARC policy + BIMI brand verification + CAA certificate restriction (RFC 8659 §4). Expanded from 5 to 8 golden rule test cases.",
                        Icon:        "check-double",
                },
                {
                        Version:     "26.20.70",
                        Date:        dateFeb19,
                        Category:    catIntelligence,
                        Title:       "DKIM Selector Expansion (81+ Selectors)",
                        Description: "Expanded default DKIM selector list from 39 to 81+ selectors covering major ESPs: HubSpot, Salesforce, Klaviyo, Intercom, ActiveCampaign, Constant Contact, MailerLite, Drip, Customer.io, Freshdesk, and more. Enhanced provider-to-selector inference from SPF/MX records. Privacy mode classification updated for expanded known-selector list.",
                        Icon:        "key",
                },
                {
                        Version:     "26.20.56",
                        Date:        dateFeb18,
                        Category:    catSecurity,
                        Title:       "Google OAuth 2.0 + PKCE Authentication",
                        Description: "Pure stdlib Google OAuth 2.0 implementation with PKCE (Proof Key for Code Exchange) — no external OAuth libraries. Advanced Protection compatible. Email verification enforced, ID token claims validated, rate-limited auth endpoints, no tokens stored server-side. Route protection for sensitive endpoints. All analysis remains no-login-required.",
                        Icon:        "user-shield",
                },
                {
                        Version:     "26.19.43",
                        Date:        dateFeb18,
                        Category:    catSecurity,
                        Title:       "Security Redaction & Mission Statement",
                        Description: "Comprehensive security audit: removed server version exposure from HTTP headers, redacted internal paths from error responses, hardened SSRF prevention. Added mission statement to the Security Policy page defining scope, principles, and responsible disclosure process.",
                        Icon:        "lock",
                },
                {
                        Version:     "26.19.18",
                        Date:        dateFeb17,
                        Category:    "Quality",
                        Title:       "Boundary Integrity Test Suite",
                        Description: "Comprehensive test suite protecting the architecture boundary: boundary files verified across multiple categories including file presence, build tags, function signatures, and package consistency. Catches contract violations and architecture drift before they reach production.",
                        Icon:        "cogs",
                },
                {
                        Version:     "26.19.0",
                        Date:        dateFeb17,
                        Category:    "Licensing",
                        Title:       "BUSL-1.1 License Migration",
                        Description: "Migrated from AGPL-3.0 to Business Source License 1.1 (SPDX: BUSL-1.1) with a 3-year rolling Change Date converting to Apache-2.0. Explicit MSP/consultant carve-out permits security professionals to use the tool for client audits. All 111 Go source files updated. Both public and private repositories under BUSL-1.1.",
                        Icon:        "balance-scale",
                },
                {
                        Version:     "26.17.2",
                        Date:        dateFeb15,
                        Category:    catSecurity,
                        Title:       "CSP Compliance & XSS Hardening",
                        Description: "Eliminated all inline style attributes from report templates to resolve Content Security Policy violations flagged by Lighthouse/PageSpeed Insights. All styles moved to CSS utility classes. DNS history table rendering refactored to safe DOM methods, eliminating XSS anti-pattern. Fixed protocol navigation links: MTA-STS and TLS-RPT now correctly scroll to Email Security section, CAA scrolls to Brand Security section.",
                        Icon:        iconShieldAlt,
                },
                {
                        Version:     "26.17.1",
                        Date:        dateFeb15,
                        Category:    catSecurity,
                        Title:       "Expanded Exposure Checks (Opt-In)",
                        Description: "New opt-in OSINT exposure scanner checks well-known misconfiguration paths on target domains. Content validation reduces false positives — each path is checked for characteristic content, not just HTTP 200 status. Sequential requests with proper rate limiting and User-Agent identification. Results include severity badges, risk descriptions, and specific remediation guidance. Explicit PCI DSS disclaimer: these are OSINT collection, not ASV compliance scans.",
                        Icon:        "search",
                },
                {
                        Version:     "26.17.0",
                        Date:        dateFeb15,
                        Category:    "Integrity",
                        Title:       "Report Integrity Hash & Header Preview",
                        Description: "Every analysis now generates a SHA-256 integrity fingerprint binding domain, analysis ID, timestamp, tool version, and canonicalized results data into a tamper-evident hash. Displayed at the bottom of both Engineer's DNS Intelligence Report and Executive's DNS Intelligence Brief with copy-to-clipboard. Short hash preview (first 8 characters) shown in the report header metadata bar with anchor link to the full hash section. Distinct from posture hash (drift detection) — the integrity hash uniquely identifies each specific report instance.",
                        Icon:        "fingerprint",
                },
                {
                        Version:     "26.16.11",
                        Date:        dateFeb15,
                        Category:    catBrand,
                        Title:       "Intelligence Document Naming Convention",
                        Description: "Adopted IC (Intelligence Community) document naming: Engineer's DNS Intelligence Report (comprehensive, like a National Intelligence Estimate) and Executive's DNS Intelligence Brief (concise, like a Presidential Daily Brief). Possessive form signals personal ownership. 'DNS Intelligence' avoids MI5 brand conflict. Updated all title tags, print headers, screen headers, OG/Twitter meta, and JSON-LD schema. Homepage hero subtitle now explicitly references both intelligence products.",
                        Icon:        "file-alt",
                },
                {
                        Version:     "26.16.10",
                        Date:        dateFeb15,
                        Category:    catBrand,
                        Title:       "Sophistication Accent Tokens & Color Flow",
                        Description: "Added steel-blue (#7d8ea8) and deep navy (#1e3a5f) brand accent tokens for premium intelligence aesthetic. Color flow continuity from homepage through results pages via gradients, borders, and card hover effects. Hero typography upgraded to 3.5rem/800 weight with tighter tracking. All non-status visual elements use brand accents while RFC/CVSS status colors remain untouched.",
                        Icon:        "palette",
                },
                {
                        Version:     "26.15.30",
                        Date:        dateFeb15,
                        Category:    "Reporting",
                        Title:       "TLP:AMBER Default & Colored Selector",
                        Description: "Report distribution now defaults to TLP:AMBER per CISA/FIRST standards for security posture reports. TLP selector button and dropdown badges show FIRST TLP v2.0 colors (amber, green, clear). Font cache-busting ensures all icons render correctly across browsers.",
                        Icon:        iconShieldAlt,
                },
                {
                        Version:     "26.15.26",
                        Date:        dateFeb15,
                        Category:    "Reporting",
                        Title:       "Dual Intelligence Products: Engineer's DNS Intelligence Report & Executive's DNS Intelligence Brief",
                        Description: "Two intelligence products: Engineer's DNS Intelligence Report (comprehensive technical detail with all protocol analysis) and Executive's DNS Intelligence Brief (concise board-ready summary with security scorecard, risk posture, and priority actions). Both use the same live analysis data — different formats for different audiences. Includes posture drift detection foundation with canonical SHA-256 hashing for future longitudinal monitoring.",
                        Icon:        "file-alt",
                },
                {
                        Version:     "26.15.25",
                        Date:        dateFeb15,
                        Category:    catTransparency,
                        Title:       "OpenPhish Threat Intelligence Attribution",
                        Description: "Added OpenPhish Community Feed to the Intelligence Sources page with its own Threat Intelligence category. Added OpenPhish attribution to the Email Header Analyzer trust bar and body analysis results. Proper credit for the free community phishing URL feed that powers our phishing detection.",
                        Icon:        "fish",
                },
                {
                        Version:     "26.15.24",
                        Date:        dateFeb15,
                        Category:    catUX,
                        Title:       "Email Header Analyzer Homepage Promotion",
                        Description: "Added a promotional banner for the Email Header Analyzer on the homepage, matching the IP Investigate card style. Makes the feature more discoverable for users landing on the main page.",
                        Icon:        "envelope",
                },
                {
                        Version:     "26.14.7",
                        Date:        dateFeb14,
                        Category:    "Performance",
                        Title:       "High-Speed Subdomain Discovery",
                        Description: "Subdomain probing now uses lightweight UDP DNS queries instead of DNS-over-HTTPS, with independent timeouts and 20-goroutine concurrency. Discovery completes in ~1 second instead of timing out. All subdomains found reliably.",
                        Icon:        "tachometer-alt",
                },
                {
                        Version:     "26.14.6",
                        Date:        dateFeb12,
                        Category:    catTransparency,
                        Title:       "Intelligence Sources Inventory",
                        Description: "New /sources page documents every intelligence source used by DNS Tool — DNS resolvers, reverse DNS, Team Cymru ASN attribution, SMTP probing, SecurityTrails, crt.sh, IANA RDAP — with methodology, rate limits, and verification commands. No black boxes.",
                        Icon:        iconSatDish,
                },
                {
                        Version:     "26.14.5",
                        Date:        dateFeb12,
                        Category:    catIntelligence,
                        Title:       "PTR-Based Hosting Detection",
                        Description: "Reverse DNS (PTR) lookups now identify hosting providers directly from IP addresses — the classic Unix-era technique. CloudFront, AWS, Google Cloud, Azure, and more detected without any third-party API.",
                        Icon:        "undo-alt",
                },
                {
                        Version:     "26.14.4",
                        Date:        dateFeb12,
                        Category:    catIntelligence,
                        Title:       "IP-to-ASN Attribution",
                        Description: "Team Cymru DNS-based IP-to-ASN mapping identifies which organization owns each IP address (AWS, Cloudflare, Google, etc.). Free community service with no API key and no rate limits.",
                        Icon:        "map-marked-alt",
                },
                {
                        Version:     "26.14.3",
                        Date:        dateFeb11,
                        Category:    catTransparency,
                        Title:       "Incident Disclosure: Inaccurate Analysis Output",
                        Description: "A data-processing issue caused some reports to display incorrect analysis results. The root cause has been identified and fixed, and safeguards have been added so incomplete or failed data retrieval can never be silently presented as valid results. We believe in full transparency — you deserve to know when we get it wrong.",
                        Icon:        "exclamation-triangle",
                        IsIncident:  true,
                },
                {
                        Version:     "26.14.2",
                        Date:        dateFeb11,
                        Category:    catTransparency,
                        Title:       "Honest Data Reporting",
                        Description: "When third-party data sources are rate-limited or unavailable, reports now say exactly that — never claiming 'no changes detected' when the data simply couldn't be checked. Four clear states: success, rate-limited, error, and partial.",
                        Icon:        "gavel",
                },
                {
                        Version:     "26.14.1",
                        Date:        dateFeb13,
                        Category:    "Performance",
                        Title:       "DNS History Cache",
                        Description: "Successful DNS history lookups are now cached for 24 hours, completely isolated from live analysis. Reduces API calls while ensuring live DNS queries are never served stale data.",
                        Icon:        "database",
                },
                {
                        Version:     "26.13.7",
                        Date:        dateFeb13,
                        Category:    catIntelligence,
                        Title:       "Verify It Yourself",
                        Description: "Each report now includes terminal commands (dig, openssl, curl) to independently verify the underlying DNS queries. Our analysis adds consensus and RFC evaluation on top — but the raw data is always verifiable.",
                        Icon:        "laptop-code",
                },
                {
                        Version:     "26.13.6",
                        Date:        dateFeb13,
                        Category:    catTransparency,
                        Title:       "Confidence Indicators",
                        Description: "Every attribution now shows whether data was directly observed (RDAP lookup, DNS record), inferred (pattern matching), or sourced from a third party — so you know exactly how each conclusion was reached.",
                        Icon:        "eye",
                },
                {
                        Version:     "26.13.5",
                        Date:        dateFeb13,
                        Category:    catSecurity,
                        Title:       "SMTP Transport Verification",
                        Description: "Live STARTTLS probing of mail servers with certificate validation, cipher suite analysis, and TLS version checking. DNS-inferred fallback when direct connection is unavailable.",
                        Icon:        "lock",
                },
                {
                        Version:     "26.13.4",
                        Date:        dateFeb13,
                        Category:    catIntelligence,
                        Title:       "AI Surface Scanner",
                        Description: "Detects AI governance signals across domains — llms.txt discovery, AI crawler policies in robots.txt, and prompt injection artifacts. Helps organizations understand their AI exposure.",
                        Icon:        "robot",
                },
                {
                        Version:     "26.13.3",
                        Date:        dateFeb13,
                        Category:    catIntelligence,
                        Title:       "DNS History Timeline",
                        Description: "SecurityTrails-powered historical DNS record tracking shows how a domain's DNS configuration has changed over time. Users provide their own API key — never stored server-side.",
                        Icon:        "clock",
                },
                {
                        Version:     "26.13.2",
                        Date:        dateFeb13,
                        Category:    "Analysis",
                        Title:       "Enhanced Remediation Engine",
                        Description: "RFC-cited remediation guidance now distinguishes SPF softfail vs hardfail context per RFC 7489, with nuanced recommendations based on whether DKIM is present.",
                        Icon:        "cogs",
                },
                {
                        Version:     "26.13.1",
                        Date:        dateFeb13,
                        Category:    catIntelligence,
                        Title:       "Email Security Management Detection",
                        Description: "Automatic identification of DMARC monitoring providers, SPF flattening services, and TLS-RPT reporting platforms from DNS records.",
                        Icon:        "envelope",
                },
                {
                        Version:     "26.12.2",
                        Date:        dateFeb12,
                        Category:    "Analysis",
                        Title:       "DANE/TLSA Deep Analysis",
                        Description: "Full TLSA record parsing for every MX host with certificate usage, selector, matching type validation, and DNSSEC dependency checking per RFC 7672.",
                        Icon:        iconShieldAlt,
                },
                {
                        Version:     "26.12.1",
                        Date:        dateFeb12,
                        Category:    catCore,
                        Title:       "Go Performance Rewrite",
                        Description: "Complete rewrite from Python/Flask to Go/Gin for dramatically improved performance and concurrency. Multi-resolver consensus DNS client with DoH fallback. The second attempt at Go — this time it stuck.",
                        Icon:        "bolt",
                },
                {
                        Version:     "26.12.0",
                        Date:        dateFeb12,
                        Category:    catIntelligence,
                        Title:       "IP Investigation Workflow",
                        Description: "New /investigate page for IP-to-domain reverse lookups with ASN attribution, hosting provider detection, and infrastructure mapping.",
                        Icon:        "search-location",
                },
                {
                        Version:     "26.12.E",
                        Date:        dateFeb12,
                        Category:    catIntelligence,
                        Title:       "Email Header Analyzer",
                        Description: "Paste or upload .eml files for SPF/DKIM/DMARC verification, delivery route tracing, spoofing detection, and phishing pattern scanning with critical thinking prompts.",
                        Icon:        "envelope-open-text",
                },
                {
                        Version:     "26.12.D",
                        Date:        dateFeb12,
                        Category:    catSecurity,
                        Title:       "Enterprise DNS Detection & Golden Rules",
                        Description: "Automatic identification of enterprise-grade DNS providers with test-guarded detection. Legacy provider blocklist prevents false enterprise tagging. Protected by automated golden rules tests.",
                        Icon:        "building",
                },
        }
}

func GetLegacyChangelog() []ChangelogEntry {
        return []ChangelogEntry{
                {
                        Version:     "26.1.0",
                        Date:        dateJan22,
                        Category:    catCore,
                        Title:       "Python Web App: Registrar & Hosting Intelligence",
                        Description: "Major development sprint added RDAP-based registrar detection, hosting provider identification, parallel DNS lookups, and authoritative nameserver queries. The Python/Flask web app grew from basic DNS lookups into a real analysis platform.",
                        Icon:        "code",
                        IsLegacy:    true,
                },
                {
                        Version:     "25.11.1",
                        Date:        dateNov05,
                        Category:    catCore,
                        Title:       "Web App Revival: DoH & Grid Layout",
                        Description: "Returned to the web app after five months. Reset the database, switched to Google's DNS-over-HTTPS for reliability, and reorganized the results into a clean grid layout. The foundation for everything that followed.",
                        Icon:        "th",
                        IsLegacy:    true,
                },
                {
                        Version:     "25.6.1",
                        Date:        dateJun05,
                        Category:    catCore,
                        Title:       "First Web App: Python/Flask on Replit",
                        Description: "DNS Tool became a web application. Built with Python and Flask on Replit — DNS-over-HTTPS queries, PostgreSQL database for scan history, statistics page, and the first version of the analysis results UI. The beginning of dnstool.it-help.tech.",
                        Icon:        "globe",
                        IsLegacy:    true,
                },
                {
                        Version:     "25.5.2",
                        Date:        dateMay24,
                        Category:    catCore,
                        Title:       "CLI Tool: Build System & Quality",
                        Description: "Added reproducible Makefile builds, SonarCloud code quality integration, and archived the working CLI version. The tool was maturing, but the vision was shifting toward a web platform.",
                        Icon:        "hammer",
                        IsLegacy:    true,
                },
                {
                        Version:     "25.5.1",
                        Date:        dateMay18,
                        Category:    catOrigins,
                        Title:       "New Name, New Repo: DNS Tool",
                        Description: "DNS Scout was renamed to DNS Tool and given a fresh GitHub repository. Python CLI with terminal output, visual indicators, interactive and batch modes, pre-compiled binaries for Linux, macOS, and Windows. Documentation, FAQ, and changelog from day one.",
                        Icon:        "terminal",
                        IsLegacy:    true,
                },
                {
                        Version:     "23.11.1",
                        Date:        dateNov23,
                        Category:    catOrigins,
                        Title:       "DNS Scout: Snap & Launchpad Release",
                        Description: "DNS Scout v6.20 published to Launchpad PPA and Snapcraft — the first packaged, installable release. A working DNS security analysis tool available as a .deb and a Snap. The earliest externally verifiable timestamp of the project.",
                        Icon:        "box",
                        IsLegacy:    true,
                },
                {
                        Version:     "19.0.0",
                        Date:        date2019,
                        Category:    catOrigins,
                        Title:       "DNS Scout Is Born",
                        Description: "The project that became DNS Tool started life as DNS Scout — a command-line DNS and email security analysis tool. The seed of an idea: transparent, RFC-compliant domain intelligence with no black boxes.",
                        Icon:        "birthday-cake",
                        IsLegacy:    true,
                },
        }
}
