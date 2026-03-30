// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "net/http"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

const (
        roadmapDateFeb2026   = "Feb 2026"
        roadmapDateMar2026   = "Mar 2026"
        strV263830           = "v26.38.30"
        roadmapVersionV2620 = "v26.20.0+"
        roadmapTypeFeature  = "Feature"

        priorityLow  = "Low"
        priorityHigh = "High"
        strMedium    = "Medium"
        strQuality   = "Quality"
        strV262594   = "v26.25.94"
        strV262602   = "v26.26.02"
        strV262605   = "v26.26.05"
        strV262707   = "v26.27.07"
        strV262836   = "v26.28.36"
)

type RoadmapItem struct {
        Title    string
        Version  string
        Date     string
        Notes    string
        Type     string
        Priority string
}

type RoadmapHandler struct {
        Config *config.Config
}

func NewRoadmapHandler(cfg *config.Config) *RoadmapHandler {
        return &RoadmapHandler{Config: cfg}
}

func (h *RoadmapHandler) Roadmap(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")

        done := []RoadmapItem{
                {Title: "Intelligence Confidence Audit Engine (ICAE)", Version: "129 Test Cases", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Intelligence Currency Assurance Engine (ICuAE)", Version: "29 Test Cases", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Email Header Analyzer", Version: roadmapVersionV2620, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Drift Engine Phases 1–2", Version: "v26.19.40", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Architecture Page", Version: "v26.20.77–83", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "DKIM Selector Expansion (39→81+)", Version: "v26.20.69–70", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Brand Verdict Matrix Overhaul", Version: "v26.20.71", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Optional Authentication (Google OAuth 2.0 PKCE)", Version: "v26.20.56–57", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Probe Network First Node", Version: roadmapVersionV2620, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "LLM Documentation Strategy", Version: "v26.25.26", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "XSS Security Fix (Tooltip Safe DOM)", Version: "v26.25.26", Date: roadmapDateFeb2026, Type: "Security"},
                {Title: "Color Science Page (CIE Scotopic, WCAG)", Version: roadmapVersionV2620, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Badge System (SVG, Shields.io)", Version: roadmapVersionV2620, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Domain Snapshot", Version: roadmapVersionV2620, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Certificate Transparency Resilience", Version: "v26.20.76", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Nmap DNS Security Probing", Version: roadmapVersionV2620, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "One-Liner Verification Commands", Version: roadmapVersionV2620, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Zone File Upload for Analysis", Version: roadmapVersionV2620, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Hash Integrity Audit Engine", Version: "v26.21.45", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Download Verification (SHA-3-512)", Version: "v26.21.49–50", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Accountability Log", Version: "v26.21.46", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Glass Badge System (ICAE, Protocol, Section)", Version: "v26.25.38–43", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Covert Recon Mode", Version: roadmapVersionV2620, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Web/DNS/Email Hosting Detection", Version: "v26.25.43", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Question Branding System (dt-question)", Version: "v26.25.70", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Approach & Methodology Page", Version: "v26.25.83", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "TTL Alignment & Big Picture Questions", Version: "v26.25.93", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Unified Confidence Aggregation (ICD 203)", Version: strV262594, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Homepage Simplification & TTL Deep Linking", Version: "v26.25.95", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "DMARC External Auth Remediation", Version: "v26.25.95", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Symbiotic Security — Five Archetypes Section", Version: "v26.25.96", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Methodology Page Rename & Cross-Links", Version: "v26.25.96", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Delegation Consistency Analyzer", Version: strV262594, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Nameserver Fleet Matrix", Version: strV262594, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "DNSSEC Operations Deep Dive", Version: strV262594, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Live SonarCloud Badge & Evidence Qualification", Version: "v26.25.97", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Probe Network Second Node (Kali)", Version: strV262602, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Multi-Probe Consensus Engine", Version: strV262602, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Public Roadmap Page", Version: strV262602, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "SonarCloud Quality Gate Fix", Version: "v26.26.03", Date: roadmapDateFeb2026, Type: strQuality},
                {Title: "Nmap Subdomain Enrichment", Version: strV262602, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Admin Probe Management Panel", Version: strV262602, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "LLMs.txt & JSON-LD Consistency Audit", Version: "v26.26.04", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Stats Page Visual Redesign", Version: strV262605, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Notion Bidirectional Sync", Version: strV262605, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Covert Mode Color Leak Audit", Version: strV262605, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Stats Confidence Engine Preview Card", Version: strV262605, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Failed Analysis Transparency Page", Version: strV262605, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Documentation Reality Check (LLMs + JSON-LD + Roadmap)", Version: "v26.26.06", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Covert Mode Tactical Red Filter (MIL-STD-3009)", Version: "v26.26.08", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Covert Mode Environment Presets (Submarine/Tactical/Operator)", Version: "v26.26.10", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Operator Mode Color Science (mix-blend-mode: color)", Version: "v26.26.11", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Covert Environment Icons & Accent Gray Hierarchy", Version: "v26.26.12", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "SonarCloud Deep Sweep — String Constants & Regex Hardening", Version: "v26.26.12", Date: roadmapDateFeb2026, Type: strQuality},
                {Title: "SonarCloud Hotspot & Vulnerability Review — Full Audit Trail", Version: "v26.26.15", Date: roadmapDateFeb2026, Type: strQuality},
                {Title: "Zone Health — Context-Aware Policy & Security Signals", Version: strV262707, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Zone Health Golden Rules (9 Tests, 15 Sub-Tests)", Version: strV262707, Date: roadmapDateFeb2026, Type: strQuality},
                {Title: "Zone File Upload — Auth-Aware Size Limits (1 MB/2 MB)", Version: "v26.27.08", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Golden Rules Export (JSON + Markdown for External Audit)", Version: "v26.27.08", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "PWA Hardening (Offline Page, Page Cache, Splash Screens)", Version: strV262707, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Owl of Athena Logo (AI-Generated Original)", Version: roadmapVersionV2620, Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "TTL Tuner (Beta)", Version: "v26.25.86–88", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Six-Agent Security & Performance Audit", Version: "v26.25.88", Date: roadmapDateFeb2026, Type: strQuality},
                {Title: "TLD NS Count Bug Fix + Executive TLD Gating", Version: "v26.25.90", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "CSRF Form Fix (TTL Tuner & Watchlist)", Version: "v26.26.41", Date: roadmapDateFeb2026, Type: "Security"},
                {Title: "TTL Tuner UX Overhaul (Loading, Auto-Scroll, Profile Selection)", Version: "v26.26.42–43", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "DNS Provider Detection Expansion (5→15 Providers)", Version: "v26.26.44", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "NS Provider-Locked Display + Rate Limit Redirect Fix", Version: "v26.26.44", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "HTTP Observatory A+ Infrastructure (Secure Cookies, Full Header Suite)", Version: "v26.27.01", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Mobile Homepage Scroll Fix + Navbar Dropdown Refinement", Version: "v26.27.01", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "TTL Tuner Mobile Responsive Table", Version: "v26.27.02", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "SonarCloud Quality Gate Fixes (Unchecked Error Returns)", Version: "v26.27.02", Date: roadmapDateFeb2026, Type: strQuality},
                {Title: "RFC Compliance vs Operational Security Pattern (SPF/DKIM/DMARC)", Version: strV262836, Date: roadmapDateMar2026, Type: roadmapTypeFeature},
                {Title: "CVE Context in Email Security Panels (CVE-2024-7208/7209/49040)", Version: strV262836, Date: roadmapDateMar2026, Type: roadmapTypeFeature},
                {Title: "DMARCbis Forward-Looking Notes (Standards Track, pct→t, np=)", Version: strV262836, Date: roadmapDateMar2026, Type: roadmapTypeFeature},
                {Title: "DANE Context Deadline Fix", Version: "v26.28.34", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "DNS Intelligence Upgrade (EDNS0 + DO Bit, AD Flag Tracking)", Version: "v26.28.35", Date: roadmapDateFeb2026, Type: roadmapTypeFeature},
                {Title: "Topology Text & Container Sizing", Version: "v26.28.37", Date: roadmapDateMar2026, Type: roadmapTypeFeature},
                {Title: "Golden Fixtures Node Promoted to Cylinder", Version: "v26.28.38", Date: roadmapDateMar2026, Type: roadmapTypeFeature},
                {Title: "Action Pill Nodes (Persist, Seeds, Baselines, Validates)", Version: "v26.28.39", Date: roadmapDateMar2026, Type: roadmapTypeFeature},
                {Title: "Fully Responsive Zone-Based Layout with Collision Enforcement", Version: "v26.28.40", Date: roadmapDateMar2026, Type: roadmapTypeFeature},
                {Title: "Edge Labels Hover-Only, Explicit Protocol Angle Mapping", Version: "v26.28.41", Date: roadmapDateMar2026, Type: roadmapTypeFeature},
                {Title: "Unified OG Image System (6 images, ImageMagick generator)", Version: "v26.28.44", Date: roadmapDateMar2026, Type: roadmapTypeFeature},
                {Title: "Forgotten Domain Video (approach page + /video/forgotten-domain)", Version: "v26.28.44", Date: roadmapDateMar2026, Type: roadmapTypeFeature},
                {Title: "Performance Optimization (gzip, CSS/font preload hints)", Version: "v26.28.45", Date: roadmapDateMar2026, Type: roadmapTypeFeature},
                {Title: "Video Styling Fix (approach page — constrained width, poster)", Version: "v26.28.46", Date: roadmapDateMar2026, Type: roadmapTypeFeature},
                {Title: "Test Coverage Expansion (exports_ice, coverage_boost14, main)", Version: "v26.28.46", Date: roadmapDateMar2026, Type: strQuality},
                {Title: "Publications & Research Index Page", Version: "v26.38.02", Date: roadmapDateMar2026, Type: roadmapTypeFeature},
                {Title: "Case Study Index & Intelligence DMARC Case Study", Version: "v26.38.02", Date: roadmapDateMar2026, Type: roadmapTypeFeature},
                {Title: "Founder's Manifesto & Communication Standards (HTML + PDF)", Version: "v26.37.32", Date: roadmapDateMar2026, Type: roadmapTypeFeature},
                {Title: "ICSAE Standards Evaluation Engine (ISO 27001/27002, INCITS 585)", Version: "v26.37.16", Date: roadmapDateMar2026, Type: roadmapTypeFeature},
                {Title: "UX Palette Warm-Shift (Gold/Amber, WCAG AA, CSP Deep Audit)", Version: "v26.36.11", Date: roadmapDateMar2026, Type: strQuality},
                {Title: "Web3 Analysis Node & Topology Globe (ENS, HNS, IPFS)", Version: "v26.36.09", Date: roadmapDateMar2026, Type: roadmapTypeFeature},
                {Title: "ICAE Progress Bar Color Science Overhaul (Scotopic-Safe)", Version: strV263830, Date: roadmapDateMar2026, Type: strQuality},
                {Title: "SAST False-Positive Suppression (17 HIGH, 5-Scanner Tags)", Version: strV263830, Date: roadmapDateMar2026, Type: "Security"},
                {Title: "Off-Site Backup Automation (Daily Cron)", Version: strV263830, Date: roadmapDateMar2026, Type: "Security"},
                {Title: "Pre-Release Science Documentation Audit", Version: strV263830, Date: roadmapDateMar2026, Type: strQuality},
        }

        inProgress := []RoadmapItem{
                {Title: "Non-Authenticated Zone Upload (One-Time View)", Type: roadmapTypeFeature, Priority: priorityHigh, Notes: "Open zone upload to non-auth users with 1 MB limit, IP rate limiting, no persistence — funnel to signup"},
                {Title: "SonarCloud Coverage Push (80%+ Target)", Type: strQuality, Priority: priorityHigh, Notes: "Systematic coverage improvement across handlers, analyzer, dnsclient, and middleware packages"},
                {Title: "Visual Cohesion — Top-to-Bottom Consistency", Type: roadmapTypeFeature, Priority: strMedium, Notes: "Glass treatment, question branding, and token system across all report modes"},
                {Title: "Morse Code Easter Egg", Type: roadmapTypeFeature, Priority: priorityLow, Notes: "Web Audio API Morse code on Covert Mode toggle — 'GONNA HACK THE PLANET BUT FIRST I NEED A SICK HANDLE'"},
        }

        nextUp := []RoadmapItem{
                {Title: "Paid Storage Tier (TLD Operators)", Type: roadmapTypeFeature, Priority: priorityHigh, Notes: "Account storage quotas for serious operators — free users get persistence, paid tier expands storage for large zone files and history retention"},
                {Title: "Drift UI — Divergence Caveats", Type: roadmapTypeFeature, Priority: priorityHigh, Notes: "Label drift results as divergence with caveats for known false-positive edges (CNAME flattening, DNSSEC records, resolver TTL caching)"},
                {Title: "DoH/DoT Detection", Type: roadmapTypeFeature, Priority: priorityHigh, Notes: "Test whether domains support DNS-over-HTTPS (RFC 8484) and DNS-over-TLS (RFC 7858) — encrypted transport posture analysis"},
                {Title: "Distributed Probe Mesh (Good Net Citizens)", Type: roadmapTypeFeature, Priority: priorityHigh, Notes: "Volunteer browser-based DNS probes via DoH relay — multi-vantage consensus with Byzantine-resilient thresholds, reputation scoring, and privacy-preserving blinded work queues"},
                {Title: "API Access (Programmatic Analysis)", Type: roadmapTypeFeature, Priority: priorityHigh, Notes: "Programmatic analysis for automation workflows with rate limiting, authentication, versioning"},
                {Title: "CLI App (Homebrew/Binary)", Type: roadmapTypeFeature, Priority: priorityHigh, Notes: "Terminal application for macOS/Linux — works without login for basic analysis"},
        }

        backlog := []RoadmapItem{
                {Title: "Probe Network Expansion (Additional Nodes)", Type: roadmapTypeFeature, Priority: priorityHigh, Notes: "Additional OSINT verification nodes beyond current two-node deployment"},
                {Title: "Personal Analysis History", Type: roadmapTypeFeature, Priority: strMedium, Notes: "Per-user session tracking and analysis library"},
                {Title: "Drift Engine Alerts", Type: roadmapTypeFeature, Priority: strMedium, Notes: "Webhook/email notifications when domain security posture changes"},
                {Title: "Saved Reports", Type: roadmapTypeFeature, Priority: strMedium, Notes: "Bookmark and revisit past analyses with snapshot storage"},
                {Title: "Drift Engine Phases 3–4", Type: roadmapTypeFeature, Priority: strMedium, Notes: "Timeline visualization and scheduled monitoring with baselines"},
                {Title: "Probe Security.txt + Landing Pages", Type: roadmapTypeFeature, Priority: strMedium, Notes: "Transparency artifacts for probe VPS nodes"},
                {Title: "Homebrew Distribution", Type: roadmapTypeFeature, Priority: strMedium, Notes: "macOS/Linux package distribution for CLI app"},
                {Title: "CVE Database Matching", Type: roadmapTypeFeature, Priority: strMedium, Notes: "Automated CVE cross-referencing for protocol findings against NVD/MITRE"},
                {Title: "DMARCbis Standards Track Tracking", Type: roadmapTypeFeature, Priority: strMedium, Notes: "Monitor draft-ietf-dmarc-dmarcbis progression through IETF"},
                {Title: "TLD Zone Health: Multi-Vantage Availability", Type: roadmapTypeFeature, Priority: strMedium, Notes: "Global latency distribution, timeout/SERVFAIL rates, regional anomalies"},
                {Title: "TLD Zone Health: Pre-Delegation Simulation", Type: roadmapTypeFeature, Priority: strMedium, Notes: "Zonemaster-style delegation quality testing and ICANN PDT readiness"},
                {Title: "TLD Zone Health: Change Detection & Alerting", Type: roadmapTypeFeature, Priority: strMedium, Notes: "Registry-specific drift with alerts on DS mismatch, DNSKEY changes, SOA serial divergence"},
                {Title: "Globalping.io Integration", Type: roadmapTypeFeature, Priority: priorityLow, Notes: "Distributed DNS resolution from 100+ global locations"},
                {Title: "Zone File Import as Drift Baseline", Type: roadmapTypeFeature, Priority: priorityLow, Notes: "Upload zone files to establish posture baseline for drift detection"},
                {Title: "Raw Intelligence API Access", Type: roadmapTypeFeature, Priority: priorityLow, Notes: "Direct access to collected intelligence without processing layers"},
                {Title: "ISC Recommendation Path Integration", Type: roadmapTypeFeature, Priority: priorityLow, Notes: "Integration with ISC remediation/hardening recommendations"},
                {Title: "TLD Zone Health: Machine-Consumable Outputs", Type: roadmapTypeFeature, Priority: priorityLow, Notes: "Stable versioned JSON API for current TLD status, webhook events for state transitions"},
                {Title: "TLD Zone Health: Registry Identification", Type: roadmapTypeFeature, Priority: priorityLow, Notes: "Show registry operator + IANA metadata"},
        }

        data := gin.H{
                keyAppVersion:      h.Config.AppVersion,
                keyMaintenanceNote: h.Config.MaintenanceNote,
                keyBetaPages:       h.Config.BetaPages,
                keyCspNonce:        nonce,
                keyActivePage:      "roadmap",
                "Done":            done,
                "DoneCount":       len(done),
                "InProgress":      inProgress,
                "InProgressCount": len(inProgress),
                "NextUp":          nextUp,
                "NextUpCount":     len(nextUp),
                "Backlog":         backlog,
                "BacklogCount":    len(backlog),
        }
        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, "roadmap.html", data)
}
