// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "context"
        "fmt"
        "html/template"
        "log/slog"
        "net/http"
        "net/url"
        "strings"
        "time"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/dnsclient"

        "github.com/gin-gonic/gin"
)

const (
        agentContentTypeHTML  = "text/html; charset=utf-8"
        agentFmtWayback       = "%s/agent/wayback?domain=%s"
        agentFmtAnalyzeSrc    = "%s/analyze?domain=%s&src=agent"
        agentFmtAnalyze       = "%s/analyze?domain=%s"
        agentErrMissingDomain = "missing domain parameter"
        agentErrInvalidDomain = "invalid domain"
        agentErrNotFound      = "not found"
)

type AgentSaveFn func(ctx context.Context, domain, asciiDomain string, results map[string]any) int32

type AgentHandler struct {
        Config      *config.Config
        Analyzer    *analyzer.Analyzer
        lookupStore LookupStore
        SaveFn      AgentSaveFn
}

func NewAgentHandler(cfg *config.Config, a *analyzer.Analyzer, store ...LookupStore) *AgentHandler {
        h := &AgentHandler{Config: cfg, Analyzer: a}
        if len(store) > 0 {
                h.lookupStore = store[0]
        }
        return h
}

func (h *AgentHandler) OpenSearchXML(c *gin.Context) {
        baseURL := h.Config.BaseURL
        xml := `<?xml version="1.0" encoding="UTF-8"?>
<OpenSearchDescription xmlns="http://a9.com/-/spec/opensearch/1.1/">
  <ShortName>DNS Tool</ShortName>
  <Description>DNS Security Intelligence — RFC-grounded domain analysis by IT Help San Diego Inc.</Description>
  <Tags>dns security subdomain certificate transparency DMARC SPF DKIM</Tags>
  <Contact>security@it-help.tech</Contact>
  <Url type="text/html" method="get" template="` + baseURL + `/agent/search?q={searchTerms}"/>
  <Url type="application/json" method="get" template="` + baseURL + `/agent/api?q={searchTerms}"/>
  <Image height="48" width="48" type="image/png">` + baseURL + `/static/icons/favicon-48x48.png</Image>
  <LongName>DNS Tool — Engineer's DNS Intelligence Report</LongName>
  <Attribution>Copyright (c) 2024-2026 IT Help San Diego Inc. Concept DOI: 10.5281/zenodo.18854899</Attribution>
  <SyndicationRight>open</SyndicationRight>
  <AdultContent>false</AdultContent>
  <Language>en-us</Language>
  <OutputEncoding>UTF-8</OutputEncoding>
  <InputEncoding>UTF-8</InputEncoding>
</OpenSearchDescription>`

        c.Header(headerCacheControl, "public, max-age=86400")
        c.Data(http.StatusOK, "application/opensearchdescription+xml; charset=utf-8", []byte(xml))
}

func extractAgentQuery(c *gin.Context) string {
        for _, key := range []string{"q", "domain", "query", "search", "searchTerms"} {
                if v := strings.TrimSpace(c.Query(key)); v != "" {
                        return cleanAgentQuery(v)
                }
        }
        return ""
}

func cleanAgentQuery(q string) string {
        q = strings.ToLower(strings.TrimSpace(q))
        q = strings.Trim(q, "_ \t")
        q = strings.Trim(q, `"'`)
        q = strings.Trim(q, "_ \t")
        return q
}

func (h *AgentHandler) AgentSearch(c *gin.Context) {
        slog.Info("Agent search request",
                "raw_query", c.Request.URL.RawQuery,
                "full_url", c.Request.URL.String(),
                "remote_addr", c.ClientIP(),
                "user_agent", c.Request.UserAgent())

        domain := extractAgentQuery(c)
        if domain == "" {
                base := h.Config.BaseURL
                c.Data(http.StatusOK, agentContentTypeHTML,
                        []byte(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>DNS Tool — Agent Search</title>`+
                                `<link rel="search" type="application/opensearchdescription+xml" title="DNS Tool" href="`+base+`/agent/opensearch.xml">`+
                                `</head><body><h1>DNS Tool — Agent Search</h1>`+
                                `<p>Usage: <code>`+base+`/agent/search?q=example.com</code></p>`+
                                `<ul>`+
                                `<li><a href="`+base+`/agent/search?q=it-help.tech">Analyze it-help.tech</a></li>`+
                                `<li><a href="`+base+`/agent/search?q=apple.com">Analyze apple.com</a></li>`+
                                `<li><a href="`+base+`/agent/search?q=red.com">Analyze red.com</a></li>`+
                                `<li><a href="`+base+`">DNS Tool Home</a></li>`+
                                `<li><a href="`+base+`/agent/opensearch.xml">OpenSearch Descriptor</a></li>`+
                                `</ul></body></html>`))
                return
        }

        if !dnsclient.ValidateDomain(domain) && !analyzer.IsWeb3Input(domain) {
                c.Data(http.StatusBadRequest, agentContentTypeHTML,
                        []byte(fmt.Sprintf(`<!DOCTYPE html><html><head><title>DNS Tool Agent — Error</title></head><body><h1>Error</h1><p>Invalid domain: %s</p></body></html>`,
                                template.HTMLEscapeString(domain))))
                return
        }

        asciiDomain, err := dnsclient.DomainToASCII(domain)
        if err != nil {
                asciiDomain = domain
        }

        analysisCtx, analysisCancel := context.WithTimeout(context.Background(), 90*time.Second)
        defer analysisCancel()
        results := h.Analyzer.AnalyzeDomain(analysisCtx, asciiDomain, nil, analyzer.AnalysisOptions{})

        analysisSuccess := true
        if s, ok := results["analysis_success"].(bool); ok {
                analysisSuccess = s
        }

        if !analysisSuccess {
                errMsg := "Analysis failed"
                if e, ok := results["error"].(string); ok {
                        errMsg = e
                }
                c.Data(http.StatusOK, agentContentTypeHTML,
                        []byte(fmt.Sprintf(`<!DOCTYPE html><html><head><title>DNS Tool Agent — %s</title></head><body><h1>DNS Tool — %s</h1><p>%s</p></body></html>`,
                                template.HTMLEscapeString(asciiDomain),
                                template.HTMLEscapeString(asciiDomain),
                                template.HTMLEscapeString(errMsg))))
                return
        }

        var analysisID int32
        if h.SaveFn != nil {
                analysisID = h.SaveFn(c.Request.Context(), domain, asciiDomain, results)
                slog.Info("Agent search: analysis saved", "domain", asciiDomain, "analysis_id", analysisID)
        }
        if analysisID == 0 && h.lookupStore != nil {
                if recent, err := h.lookupStore.GetRecentAnalysisByDomain(c.Request.Context(), asciiDomain); err == nil {
                        analysisID = recent.ID
                }
        }

        html := h.buildAgentHTML(asciiDomain, results, analysisID)
        c.Data(http.StatusOK, agentContentTypeHTML, []byte(html))
}

func (h *AgentHandler) AgentAPI(c *gin.Context) {
        domain := extractAgentQuery(c)
        if domain == "" {
                c.JSON(http.StatusBadRequest, gin.H{"error": "Missing query parameter: q (domain name required)"})
                return
        }

        if !dnsclient.ValidateDomain(domain) && !analyzer.IsWeb3Input(domain) {
                c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid domain format"})
                return
        }

        asciiDomain, err := dnsclient.DomainToASCII(domain)
        if err != nil {
                asciiDomain = domain
        }

        apiCtx, apiCancel := context.WithTimeout(context.Background(), 90*time.Second)
        defer apiCancel()
        results := h.Analyzer.AnalyzeDomain(apiCtx, asciiDomain, nil, analyzer.AnalysisOptions{})

        analysisSuccess := true
        if s, ok := results["analysis_success"].(bool); ok {
                analysisSuccess = s
        }

        if !analysisSuccess {
                errMsg := "Analysis failed"
                if e, ok := results["error"].(string); ok {
                        errMsg = e
                }
                c.JSON(http.StatusOK, gin.H{
                        "domain": asciiDomain,
                        "error":  errMsg,
                        "status": "failed",
                })
                return
        }

        response := h.buildAgentJSON(asciiDomain, results)
        c.JSON(http.StatusOK, response)
}

func safeString(m map[string]any, key string) string {
        if v, ok := m[key].(string); ok {
                return v
        }
        return ""
}

func safeInt(m map[string]any, key string) int {
        switch v := m[key].(type) {
        case int:
                return v
        case int64:
                return int(v)
        case float64:
                return int(v)
        }
        return 0
}

func safeBool(m map[string]any, key string) bool {
        if v, ok := m[key].(bool); ok {
                return v
        }
        return false
}

func safeMap(m map[string]any, key string) map[string]any {
        if v, ok := m[key].(map[string]any); ok {
                return v
        }
        return nil
}

func safeFloat64(m map[string]any, key string) float64 {
        switch v := m[key].(type) {
        case float64:
                return v
        case int:
                return float64(v)
        case int64:
                return float64(v)
        }
        return 0
}

func extractVerdict(m map[string]any, fallback string) string {
        if m == nil {
                return agentErrNotFound
        }
        v := safeString(m, "status")
        if v == "" {
                v = safeString(m, "verdict")
        }
        if v == "" {
                return fallback
        }
        return v
}

func extractDNSSECStatus(results map[string]any) string {
        dnssec := safeMap(results, "dnssec_analysis")
        if dnssec == nil {
                return "unknown"
        }
        if safeBool(dnssec, "signed") {
                return "signed"
        }
        return "unsigned"
}

func extractPosture(results map[string]any) (int, string, string) {
        posture := safeMap(results, "posture")
        if posture == nil {
                return 0, "N/A", ""
        }
        return int(safeFloat64(posture, "score")), safeString(posture, "grade"), safeString(posture, "label")
}

func (h *AgentHandler) buildAgentJSON(domain string, results map[string]any) gin.H {
        spf := safeMap(results, "spf_analysis")
        dmarc := safeMap(results, "dmarc_analysis")
        dkim := safeMap(results, "dkim_analysis")
        subdomains := safeMap(results, "subdomain_discovery")

        spfVerdict := extractVerdict(spf, "missing")

        dmarcVerdict := extractVerdict(dmarc, "missing")
        dmarcPolicy := "none"
        if dmarc != nil {
                dmarcPolicy = safeString(dmarc, "policy")
                if dmarcPolicy == "" {
                        dmarcPolicy = "none"
                }
        }

        dkimVerdict := extractVerdict(dkim, "not detected")

        subdomainCount := 0
        certCount := 0
        cnameCount := 0
        if subdomains != nil {
                subdomainCount = safeInt(subdomains, "unique_subdomains")
                certCount = safeInt(subdomains, "unique_certs")
                cnameCount = safeInt(subdomains, "cname_count")
        }

        riskLevel := safeString(results, "risk_level")
        domainExists := safeBool(results, "domain_exists")
        dnssecStatus := extractDNSSECStatus(results)

        mtaSTSMode := "none"
        if mtaSTS := safeMap(results, "mta_sts_analysis"); mtaSTS != nil {
                mtaSTSMode = safeString(mtaSTS, "mode")
        }

        bimiPresent := false
        if bimi := safeMap(results, "bimi_analysis"); bimi != nil {
                bimiPresent = safeBool(bimi, "has_bimi")
        }

        caaPresent := false
        if caa := safeMap(results, "caa_analysis"); caa != nil {
                caaPresent = safeBool(caa, "has_caa")
        }

        postureScore, postureGrade, postureLabel := extractPosture(results)

        base := h.Config.BaseURL
        analyzeURL := fmt.Sprintf(agentFmtAnalyze, base, domain)
        waybackURL := fmt.Sprintf(agentFmtWayback, base, domain)

        return gin.H{
                "tool":       "DNS Tool",
                "version":    h.Config.AppVersion,
                "timestamp":  time.Now().UTC().Format(time.RFC3339),
                "domain":     domain,
                "status":     "success",
                "summary": gin.H{
                        "domain_exists":  domainExists,
                        "risk_level":     riskLevel,
                        "posture_score":  postureScore,
                        "posture_grade":  postureGrade,
                        "posture_label":  postureLabel,
                },
                "links": gin.H{
                        "report":          analyzeURL,
                        "report_page":     fmt.Sprintf(agentFmtAnalyzeSrc, base, domain),
                        "snapshot":        fmt.Sprintf("%s/snapshot/%s", base, domain),
                        "topology":        fmt.Sprintf("%s/topology?domain=%s", base, domain),
                        "wayback_archive": waybackURL,
                        "wayback_page":    fmt.Sprintf(agentFmtWayback, base, domain),
                        "api_json":        fmt.Sprintf("%s/agent/api?q=%s", base, domain),
                        "csv_export":      fmt.Sprintf("%s/export/subdomains?domain=%s&format=csv", base, domain),
                        "sources":         fmt.Sprintf("%s/sources", base),
                        "zenodo_doi":      "https://doi.org/10.5281/zenodo.18854899",
                },
                "badges": gin.H{
                        "detailed_svg":  fmt.Sprintf("%s/badge?domain=%s&style=detailed", base, domain),
                        "covert_svg":    fmt.Sprintf("%s/badge?domain=%s&style=covert", base, domain),
                        "flat_svg":      fmt.Sprintf("%s/badge?domain=%s", base, domain),
                        "shields_io":    fmt.Sprintf("%s/badge/shields?domain=%s", base, domain),
                        "animated_svg":  fmt.Sprintf("%s/badge/animated?domain=%s", base, domain),
                        "embed_page":    fmt.Sprintf("%s/badge/embed", base),
                        "detailed_page": fmt.Sprintf("%s/agent/badge-view?domain=%s&style=detailed", base, domain),
                        "covert_page":   fmt.Sprintf("%s/agent/badge-view?domain=%s&style=covert", base, domain),
                        "flat_page":     fmt.Sprintf("%s/agent/badge-view?domain=%s&style=flat", base, domain),
                },
                "email_authentication": gin.H{
                        "spf":   gin.H{"status": spfVerdict},
                        "dkim":  gin.H{"status": dkimVerdict},
                        "dmarc": gin.H{"status": dmarcVerdict, "policy": dmarcPolicy},
                        "bimi":  gin.H{"present": bimiPresent},
                },
                "transport_security": gin.H{
                        "mta_sts": gin.H{"mode": mtaSTSMode},
                        "dnssec":  gin.H{"status": dnssecStatus},
                        "caa":     gin.H{"present": caaPresent},
                },
                "subdomain_discovery": gin.H{
                        "subdomains_found": subdomainCount,
                        "certificates":     certCount,
                        "cnames":           cnameCount,
                },
                "provenance": gin.H{
                        "tool":           "DNS Tool by IT Help San Diego Inc.",
                        "methodology":    "RFC-grounded analysis with Bayesian confidence scoring",
                        "concept_doi":    "10.5281/zenodo.18854899",
                        "doi_url":        "https://doi.org/10.5281/zenodo.18854899",
                        "license":        "BUSL-1.1",
                        "publisher":      "IT Help San Diego Inc.",
                        "publisher_url":  "https://it-help.tech",
                        "issn":           "",
                },
        }
}

func esc(s string) string {
        return template.HTMLEscapeString(s)
}

func safeInternalURL(base, path string, params map[string]string) string {
        u, err := url.Parse(base)
        if err != nil {
                u = &url.URL{Path: "/"}
        }
        u.Path = path
        q := u.Query()
        for k, v := range params {
                q.Set(k, v)
        }
        u.RawQuery = q.Encode()
        return u.String()
}

type agentHTMLData struct {
        riskLevel, postureGrade, postureLabel   string
        postureScore                            int
        spfStatus, dkimStatus, dmarcStatus      string
        dmarcPolicy, dnssecStatus, mtaSTSMode   string
        bimiPresent, caaPresent                 bool
        subCount, certCountVal, cnameCountVal   int
}

func extractSummaryData(d *agentHTMLData, j gin.H) {
        summary, ok := j["summary"].(gin.H)
        if !ok {
                return
        }
        if rl, ok := summary["risk_level"].(string); ok && rl != "" {
                d.riskLevel = rl
        }
        d.postureScore, _ = summary["posture_score"].(int)
        if pg, ok := summary["posture_grade"].(string); ok {
                d.postureGrade = pg
        }
        if pl, ok := summary["posture_label"].(string); ok {
                d.postureLabel = pl
        }
}

func extractEmailAuthData(d *agentHTMLData, j gin.H) {
        emailAuth, ok := j["email_authentication"].(gin.H)
        if !ok {
                return
        }
        d.spfStatus = extractNestedStatus(emailAuth, "spf")
        d.dkimStatus = extractNestedStatus(emailAuth, "dkim")
        d.dmarcStatus = extractNestedStatus(emailAuth, "dmarc")
        if dm, ok := emailAuth["dmarc"].(gin.H); ok {
                if p, ok := dm["policy"].(string); ok && p != "" {
                        d.dmarcPolicy = p
                }
        }
        if b, ok := emailAuth["bimi"].(gin.H); ok {
                d.bimiPresent, _ = b["present"].(bool)
        }
}

func extractTransportData(d *agentHTMLData, j gin.H) {
        transport, ok := j["transport_security"].(gin.H)
        if !ok {
                return
        }
        d.dnssecStatus = extractNestedStatus(transport, "dnssec")
        if m, ok := transport["mta_sts"].(gin.H); ok {
                if mode, ok := m["mode"].(string); ok && mode != "" {
                        d.mtaSTSMode = mode
                }
        }
        if ca, ok := transport["caa"].(gin.H); ok {
                d.caaPresent, _ = ca["present"].(bool)
        }
}

func extractHTMLData(j gin.H) agentHTMLData {
        d := agentHTMLData{riskLevel: "Unknown", postureGrade: "N/A", dmarcPolicy: "none", mtaSTSMode: "none"}
        extractSummaryData(&d, j)
        extractEmailAuthData(&d, j)
        extractTransportData(&d, j)
        if sd, ok := j["subdomain_discovery"].(gin.H); ok {
                d.subCount, _ = sd["subdomains_found"].(int)
                d.certCountVal, _ = sd["certificates"].(int)
                d.cnameCountVal, _ = sd["cnames"].(int)
        }
        return d
}

func (h *AgentHandler) buildAgentHTML(domain string, results map[string]any, analysisID int32) string {
        j := h.buildAgentJSON(domain, results)
        d := extractHTMLData(j)

        links := j["links"].(gin.H)
        badges := j["badges"].(gin.H)

        ed := esc(domain)
        base := h.Config.BaseURL
        reportURL := esc(links["report"].(string))
        snapshotURL := esc(links["snapshot"].(string))
        topologyURL := esc(links["topology"].(string))
        apiURL := esc(links["api_json"].(string))
        reportPageURL := esc(fmt.Sprintf(agentFmtAnalyzeSrc, base, domain))
        badgeDetailed := esc(badges["detailed_svg"].(string))
        badgeCovert := esc(badges["covert_svg"].(string))
        badgeViewDetailed := esc(fmt.Sprintf("%s/agent/badge-view?domain=%s&style=detailed", base, domain))
        badgeViewCovert := esc(fmt.Sprintf("%s/agent/badge-view?domain=%s&style=covert", base, domain))
        csvExportURL := esc(fmt.Sprintf("%s/export/subdomains?domain=%s&format=csv", base, domain))
        sourcesURL := esc(fmt.Sprintf("%s/sources", base))
        waybackViewURL := esc(fmt.Sprintf(agentFmtWayback, base, domain))
        confidenceURL := esc(fmt.Sprintf("%s/confidence", base))

        var checksumURL, remediationURL, covertReportURL, executiveReportURL string
        if analysisID > 0 {
                checksumURL = esc(fmt.Sprintf("%s/api/analysis/%d/checksum", base, analysisID))
                remediationURL = esc(fmt.Sprintf("%s/remediation?analysis_id=%d", base, analysisID))
                covertReportURL = esc(fmt.Sprintf("%s/analysis/%d/view/C", base, analysisID))
                executiveReportURL = esc(fmt.Sprintf("%s/analysis/%d/executive", base, analysisID))
        } else {
                checksumURL = esc(fmt.Sprintf(agentFmtAnalyzeSrc, base, domain))
                remediationURL = esc(fmt.Sprintf("%s/remediation?domain=%s", base, domain))
                covertReportURL = esc(fmt.Sprintf(agentFmtAnalyzeSrc, base, domain))
                executiveReportURL = esc(fmt.Sprintf(agentFmtAnalyzeSrc, base, domain))
        }

        now := time.Now().UTC()
        isoDate := now.Format("2006-01-02")
        isoTimestamp := now.Format(time.RFC3339)

        var sb strings.Builder
        sb.WriteString(`<!DOCTYPE html>
<html lang="en" prefix="og: http://ogp.me/ns# DC: http://purl.org/dc/elements/1.1/ DCTERMS: http://purl.org/dc/terms/">
<head>
  <meta charset="UTF-8">
  <title>DNS Tool — ` + ed + ` — DNS Security Intelligence Report</title>
  <meta name="description" content="DNS Security Intelligence Report for ` + ed + ` — Risk: ` + esc(d.riskLevel) + `, Posture: ` + fmt.Sprintf("%d", d.postureScore) + `/100 (` + esc(d.postureGrade) + `)">
  <meta name="generator" content="DNS Tool ` + esc(h.Config.AppVersion) + `">
  <meta name="robots" content="noindex, noarchive">
  <link rel="search" type="application/opensearchdescription+xml" title="DNS Tool" href="` + esc(base) + `/agent/opensearch.xml">

  <!-- Dublin Core metadata (Zotero, Mendeley, citation managers) -->
  <meta name="DC.title" content="DNS Security Intelligence Report: ` + ed + `">
  <meta name="DC.creator" content="DNS Tool by IT Help San Diego Inc.">
  <meta name="DC.publisher" content="IT Help San Diego Inc.">
  <meta name="DC.date" content="` + isoDate + `">
  <meta name="DC.type" content="Dataset">
  <meta name="DC.format" content="text/html">
  <meta name="DC.identifier" content="` + reportURL + `">
  <meta name="DC.relation" content="https://doi.org/10.5281/zenodo.18854899">
  <meta name="DC.rights" content="BUSL-1.1">
  <meta name="DC.subject" content="DNS; email security; SPF; DKIM; DMARC; DNSSEC; subdomain discovery; certificate transparency">
  <meta name="DC.language" content="en">
  <meta name="DCTERMS.issued" content="` + isoDate + `">

  <!-- Highwire Press tags (Google Scholar, Zotero) -->
  <meta name="citation_title" content="DNS Security Intelligence Report: ` + ed + `">
  <meta name="citation_author" content="IT Help San Diego Inc.">
  <meta name="citation_publication_date" content="` + isoDate + `">
  <meta name="citation_online_date" content="` + isoDate + `">
  <meta name="citation_doi" content="10.5281/zenodo.18854899">
  <meta name="citation_publisher" content="IT Help San Diego Inc.">
  <meta name="citation_technical_report_institution" content="IT Help San Diego Inc.">
  <meta name="citation_public_url" content="` + reportURL + `">

  <!-- Open Graph (social sharing, DEVONthink) -->
  <meta property="og:title" content="DNS Tool — ` + ed + `">
  <meta property="og:description" content="Risk: ` + esc(d.riskLevel) + ` | Posture: ` + fmt.Sprintf("%d", d.postureScore) + `/100 (` + esc(d.postureGrade) + `) | ` + fmt.Sprintf("%d", d.subCount) + ` subdomains">
  <meta property="og:type" content="article">
  <meta property="og:url" content="` + reportURL + `">
  <meta property="og:image" content="` + badgeDetailed + `">
  <meta property="og:site_name" content="DNS Tool">
  <meta property="article:published_time" content="` + isoTimestamp + `">
</head>
<body>

<!-- COinS span for Zotero one-click capture -->
<span class="Z3988" title="ctx_ver=Z39.88-2004&amp;rft_val_fmt=info%3Aofi%2Ffmt%3Akev%3Amtx%3Adc&amp;rft.type=Dataset&amp;rft.title=DNS+Security+Intelligence+Report%3A+` + esc(domain) + `&amp;rft.creator=IT+Help+San+Diego+Inc.&amp;rft.date=` + isoDate + `&amp;rft.identifier=` + esc(reportURL) + `&amp;rft.relation=https%3A%2F%2Fdoi.org%2F10.5281%2Fzenodo.18854899&amp;rft.publisher=IT+Help+San+Diego+Inc.&amp;rft.rights=BUSL-1.1&amp;rft.subject=DNS+security&amp;rft.format=text%2Fhtml"></span>

<h1>DNS Tool — ` + ed + `</h1>

<h2>Summary</h2>
<table>
  <tr><th>Metric</th><th>Value</th></tr>
  <tr><td>Risk Level</td><td>` + esc(d.riskLevel) + `</td></tr>
  <tr><td>Posture Score</td><td>` + fmt.Sprintf("%d/100", d.postureScore) + `</td></tr>
  <tr><td>Posture Grade</td><td>` + esc(d.postureGrade) + `</td></tr>
  <tr><td>Posture Label</td><td>` + esc(d.postureLabel) + `</td></tr>
</table>

<h2>Reports &amp; Intelligence</h2>
<ol>
  <li><a href="` + reportPageURL + `">Engineer's DNS Intelligence Report</a> — full security analysis with live scanning (the engineering report)</li>
  <li><a href="` + snapshotURL + `">Observed Records Snapshot</a> — reconstructed zone file, SHA-3-512 verified</li>
  <li><a href="` + badgeViewDetailed + `" title="DNS Tool Detailed Security Badge for ` + ed + `">Detailed Security Badge</a> — full posture badge (<img src="` + badgeDetailed + `" alt="Detailed Badge" width="300">)</li>
  <li><a href="` + badgeViewCovert + `" title="DNS Tool Covert Security Badge for ` + ed + `">Covert Security Badge</a> — scotopic-optimized badge (<img src="` + badgeCovert + `" alt="Covert Badge" width="200">)</li>
  <li><a href="` + covertReportURL + `">Covert Recon Report</a> — full analysis in covert operations mode</li>
  <li><a href="` + executiveReportURL + `">Executive Intelligence Brief</a> — board-ready executive summary</li>
  <li><a href="` + topologyURL + `">DNS Topology</a> — topology visualization, signal flow, and RFC source mapping</li>
  <li><a href="https://doi.org/10.5281/zenodo.18854899">Zenodo — Concept DOI</a> — permanent scientific record (10.5281/zenodo.18854899)</li>
  <li><a href="` + apiURL + `">Full Intelligence Data (JSON)</a> — complete analysis payload with all collected intelligence</li>
  <li><a href="` + csvExportURL + `">Discovered Domains &amp; Subdomains</a> — human-readable subdomain reconnaissance data (CSV)</li>
  <li><a href="` + sourcesURL + `">Sources &amp; Methodology</a> — RFC citations, data sources, and scoring methodology</li>
  <li><a href="` + checksumURL + `">SHA-3 Integrity Checksum</a> — cryptographic verification of analysis data</li>
  <li><a href="` + remediationURL + `">Security Remediation Plan</a> — actionable remediation steps for this domain</li>
  <li><a href="` + waybackViewURL + `">Internet Archive (Wayback Machine)</a> — permanent archived record of the analysis</li>
  <li><a href="` + confidenceURL + `">Confidence Page</a> — SHA-3 hash audit, integrity timestamps, and analysis confidence metrics</li>
</ol>`)

        sb.WriteString(`

<h2>Email Authentication</h2>
<table>
  <tr><th>Control</th><th>Status</th></tr>
  <tr><td>SPF</td><td>` + esc(d.spfStatus) + `</td></tr>
  <tr><td>DKIM</td><td>` + esc(d.dkimStatus) + `</td></tr>
  <tr><td>DMARC</td><td>` + esc(d.dmarcStatus) + ` (policy: ` + esc(d.dmarcPolicy) + `)</td></tr>
  <tr><td>BIMI</td><td>` + boolToPresence(d.bimiPresent) + `</td></tr>
</table>

<h2>Transport Security</h2>
<table>
  <tr><th>Control</th><th>Status</th></tr>
  <tr><td>DNSSEC</td><td>` + esc(d.dnssecStatus) + `</td></tr>
  <tr><td>MTA-STS</td><td>` + esc(d.mtaSTSMode) + `</td></tr>
  <tr><td>CAA</td><td>` + boolToPresence(d.caaPresent) + `</td></tr>
</table>

<h2>Subdomain Discovery</h2>
<table>
  <tr><th>Metric</th><th>Value</th></tr>
  <tr><td>Subdomains Found</td><td>` + fmt.Sprintf("%d", d.subCount) + `</td></tr>
  <tr><td>Unique Certificates</td><td>` + fmt.Sprintf("%d", d.certCountVal) + `</td></tr>
  <tr><td>CNAME Records</td><td>` + fmt.Sprintf("%d", d.cnameCountVal) + `</td></tr>
</table>

<h2>Provenance &amp; Citation</h2>
<p>
  <strong>Tool:</strong> DNS Tool by <a href="https://it-help.tech">IT Help San Diego Inc.</a><br>
  <strong>Methodology:</strong> RFC-grounded analysis with Bayesian confidence scoring<br>
  <strong>Concept DOI:</strong> <a href="https://doi.org/10.5281/zenodo.18854899">10.5281/zenodo.18854899</a><br>
  <strong>Version:</strong> ` + esc(h.Config.AppVersion) + `<br>
  <strong>License:</strong> BUSL-1.1<br>
  <strong>Timestamp:</strong> <time datetime="` + isoTimestamp + `">` + isoTimestamp + `</time>
</p>
</body>
</html>`)

        return sb.String()
}

func extractNestedStatus(parent gin.H, key string) string {
        if m, ok := parent[key].(gin.H); ok {
                if s, ok := m["status"].(string); ok {
                        return s
                }
        }
        return "unknown"
}

func boolToPresence(b bool) string {
        if b {
                return "present"
        }
        return agentErrNotFound
}

func (h *AgentHandler) BadgeView(c *gin.Context) {
        domain := extractAgentQuery(c)
        if domain == "" {
                c.String(http.StatusBadRequest, agentErrMissingDomain)
                return
        }
        if !dnsclient.ValidateDomain(domain) {
                c.String(http.StatusBadRequest, agentErrInvalidDomain)
                return
        }

        style := strings.TrimSpace(c.Query("style"))
        if style == "" {
                style = "detailed"
        }
        switch style {
        case "detailed", "covert", "flat":
        default:
                style = "detailed"
        }

        base := h.Config.BaseURL
        ed := esc(domain)
        es := esc(style)

        badgeURL := fmt.Sprintf("%s/badge?domain=%s", base, domain)
        if style != "flat" {
                badgeURL += "&style=" + style
        }
        eb := esc(badgeURL)
        reportURL := esc(fmt.Sprintf(agentFmtAnalyze, base, domain))

        styleName := style
        if style == "flat" {
                styleName = "compact"
        }

        var sb strings.Builder
        sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>DNS Security Badge (` + es + `) — ` + ed + ` — DNS Tool</title>
  <meta name="description" content="` + es + ` DNS security posture badge for ` + ed + ` — generated by DNS Tool.">
  <meta name="robots" content="noindex, noarchive">
  <meta property="og:title" content="DNS Security Badge (` + es + `) — ` + ed + `">
  <meta property="og:description" content="DNS security posture badge for ` + ed + `.">
  <meta property="og:type" content="article">
  <meta property="og:image" content="` + eb + `">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 2rem; }
    .container { max-width: 800px; margin: 0 auto; }
    h1 { font-size: 1.4rem; margin-bottom: .5rem; }
    .meta { color: #8b949e; font-size: .85rem; margin-bottom: 1.5rem; }
    .meta a { color: #58a6ff; text-decoration: none; }
    .meta a:hover { text-decoration: underline; }
    .badge-frame { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; text-align: center; }
    .badge-frame img { max-width: 100%; height: auto; pointer-events: none; }
    .badge-frame a { display: block; }
    .links { margin-top: 1.5rem; font-size: .9rem; }
    .links a { color: #58a6ff; text-decoration: none; margin-right: 1.5rem; }
    .links a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="container">
    <h1>DNS Security Badge — ` + ed + `</h1>
    <p class="meta">Style: <strong>` + esc(styleName) + `</strong> · Generated by <a href="` + esc(base) + `">DNS Tool</a> · <a href="` + reportURL + `">View full report →</a></p>
    <div class="badge-frame">
      <a href="` + reportURL + `"><img src="` + eb + `" alt="DNS Tool ` + es + ` security badge for ` + ed + `" style="max-width:100%;height:auto"></a>
    </div>
    <div class="links">
      <a href="` + reportURL + `">Full Analysis Report</a>
      <a href="` + eb + `">Direct Badge SVG</a>
      <a href="` + esc(fmt.Sprintf("%s/badge/embed", base)) + `">Badge Generator</a>
    </div>
  </div>
</body>
</html>`)

        c.Data(http.StatusOK, agentContentTypeHTML, []byte(sb.String()))
}

func (h *AgentHandler) WaybackView(c *gin.Context) {
        domain := extractAgentQuery(c)
        if domain == "" {
                c.String(http.StatusBadRequest, agentErrMissingDomain)
                return
        }
        if !dnsclient.ValidateDomain(domain) {
                c.String(http.StatusBadRequest, agentErrInvalidDomain)
                return
        }

        base := h.Config.BaseURL

        if h.lookupStore != nil {
                if recent, err := h.lookupStore.GetRecentAnalysisByDomain(c.Request.Context(), domain); err == nil {
                        if recent.WaybackUrl != nil && *recent.WaybackUrl != "" && strings.HasPrefix(*recent.WaybackUrl, "https://web.archive.org/") {
                                c.Redirect(http.StatusFound, *recent.WaybackUrl)
                                return
                        }
                }
        }

        c.Redirect(http.StatusFound, safeInternalURL(base, "/analyze", map[string]string{"domain": domain}))
}

func (h *AgentHandler) ReportView(c *gin.Context) {
        domain := extractAgentQuery(c)
        if domain == "" {
                c.String(http.StatusBadRequest, agentErrMissingDomain)
                return
        }
        if !dnsclient.ValidateDomain(domain) {
                c.String(http.StatusBadRequest, agentErrInvalidDomain)
                return
        }
        c.Redirect(http.StatusMovedPermanently, safeInternalURL("", "/analyze", map[string]string{"domain": domain}))
}

func extractRecordStrings(results map[string]any, section string) []string {
        sec, ok := results[section].(map[string]any)
        if !ok {
                return nil
        }
        for _, key := range []string{"records", "txt_records", "values", "mechanisms"} {
                if arr, ok := sec[key].([]any); ok {
                        out := make([]string, 0, len(arr))
                        for _, v := range arr {
                                if s, ok := v.(string); ok && s != "" {
                                        out = append(out, s)
                                }
                        }
                        if len(out) > 0 {
                                return out
                        }
                }
        }
        return nil
}

func extractMapField(results map[string]any, section, field string) string {
        sec, ok := results[section].(map[string]any)
        if !ok {
                return ""
        }
        v, ok := sec[field].(string)
        if ok {
                return v
        }
        return ""
}

func extractDKIMSelectors(results map[string]any) []string {
        sec, ok := results["dkim"].(map[string]any)
        if !ok {
                return nil
        }
        if sels, ok := sec["selectors"].([]any); ok {
                out := make([]string, 0, len(sels))
                for _, s := range sels {
                        switch v := s.(type) {
                        case string:
                                out = append(out, v)
                        case map[string]any:
                                if name, ok := v["selector"].(string); ok {
                                        out = append(out, name)
                                }
                        }
                }
                return out
        }
        return nil
}

func extractSubdomains(results map[string]any) []string {
        sec, ok := results["subdomains"].(map[string]any)
        if !ok {
                return nil
        }
        if subs, ok := sec["subdomains"].([]any); ok {
                out := make([]string, 0, len(subs))
                for _, s := range subs {
                        switch v := s.(type) {
                        case string:
                                out = append(out, v)
                        case map[string]any:
                                if name, ok := v["domain"].(string); ok {
                                        out = append(out, name)
                                } else if name, ok := v["name"].(string); ok {
                                        out = append(out, name)
                                }
                        }
                }
                return out
        }
        return nil
}

func (h *AgentHandler) PluginPage(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        data := gin.H{
                keyAppVersion:      h.Config.AppVersion,
                keyMaintenanceNote: h.Config.MaintenanceNote,
                keyBetaPages:       h.Config.BetaPages,
                keyCspNonce:        nonce,
                keyActivePage:      "agent_plugin",
        }
        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, "agent_plugin.html", data)
}
