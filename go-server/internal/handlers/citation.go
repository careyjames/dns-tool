// dns-tool:scrutiny design
package handlers

import (
        "encoding/json"
        "fmt"
        "log/slog"
        "net/http"
        "os"
        "regexp"
        "strconv"
        "strings"

        "dnstool/go-server/internal/citation"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"
        "dnstool/go-server/internal/icae"
        "dnstool/go-server/internal/icuae"

        "github.com/gin-gonic/gin"
        "github.com/goccy/go-yaml"
)

var safeFilenameRe = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

const sectionSeparator = "\u00a7"

type citationCFF struct {
        Title        string      `yaml:"title"`
        Version      string      `yaml:"version"`
        DateReleased string      `yaml:"date-released"`
        DOI          string      `yaml:"doi"`
        URL          string      `yaml:"url"`
        Authors      []cffAuthor `yaml:"authors"`
}

type cffAuthor struct {
        FamilyNames string `yaml:"family-names"`
        GivenNames  string `yaml:"given-names"`
        ORCID       string `yaml:"orcid"`
}

func loadCitationCFF() *citationCFF {
        for _, path := range []string{"CITATION.cff", "../CITATION.cff", "../../CITATION.cff"} {
                data, err := os.ReadFile(path)
                if err != nil {
                        continue
                }
                var cff citationCFF
                if err := yaml.Unmarshal(data, &cff); err != nil {
                        slog.Warn("Failed to parse CITATION.cff", "path", path, "error", err)
                        return nil
                }
                return &cff
        }
        return nil
}

type CitationHandler struct {
        Config      *config.Config
        Registry    *citation.Registry
        DB          *db.Database
        lookupStore LookupStore
}

func (h *CitationHandler) store() LookupStore {
        if h.lookupStore != nil {
                return h.lookupStore
        }
        if h.DB != nil {
                return h.DB.Queries
        }
        return nil
}

func NewCitationHandler(cfg *config.Config, reg *citation.Registry, database *db.Database) *CitationHandler {
        return &CitationHandler{Config: cfg, Registry: reg, DB: database}
}

func (h *CitationHandler) Authorities(c *gin.Context) {
        typ := c.Query("type")
        status := c.Query("status")
        area := c.Query("area")
        query := c.Query("q")

        var entries []citation.Entry
        if typ == "" && status == "" && area == "" && query == "" {
                entries = h.Registry.All()
        } else {
                entries = h.Registry.Filter(typ, status, area, query)
        }

        c.JSON(http.StatusOK, gin.H{
                "count":   len(entries),
                "entries": entries,
        })
}

func (h *CitationHandler) SoftwareCitation(c *gin.Context) {
        format := c.DefaultQuery("format", "csljson")
        if format != "bibtex" && format != "ris" && format != "csljson" {
                c.JSON(http.StatusBadRequest, gin.H{"error": "invalid format: must be bibtex, ris, or csljson"})
                return
        }

        title, version, doi, url, authorFamily, authorGiven, date := h.resolveSoftwareMeta()

        switch format {
        case "bibtex":
                out := citation.SoftwareToBibTeX(title, version, doi, url, authorFamily, authorGiven, date)
                c.Header(headerContentDisposition, `attachment; filename="dnstool.bib"`)
                c.Data(http.StatusOK, "application/x-bibtex; charset=utf-8", []byte(out))
        case "ris":
                out := citation.SoftwareToRIS(title, version, doi, url, authorFamily, authorGiven, date)
                c.Header(headerContentDisposition, `attachment; filename="dnstool.ris"`)
                c.Data(http.StatusOK, "application/x-research-info-systems; charset=utf-8", []byte(out))
        default:
                out, err := citation.SoftwareToCSLJSON(title, version, doi, url, authorFamily, authorGiven, date)
                if err != nil {
                        c.JSON(http.StatusInternalServerError, gin.H{"error": "export failed"})
                        return
                }
                c.Header(headerContentDisposition, `attachment; filename="dnstool.json"`)
                c.Data(http.StatusOK, "application/json; charset=utf-8", []byte(out))
        }
}

func (h *CitationHandler) resolveSoftwareMeta() (title, version, doi, url, authorFamily, authorGiven, date string) {
        title = "DNS Tool: Domain Security Audit Platform"
        version = h.Config.AppVersion
        doi = "10.5281/zenodo.18854899"
        url = "https://dnstool.it-help.tech"
        authorFamily = "Balboa"
        authorGiven = "Carey James"
        date = "2026-03-09"

        cff := loadCitationCFF()
        if cff == nil {
                return
        }
        if cff.Title != "" {
                title = cff.Title
        }
        if cff.Version != "" {
                version = cff.Version
        }
        if cff.DOI != "" {
                doi = cff.DOI
        }
        if cff.URL != "" {
                url = cff.URL
        }
        if cff.DateReleased != "" {
                date = cff.DateReleased
        }
        if len(cff.Authors) > 0 {
                authorFamily = cff.Authors[0].FamilyNames
                authorGiven = cff.Authors[0].GivenNames
        }
        return
}

func (h *CitationHandler) ResearchAPI(c *gin.Context) {
        title, version, doi, url, authorFamily, authorGiven, date := h.resolveSoftwareMeta()

        cff := loadCitationCFF()
        orcid := "0009-0000-5237-9065"
        license := "BUSL-1.1"
        if cff != nil {
                if len(cff.Authors) > 0 && cff.Authors[0].ORCID != "" {
                        orcid = strings.TrimPrefix(cff.Authors[0].ORCID, "https://orcid.org/")
                }
        }

        analysisCases := icae.AnalysisTestCases()
        collectionCases := icae.CollectionTestCases()
        icaeTotalCases := len(analysisCases) + len(collectionCases)

        protoCounts := icae.CountCasesByProtocol()
        protocols := make([]gin.H, 0, len(protoCounts))
        for proto, pc := range protoCounts {
                protocols = append(protocols, gin.H{
                        "protocol":   proto,
                        "analysis":   pc.Analysis,
                        "collection": pc.Collection,
                        "total":      pc.Total,
                })
        }

        icuaeInv := icuae.GetTestInventory()
        icuaeCategories := make([]gin.H, 0, len(icuaeInv.Categories))
        for _, cat := range icuaeInv.Categories {
                icuaeCategories = append(icuaeCategories, gin.H{
                        "name":     cat.Name,
                        "standard": cat.Standard,
                        "cases":    cat.Cases,
                })
        }

        citationReg := citation.Global()
        allEntries := citationReg.All()

        c.JSON(http.StatusOK, gin.H{
                "label":       "Published Research Software",
                "title":       title,
                "version":     version,
                "concept_doi": "10.5281/zenodo.18854899",
                "latest_doi":  doi,
                "orcid":       orcid,
                "author":      authorGiven + " " + authorFamily,
                "license":     license,
                "date":        date,
                "url":         url,
                "citation":    fmt.Sprintf("Balboa, C. J. (%s). %s (Version %s) [Computer software]. %s", date[:4], title, version, "https://doi.org/"+doi),
                "engines": gin.H{
                        "icae": gin.H{
                                "name":             "Intelligence Confidence Audit Engine",
                                "total_cases":      icaeTotalCases,
                                "analysis_cases":   len(analysisCases),
                                "collection_cases": len(collectionCases),
                                "maturity_tiers":   []string{"Development", "Verified", "Consistent", "Gold", "Gold Master"},
                                "protocols":        protocols,
                        },
                        "icuae": gin.H{
                                "name":             "Intelligence Currency Assurance Engine",
                                "total_cases":      icuaeInv.TotalCases,
                                "total_dimensions": icuaeInv.TotalDimensions,
                                "categories":       icuaeCategories,
                        },
                },
                "authorities_registry": gin.H{
                        "total_entries": len(allEntries),
                        "url":           url + "/api/authorities",
                },
                "documents": []gin.H{
                        {
                                "title":       "DNS Tool: Confidence-Scored Analysis of Domain Security Infrastructure",
                                "type":        "methodology",
                                "url":         url + "/methodology",
                                "description": "Primary methodology document covering ICAE/ICuAE confidence framework, multi-resolver consensus, and RFC-grounded analysis engines.",
                        },
                        {
                                "title":       "Philosophical Foundations for Security Analysis Communication",
                                "type":        "companion",
                                "url":         url + "/foundations",
                                "description": "Companion document covering Aristotelian rhetoric, Socratic verification, scotopic interface design, and narrative architecture.",
                        },
                },
                "endpoints": gin.H{
                        "cite_page":         url + "/cite",
                        "software_citation": url + "/cite/software",
                        "authorities":       url + "/api/authorities",
                        "research":          url + "/api/research",
                },
        })
}

func (h *CitationHandler) CitePage(c *gin.Context) {
        title, version, doi, url, authorFamily, authorGiven, date := h.resolveSoftwareMeta()

        cff := loadCitationCFF()
        orcid := "0009-0000-5237-9065"
        if cff != nil && len(cff.Authors) > 0 && cff.Authors[0].ORCID != "" {
                orcid = strings.TrimPrefix(cff.Authors[0].ORCID, "https://orcid.org/")
        }

        analysisCases := icae.AnalysisTestCases()
        collectionCases := icae.CollectionTestCases()
        icuaeInv := icuae.GetTestInventory()
        protoCounts := icae.CountCasesByProtocol()

        citationReg := citation.Global()
        allEntries := citationReg.All()

        nonce, _ := c.Get("csp_nonce")

        c.HTML(http.StatusOK, "cite.html", gin.H{
                "AppVersion":      h.Config.AppVersion,
                "MaintenanceNote": h.Config.MaintenanceNote,
                "BetaPages":       h.Config.BetaPages,
                "CspNonce":        nonce,
                "Title":           title,
                "Version":         version,
                "DOI":             doi,
                "URL":             url,
                "AuthorFamily":    authorFamily,
                "AuthorGiven":     authorGiven,
                "ORCID":           orcid,
                "Date":            date,
                "Year":            date[:4],
                "ICAETotal":       len(analysisCases) + len(collectionCases),
                "ICAEAnalysis":    len(analysisCases),
                "ICAECollection":  len(collectionCases),
                "ICAEProtocols":   len(protoCounts),
                "ICuAETotal":      icuaeInv.TotalCases,
                "ICuAEDimensions": icuaeInv.TotalDimensions,
                "AuthoritiesTotal": len(allEntries),
        })
}

func (h *CitationHandler) AnalysisCitation(c *gin.Context) {
        format := c.DefaultQuery("format", "csljson")
        if format != "bibtex" && format != "ris" && format != "csljson" {
                c.JSON(http.StatusBadRequest, gin.H{"error": "invalid format: must be bibtex, ris, or csljson"})
                return
        }
        idStr := c.Param("id")

        id, err := strconv.ParseInt(idStr, 10, 32)
        if err != nil || id <= 0 {
                c.JSON(http.StatusBadRequest, gin.H{"error": "invalid analysis ID"})
                return
        }

        analysis, err := h.store().GetAnalysisByID(c.Request.Context(), int32(id))
        if err != nil {
                c.JSON(http.StatusNotFound, gin.H{"error": "analysis not found"})
                return
        }

        if !h.checkCitationAccess(c, analysis.ID, analysis.Private) {
                c.JSON(http.StatusNotFound, gin.H{"error": "analysis not found"})
                return
        }

        manifestEntries := h.buildAnalysisManifest(analysis.FullResults)
        safeID := safeFilenameRe.ReplaceAllString(idStr, "")

        switch format {
        case "bibtex":
                out := citation.EntriesToBibTeX(manifestEntries)
                c.Header(headerContentDisposition, fmt.Sprintf(`attachment; filename="analysis-%s.bib"`, safeID))
                c.Data(http.StatusOK, "application/x-bibtex; charset=utf-8", []byte(out))
        case "ris":
                out := citation.EntriesToRIS(manifestEntries)
                c.Header(headerContentDisposition, fmt.Sprintf(`attachment; filename="analysis-%s.ris"`, safeID))
                c.Data(http.StatusOK, "application/x-research-info-systems; charset=utf-8", []byte(out))
        default:
                out, err := citation.EntriesToCSLJSON(manifestEntries)
                if err != nil {
                        c.JSON(http.StatusInternalServerError, gin.H{"error": "export failed"})
                        return
                }
                c.Header(headerContentDisposition, fmt.Sprintf(`attachment; filename="analysis-%s.json"`, safeID))
                c.Data(http.StatusOK, "application/json; charset=utf-8", []byte(out))
        }
}

func (h *CitationHandler) checkCitationAccess(c *gin.Context, analysisID int32, private bool) bool {
        if !private {
                return true
        }
        auth, exists := c.Get(mapKeyAuthenticated)
        if !exists || auth != true {
                return false
        }
        uid, ok := c.Get(mapKeyUserId)
        if !ok {
                return false
        }
        userID, ok := uid.(int32)
        if !ok {
                return false
        }
        isOwner, err := h.store().CheckAnalysisOwnership(c.Request.Context(), dbq.CheckAnalysisOwnershipParams{
                AnalysisID: analysisID,
                UserID:     userID,
        })
        return err == nil && isOwner
}

func (h *CitationHandler) buildAnalysisManifest(fullResults json.RawMessage) []citation.ManifestEntry {
        return buildCitationManifestFromResults(fullResults)
}

var analysisCitationRules = []struct {
        key  string
        rfcs []string
}{
        {"spf_analysis", []string{"rfc:7208"}},
        {"dmarc_analysis", []string{"rfc:7489"}},
        {"dkim_analysis", []string{"rfc:6376", "rfc:8301"}},
        {"dnssec_analysis", []string{"rfc:4033", "rfc:4034", "rfc:4035"}},
        {"dane_analysis", []string{"rfc:6698", "rfc:7672"}},
        {"mta_sts_analysis", []string{"rfc:8461"}},
        {"tlsrpt_analysis", []string{"rfc:8460"}},
        {"bimi_analysis", []string{"rfc:9495"}},
        {"caa_analysis", []string{"rfc:8659"}},
        {"ns_records", []string{"rfc:1034", "rfc:1035"}},
}

func buildCitationManifestFromResults(fullResults json.RawMessage) []citation.ManifestEntry {
        reg := citation.Global()
        m := citation.NewManifest()

        var results map[string]any
        if err := json.Unmarshal(fullResults, &results); err != nil {
                return nil
        }

        for _, rule := range analysisCitationRules {
                if _, ok := results[rule.key]; ok {
                        for _, rfc := range rule.rfcs {
                                m.Cite(rfc)
                        }
                }
        }

        if rem, ok := results["remediation"].(map[string]any); ok {
                extractRemCitations(rem, m)
        }

        m.Cite("nist:800-177")
        m.Cite("odni:icd-203")

        return m.Entries(reg)
}

func extractRemCitations(rem map[string]any, m *citation.Manifest) {
        sections, ok := rem["per_section"].(map[string]any)
        if !ok {
                return
        }
        for _, v := range sections {
                fixes, ok := v.([]any)
                if !ok {
                        continue
                }
                extractFixCitations(fixes, m)
        }
}

func extractFixCitations(fixes []any, m *citation.Manifest) {
        for _, f := range fixes {
                fix, ok := f.(map[string]any)
                if !ok {
                        continue
                }
                rfc, ok := fix["rfc"].(string)
                if !ok || rfc == "" {
                        continue
                }
                if citID := rfcLabelToSectionID(rfc); citID != "" {
                        m.Cite(citID)
                }
        }
}

func rfcLabelToSectionID(label string) string {
        label = strings.TrimSpace(label)
        if !strings.HasPrefix(label, "RFC ") {
                return ""
        }
        rest := strings.TrimPrefix(label, "RFC ")
        parts := strings.SplitN(rest, " ", 2)
        num := parts[0]

        if idx := strings.Index(num, sectionSeparator); idx != -1 {
                section := num[idx+len(sectionSeparator):]
                num = num[:idx]
                return "rfc:" + strings.TrimSpace(num) + sectionSeparator + strings.TrimSpace(section)
        }

        if len(parts) > 1 {
                after := strings.TrimSpace(parts[1])
                if strings.HasPrefix(after, sectionSeparator) {
                        section := strings.TrimPrefix(after, sectionSeparator)
                        return "rfc:" + strings.TrimSpace(num) + sectionSeparator + strings.TrimSpace(section)
                }
        }

        return "rfc:" + strings.TrimSpace(num)
}
