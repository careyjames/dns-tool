// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "encoding/json"
        "fmt"
        "log/slog"
        "net/http"
        "strconv"
        "strings"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
)

const remediationTemplate = "remediation.html"

type RemediationHandler struct {
        DB          *db.Database
        Config      *config.Config
        lookupStore LookupStore
}

func (h *RemediationHandler) store() LookupStore {
        if h.lookupStore != nil {
                return h.lookupStore
        }
        if h.DB != nil {
                return h.DB.Queries
        }
        return nil
}

func NewRemediationHandler(database *db.Database, cfg *config.Config) *RemediationHandler {
        return &RemediationHandler{DB: database, Config: cfg}
}

func (h *RemediationHandler) RemediationPage(c *gin.Context) {
        nonce, _ := c.Get(mapKeyCspNonce)
        csrfToken, _ := c.Get(mapKeyCsrfToken)

        analysisIDStr := c.Query("analysis_id")
        domain := c.Query("domain")

        data := gin.H{
                strAppversion:      h.Config.AppVersion,
                strMaintenancenote: h.Config.MaintenanceNote,
                strBetapages:       h.Config.BetaPages,
                strCspnonce:        nonce,
                strCsrftoken:       csrfToken,
                strActivepage:      "remediation",
                strShowform:        true,
                "BaseURL":          h.Config.BaseURL,
        }
        mergeAuthData(c, h.Config, data)

        if analysisIDStr == "" && domain == "" {
                c.HTML(http.StatusOK, remediationTemplate, data)
                return
        }

        var analysis dbq.DomainAnalysis
        var err error
        ctx := c.Request.Context()

        if analysisIDStr != "" {
                id, parseErr := strconv.ParseInt(analysisIDStr, 10, 32)
                if parseErr != nil {
                        data["FlashMessages"] = []FlashMessage{{Category: mapKeyDanger, Message: "Invalid analysis ID."}}
                        c.HTML(http.StatusOK, remediationTemplate, data)
                        return
                }
                analysis, err = h.store().GetAnalysisByID(ctx, int32(id))
                if err != nil {
                        data["FlashMessages"] = []FlashMessage{{Category: mapKeyDanger, Message: "Analysis not found. Please check the scan number and try again."}}
                        c.HTML(http.StatusOK, remediationTemplate, data)
                        return
                }
        } else {
                domain = strings.TrimSpace(strings.ToLower(domain))
                if domain == "" {
                        data["FlashMessages"] = []FlashMessage{{Category: mapKeyDanger, Message: "Please enter a valid domain name."}}
                        data["FormDomain"] = domain
                        c.HTML(http.StatusOK, remediationTemplate, data)
                        return
                }
                analysis, err = h.store().GetRecentAnalysisByDomain(ctx, domain)
                if err != nil {
                        data["FlashMessages"] = []FlashMessage{{Category: mapKeyWarning, Message: fmt.Sprintf("No analysis found for %s. Run a scan first, then come back here.", domain)}}
                        data["FormDomain"] = domain
                        data["SuggestScan"] = true
                        data["SuggestDomain"] = domain
                        c.HTML(http.StatusOK, remediationTemplate, data)
                        return
                }
        }

        if analysis.Private {
                if !h.checkPrivateAccess(c, analysis.ID) {
                        data["FlashMessages"] = []FlashMessage{{Category: mapKeyDanger, Message: "This analysis is private. Please sign in to access it."}}
                        c.HTML(http.StatusOK, remediationTemplate, data)
                        return
                }
        }

        if analysis.AnalysisSuccess == nil || !*analysis.AnalysisSuccess || len(analysis.FullResults) == 0 || string(analysis.FullResults) == "null" {
                data["FlashMessages"] = []FlashMessage{{Category: mapKeyWarning, Message: "This analysis did not complete successfully. No remediation data is available."}}
                c.HTML(http.StatusOK, remediationTemplate, data)
                return
        }

        results := NormalizeResults(analysis.FullResults)
        remData, hasRem := results["remediation"].(map[string]any)
        if !hasRem {
                data["FlashMessages"] = []FlashMessage{{Category: "info", Message: "No remediation items found — this domain may already be well-configured."}}
                data["ShowResults"] = true
                data["AnalysisDomain"] = analysis.Domain
                data["AnalysisID"] = analysis.ID
                data["AnalysisTime"] = formatTimestamp(analysis.CreatedAt)
                data["FixCount"] = 0
                c.HTML(http.StatusOK, remediationTemplate, data)
                return
        }

        allFixes, _ := remData["all_fixes"].([]any)
        topFixes, _ := remData["top_fixes"].([]any)
        fixCount := len(allFixes)
        postureAchievable, _ := remData["posture_achievable"].(string)

        remediationItems := buildRemediationItems(allFixes)

        var dnsFixes, manualFixes []remediationItem
        for _, item := range remediationItems {
                if item.HasDNS {
                        dnsFixes = append(dnsFixes, item)
                } else {
                        manualFixes = append(manualFixes, item)
                }
        }

        data[strShowform] = false
        data["ShowResults"] = true
        data["AnalysisDomain"] = analysis.Domain
        data["AnalysisID"] = analysis.ID
        data["AnalysisTime"] = formatTimestamp(analysis.CreatedAt)
        data["FixCount"] = fixCount
        data["TopFixes"] = topFixes
        data["PostureAchievable"] = postureAchievable
        data["DNSFixes"] = dnsFixes
        data["ManualFixes"] = manualFixes
        data["AllFixes"] = remediationItems

        c.HTML(http.StatusOK, remediationTemplate, data)
}

func (h *RemediationHandler) RemediationSubmit(c *gin.Context) {
        analysisID := strings.TrimSpace(c.PostForm("analysis_id"))
        domain := strings.TrimSpace(c.PostForm("domain"))

        if analysisID != "" {
                c.Redirect(http.StatusSeeOther, "/remediation?analysis_id="+analysisID)
                return
        }
        if domain != "" {
                domain = strings.ToLower(domain)
                c.Redirect(http.StatusSeeOther, "/remediation?domain="+domain)
                return
        }
        c.Redirect(http.StatusSeeOther, "/remediation")
}

func (h *RemediationHandler) checkPrivateAccess(c *gin.Context, analysisID int32) bool {
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

type remediationItem struct {
        Title          string
        Description    string
        Section        string
        SeverityLabel  string
        SeverityColor  string
        RFC            string
        RFCURL         string
        HasDNS         bool
        DNSType        string
        DNSHost        string
        DNSValue       string
        DNSPurpose     string
        DNSHostHelp    string
        DNSRecord      string
        CopyableRecord string
}

func buildRemediationItems(allFixes []any) []remediationItem {
        items := make([]remediationItem, 0, len(allFixes))
        for _, f := range allFixes {
                fixMap, ok := f.(map[string]any)
                if !ok {
                        raw, marshalOK := json.Marshal(f)
                        if marshalOK != nil {
                                continue
                        }
                        if json.Unmarshal(raw, &fixMap) != nil {
                                continue
                        }
                }

                item := remediationItem{
                        Title:         getStr(fixMap, "title"),
                        Description:   getStr(fixMap, "fix"),
                        Section:       getStr(fixMap, "section"),
                        SeverityLabel: getStr(fixMap, "severity_label"),
                        SeverityColor: getStr(fixMap, "severity_color"),
                        RFC:           getStr(fixMap, "rfc"),
                        RFCURL:        getStr(fixMap, "rfc_url"),
                }

                dnsHost := getStr(fixMap, "dns_host")
                dnsType := getStr(fixMap, "dns_type")
                dnsValue := getStr(fixMap, "dns_value")

                if dnsHost != "" && dnsType != "" {
                        item.HasDNS = true
                        item.DNSType = dnsType
                        item.DNSHost = dnsHost
                        item.DNSValue = dnsValue
                        item.DNSPurpose = getStr(fixMap, "dns_purpose")
                        item.DNSHostHelp = getStr(fixMap, "dns_host_help")
                        item.CopyableRecord = buildCopyableRecord(dnsType, dnsHost, dnsValue)
                } else if rec := getStr(fixMap, "dns_record"); rec != "" {
                        item.HasDNS = true
                        item.DNSRecord = rec
                        item.CopyableRecord = rec
                }

                items = append(items, item)
        }
        return items
}

func buildCopyableRecord(dnsType, host, value string) string {
        if value == "" {
                return ""
        }
        return fmt.Sprintf("%s  %s  %s", host, dnsType, value)
}

func getStr(m map[string]any, key string) string {
        v, ok := m[key]
        if !ok {
                return ""
        }
        s, ok := v.(string)
        if !ok {
                return fmt.Sprintf("%v", v)
        }
        return s
}

func init() {
        slog.Debug("remediation handler registered")
}
