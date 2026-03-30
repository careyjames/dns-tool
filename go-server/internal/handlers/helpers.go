// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "context"
        "encoding/json"
        "fmt"
        "log/slog"
        "math"
        "sort"
        "strings"

        "golang.org/x/net/publicsuffix"
        "golang.org/x/text/cases"
        "golang.org/x/text/language"
)

const (
        mapKeyAnswer    = "answer"
        mapKeyPosture   = "posture"
        mapKeyReason    = "reason"
        mapKeySecondary = "secondary"
        mapKeyState     = "state"
        mapKeySuccess   = "success"
        mapKeyUnknown   = "unknown"
        strPossible     = "Possible"
        strProtected    = "Protected"
        strSecure       = "Secure"
        answerYes       = "Yes"
)

type PaginationInfo struct {
        Page       int   `json:"page"`
        PerPage    int   `json:"per_page"`
        Total      int64 `json:"total"`
        TotalPages int   `json:"total_pages"`
        HasPrev    bool  `json:"has_prev"`
        HasNext    bool  `json:"has_next"`
}

func NewPagination(page, perPage int, total int64) PaginationInfo {
        if page < 1 {
                page = 1
        }
        totalPages := int(math.Ceil(float64(total) / float64(perPage)))
        if totalPages < 1 {
                totalPages = 1
        }
        return PaginationInfo{
                Page:       page,
                PerPage:    perPage,
                Total:      total,
                TotalPages: totalPages,
                HasPrev:    page > 1,
                HasNext:    page < totalPages,
        }
}

func (p PaginationInfo) Offset() int32 {
        return int32((p.Page - 1) * p.PerPage)
}

func (p PaginationInfo) Limit() int32 {
        return int32(p.PerPage)
}

func (p PaginationInfo) Pages() []int {
        pages := make([]int, 0, p.TotalPages)
        for i := 1; i <= p.TotalPages; i++ {
                pages = append(pages, i)
        }
        return pages
}

var normalizeDefaults = map[string]interface{}{
        "basic_records":         map[string]interface{}{},
        "authoritative_records": map[string]interface{}{},
        mapKeySpfAnalysis:       map[string]interface{}{mapKeyStatus: mapKeyUnknown, "records": []interface{}{}},
        mapKeyDmarcAnalysis:     map[string]interface{}{mapKeyStatus: mapKeyUnknown, "policy": nil, "records": []interface{}{}},
        "dkim_analysis":         map[string]interface{}{mapKeyStatus: mapKeyUnknown, "selectors": map[string]interface{}{}},
        "registrar_info":        map[string]interface{}{"registrar": nil, "source": nil},
        mapKeyPosture:           map[string]interface{}{mapKeyState: mapKeyUnknown, "label": "Unknown", "icon": "question-circle", mapKeyColor: mapKeySecondary, "message": "Posture data unavailable", "deliberate_monitoring": false, "deliberate_monitoring_note": "", "issues": []interface{}{}, "monitoring": []interface{}{}, "configured": []interface{}{}, "absent": []interface{}{}},
        "dane_analysis":         map[string]interface{}{mapKeyStatus: "info", "has_dane": false, "tlsa_records": []interface{}{}, "issues": []interface{}{}},
        "mta_sts_analysis":      map[string]interface{}{mapKeyStatus: mapKeyWarning},
        "tlsrpt_analysis":       map[string]interface{}{mapKeyStatus: mapKeyWarning},
        "bimi_analysis":         map[string]interface{}{mapKeyStatus: mapKeyWarning},
        "caa_analysis":          map[string]interface{}{mapKeyStatus: mapKeyWarning},
        "dnssec_analysis":       map[string]interface{}{mapKeyStatus: mapKeyWarning},
        "ct_subdomains":         map[string]interface{}{},
        "mail_posture":          map[string]interface{}{"classification": mapKeyUnknown},
        "_data_freshness":       map[string]interface{}{},
}

var legacyPostureStates = map[string]string{
        "Low":           "Low Risk",
        "Medium":        "Medium Risk",
        "High":          "High Risk",
        "Critical":      "Critical Risk",
        "STRONG":        strSecure,
        "Informational": strSecure,
        "MODERATE":      "Medium Risk",
        "WEAK":          "High Risk",
        "NONE":          "Critical Risk",
}

func NormalizeResults(fullResults json.RawMessage) map[string]interface{} {
        if len(fullResults) == 0 {
                return nil
        }

        var results map[string]interface{}
        if json.Unmarshal(fullResults, &results) != nil {
                return nil
        }

        for key, defaultVal := range normalizeDefaults {
                if _, exists := results[key]; !exists {
                        results[key] = defaultVal
                }
        }

        if posture, ok := results[mapKeyPosture].(map[string]interface{}); ok {
                if state, ok := posture[mapKeyState].(string); ok {
                        if normalized, found := legacyPostureStates[state]; found {
                                posture[mapKeyState] = normalized
                        }
                        if posture[mapKeyState] == strSecure {
                                posture[mapKeyColor] = mapKeySuccess
                                posture["icon"] = "shield-alt"
                        }
                }
                normalizeVerdicts(results, posture)
        }

        return results
}

func normalizeVerdicts(results, posture map[string]interface{}) {
        verdicts, ok := posture["verdicts"].(map[string]interface{})
        if !ok {
                return
        }

        normalizeVerdictAnswers(verdicts)
        normalizeAIVerdicts(results, verdicts)
        normalizeEmailAnswer(verdicts)
}

func normalizeEmailAnswer(verdicts map[string]interface{}) {
        if _, has := verdicts["email_answer_short"]; has {
                return
        }
        emailAnswer, ok := verdicts["email_answer"].(string)
        if !ok || emailAnswer == "" {
                return
        }
        parts := strings.SplitN(emailAnswer, " — ", 2)
        if len(parts) == 2 {
                answer := parts[0]
                reason := parts[1]
                color := mapKeyWarning
                switch {
                case answer == "No" || answer == "Unlikely":
                        color = mapKeySuccess
                case answer == answerYes || answer == "Likely":
                        color = "danger"
                case answer == "Partially" || answer == "Uncertain":
                        color = mapKeyWarning
                }
                verdicts["email_answer_short"] = answer
                verdicts["email_answer_reason"] = reason
                verdicts["email_answer_color"] = color
        }
}

func normalizeVerdictAnswers(verdicts map[string]interface{}) {
        answerMap := map[string]map[string]string{
                "dns_tampering": {
                        strProtected:     "No",
                        "Exposed":        answerYes,
                        "Not Configured": strPossible,
                },
                "brand_impersonation": {
                        strProtected:          "No",
                        "Exposed":             answerYes,
                        "Mostly Protected":    strPossible,
                        "Partially Protected": strPossible,
                        "Basic":               "Likely",
                },
                "certificate_control": {
                        "Configured":     answerYes,
                        "Not Configured": "No",
                },
                "transport": {
                        "Fully Protected": answerYes,
                        strProtected:      answerYes,
                        "Monitoring":      "Partially",
                        "Not Enforced":    "No",
                },
        }

        for key, labelToAnswer := range answerMap {
                normalizeVerdictEntry(verdicts, key, labelToAnswer)
        }
}

func normalizeVerdictEntry(verdicts map[string]interface{}, key string, labelToAnswer map[string]string) {
        v, ok := verdicts[key].(map[string]interface{})
        if !ok {
                return
        }
        if _, hasAnswer := v[mapKeyAnswer]; hasAnswer {
                return
        }
        label, ok := v["label"].(string)
        if !ok {
                label = ""
        }
        if ans, found := labelToAnswer[label]; found {
                v[mapKeyAnswer] = ans
        }
        reasonPrefixes := []string{"No — ", "Yes — ", "Possible — "}
        if reason, ok := v[mapKeyReason].(string); ok {
                for _, prefix := range reasonPrefixes {
                        if strings.HasPrefix(reason, prefix) {
                                v[mapKeyReason] = strings.TrimPrefix(reason, prefix)
                                break
                        }
                }
        }
}

func normalizeLLMsTxtVerdict(llmsTxt map[string]interface{}) map[string]interface{} {
        found, ok := llmsTxt["found"].(bool)
        if !ok {
                found = false
        }
        fullFound, ok := llmsTxt["full_found"].(bool)
        if !ok {
                fullFound = false
        }
        if found && fullFound {
                return map[string]interface{}{mapKeyAnswer: answerYes, mapKeyColor: mapKeySuccess, mapKeyReason: "llms.txt and llms-full.txt published — AI models receive structured context about this domain"}
        }
        if found {
                return map[string]interface{}{mapKeyAnswer: answerYes, mapKeyColor: mapKeySuccess, mapKeyReason: "llms.txt published — AI models receive structured context about this domain"}
        }
        return map[string]interface{}{mapKeyAnswer: "No", mapKeyColor: mapKeySecondary, mapKeyReason: "No llms.txt file detected — AI models have no structured instructions for this domain"}
}

func normalizeRobotsTxtVerdict(robotsTxt map[string]interface{}) map[string]interface{} {
        found, ok := robotsTxt["found"].(bool)
        if !ok {
                found = false
        }
        blocksAI, ok := robotsTxt["blocks_ai_crawlers"].(bool)
        if !ok {
                blocksAI = false
        }
        if found && blocksAI {
                return map[string]interface{}{mapKeyAnswer: answerYes, mapKeyColor: mapKeySuccess, mapKeyReason: "robots.txt actively blocks AI crawlers from scraping site content"}
        }
        if found {
                return map[string]interface{}{mapKeyAnswer: "No", mapKeyColor: mapKeyWarning, mapKeyReason: "robots.txt present but does not block AI crawlers — content may be freely scraped"}
        }
        return map[string]interface{}{mapKeyAnswer: "No", mapKeyColor: mapKeySecondary, mapKeyReason: "No robots.txt found — AI crawlers have unrestricted access"}
}

func normalizeCountVerdict(section map[string]interface{}, countKey, yesReason, noReason string) map[string]interface{} {
        count := getNumValue(section, countKey)
        if count > 0 {
                return map[string]interface{}{mapKeyAnswer: answerYes, mapKeyColor: "danger", mapKeyReason: fmt.Sprintf("%.0f %s", count, yesReason)}
        }
        return map[string]interface{}{mapKeyAnswer: "No", mapKeyColor: mapKeySuccess, mapKeyReason: noReason}
}

func normalizeAIVerdicts(results, verdicts map[string]interface{}) {
        if _, has := verdicts["ai_llms_txt"]; has {
                return
        }

        aiSurface, ok := results["ai_surface"].(map[string]interface{})
        if !ok {
                return
        }

        if llmsTxt, ok := aiSurface["llms_txt"].(map[string]interface{}); ok {
                verdicts["ai_llms_txt"] = normalizeLLMsTxtVerdict(llmsTxt)
        }

        if robotsTxt, ok := aiSurface["robots_txt"].(map[string]interface{}); ok {
                verdicts["ai_crawler_governance"] = normalizeRobotsTxtVerdict(robotsTxt)
        }

        if poisoning, ok := aiSurface["poisoning"].(map[string]interface{}); ok {
                verdicts["ai_poisoning"] = normalizeCountVerdict(poisoning, "ioc_count", "indicator(s) of AI recommendation manipulation detected on homepage", "No indicators of AI recommendation manipulation found")
        }

        if hidden, ok := aiSurface["hidden_prompts"].(map[string]interface{}); ok {
                verdicts["ai_hidden_prompts"] = normalizeCountVerdict(hidden, "artifact_count", "hidden prompt-like artifact(s) detected in page source", "No hidden prompt artifacts found in page source")
        }
}

func getNumValue(m map[string]interface{}, key string) float64 {
        v, ok := m[key]
        if !ok {
                return 0
        }
        switch n := v.(type) {
        case float64:
                return n
        case int:
                return float64(n)
        case int64:
                return float64(n)
        }
        return 0
}

type CompareSectionDef struct {
        Key   string
        Label string
        Icon  string
}

var CompareSections = []CompareSectionDef{
        {mapKeySpfAnalysis, "SPF", "envelope-open-text"},
        {mapKeyDmarcAnalysis, "DMARC", "shield-alt"},
        {"dkim_analysis", "DKIM", "key"},
        {"dnssec_analysis", "DNSSEC", "lock"},
        {"dane_analysis", "DANE / TLSA", "certificate"},
        {"mta_sts_analysis", "MTA-STS", "paper-plane"},
        {"tlsrpt_analysis", "TLS-RPT", "file-alt"},
        {"bimi_analysis", "BIMI", "image"},
        {"caa_analysis", "CAA", "certificate"},
        {mapKeyPosture, "Mail Posture", "mail-bulk"},
}

var compareSkipKeys = map[string]bool{
        mapKeyStatus: true, mapKeyState: true, "_schema_version": true,
        "_tool_version": true, "_captured_at": true,
}

type DetailChange struct {
        Field string      `json:"field"`
        Old   interface{} `json:"old"`
        New   interface{} `json:"new"`
}

type SectionDiff struct {
        Key           string         `json:"key"`
        Label         string         `json:"label"`
        Icon          string         `json:"icon"`
        StatusA       string         `json:"status_a"`
        StatusB       string         `json:"status_b"`
        Changed       bool           `json:"changed"`
        DetailChanges []DetailChange `json:"detail_changes"`
}

func getStatus(section map[string]interface{}) string {
        if s, ok := section[mapKeyStatus].(string); ok {
                return s
        }
        if s, ok := section[mapKeyState].(string); ok {
                return s
        }
        return mapKeyUnknown
}

func ComputeSectionDiff(secA, secB map[string]interface{}, key, label, icon string) SectionDiff {
        statusA := getStatus(secA)
        statusB := getStatus(secB)

        allKeys := make(map[string]bool)
        for k := range secA {
                allKeys[k] = true
        }
        for k := range secB {
                allKeys[k] = true
        }

        sortedKeys := make([]string, 0, len(allKeys))
        for k := range allKeys {
                if !compareSkipKeys[k] {
                        sortedKeys = append(sortedKeys, k)
                }
        }
        sort.Strings(sortedKeys)

        var detailChanges []DetailChange
        for _, k := range sortedKeys {
                valA := normalizeForCompare(secA[k])
                valB := normalizeForCompare(secB[k])
                jsonA, errA := json.Marshal(valA)
                jsonB, errB := json.Marshal(valB)
                if errA != nil || errB != nil {
                        slog.Debug("json.Marshal failed in section diff", "field", k, "errA", errA, "errB", errB)
                        continue
                }
                if string(jsonA) != string(jsonB) {
                        fieldName := strings.ReplaceAll(k, "_", " ")
                        fieldName = cases.Title(language.English).String(fieldName)
                        detailChanges = append(detailChanges, DetailChange{
                                Field: fieldName,
                                Old:   valA,
                                New:   valB,
                        })
                }
        }

        return SectionDiff{
                Key:           key,
                Label:         label,
                Icon:          icon,
                StatusA:       statusA,
                StatusB:       statusB,
                Changed:       statusA != statusB || len(detailChanges) > 0,
                DetailChanges: detailChanges,
        }
}

func normalizeForCompare(v interface{}) interface{} {
        arr, ok := v.([]interface{})
        if !ok || len(arr) < 2 {
                return v
        }
        strs := make([]string, len(arr))
        for i, elem := range arr {
                switch e := elem.(type) {
                case string:
                        strs[i] = e
                default:
                        b, err := json.Marshal(e)
                        if err != nil {
                                slog.Debug("json.Marshal failed in normalizeForCompare", "error", err)
                                strs[i] = fmt.Sprintf("%v", e)
                                continue
                        }
                        strs[i] = string(b)
                }
        }
        sort.Strings(strs)
        _, firstIsString := arr[0].(string)
        sorted := make([]interface{}, len(strs))
        for i, s := range strs {
                sorted[i] = parseSortedElement(s, firstIsString)
        }
        return sorted
}

func parseSortedElement(s string, firstIsString bool) interface{} {
        var parsed interface{}
        if json.Unmarshal([]byte(s), &parsed) == nil && !firstIsString {
                return parsed
        }
        return s
}

func ComputeAllDiffs(resultsA, resultsB map[string]interface{}) []SectionDiff {
        diffs := make([]SectionDiff, 0, len(CompareSections))
        for _, sec := range CompareSections {
                secA := getSection(resultsA, sec.Key)
                secB := getSection(resultsB, sec.Key)
                diffs = append(diffs, ComputeSectionDiff(secA, secB, sec.Key, sec.Label, sec.Icon))
        }
        return diffs
}

func getSection(results map[string]interface{}, key string) map[string]interface{} {
        if s, ok := results[key].(map[string]interface{}); ok {
                return s
        }
        return map[string]interface{}{}
}

func extractRootDomain(domain string) (isSubdomain bool, root string) {
        domain = strings.TrimRight(domain, ".")
        registrable, err := publicsuffix.EffectiveTLDPlusOne(domain)
        if err != nil {
                return false, ""
        }
        if strings.EqualFold(domain, registrable) {
                return false, ""
        }
        return true, registrable
}

func isPublicSuffixDomain(domain string) bool {
        domain = strings.TrimRight(domain, ".")
        _, err := publicsuffix.EffectiveTLDPlusOne(domain)
        if err == nil {
                return false
        }
        suffix, _ := publicsuffix.PublicSuffix(domain)
        if strings.EqualFold(domain, suffix) {
                return true
        }
        return isTwoPartSuffix(domain)
}

func isTwoPartSuffix(domain string) bool {
        parts := strings.Split(domain, ".")
        if len(parts) < 2 {
                return false
        }
        joined := strings.Join(parts[len(parts)-2:], ".")
        if !strings.EqualFold(domain, joined) {
                return false
        }
        suffixCheck, _ := publicsuffix.PublicSuffix(domain)
        return strings.EqualFold(suffixCheck, domain)
}

type subdomainEmailScope struct {
        IsSubdomain   bool   `json:"is_subdomain"`
        ParentDomain  string `json:"parent_domain"`
        SPFScope      string `json:"spf_scope"`
        DMARCScope    string `json:"dmarc_scope"`
        SPFNote       string `json:"spf_note"`
        DMARCNote     string `json:"dmarc_note"`
        HasLocalEmail bool   `json:"has_local_email"`
}

func isActiveStatus(status string) bool {
        return status == mapKeySuccess || status == mapKeyWarning
}

func parseOrgDMARC(records []string) (bool, string) {
        for _, r := range records {
                lower := strings.ToLower(strings.TrimSpace(r))
                if lower != "v=dmarc1" && !strings.HasPrefix(lower, "v=dmarc1;") && !strings.HasPrefix(lower, "v=dmarc1 ") {
                        continue
                }
                policy := ""
                if idx := strings.Index(lower, "p="); idx >= 0 {
                        rest := lower[idx+2:]
                        if semi := strings.IndexByte(rest, ';'); semi >= 0 {
                                policy = strings.TrimSpace(rest[:semi])
                        } else {
                                policy = strings.TrimSpace(rest)
                        }
                }
                return true, policy
        }
        return false, ""
}

func determineDMARCScope(subHasDMARC, orgHasDMARC bool, orgDMARCPolicy, rootDomain string) (string, string) {
        if subHasDMARC {
                return "local", "DMARC record published at this subdomain"
        }
        if orgHasDMARC {
                policyNote := ""
                if orgDMARCPolicy != "" {
                        policyNote = fmt.Sprintf(" (p=%s)", orgDMARCPolicy)
                }
                return "inherited", fmt.Sprintf("No subdomain DMARC record — organizational domain policy from %s%s applies per RFC 7489 §6.6.3", rootDomain, policyNote)
        }
        return "none", fmt.Sprintf("No DMARC record at this subdomain or organizational domain %s", rootDomain)
}

type dnsQuerier interface {
        QueryDNS(ctx context.Context, recordType, domain string) []string
}

func computeSubdomainEmailScope(ctx context.Context, dns dnsQuerier, domain, rootDomain string, results map[string]any) subdomainEmailScope {
        scope := subdomainEmailScope{
                IsSubdomain:  true,
                ParentDomain: rootDomain,
        }

        spf, ok := results[mapKeySpfAnalysis].(map[string]any)
        if !ok {
                spf = map[string]any{}
        }
        dmarc, ok := results[mapKeyDmarcAnalysis].(map[string]any)
        if !ok {
                dmarc = map[string]any{}
        }

        spfStatus, ok := spf[mapKeyStatus].(string)
        if !ok {
                spfStatus = ""
        }
        dmarcStatus, ok := dmarc[mapKeyStatus].(string)
        if !ok {
                dmarcStatus = ""
        }

        scope.SPFScope, scope.SPFNote = determineSPFScope(isActiveStatus(spfStatus))

        orgDMARCRecords := dns.QueryDNS(ctx, "TXT", fmt.Sprintf("_dmarc.%s", rootDomain))
        orgHasDMARC, orgDMARCPolicy := parseOrgDMARC(orgDMARCRecords)
        scope.DMARCScope, scope.DMARCNote = determineDMARCScope(isActiveStatus(dmarcStatus), orgHasDMARC, orgDMARCPolicy, rootDomain)

        scope.HasLocalEmail = hasLocalMXRecords(results)

        return scope
}

func determineSPFScope(subHasSPF bool) (string, string) {
        if subHasSPF {
                return "local", "SPF record published at this subdomain"
        }
        return "none", "No SPF record at this subdomain — SPF does not inherit from parent domains"
}

func hasLocalMXRecords(results map[string]any) bool {
        basic, ok := results["basic_records"].(map[string]any)
        if !ok || basic == nil {
                return false
        }
        switch mx := basic["MX"].(type) {
        case []string:
                return len(mx) > 0
        case []any:
                return len(mx) > 0
        }
        return false
}
