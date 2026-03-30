// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny plumbing
package templates

import (
        "crypto/sha512"
        "encoding/base64"
        "encoding/json"
        "fmt"
        "html/template"
        "log/slog"
        "math"
        "net/url"
        "os"
        "path/filepath"
        "strconv"
        "strings"
        "sync"
        "time"

        "dnstool/go-server/internal/icons"

        "golang.org/x/text/cases"
        "golang.org/x/text/language"
)

var sriCache sync.Map

func InitSRI(staticDir string) {
        assets := []string{
                "css/foundation.min.css",
                "css/custom.min.css",
                "css/print.min.css",
                "js/main.min.js",
                "js/foundation.min.js",
                "vendor/katex/katex.min.css",
                "vendor/katex/katex.min.js",
                "vendor/katex/auto-render.min.js",
        }
        for _, asset := range assets {
                fp := filepath.Join(staticDir, asset)
                data, err := os.ReadFile(fp)
                if err != nil {
                        slog.Warn("SRI: cannot read asset", "path", fp, "error", err)
                        continue
                }
                h := sha512.Sum384(data)
                sri := "sha384-" + base64.StdEncoding.EncodeToString(h[:])
                sriCache.Store(asset, sri)
        }
        slog.Info("SRI hashes computed", "assets", len(assets))
}

func staticSRI(path string) template.HTMLAttr {
        if v, ok := sriCache.Load(path); ok {
                return template.HTMLAttr(`integrity="` + v.(string) + `" crossorigin="anonymous"`)
        }
        return ""
}

const (
        mapKeyDanger  = "danger"
        mapKeySuccess = "success"
        mapKeyWarning = "warning"
)

func FuncMap() template.FuncMap {
        m := template.FuncMap{}
        mergeFuncs(m, dateTimeFuncs())
        mergeFuncs(m, numberFuncs())
        mergeFuncs(m, stringFuncs())
        mergeFuncs(m, safeFuncs())
        mergeFuncs(m, mapFuncs())
        mergeFuncs(m, sliceFuncs())
        mergeFuncs(m, comparisonFuncs())
        mergeFuncs(m, displayFuncs())
        mergeFuncs(m, iconFuncs())
        return m
}

func iconFuncs() template.FuncMap {
        return template.FuncMap{
                "icon":     icons.Icon,
                "iconJSON": icons.IconSVGJSON,
        }
}

func mergeFuncs(dst, src template.FuncMap) {
        for k, v := range src {
                dst[k] = v
        }
}

func formatTimeValue(t interface{}, layout, defaultVal string) string {
        switch v := t.(type) {
        case time.Time:
                return v.Format(layout)
        case string:
                return v
        default:
                return defaultVal
        }
}

func formatDate(t interface{}) string {
        return formatTimeValue(t, "Jan 02, 2006 15:04 UTC", fmt.Sprintf("%v", t))
}

func formatDateShort(t interface{}) string {
        return formatTimeValue(t, "2006-01-02", "")
}

func formatTime(t interface{}) string {
        return formatTimeValue(t, "15:04:05", "")
}

func formatDateTime(t interface{}) string {
        return formatTimeValue(t, "2006-01-02 15:04:05", "")
}

func formatDateMonthDay(t interface{}) string {
        return formatTimeValue(t, "01/02", "")
}

func formatDuration(d interface{}) string {
        switch v := d.(type) {
        case float64:
                if v < 1.0 {
                        return fmt.Sprintf("%.0fms", v*1000)
                }
                return fmt.Sprintf("%.1fs", v)
        case float32:
                return fmt.Sprintf("%.1fs", v)
        default:
                return fmt.Sprintf("%v", d)
        }
}

func dateTimeFuncs() template.FuncMap {
        return template.FuncMap{
                "formatDate":         formatDate,
                "formatDateShort":    formatDateShort,
                "formatTime":         formatTime,
                "formatDateTime":     formatDateTime,
                "formatDateMonthDay": formatDateMonthDay,
                "formatDuration":     formatDuration,
                "currentYear": func() int {
                        return time.Now().Year()
                },
        }
}

func formatFloat(precision int, f interface{}) string {
        switch v := f.(type) {
        case float64:
                return fmt.Sprintf("%.*f", precision, v)
        case float32:
                return fmt.Sprintf("%.*f", precision, float64(v))
        case int:
                return fmt.Sprintf("%.*f", precision, float64(v))
        case int64:
                return fmt.Sprintf("%.*f", precision, float64(v))
        default:
                return fmt.Sprintf("%v", f)
        }
}

func successRate(successful, total interface{}) string {
        s := toFloat64(successful)
        t := toFloat64(total)
        if t == 0 {
                return "0"
        }
        return fmt.Sprintf("%.1f", (s/t)*100)
}

func percent(value, total interface{}) float64 {
        v := toFloat64(value)
        t := toFloat64(total)
        if t == 0 {
                return 0
        }
        return math.Round(v/t*1000) / 10
}

func addInt(a, b int) int { return a + b }
func subInt(a, b int) int { return a - b }
func mulInt(a, b int) int { return a * b }
func maxInt(a, b int) int {
        if a > b {
                return a
        }
        return b
}
func minInt(a, b int) int {
        if a < b {
                return a
        }
        return b
}

func divFloat(a, b float64) float64 {
        if b == 0 {
                return 0
        }
        return a / b
}

func modInt(a, b int) int {
        if b == 0 {
                return 0
        }
        return a % b
}

func intDiv(a, b interface{}) int {
        ai := int(toFloat64(a))
        bi := int(toFloat64(b))
        if bi == 0 {
                return 0
        }
        return ai / bi
}

func maxIntIface(a, b interface{}) int {
        ai := int(toFloat64(a))
        bi := int(toFloat64(b))
        if ai > bi {
                return ai
        }
        return bi
}

func numberFuncs() template.FuncMap {
        return template.FuncMap{
                "formatFloat": formatFloat,
                "successRate": successRate,
                "percent":     percent,
                "add":         addInt,
                "sub":         subInt,
                "mul":         mulInt,
                "divf":        divFloat,
                "mod":         modInt,
                "max":         maxInt,
                "min":         minInt,
                "intDiv":      intDiv,
                "maxInt":      maxIntIface,
        }
}

func truncateStr(length int, s string) string {
        if len(s) <= length {
                return s
        }
        return s[:length] + "..."
}

func substrStr(start, length int, s string) string {
        if start >= len(s) {
                return ""
        }
        end := start + length
        if end > len(s) {
                end = len(s)
        }
        return s[start:end]
}

func replaceStr(old, new, s string) string {
        return strings.ReplaceAll(s, old, new)
}

func urlEncode(s string) string {
        return url.QueryEscape(s)
}

func slugify(s string) string {
        var b strings.Builder
        for _, c := range strings.ToLower(s) {
                if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
                        b.WriteRune(c)
                } else {
                        b.WriteByte('-')
                }
        }
        return b.String()
}

func bimiProxyURL(logoURL string) template.URL {
        return template.URL("/proxy/bimi-logo?url=" + url.QueryEscape(logoURL))
}

func stringFuncs() template.FuncMap {
        return template.FuncMap{
                "upper":        strings.ToUpper,
                "lower":        strings.ToLower,
                "title":        cases.Title(language.English).String,
                "contains":     strings.Contains,
                "hasPrefix":    strings.HasPrefix,
                "hasSuffix":    strings.HasSuffix,
                "join":         strings.Join,
                "trimSpace":    strings.TrimSpace,
                "truncate":     truncateStr,
                "substr":       substrStr,
                "replace":      replaceStr,
                "urlEncode":    urlEncode,
                "bimiProxyURL": bimiProxyURL,
                "slugify":      slugify,
        }
}

func safeFuncs() template.FuncMap {
        return template.FuncMap{
                "safeHTML": func(s string) template.HTML {
                        return template.HTML(template.HTMLEscapeString(s))
                },
                "safeURL": func(s string) template.URL {
                        return template.URL(url.QueryEscape(s))
                },
                "safeAttr": func(s string) template.HTMLAttr {
                        return template.HTMLAttr(template.HTMLEscapeString(s))
                },
                "safeJS": func(s string) template.JS {
                        return template.JS(template.JSEscapeString(s))
                },
        }
}

func mapGet(key string, m map[string]interface{}) interface{} {
        if m == nil {
                return nil
        }
        return m[key]
}

func mapGetStr(key string, m map[string]interface{}) string {
        if m == nil {
                return ""
        }
        v, ok := m[key]
        if !ok || v == nil {
                return ""
        }
        s, ok := v.(string)
        if !ok {
                return fmt.Sprintf("%v", v)
        }
        return s
}

func mapGetInt(key string, m map[string]interface{}) int {
        if m == nil {
                return 0
        }
        v, ok := m[key]
        if !ok || v == nil {
                return 0
        }
        switch n := v.(type) {
        case int:
                return n
        case int64:
                return int(n)
        case float64:
                return int(n)
        default:
                return 0
        }
}

func mapGetFloat(key string, m map[string]interface{}) float64 {
        if m == nil {
                return 0
        }
        return toFloat64(m[key])
}

func mapGetBool(key string, m map[string]interface{}) bool {
        if m == nil {
                return false
        }
        v, ok := m[key]
        if !ok || v == nil {
                return false
        }
        b, ok := v.(bool)
        return ok && b
}

func mapGetMap(key string, m map[string]interface{}) map[string]interface{} {
        if m == nil {
                return nil
        }
        v, ok := m[key]
        if !ok || v == nil {
                return nil
        }
        sub, ok := v.(map[string]interface{})
        if !ok {
                return nil
        }
        return sub
}

func mapGetSlice(key string, m map[string]interface{}) []interface{} {
        if m == nil {
                return nil
        }
        v, ok := m[key]
        if !ok || v == nil {
                return nil
        }
        switch s := v.(type) {
        case []interface{}:
                return s
        case []string:
                result := make([]interface{}, len(s))
                for i, str := range s {
                        result[i] = str
                }
                return result
        case []map[string]interface{}:
                result := make([]interface{}, len(s))
                for i, m := range s {
                        result[i] = m
                }
                return result
        default:
                return nil
        }
}

func mapKeys(m map[string]interface{}) []string {
        if m == nil {
                return nil
        }
        keys := make([]string, 0, len(m))
        for k := range m {
                keys = append(keys, k)
        }
        return keys
}

func dict(values ...interface{}) map[string]interface{} {
        if len(values)%2 != 0 {
                return nil
        }
        d := make(map[string]interface{}, len(values)/2)
        for i := 0; i < len(values); i += 2 {
                key, ok := values[i].(string)
                if !ok {
                        continue
                }
                d[key] = values[i+1]
        }
        return d
}

func isMap(v interface{}) bool {
        _, ok := v.(map[string]interface{})
        return ok
}

func toMap(v interface{}) map[string]interface{} {
        if v == nil {
                return nil
        }
        m, ok := v.(map[string]interface{})
        if !ok {
                return nil
        }
        return m
}

func mapFuncs() template.FuncMap {
        return template.FuncMap{
                "mapGet":      mapGet,
                "mapGetStr":   mapGetStr,
                "mapGetInt":   mapGetInt,
                "mapGetFloat": mapGetFloat,
                "mapGetBool":  mapGetBool,
                "mapGetMap":   mapGetMap,
                "mapGetSlice": mapGetSlice,
                "mapKeys":     mapKeys,
                "dict":        dict,
                "isMap":       isMap,
                "toMap":       toMap,
        }
}

func listSlice(values ...interface{}) []interface{} {
        return values
}

func seq(start, end int) []int {
        var result []int
        for i := start; i <= end; i++ {
                result = append(result, i)
        }
        return result
}

func isSlice(v interface{}) bool {
        switch v.(type) {
        case []interface{}, []string, []int, []float64:
                return true
        default:
                return false
        }
}

func sliceFrom(start int, s []interface{}) []interface{} {
        if start >= len(s) {
                return nil
        }
        return s[start:]
}

func sliceIndex(i int, s []interface{}) interface{} {
        if i < 0 || i >= len(s) {
                return nil
        }
        return s[i]
}

func toInt(v interface{}) int {
        switch n := v.(type) {
        case int:
                return n
        case int32:
                return int(n)
        case int64:
                return int(n)
        case float64:
                return int(n)
        case float32:
                return int(n)
        default:
                return 0
        }
}

func toStringSlice(v interface{}) []string {
        if v == nil {
                return nil
        }
        switch s := v.(type) {
        case []string:
                return s
        case []interface{}:
                result := make([]string, 0, len(s))
                for _, item := range s {
                        if str, ok := item.(string); ok {
                                result = append(result, str)
                        }
                }
                return result
        default:
                return nil
        }
}

func toMapSlice(v interface{}) []map[string]interface{} {
        if v == nil {
                return nil
        }
        switch s := v.(type) {
        case []map[string]interface{}:
                return s
        case []interface{}:
                result := make([]map[string]interface{}, 0, len(s))
                for _, item := range s {
                        if m, ok := item.(map[string]interface{}); ok {
                                result = append(result, m)
                        }
                }
                return result
        default:
                return nil
        }
}

func sliceFuncs() template.FuncMap {
        return template.FuncMap{
                "list":          listSlice,
                "seq":           seq,
                "isSlice":       isSlice,
                "sliceFrom":     sliceFrom,
                "sliceIndex":    sliceIndex,
                "toInt":         toInt,
                "toStringSlice": toStringSlice,
                "toMapSlice":    toMapSlice,
        }
}

func isNumeric(v interface{}) bool {
        switch v.(type) {
        case int, int8, int16, int32, int64,
                uint, uint8, uint16, uint32, uint64,
                float32, float64:
                return true
        default:
                return false
        }
}

func safeEqual(a, b interface{}) bool {
        if isNumeric(a) && isNumeric(b) {
                return toFloat64(a) == toFloat64(b)
        }
        if a == nil || b == nil {
                return a == b
        }
        return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func safeEq(arg1 interface{}, args ...interface{}) bool {
        for _, arg2 := range args {
                if safeEqual(arg1, arg2) {
                        return true
                }
        }
        return false
}

func safeNe(a, b interface{}) bool { return !safeEqual(a, b) }

func gtCmp(a, b interface{}) bool  { return toFloat64(a) > toFloat64(b) }
func gteCmp(a, b interface{}) bool { return toFloat64(a) >= toFloat64(b) }
func ltCmp(a, b interface{}) bool  { return toFloat64(a) < toFloat64(b) }
func lteCmp(a, b interface{}) bool { return toFloat64(a) <= toFloat64(b) }
func geCmp(a, b interface{}) bool  { return toFloat64(a) >= toFloat64(b) }
func leCmp(a, b interface{}) bool  { return toFloat64(a) <= toFloat64(b) }
func isNil(v interface{}) bool     { return v == nil }
func notNil(v interface{}) bool    { return v != nil }

func defaultVal(defaultV, val interface{}) interface{} {
        if val == nil {
                return defaultV
        }
        if s, ok := val.(string); ok && s == "" {
                return defaultV
        }
        return val
}

func coalesce(vals ...interface{}) interface{} {
        for _, v := range vals {
                if v == nil {
                        continue
                }
                if s, ok := v.(string); ok && s == "" {
                        continue
                }
                return v
        }
        return nil
}

func comparisonFuncs() template.FuncMap {
        return template.FuncMap{
                "eq":       safeEq,
                "ne":       safeNe,
                "gt":       gtCmp,
                "gte":      gteCmp,
                "lt":       ltCmp,
                "lte":      lteCmp,
                "ge":       geCmp,
                "le":       leCmp,
                "isNil":    isNil,
                "notNil":   notNil,
                "default":  defaultVal,
                "coalesce": coalesce,
        }
}

const bgDanger = "bg-danger"
const iconWrench = "wrench"

var statusBadgeClassMap = map[string]string{
        mapKeySuccess: "bg-success",
        mapKeyWarning: "bg-warning",
        "info":        "bg-info",
        mapKeyDanger:  bgDanger,
        "error":       bgDanger,
        "critical":    bgDanger,
}

var statusColorMap = map[string]string{
        mapKeySuccess: mapKeySuccess,
        mapKeyWarning: mapKeyWarning,
        "partial":     mapKeyWarning,
        "error":       mapKeyDanger,
        mapKeyDanger:  mapKeyDanger,
        "critical":    mapKeyDanger,
        "info":        "info",
}

func statusBadgeClass(status string) string {
        if c, ok := statusBadgeClassMap[strings.ToLower(status)]; ok {
                return c
        }
        return "bg-secondary"
}

func statusColor(status string) string {
        if c, ok := statusColorMap[strings.ToLower(status)]; ok {
                return c
        }
        return "secondary"
}

func countryFlag(code string) string {
        if len(code) != 2 {
                return ""
        }
        code = strings.ToUpper(code)
        r1 := rune(0x1F1E6 + int(code[0]) - int('A'))
        r2 := rune(0x1F1E6 + int(code[1]) - int('A'))
        return string([]rune{r1, r2})
}

func staticURL(path string) string {
        return "/static/" + path
}

func staticVersionURL(path, version string) string {
        u := "/static/" + path + "?v=" + version
        if v, ok := sriCache.Load(path); ok {
                sri := v.(string)
                if len(sri) > 12 {
                        u += "&h=" + sri[len(sri)-8:]
                }
        }
        return u
}

func toJSON(v interface{}) string {
        b, err := json.Marshal(v)
        if err != nil {
                return "{}"
        }
        return string(b)
}

func toStr(v interface{}) string {
        if v == nil {
                return ""
        }
        s, ok := v.(string)
        if ok {
                return s
        }
        return fmt.Sprintf("%v", v)
}

func pluralize(count interface{}, singular, plural string) string {
        n := toFloat64(count)
        if n == 1 {
                return singular
        }
        return plural
}

func htmlComment(s string) template.HTML {
        clean := strings.ReplaceAll(s, "--", "\u2014")
        clean = strings.ReplaceAll(clean, ">", "\u203A")
        return template.HTML("<!--\n" + clean + "\n-->")
}

func displayFuncs() template.FuncMap {
        return template.FuncMap{
                "statusBadgeClass":  statusBadgeClass,
                "statusColor":       statusColor,
                "sectionStatusCSS":  sectionStatusCSS,
                "sectionStatusIcon": sectionStatusIcon,
                "countryFlag":       countryFlag,
                "staticURL":         staticURL,
                "staticVersionURL":  staticVersionURL,
                "staticSRI":         staticSRI,
                "toJSON":            toJSON,
                "toStr":             toStr,
                "pluralize":         pluralize,
                "htmlComment":       htmlComment,
                "levelBadge":        logLevelBadge,
                "levelColor":        logLevelColor,
                "buildExportQuery":  buildExportQuery,
        }
}

func logLevelBadge(level string) string {
        switch strings.ToUpper(level) {
        case "ERROR":
                return "bg-danger"
        case "WARN":
                return "bg-warning text-dark"
        case "INFO":
                return "bg-info text-dark"
        case "DEBUG":
                return "bg-secondary"
        default:
                return "bg-light text-dark"
        }
}

func logLevelColor(level string) string {
        switch strings.ToUpper(level) {
        case "ERROR":
                return "text-danger"
        case "WARN":
                return "text-warning"
        case "INFO":
                return "text-info"
        case "DEBUG":
                return "text-secondary"
        default:
                return ""
        }
}

func buildExportQuery(level, category, domain, traceID, after, before string) string {
        params := url.Values{}
        if level != "" {
                params.Set("level", level)
        }
        if category != "" {
                params.Set("category", category)
        }
        if domain != "" {
                params.Set("domain", domain)
        }
        if traceID != "" {
                params.Set("trace_id", traceID)
        }
        if after != "" {
                params.Set("after", after)
        }
        if before != "" {
                params.Set("before", before)
        }
        if len(params) == 0 {
                return ""
        }
        return "?" + params.Encode()
}

var sectionStatusCSSMap = map[string]string{
        "beta":               "u-status-beta",
        "active development": "u-status-active",
        "maintenance":        "u-status-maintenance",
        "experimental":       "u-status-experimental",
        "deprecated":         "u-status-deprecated",
        "accuracy tuning":    "u-section-tuning",
}

var sectionStatusIconMap = map[string]string{
        "beta":               "flask",
        "active development": "code",
        "maintenance":        iconWrench,
        "experimental":       "microscope",
        "deprecated":         "archive",
        "accuracy tuning":    iconWrench,
}

func sectionStatusCSS(status string) string {
        if c, ok := sectionStatusCSSMap[strings.ToLower(status)]; ok {
                return c
        }
        return "u-section-tuning"
}

func sectionStatusIcon(status string) string {
        if c, ok := sectionStatusIconMap[strings.ToLower(status)]; ok {
                return c
        }
        return iconWrench
}

func toFloat64(v interface{}) float64 {
        switch n := v.(type) {
        case int:
                return float64(n)
        case int8:
                return float64(n)
        case int16:
                return float64(n)
        case int32:
                return float64(n)
        case int64:
                return float64(n)
        case uint:
                return float64(n)
        case uint8:
                return float64(n)
        case uint16:
                return float64(n)
        case uint32:
                return float64(n)
        case uint64:
                return float64(n)
        case float32:
                return float64(n)
        case float64:
                return n
        case string:
                if f, err := strconv.ParseFloat(n, 64); err == nil {
                        return f
                }
                return 0
        default:
                return 0
        }
}
