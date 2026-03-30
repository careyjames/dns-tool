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
        "net/http"
        "strconv"
        "strings"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dnsclient"

        "github.com/gin-gonic/gin"
)

const (
        colorDanger    = "#e05d44"
        colorGrey      = "#9f9f9f"
        contentTypeSVG = "image/svg+xml; charset=utf-8"
        labelDNSTool   = "DNS Tool"

        mapKeyColor      = "color"
        mapKeyLabel      = "label"
        mapKeyLightgrey  = "lightgrey"
        strSchemaversion = "schemaVersion"

        hexRed       = "#f85149"
        hexGreen     = "#3fb950"
        hexYellow    = "#d29922"
        hexScGreen   = "#58E790"
        hexScYellow  = "#C7C400"
        hexScRed     = "#B43C29"
        hexDimGrey   = "#30363d"

        labelGatewayDerived = "Gateway Derived"

        protoMTASTS = "MTA-STS"
        protoTLSRPT = "TLS-RPT"
        protoDMARC  = "DMARC"
        protoDNSSEC = "DNSSEC"
)

type BadgeHandler struct {
        DB          *db.Database
        Config      *config.Config
        lookupStore LookupStore
}

func (h *BadgeHandler) store() LookupStore {
        if h.lookupStore != nil {
                return h.lookupStore
        }
        if h.DB != nil {
                return h.DB.Queries
        }
        return nil
}

func NewBadgeHandler(database *db.Database, cfg *config.Config) *BadgeHandler {
        return &BadgeHandler{DB: database, Config: cfg}
}

func (h *BadgeHandler) resolveAnalysis(c *gin.Context) (domain string, results map[string]any, scanTime time.Time, scanID int32, postureHash string, ok bool) {
        domainQ := strings.TrimSpace(c.Query(mapKeyDomain))
        idQ := strings.TrimSpace(c.Query("id"))

        if domainQ == "" && idQ == "" {
                c.Data(http.StatusBadRequest, contentTypeSVG, badgeSVG(mapKeyError, "missing domain or id", colorDanger))
                return "", nil, time.Time{}, 0, "", false
        }

        ctx := c.Request.Context()

        if idQ != "" {
                sid, err := strconv.ParseInt(idQ, 10, 32)
                if err != nil {
                        c.Data(http.StatusBadRequest, contentTypeSVG, badgeSVG(mapKeyError, "invalid scan id", colorDanger))
                        return "", nil, time.Time{}, 0, "", false
                }
                analysis, err := h.store().GetAnalysisByID(ctx, int32(sid))
                if err != nil || analysis.Private {
                        c.Data(http.StatusNotFound, contentTypeSVG, badgeSVG(labelDNSTool, "scan not found", colorGrey))
                        return "", nil, time.Time{}, 0, "", false
                }
                results := unmarshalResults(analysis.FullResults, "Badge")
                return analysis.Domain, results, analysis.CreatedAt.Time, analysis.ID, derefString(analysis.PostureHash), true
        }

        ascii, err := dnsclient.DomainToASCII(domainQ)
        if err != nil || !dnsclient.ValidateDomain(ascii) {
                c.Data(http.StatusBadRequest, contentTypeSVG, badgeSVG(mapKeyError, "invalid domain", colorDanger))
                return "", nil, time.Time{}, 0, "", false
        }

        analysis, err := h.store().GetRecentAnalysisByDomain(ctx, ascii)
        if err != nil || analysis.Private {
                c.Data(http.StatusNotFound, contentTypeSVG, badgeSVG(labelDNSTool, "not scanned", colorGrey))
                return "", nil, time.Time{}, 0, "", false
        }
        res := unmarshalResults(analysis.FullResults, "Badge")
        return ascii, res, analysis.CreatedAt.Time, analysis.ID, derefString(analysis.PostureHash), true
}

func (h *BadgeHandler) Badge(c *gin.Context) {
        domain, results, scanTime, scanID, postureHash, ok := h.resolveAnalysis(c)
        if !ok {
                return
        }
        if results == nil {
                c.Data(http.StatusOK, contentTypeSVG, badgeSVG(labelDNSTool, "no data", colorGrey))
                return
        }

        riskLabel, riskColor := extractPostureRisk(results)
        riskHex := riskColorToHex(riskColor)
        score := extractPostureScore(results)
        exposure := extractExposure(results)
        style := c.DefaultQuery("style", "flat")

        if isGatewayDerivedResult(results) {
                riskLabel = labelGatewayDerived
                riskHex = hexYellow
                score = -1
        }

        compactValue := riskLabel
        if score >= 0 {
                compactValue = fmt.Sprintf("%s (%d/100)", riskLabel, score)
        }
        if isGatewayDerivedResult(results) {
                compactValue = "Gateway Derived — attribution limited"
        }
        if exposure.status == "exposed" && exposure.findingCount > 0 {
                compactValue += fmt.Sprintf(" · %d secret%s exposed", exposure.findingCount, pluralS(exposure.findingCount))
                riskHex = hexRed
        }

        c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
        c.Header("Pragma", "no-cache")
        c.Header("Expires", "0")

        switch style {
        case "covert":
                c.Data(http.StatusOK, contentTypeSVG, badgeSVGCovert(domain, results, scanTime, scanID, postureHash, h.Config.BaseURL))
        case "detailed":
                c.Data(http.StatusOK, contentTypeSVG, badgeSVGDetailed(domain, results, scanTime, scanID, postureHash, h.Config.BaseURL))
        default:
                c.Data(http.StatusOK, contentTypeSVG, badgeSVG(domain, compactValue, riskHex))
        }
}

func (h *BadgeHandler) BadgeEmbed(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")
        c.HTML(http.StatusOK, "badge_embed.html", gin.H{
                keyCspNonce:        nonce,
                "CsrfToken":       csrfToken,
                keyAppVersion:      h.Config.AppVersion,
                "BaseURL":         h.Config.BaseURL,
                keyMaintenanceNote: h.Config.MaintenanceNote,
                keyBetaPages:       h.Config.BetaPages,
        })
}

func unmarshalResults(fullResults []byte, caller string) map[string]any {
        if len(fullResults) == 0 {
                return nil
        }
        var results map[string]any
        if err := json.Unmarshal(fullResults, &results); err != nil {
                slog.Warn(caller+": unmarshal full_results", mapKeyError, err)
                return nil
        }
        return results
}

func extractPostureRisk(results map[string]any) (string, string) {
        riskLabel := "Unknown"
        riskColor := ""
        if results == nil {
                return riskLabel, riskColor
        }
        postureRaw, ok := results["posture"]
        if !ok {
                return riskLabel, riskColor
        }
        posture, ok := postureRaw.(map[string]any)
        if !ok {
                return riskLabel, riskColor
        }
        if rl, ok := posture[mapKeyLabel].(string); ok && rl != "" {
                riskLabel = rl
        } else if rl, ok := posture["grade"].(string); ok && rl != "" {
                riskLabel = rl
        }
        if rc, ok := posture[mapKeyColor].(string); ok {
                riskColor = rc
        }
        return riskLabel, riskColor
}

func riskColorToHex(color string) string {
        switch color {
        case "success":
                return hexGreen
        case "warning":
                return hexYellow
        case "danger":
                return colorDanger
        default:
                return colorGrey
        }
}

func normalizeRiskColor(label, color string) string {
        switch color {
        case "success", "warning", "danger":
                return color
        }
        ll := strings.ToLower(label)
        switch {
        case strings.Contains(ll, "low"):
                return "success"
        case strings.Contains(ll, "medium"):
                return "warning"
        case strings.Contains(ll, "high"), strings.Contains(ll, "critical"):
                return "danger"
        }
        return color
}

func reportRiskColor(color string) string {
        switch color {
        case "success":
                return "#198754"
        case "warning":
                return "#ffc107"
        case "danger":
                return "#dc3545"
        default:
                return colorGrey
        }
}

func scotopicRiskColor(color string) string {
        switch color {
        case "success":
                return hexScGreen
        case "warning":
                return hexScYellow
        case "danger":
                return hexScRed
        default:
                return "#9C7645"
        }
}

func badgeSVG(label, value, color string) []byte {
        labelWidth := len(label)*7 + 10
        valueWidth := len(value)*7 + 10
        totalWidth := labelWidth + valueWidth

        svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="%s: %s">
  <title>%s: %s</title>
  <linearGradient id="s" x2="0" y2="100%%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="%d" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="%d" height="20" fill="#555"/>
    <rect x="%d" width="%d" height="20" fill="%s"/>
    <rect width="%d" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text aria-hidden="true" x="%d" y="15" fill="#010101" fill-opacity=".3">%s</text>
    <text x="%d" y="14">%s</text>
    <text aria-hidden="true" x="%d" y="15" fill="#010101" fill-opacity=".3">%s</text>
    <text x="%d" y="14">%s</text>
  </g>
</svg>`,
                totalWidth, label, value, label, value,
                totalWidth,
                labelWidth,
                labelWidth, valueWidth, color,
                totalWidth,
                labelWidth/2+1, label,
                labelWidth/2+1, label,
                labelWidth+valueWidth/2-1, value,
                labelWidth+valueWidth/2-1, value,
        )
        return []byte(svg)
}

func shieldsErrorJSON(msg string, isError bool) gin.H {
        resp := gin.H{
                strSchemaversion: 1,
                mapKeyLabel:      labelDNSTool,
                mapKeyMessage:    msg,
                mapKeyColor:      mapKeyLightgrey,
        }
        if isError {
                resp["isError"] = true
        }
        return resp
}

func (h *BadgeHandler) BadgeShieldsIO(c *gin.Context) {
        domainQ := strings.TrimSpace(c.Query(mapKeyDomain))
        idQ := strings.TrimSpace(c.Query("id"))

        if domainQ == "" && idQ == "" {
                c.JSON(http.StatusOK, shieldsErrorJSON("missing domain or id", true))
                return
        }

        results, errResp := h.loadShieldsResults(c.Request.Context(), idQ, domainQ)
        if errResp != nil {
                c.JSON(http.StatusOK, errResp)
                return
        }

        riskLabel, riskColorRaw := extractPostureRisk(results)
        if isGatewayDerivedResult(results) {
                riskLabel = labelGatewayDerived
                riskColorRaw = "warning"
        }
        shieldsColor := riskColorToShields(riskColorRaw)

        c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
        c.Header("Pragma", "no-cache")
        c.Header("Expires", "0")

        resp := gin.H{
                strSchemaversion: 1,
                mapKeyLabel:      labelDNSTool,
                mapKeyMessage:    riskLabel,
                mapKeyColor:      shieldsColor,
                "namedLogo":      "shield",
                "cacheSeconds":   3600,
        }

        c.JSON(http.StatusOK, resp)
}

func (h *BadgeHandler) loadShieldsResults(ctx context.Context, idQ, domainQ string) (map[string]any, gin.H) {
        if idQ != "" {
                scanID, err := strconv.ParseInt(idQ, 10, 32)
                if err != nil {
                        return nil, shieldsErrorJSON("invalid scan id", true)
                }
                analysis, err := h.store().GetAnalysisByID(ctx, int32(scanID))
                if err != nil || analysis.Private {
                        return nil, shieldsErrorJSON("scan not found", false)
                }
                return unmarshalResults(analysis.FullResults, "BadgeShieldsIO"), nil
        }
        ascii, err := dnsclient.DomainToASCII(domainQ)
        if err != nil || !dnsclient.ValidateDomain(ascii) {
                return nil, shieldsErrorJSON("invalid domain", true)
        }
        analysis, err := h.store().GetRecentAnalysisByDomain(ctx, ascii)
        if err != nil || analysis.Private {
                return nil, shieldsErrorJSON("not scanned", false)
        }
        return unmarshalResults(analysis.FullResults, "BadgeShieldsIO"), nil
}

func riskColorToShields(color string) string {
        switch color {
        case "success":
                return "brightgreen"
        case "warning":
                return "yellow"
        case "danger":
                return "red"
        default:
                return mapKeyLightgrey
        }
}

func covertRiskLabel(riskLabel string) string {
        switch riskLabel {
        case "Low Risk":
                return "Hardened"
        case "Medium Risk":
                return "Partial"
        case "High Risk":
                return "Exposed"
        case "Critical Risk":
                return "Wide Open"
        default:
                return riskLabel
        }
}

func covertTagline(riskLabel string) string {
        switch riskLabel {
        case "Low Risk":
                return "Good luck with that."
        case "Medium Risk":
                return "Gaps in the armor."
        case "High Risk":
                return "Door's open."
        case "Critical Risk":
                return "Free real estate."
        default:
                return ""
        }
}

func riskBorderColor(riskColorName string) string {
        switch riskColorName {
        case "success":
                return "#238636"
        case "warning":
                return "#9e6a03"
        case "danger":
                return "#da3633"
        default:
                return hexDimGrey
        }
}

func countMissing(nodes []protocolNode) int {
        count := 0
        for _, n := range nodes {
                if n.status == "missing" || n.status == "error" {
                        count++
                }
        }
        return count
}

func countVulnerable(nodes []protocolNode) int {
        count := 0
        for _, n := range nodes {
                if n.status != "success" && n.status != "warning" && n.status != "info" {
                        count++
                }
        }
        return count
}

type covertLine struct {
        prefix      string
        text        string
        color       string
        prefixColor string
        desc        string
        descColor   string
        link        string
}

type covertDesc struct {
        success string
        warning string
        fail    string
}

type covertRenderCtx struct {
        xPad          int
        lineH         int
        fontSize      int
        charW         int
        width         int
        monoFont      string
        dimLocked     string
        sRed          string
        alt           string
        resultStartAt float64
}

var covertDescriptions = map[string]covertDesc{
        "SPF":       {success: "can't forge sender envelope", warning: "partial — spoofing harder", fail: "sender spoofing possible"},
        "DKIM":      {success: "can't forge signatures", warning: "weak key — forgery harder", fail: "message forgery possible"},
        protoDMARC:  {success: "spoofing rejected at gate", warning: "monitoring only — not blocking", fail: "email spoofing wide open"},
        protoDNSSEC: {success: "can't poison DNS cache", warning: "partial — some zones exposed", fail: "DNS cache poisoning possible"},
        "DANE":      {success: "can't downgrade TLS", warning: "TLSA present but weak", fail: "TLS downgrade possible"},
        protoMTASTS: {success: "can't intercept mail", warning: "testing mode — not enforcing", fail: "mail interception possible"},
        protoTLSRPT: {success: "transport monitored", warning: "partial reporting", fail: "no transport monitoring"},
        "BIMI":      {success: "brand verification active", warning: "present but no VMC cert", fail: "brand impersonation possible"},
        "CAA":       {success: "cert issuance locked", warning: "policy present but weak", fail: "anyone can issue certs"},
        "Web3":      {success: "Web3 infra detected", warning: "partial Web3 presence", fail: "no Web3 detected"},
}

func covertStatusPrefix(status string) string {
        switch status {
        case "success":
                return "[+]"
        case "warning":
                return "[~]"
        default:
                return "[-]"
        }
}

func covertProtocolLine(abbrev, status string) covertLine {
        pad := 10 - len(abbrev)
        if pad < 1 {
                pad = 1
        }
        dots := strings.Repeat(".", pad)
        label := abbrev + " " + dots + " "

        desc, ok := covertDescriptions[abbrev]
        if !ok {
                return covertLine{prefix: "[?]", text: label, color: hexScRed, desc: "unknown", descColor: hexScRed}
        }

        msg := desc.fail
        switch status {
        case "success":
                msg = desc.success
        case "warning":
                msg = desc.warning
        }

        return covertLine{prefix: covertStatusPrefix(status), text: label, color: hexScRed, desc: msg, descColor: hexScRed}
}

func covertExposureLines(exposure exposureData, sRed, alt, baseURL string, scanID int32) []covertLine {
        if exposure.status != "exposed" || exposure.findingCount == 0 {
                return nil
        }
        cl := func(pfx, txt, c string) covertLine {
                return covertLine{prefix: pfx, text: txt, color: c}
        }
        var lines []covertLine
        lines = append(lines, cl("", "", ""))
        lines = append(lines, cl("", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", alt))
        lines = append(lines, cl("[!!]", fmt.Sprintf("SECRET EXPOSURE — %d credential%s found", exposure.findingCount, pluralS(exposure.findingCount)), sRed))
        lines = append(lines, cl("", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", alt))
        for _, f := range exposure.findings {
                label := f.findingType
                if label == "" {
                        label = "Secret"
                }
                redacted := f.redacted
                if len(redacted) > 24 {
                        redacted = redacted[:21] + "..."
                }
                sevTag := covertSeverityTag(f.severity)
                findingLine := cl("[!!]", fmt.Sprintf("  >>> %s: %s%s", label, redacted, sevTag), alt)
                findingLine.link = fmt.Sprintf("%s/analysis/%d/view/C#secret-exposure", baseURL, scanID)
                lines = append(lines, findingLine)
        }
        lines = append(lines, cl("[!!]", "  Credentials are publicly accessible.", sRed))
        return lines
}

func covertSeverityTag(severity string) string {
        switch severity {
        case "critical":
                return " [CRITICAL]"
        case "high":
                return " [HIGH]"
        default:
                return ""
        }
}

func covertPrefixColor(prefix, dimLocked, sRed, alt string) string {
        switch prefix {
        case "[+]":
                return dimLocked
        case "[~]":
                return "#8a8a00"
        case "[-]":
                return "#7a2419"
        case "[!!]", "[!]":
                return sRed
        default:
                return alt
        }
}

type covertSummaryParams struct {
        vulnerable, findingCount int
        tagline                  string
        locked, dimLocked        string
        sRed, alt                string
}

func covertSummaryLines(p covertSummaryParams) []covertLine {
        cl := func(pfx, txt, c string) covertLine {
                return covertLine{prefix: pfx, text: txt, color: c}
        }
        checkCount := 10
        if p.vulnerable == 0 && p.findingCount == 0 {
                return []covertLine{
                        cl("[!]", fmt.Sprintf("All %d checks configured — target is hardened", checkCount), p.locked),
                        cl("[!]", p.tagline, p.dimLocked),
                }
        }
        if p.vulnerable == 0 {
                return []covertLine{
                        cl("[!]", "Infrastructure hardened — but secrets are leaking", p.sRed),
                        cl("[!]", "Rotate exposed credentials immediately.", p.alt),
                }
        }
        vectors := p.vulnerable + p.findingCount
        var lines []covertLine
        if vectors <= 2 && p.vulnerable <= 1 {
                lines = append(lines, cl("[!]", fmt.Sprintf("%d attack vector%s available — mostly locked down", vectors, pluralS(vectors)), p.locked))
                if p.findingCount > 0 {
                        lines = append(lines, cl("[!]", "Rotate exposed credentials.", p.alt))
                } else if p.tagline != "" {
                        lines = append(lines, cl("[!]", p.tagline, p.dimLocked))
                }
        } else {
                lines = append(lines, cl("[!]", fmt.Sprintf("%d of %d attack vectors available", vectors, checkCount), p.sRed))
                if p.findingCount > 0 {
                        lines = append(lines, cl("[!]", "Leaked secrets make infrastructure gaps worse.", p.alt))
                } else if p.tagline != "" {
                        lines = append(lines, cl("[!]", p.tagline, p.alt))
                }
        }
        return lines
}

func renderCovertLines(svg *strings.Builder, lines []covertLine, startY int, rc covertRenderCtx) (lineIdx, y int) {
        y = startY
        for _, line := range lines {
                if line.text == "" && line.prefix == "" {
                        y += rc.lineH / 2
                        continue
                }

                delay := rc.resultStartAt + float64(lineIdx)*0.12

                color := line.color
                if color == "" {
                        color = rc.alt
                }

                pfxColor := line.prefixColor
                if pfxColor == "" && line.prefix != "" {
                        pfxColor = covertPrefixColor(line.prefix, rc.dimLocked, rc.sRed, rc.alt)
                }

                svg.WriteString(fmt.Sprintf(`<g opacity="0"><animate attributeName="opacity" from="0" to="1" dur="0.15s" begin="%.2fs" fill="freeze"/>`, delay))

                if line.link != "" {
                        svg.WriteString(fmt.Sprintf(`<a href="%s" target="_blank">`, line.link))
                }

                renderCovertLineText(svg, line, y, pfxColor, color, rc)

                if line.link != "" {
                        svg.WriteString(`</a>`)
                }
                svg.WriteString(`</g>`)
                y += rc.lineH
                lineIdx++
        }
        return lineIdx, y
}

func renderCovertLineText(svg *strings.Builder, line covertLine, y int, pfxColor, color string, rc covertRenderCtx) {
        if line.prefix == "" {
                svg.WriteString(fmt.Sprintf(
                        `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">%s</text>`,
                        rc.xPad, y, color, rc.fontSize, rc.monoFont, line.text,
                ))
                return
        }
        svg.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">%s</text>`,
                rc.xPad, y, pfxColor, rc.fontSize, rc.monoFont, line.prefix,
        ))
        if line.desc != "" {
                svg.WriteString(fmt.Sprintf(
                        `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">%s</text>`,
                        rc.xPad+28, y, color, rc.fontSize, rc.monoFont, line.text,
                ))
                descX := rc.xPad + 28 + len(line.text)*rc.charW
                dc := line.descColor
                if dc == "" {
                        dc = color
                }
                svg.WriteString(fmt.Sprintf(
                        `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">%s</text>`,
                        descX, y, dc, rc.fontSize, rc.monoFont, line.desc,
                ))
        } else {
                svg.WriteString(fmt.Sprintf(
                        `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">%s</text>`,
                        rc.xPad+28, y, color, rc.fontSize, rc.monoFont, line.text,
                ))
        }
}

func renderCovertFooter(svg *strings.Builder, lineIdx, y int, rc covertRenderCtx, domainDisplay, scanTimeStr string) {
        planetText := "#HackThePlanet!   |  #2600"
        owlDelay := rc.resultStartAt + float64(lineIdx)*0.12
        owlY := y - rc.lineH + 2
        owlX := rc.xPad + 28 + len(planetText)*rc.charW - 14
        svg.WriteString(fmt.Sprintf(`<g opacity="0" transform="translate(%d,%d) scale(0.8)"><animate attributeName="opacity" from="0" to="0.9" dur="0.3s" begin="%.2fs" fill="freeze"/>`, owlX, owlY-11, owlDelay))
        svg.WriteString(fmt.Sprintf(`<circle cx="4" cy="5" r="3" fill="none" stroke="%s" stroke-width="1"/>`, rc.alt))
        svg.WriteString(fmt.Sprintf(`<circle cx="12" cy="5" r="3" fill="none" stroke="%s" stroke-width="1"/>`, rc.alt))
        svg.WriteString(fmt.Sprintf(`<circle cx="4" cy="5" r="1.2" fill="%s"/>`, rc.sRed))
        svg.WriteString(fmt.Sprintf(`<circle cx="12" cy="5" r="1.2" fill="%s"/>`, rc.sRed))
        svg.WriteString(fmt.Sprintf(`<path d="M7,3 L8,0 L9,3" fill="none" stroke="%s" stroke-width="0.8"/>`, rc.alt))
        svg.WriteString(fmt.Sprintf(`<path d="M3,8 Q8,14 13,8" fill="none" stroke="%s" stroke-width="0.8"/>`, rc.alt))
        svg.WriteString(`</g>`)

        bottomY1 := y + 6
        bottomDelay := owlDelay + 0.3
        svg.WriteString(fmt.Sprintf(`<g opacity="0"><animate attributeName="opacity" from="0" to="1" dur="0.15s" begin="%.2fs" fill="freeze"/>`, bottomDelay))
        svg.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">┌──(kali㉿kali)-[~/recon/%s]</text>`,
                rc.xPad, bottomY1, rc.alt, rc.fontSize, rc.monoFont, domainDisplay,
        ))
        svg.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s" text-anchor="end">%s</text>`,
                rc.width-rc.xPad, bottomY1, rc.alt, rc.fontSize, rc.monoFont, scanTimeStr,
        ))
        bottomY2 := bottomY1 + rc.lineH
        svg.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">└─$</text>`,
                rc.xPad, bottomY2, rc.alt, rc.fontSize, rc.monoFont,
        ))
        svg.WriteString(fmt.Sprintf(
                `<rect x="%d" y="%d" width="2" height="%d" fill="%s" class="cursor"/>`,
                rc.xPad+4*rc.charW, bottomY2-10, 12, rc.sRed,
        ))
        svg.WriteString(`</g>`)
}

func badgeSVGCovert(domain string, results map[string]any, scanTime time.Time, scanID int32, postureHash string, baseURL string) []byte {
        riskLabel, riskColorName := extractPostureRisk(results)
        score := extractPostureScore(results)
        if isGatewayDerivedResult(results) {
                riskLabel = labelGatewayDerived
                riskColorName = "warning"
                score = -1
        }
        nodes := extractProtocolIndicators(results)
        vulnerable := countVulnerable(nodes)
        exposure := extractExposure(results)

        covertLabel := covertRiskLabel(riskLabel)
        tagline := covertTagline(riskLabel)

        domainDisplay := domain
        if len(domainDisplay) > 35 {
                domainDisplay = domainDisplay[:32] + "..."
        }

        scoreText := "--"
        if score >= 0 {
                scoreText = strconv.Itoa(score)
        }

        scanDate := scanTime.UTC().Format("2006-01-02")

        const (
                width    = 460
                lineH    = 15
                fontSize = 11
                xPad     = 14
                charW    = 7
                monoFont = "'Hack','Fira Code','JetBrains Mono','Menlo','Monaco','Source Code Pro','SF Mono','Ubuntu Mono','Courier New',monospace"
        )

        sRed := hexScRed
        alt := "#664d2e"
        locked := hexScGreen
        dimLocked := "#2d7a47"

        cl := func(pfx, txt, c string) covertLine {
                return covertLine{prefix: pfx, text: txt, color: c}
        }

        var lines []covertLine

        lines = append(lines, cl("", "", ""))

        lines = append(lines, cl("[*]", fmt.Sprintf("Target: %s", domainDisplay), alt))
        lines = append(lines, cl("[*]", fmt.Sprintf("Score: %s/100 — %s", scoreText, covertLabel), scotopicRiskColor(riskColorName)))
        lines = append(lines, cl("", "", ""))

        protocols := []string{"SPF", "DKIM", protoDMARC, protoDNSSEC, "DANE", protoMTASTS, protoTLSRPT, "BIMI", "CAA"}
        for i, p := range protocols {
                if i < len(nodes) {
                        lines = append(lines, covertProtocolLine(p, nodes[i].status))
                }
        }

        web3Status := extractWeb3Status(results)
        if web3Status != "" {
                lines = append(lines, covertProtocolLine("Web3", web3Status))
        }

        lines = append(lines, covertExposureLines(exposure, sRed, alt, baseURL, scanID)...)

        lines = append(lines, cl("", "", ""))

        lines = append(lines, covertSummaryLines(covertSummaryParams{
                vulnerable: vulnerable, findingCount: exposure.findingCount,
                tagline: tagline, locked: locked, dimLocked: dimLocked,
                sRed: sRed, alt: alt,
        })...)

        lines = append(lines, cl("", "", ""))
        hashDisplay := postureHash
        if len(hashDisplay) > 8 {
                hashDisplay = hashDisplay[:8]
        }
        if hashDisplay == "" {
                hashDisplay = "--------"
        }
        reportURL := fmt.Sprintf("%s/analyze?domain=%s", baseURL, domain)
        hashURL := fmt.Sprintf("%s/analysis/%d/view/C#intelligence-metadata", baseURL, scanID)
        scanLine := cl("", fmt.Sprintf("[*] %s sha3:%s | scan #%d", scanDate, hashDisplay, scanID), alt)
        scanLine.link = reportURL
        lines = append(lines, scanLine)
        shaLine := cl("", "[*] SHA-3 (Keccak-512) NIST FIPS 202", sRed)
        shaLine.link = hashURL
        lines = append(lines, shaLine)
        planetLine := cl("&amp;&amp;", "#HackThePlanet!   |  #2600", sRed)
        planetLine.prefixColor = sRed
        planetLine.link = baseURL
        lines = append(lines, planetLine)

        height := len(lines)*lineH + 24 + 2*lineH + 4 + 2*lineH + 10

        var svg strings.Builder

        cmdText := fmt.Sprintf("dnstool -R -BC %s", domainDisplay)
        cmdLen := len(cmdText)
        typeTime := float64(cmdLen) * 0.06
        cmdDoneAt := 0.8 + typeTime
        resultStartAt := cmdDoneAt + 0.4

        svg.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="DNS Recon: %s — %s">
  <title>DNS Recon: %s — %s</title>
  <defs>
    <linearGradient id="tbg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#1a0505"/>
      <stop offset="1" stop-color="#0a0000"/>
    </linearGradient>
  </defs>
  <style>
    @keyframes blink { 0%%,49%% {opacity:1} 50%%,100%% {opacity:0} }
    @keyframes typeIn { from {opacity:0} to {opacity:1} }
    @keyframes fadeIn { from {opacity:0} to {opacity:1} }
    .cursor { animation: blink 0.8s step-end infinite; animation-delay: 0s; }
    .cursor-hide { animation: blink 0.8s step-end infinite; }
  </style>
  <rect width="%d" height="%d" rx="6" fill="url(#tbg)"/>
  <rect x=".5" y=".5" width="%d" height="%d" rx="6" fill="none" stroke="#3a1515"/>`,
                width, height, width, height,
                domain, covertLabel,
                domain, covertLabel,
                width, height,
                width-1, height-1,
        ))

        svg.WriteString(fmt.Sprintf(`
  <circle cx="16" cy="10" r="4" fill="#ff5f57"/>
  <circle cx="28" cy="10" r="4" fill="#febc2e"/>
  <circle cx="40" cy="10" r="4" fill="#28c840"/>
  <text x="60" y="13" fill="%s" font-size="9" font-family="%s">kali@kali: ~/recon/%s</text>`,
                alt, monoFont, domainDisplay,
        ))

        scanTimeStr := scanTime.UTC().Format("15:04") + "Z"

        promptY := 28
        svg.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">┌──(kali㉿kali)-[~/recon/%s]</text>`,
                xPad, promptY, alt, fontSize, monoFont, domainDisplay,
        ))
        svg.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s" text-anchor="end">%s</text>`,
                width-xPad, promptY, alt, fontSize, monoFont, scanTimeStr,
        ))
        promptY2 := promptY + lineH
        svg.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">└─$</text>`,
                xPad, promptY2, alt, fontSize, monoFont,
        ))

        cmdX := xPad + 4*charW
        for i, ch := range cmdText {
                delay := 0.8 + float64(i)*0.06
                svg.WriteString(fmt.Sprintf(
                        `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s" opacity="0"><animate attributeName="opacity" from="0" to="1" dur="0.01s" begin="%.2fs" fill="freeze"/>%c</text>`,
                        cmdX+i*charW, promptY2, sRed, fontSize, monoFont, delay, ch,
                ))
        }

        rc := covertRenderCtx{
                xPad: xPad, lineH: lineH, fontSize: fontSize, charW: charW,
                width: width, monoFont: monoFont, dimLocked: dimLocked,
                sRed: sRed, alt: alt, resultStartAt: resultStartAt,
        }

        lineIdx, y := renderCovertLines(&svg, lines, promptY2+lineH+4, rc)

        renderCovertFooter(&svg, lineIdx, y, rc, domainDisplay, scanTimeStr)

        svg.WriteString(`</svg>`)

        return []byte(svg.String())
}

func pluralS(n int) string {
        if n == 1 {
                return ""
        }
        return "s"
}

type protocolNode struct {
        abbrev     string
        status     string
        colorHex   string
        x, y       int
        groupColor string
}

func protocolGroupColor(abbrev string) string {
        switch abbrev {
        case "SPF", "DKIM", protoDMARC:
                return "#4fc3f7"
        case protoDNSSEC, "CAA":
                return "#ffb74d"
        case "DANE", protoMTASTS, protoTLSRPT:
                return "#81c784"
        case "BIMI":
                return "#ce93d8"
        case "Web3":
                return "#d4a853"
        default:
                return "#484f58"
        }
}

func protocolStatusToNodeColor(status, groupColor string) string {
        switch status {
        case "success":
                return groupColor
        case "warning":
                return hexYellow
        case "error":
                return hexRed
        case "info":
                return groupColor
        default:
                return hexDimGrey
        }
}

func extractProtocolIndicators(results map[string]any) []protocolNode {
        protocols := []struct {
                key    string
                abbrev string
        }{
                {"spf_analysis", "SPF"},
                {"dkim_analysis", "DKIM"},
                {"dmarc_analysis", protoDMARC},
                {"dnssec_analysis", protoDNSSEC},
                {"dane_analysis", "DANE"},
                {"mta_sts_analysis", protoMTASTS},
                {"tlsrpt_analysis", protoTLSRPT},
                {"bimi_analysis", "BIMI"},
                {"caa_analysis", "CAA"},
        }

        protocols = append(protocols, struct {
                key    string
                abbrev string
        }{"web3_analysis", "Web3"})

        web3St := extractWeb3Status(results)

        nodes := make([]protocolNode, 0, len(protocols))
        for _, p := range protocols {
                status := "missing"
                if p.key == "web3_analysis" {
                        if web3St == "success" {
                                status = "success"
                        } else {
                                status = "info"
                        }
                } else if analysisRaw, ok := results[p.key]; ok {
                        if analysis, ok := analysisRaw.(map[string]any); ok {
                                if s, ok := analysis["status"].(string); ok {
                                        status = s
                                }
                        }
                }
                gc := protocolGroupColor(p.abbrev)
                nc := protocolStatusToNodeColor(status, gc)
                nodes = append(nodes, protocolNode{
                        abbrev:     p.abbrev,
                        status:     status,
                        colorHex:   nc,
                        groupColor: gc,
                })
        }
        return nodes
}

type exposureFinding struct {
        findingType string
        severity    string
        redacted    string
}

type exposureData struct {
        status       string
        findingCount int
        findings     []exposureFinding
}

func extractExposure(results map[string]any) exposureData {
        secRaw, ok := results["secret_exposure"]
        if !ok {
                return exposureData{status: "clear"}
        }
        sec, ok := secRaw.(map[string]any)
        if !ok {
                return exposureData{status: "clear"}
        }
        status, _ := sec["status"].(string)
        if status == "" {
                status = "clear"
        }
        count := 0
        if c, ok := sec["finding_count"].(float64); ok {
                count = int(c)
        }
        var findings []exposureFinding
        if fRaw, ok := sec["findings"].([]any); ok {
                for _, item := range fRaw {
                        f, ok := item.(map[string]any)
                        if !ok {
                                continue
                        }
                        ft, _ := f["type"].(string)
                        sev, _ := f["severity"].(string)
                        red, _ := f["redacted"].(string)
                        findings = append(findings, exposureFinding{
                                findingType: ft,
                                severity:    sev,
                                redacted:    red,
                        })
                }
        }
        return exposureData{
                status:       status,
                findingCount: count,
                findings:     findings,
        }
}

func extractPostureScore(results map[string]any) int {
        postureRaw, ok := results["posture"]
        if !ok {
                return -1
        }
        posture, ok := postureRaw.(map[string]any)
        if !ok {
                return -1
        }
        if s, ok := posture["score"].(float64); ok {
                v := int(s)
                if v < 0 {
                        v = 0
                }
                if v > 100 {
                        v = 100
                }
                return v
        }
        return -1
}

func scoreColor(score int) string {
        if score >= 80 {
                return hexGreen
        }
        if score >= 50 {
                return hexYellow
        }
        if score >= 0 {
                return hexRed
        }
        return "#484f58"
}

func buildPostureContext(nodes []protocolNode, missing, controlCount int) string {
        if missing <= 0 {
                return fmt.Sprintf("All %d controls verified", controlCount)
        }
        first := firstMissingProtocol(nodes)
        if first != "" {
                return fmt.Sprintf("%d/%d controls missing — %s not found", missing, controlCount, first)
        }
        return fmt.Sprintf("%d/%d controls missing", missing, controlCount)
}

func firstMissingProtocol(nodes []protocolNode) string {
        for _, n := range nodes {
                if n.status == "missing" || n.status == "error" {
                        return n.abbrev
                }
        }
        return ""
}

type nodePos struct {
        x, y int
}

type topoEdge struct {
        from, to int
        label    string
        hard     bool
        labelX   int
        labelY   int
}

func renderTopoEdges(svg *strings.Builder, edges []topoEdge, nodes []protocolNode, positions []nodePos, nodeR int) {
        for _, e := range edges {
                if e.from >= len(nodes) || e.to >= len(nodes) {
                        continue
                }
                fp := positions[e.from]
                tp := positions[e.to]
                dn := nodes[e.to]

                lineColor, lineOpacity, lineW, packetColor := topoEdgeColors(dn)

                pathD := fmt.Sprintf("M%d,%d L%d,%d", fp.x, fp.y, tp.x, tp.y)
                dashArray := "4 6"
                if e.hard {
                        dashArray = "none"
                }
                svg.WriteString(fmt.Sprintf(
                        `<path d="%s" fill="none" stroke="%s" stroke-opacity="%s" stroke-width="%.1f" stroke-dasharray="%s"/>`,
                        pathD, lineColor, lineOpacity, lineW, dashArray,
                ))

                renderArrowHead(svg, fp, tp, nodeR, lineColor, lineOpacity)

                if e.label != "" && e.labelX > 0 {
                        svg.WriteString(fmt.Sprintf(
                                `<text x="%d" y="%d" text-anchor="middle" fill="#c9d1d9" font-size="7.5" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>`,
                                e.labelX, e.labelY, e.label,
                        ))
                }

                if dn.status == "success" || dn.status == "warning" {
                        dur := fmt.Sprintf("%.1fs", 1.8+float64(e.from)*0.3)
                        svg.WriteString(fmt.Sprintf(
                                `<circle r="2.5" fill="%s" opacity="0.85"><animateMotion dur="%s" repeatCount="indefinite" path="%s"/></circle>`,
                                packetColor, dur, pathD,
                        ))
                }
        }
}

func topoEdgeColors(dn protocolNode) (lineColor, lineOpacity string, lineW float64, packetColor string) {
        groupColor := protocolGroupColor(dn.abbrev)
        switch dn.status {
        case "success", "warning":
                return dn.colorHex, "0.40", 1.8, dn.colorHex
        case "error":
                return hexRed, "0.35", 1.8, hexRed
        default:
                return groupColor, "0.18", 1.5, groupColor
        }
}

func renderArrowHead(svg *strings.Builder, fp, tp nodePos, nodeR int, lineColor, lineOpacity string) {
        arrowDx := float64(tp.x - fp.x)
        arrowDy := float64(tp.y - fp.y)
        dist := math.Sqrt(arrowDx*arrowDx + arrowDy*arrowDy)
        if dist == 0 {
                return
        }
        nx := arrowDx / dist
        ny := arrowDy / dist
        arrowR := float64(nodeR) + 3
        arrowTipX := float64(tp.x) - nx*arrowR
        arrowTipY := float64(tp.y) - ny*arrowR
        perpX := -ny * 3.5
        perpY := nx * 3.5
        svg.WriteString(fmt.Sprintf(
                `<polygon points="%.1f,%.1f %.1f,%.1f %.1f,%.1f" fill="%s" fill-opacity="%s"/>`,
                arrowTipX, arrowTipY,
                arrowTipX-nx*7+perpX, arrowTipY-ny*7+perpY,
                arrowTipX-nx*7-perpX, arrowTipY-ny*7-perpY,
                lineColor, lineOpacity,
        ))
}

type topoNodeStyle struct {
        nodeColor    string
        strokeColor  string
        fillOpacity  string
        strokeOpacity string
        strokeW      float64
        glowOpacity  string
        textColor    string
}

func topoNodeStyleFor(n protocolNode) topoNodeStyle {
        s := topoNodeStyle{
                nodeColor:    n.groupColor,
                strokeColor:  n.groupColor,
                fillOpacity:  "0.10",
                strokeOpacity: "0.45",
                strokeW:      1.5,
                glowOpacity:  "0.10",
                textColor:    "#e6edf3",
        }
        switch n.status {
        case "error", "missing":
                s.nodeColor = hexRed
                s.strokeColor = hexRed
                s.fillOpacity = "0.06"
                s.strokeOpacity = "0.25"
                s.strokeW = 1
                s.glowOpacity = "0.06"
                s.textColor = hexRed
        case "warning", "success":
                s.fillOpacity = "0.14"
                s.strokeOpacity = "0.55"
                s.glowOpacity = "0.12"
        }
        return s
}

func abbrevFontSize(abbrev string) int {
        switch {
        case len(abbrev) > 6:
                return 7
        case len(abbrev) > 4:
                return 8
        default:
                return 9
        }
}

func renderTopoNodes(nodeSVG, glowDefs *strings.Builder, nodes []protocolNode, positions []nodePos, nodeR int) {
        for i, n := range nodes {
                if i >= len(positions) {
                        break
                }
                pos := positions[i]
                s := topoNodeStyleFor(n)

                glowDefs.WriteString(fmt.Sprintf(
                        `<radialGradient id="ng%d" cx="%d" cy="%d" r="%d" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="%s" stop-opacity="%s"/><stop offset="1" stop-color="%s" stop-opacity="0"/></radialGradient>`,
                        i, pos.x, pos.y, nodeR+8, s.nodeColor, s.glowOpacity, s.nodeColor,
                ))

                nodeSVG.WriteString(fmt.Sprintf(
                        `<circle cx="%d" cy="%d" r="%d" fill="url(#ng%d)"/>`,
                        pos.x, pos.y, nodeR+8, i,
                ))

                if n.status == "success" || n.status == "warning" {
                        nodeSVG.WriteString(fmt.Sprintf(
                                `<circle cx="%d" cy="%d" r="%d" fill="%s" fill-opacity="0.04"><animate attributeName="r" values="%d;%d;%d" dur="3s" repeatCount="indefinite"/><animate attributeName="fill-opacity" values="0.04;0.08;0.04" dur="3s" repeatCount="indefinite"/></circle>`,
                                pos.x, pos.y, nodeR+6, s.nodeColor, nodeR+6, nodeR+10, nodeR+6,
                        ))
                }

                nodeSVG.WriteString(fmt.Sprintf(
                        `<circle cx="%d" cy="%d" r="%d" fill="%s" fill-opacity="%s" stroke="%s" stroke-opacity="%s" stroke-width="%.1f"/>`,
                        pos.x, pos.y, nodeR, s.nodeColor, s.fillOpacity, s.strokeColor, s.strokeOpacity, s.strokeW,
                ))

                if n.status == "missing" || n.status == "error" {
                        nodeSVG.WriteString(fmt.Sprintf(
                                `<circle cx="%d" cy="%d" r="%d" fill="none" stroke="%s" stroke-opacity="0.6" stroke-width="1.5" stroke-dasharray="3 2"><animate attributeName="stroke-opacity" values="0.6;0.3;0.6" dur="2s" repeatCount="indefinite"/></circle>`,
                                pos.x, pos.y, nodeR+4, hexRed,
                        ))
                }

                nodeSVG.WriteString(fmt.Sprintf(
                        `<text x="%d" y="%d" text-anchor="middle" fill="%s" font-size="%d" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>`,
                        pos.x, pos.y+3, s.textColor, abbrevFontSize(n.abbrev), n.abbrev,
                ))
        }
}

func badgeSVGDetailed(domain string, results map[string]any, scanTime time.Time, scanID int32, postureHash, baseURL string) []byte {
        riskLabel, riskColorName := extractPostureRisk(results)
        if isGatewayDerivedResult(results) {
                riskLabel = labelGatewayDerived
                riskColorName = "warning"
        }
        riskColorName = normalizeRiskColor(riskLabel, riskColorName)
        nodes := extractProtocolIndicators(results)
        exposure := extractExposure(results)

        riskHex := riskColorToHex(riskColorName)
        riskLabelHex := reportRiskColor(riskColorName)
        borderColor := riskBorderColor(riskColorName)
        missing := countMissing(nodes)

        domainDisplay := domain
        if len(domainDisplay) > 30 {
                domainDisplay = domainDisplay[:27] + "..."
        }

        scanDate := scanTime.UTC().Format("2006-01-02")

        hashDisplay := postureHash
        if len(hashDisplay) > 8 {
                hashDisplay = hashDisplay[:8]
        }
        if hashDisplay == "" {
                hashDisplay = "--------"
        }

        hasExposure := exposure.status == "exposed" && exposure.findingCount > 0

        controlCount := 10

        postureContext := buildPostureContext(nodes, missing, controlCount)

        const (
                vbWidth  = 600
                vbHeight = 230
                scale    = 4.0 / 3.0
                pad      = 16
                nodeR    = 18
        )
        width := vbWidth
        height := vbHeight
        if hasExposure {
                height = 260
        }
        renderW := int(float64(width) * scale)
        renderH := int(float64(height) * scale)

        reportURL := fmt.Sprintf("%s/analyze?domain=%s", baseURL, domain)

        owlCX := 70
        owlCY := 110

        nodePositions := []nodePos{
                {250, 78},
                {332, 78},
                {414, 78},
                {250, 178},
                {373, 178},
                {310, 128},
                {414, 128},
                {496, 78},
                {496, 178},
                {558, 178},
        }

        edges := []topoEdge{
                {2, 0, "alignment", true, 291, 66},
                {2, 1, "", true, 0, 0},
                {7, 2, "p=quarantine+", true, 455, 66},
                {6, 5, "reports", false, 362, 118},
                {6, 4, "", false, 0, 0},
                {4, 3, "requires", true, 311, 168},
                {8, 3, "strengthens", false, 440, 168},
                {9, 8, "", false, 0, 0},
        }

        icieCX := 200
        icieCY := 54
        icieR := 13
        resolverCX := 136
        resolverCY := 54
        resolverW := 56
        resolverH := 18

        var nodeSVG strings.Builder

        resolverColor := "#5c6bc0"
        icieColor := "#e0e0e0"

        nodeSVG.WriteString(fmt.Sprintf(
                `<rect x="%d" y="%d" width="%d" height="%d" rx="4" fill="%s" fill-opacity="0.10" stroke="%s" stroke-opacity="0.45" stroke-width="1"/>`,
                resolverCX-resolverW/2, resolverCY-resolverH/2, resolverW, resolverH, resolverColor, resolverColor,
        ))
        nodeSVG.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" text-anchor="middle" fill="%s" font-size="8" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif">Resolvers</text>`,
                resolverCX, resolverCY+3, resolverColor,
        ))

        nodeSVG.WriteString(fmt.Sprintf(
                `<circle cx="%d" cy="%d" r="%d" fill="%s" fill-opacity="0.10" stroke="%s" stroke-opacity="0.45" stroke-width="1.2"/>`,
                icieCX, icieCY, icieR, icieColor, icieColor,
        ))
        nodeSVG.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" text-anchor="middle" fill="%s" font-size="8" font-weight="700" font-family="'Inter','Segoe UI',system-ui,sans-serif">ICIE</text>`,
                icieCX, icieCY+3, icieColor,
        ))

        nodeSVG.WriteString(fmt.Sprintf(
                `<path d="M%d,%d L%d,%d" fill="none" stroke="%s" stroke-opacity="0.3" stroke-width="1" stroke-dasharray="3 2"/>`,
                resolverCX+resolverW/2, resolverCY, icieCX-icieR, icieCY, icieColor,
        ))
        nodeSVG.WriteString(fmt.Sprintf(
                `<circle r="2" fill="%s" opacity="0.8"><animateMotion dur="1.2s" repeatCount="indefinite" path="M%d,%d L%d,%d"/></circle>`,
                icieColor, resolverCX+resolverW/2, resolverCY, icieCX-icieR, icieCY,
        ))

        type fanTarget struct {
                x, y int
        }
        fanTargetIdx := []int{0, 5, 3}
        fanTargets := []fanTarget{
                {nodePositions[0].x, nodePositions[0].y},
                {nodePositions[5].x, nodePositions[5].y},
                {nodePositions[3].x, nodePositions[3].y},
        }
        for fi, ft := range fanTargets {
                fx := float64(ft.x - icieCX)
                fy := float64(ft.y - icieCY)
                fd := math.Sqrt(fx*fx + fy*fy)
                if fd == 0 {
                        continue
                }
                fnx := fx / fd
                fny := fy / fd
                startX := float64(icieCX) + fnx*float64(icieR)
                startY := float64(icieCY) + fny*float64(icieR)
                endX := float64(ft.x) - fnx*float64(nodeR+2)
                endY := float64(ft.y) - fny*float64(nodeR+2)
                targetColor := protocolGroupColor(nodes[fanTargetIdx[fi]].abbrev)
                nodeSVG.WriteString(fmt.Sprintf(
                        `<path d="M%.0f,%.0f L%.0f,%.0f" fill="none" stroke="%s" stroke-opacity="0.15" stroke-width="1" stroke-dasharray="3 2"/>`,
                        startX, startY, endX, endY, targetColor,
                ))
                dur := fmt.Sprintf("%.1fs", 2.0+float64(fi)*0.5)
                nodeSVG.WriteString(fmt.Sprintf(
                        `<circle r="2" fill="%s" opacity="0.6"><animateMotion dur="%s" repeatCount="indefinite" path="M%.0f,%.0f L%.0f,%.0f"/></circle>`,
                        targetColor, dur, startX, startY, endX, endY,
                ))
        }

        renderTopoEdges(&nodeSVG, edges, nodes, nodePositions, nodeR)

        var glowDefs strings.Builder
        renderTopoNodes(&nodeSVG, &glowDefs, nodes, nodePositions, nodeR)

        totalControls := len(nodes)
        missingSVG := ""
        if missing > 0 {
                missingSVG = fmt.Sprintf(
                        `<text x="%d" y="%d" fill="%s" font-size="9" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="end">%d of %d missing</text>`,
                        width-pad, 218, hexRed, missing, totalControls,
                )
        }

        exposureSVG := ""
        exposureAnchor := fmt.Sprintf("%s/analysis/%d/view/C#secret-exposure", baseURL, scanID)
        if hasExposure {
                label := fmt.Sprintf("⚠ %d secret%s exposed", exposure.findingCount, pluralS(exposure.findingCount))
                eY := 215
                boxW := width - pad*2
                exposureSVG = fmt.Sprintf(
                        `<a href="%s" target="_blank">
  <rect x="%d" y="%d" width="%d" height="22" rx="4" fill="%s" fill-opacity="0.10" stroke="%s" stroke-width="1" cursor="pointer"/>
  <text x="%d" y="%d" fill="#ff6b6b" font-size="10" font-weight="700" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="middle" cursor="pointer">%s</text>
</a>`,
                        exposureAnchor,
                        pad, eY, boxW, hexRed, hexRed,
                        width/2, eY+15, label,
                )
        }

        hashURL := fmt.Sprintf("%s/analysis/%d/view/C#intelligence-metadata", baseURL, scanID)

        riskLine := riskLabel

        svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="%d" height="%d" viewBox="0 0 %d %d" preserveAspectRatio="xMidYMid meet" role="img" aria-label="DNS Tool: %s — %s">
  <title>DNS Tool: %s — %s</title>
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#161b22"/>
      <stop offset="1" stop-color="#0d1117"/>
    </linearGradient>
    <radialGradient id="owlGlow" cx="50%%" cy="50%%" r="50%%">
      <stop offset="0" stop-color="%s" stop-opacity=".12"/>
      <stop offset="1" stop-color="%s" stop-opacity="0"/>
    </radialGradient>
    %s
  </defs>
  <style>
    .topo-flow { stroke-dasharray: 4 3; animation: topodata 1.2s linear infinite; }
    @keyframes topodata { to { stroke-dashoffset: -7; } }
  </style>

  <rect width="%d" height="%d" rx="8" fill="url(#bg)"/>
  <rect x="1" y="1" width="%d" height="%d" rx="8" fill="none" stroke="%s" stroke-width="1.5"/>

  <text x="%d" y="26" fill="#e6edf3" font-size="14" font-weight="700" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>
  <text x="%d" y="26" fill="#484f58" font-size="10" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="end">%s</text>

  <line x1="%d" y1="34" x2="%d" y2="34" stroke="#21262d" stroke-width="1"/>

  <circle cx="%d" cy="%d" r="52" fill="url(#owlGlow)"/>
  <a href="%s" target="_blank">
    <image x="%d" y="%d" width="80" height="80" href="%s" cursor="pointer"/>
  </a>

  <rect x="%d" y="%d" width="3" height="14" rx="1.5" fill="%s"/>
  <text x="%d" y="%d" fill="%s" font-size="12" font-weight="700" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>
  <text x="%d" y="%d" fill="#8b949e" font-size="9" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>

  <text x="228" y="58" fill="#8b949e" font-size="7.5" font-weight="700" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="start" opacity="0.7" letter-spacing="0.5">AUTH</text>
  <text x="228" y="108" fill="#8b949e" font-size="7.5" font-weight="700" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="start" opacity="0.7" letter-spacing="0.5">TRANSPORT</text>
  <text x="228" y="158" fill="#8b949e" font-size="7.5" font-weight="700" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="start" opacity="0.7" letter-spacing="0.5">DNS</text>
  <line x1="228" y1="60" x2="524" y2="60" stroke="#21262d" stroke-width="0.5" stroke-dasharray="2 3"/>
  <line x1="228" y1="108" x2="450" y2="108" stroke="#21262d" stroke-width="0.5" stroke-dasharray="2 3"/>
  <line x1="228" y1="158" x2="586" y2="158" stroke="#21262d" stroke-width="0.5" stroke-dasharray="2 3"/>

  %s

  %s

  %s

  <a href="%s" target="_blank">
    <text x="%d" y="%d" fill="#484f58" font-size="8" font-family="'JetBrains Mono','Fira Code','SF Mono',monospace" cursor="pointer">sha3:%s</text>
  </a>
  <a href="%s" target="_blank">
    <text x="%d" y="%d" fill="#30363d" font-size="9" font-family="'Inter','Segoe UI',system-ui,sans-serif" cursor="pointer">dnstool.it-help.tech</text>
  </a>
</svg>`,
                renderW, renderH, width, height,
                domain, riskLabel,
                domain, riskLabel,
                riskHex, riskHex,
                glowDefs.String(),
                width, height,
                width-2, height-2, borderColor,
                pad, domainDisplay,
                width-pad, scanDate,
                pad, width-pad,
                owlCX, owlCY,
                reportURL,
                owlCX-40, owlCY-40, owlBadgePNG,
                20, 176, riskLabelHex,
                26, 188, riskLabelHex, riskLine,
                26, 202, postureContext,
                nodeSVG.String(),
                missingSVG,
                exposureSVG,
                hashURL,
                pad, height-6, hashDisplay,
                reportURL,
                pad+70, height-6,
        )

        return []byte(svg)
}

func isGatewayDerivedResult(results map[string]any) bool {
        if results == nil {
                return false
        }
        if scope, ok := results["analysis_scope"].(string); ok {
                return scope == "gateway_derived" || scope == "core_dns_only"
        }
        if postureRaw, ok := results["posture"].(map[string]any); ok {
                if reason, ok := postureRaw["reason"].(string); ok && reason == "gateway_derived" {
                        return true
                }
        }
        return false
}

func extractWeb3Status(results map[string]any) string {
        web3Raw, ok := results["web3_analysis"]
        if !ok {
                return ""
        }
        web3, ok := web3Raw.(map[string]any)
        if !ok {
                return ""
        }
        detected, _ := web3["detected"].(bool)
        if detected {
                return "success"
        }
        return ""
}
