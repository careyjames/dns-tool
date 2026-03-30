// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"net/http"
	"strings"

	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/dnsclient"

	"github.com/gin-gonic/gin"
)

const (
	mapKeyInvestigate = "investigate"
)

const investigateTemplate = "investigate.html"

type InvestigateHandler struct {
	Config   *config.Config
	Analyzer *analyzer.Analyzer
}

func NewInvestigateHandler(cfg *config.Config, a *analyzer.Analyzer) *InvestigateHandler {
	return &InvestigateHandler{Config: cfg, Analyzer: a}
}

func (h *InvestigateHandler) InvestigatePage(c *gin.Context) {
	nonce, _ := c.Get(mapKeyCspNonce)
	csrfToken, _ := c.Get(mapKeyCsrfToken)

	data := gin.H{
		strAppversion:      h.Config.AppVersion,
		strMaintenancenote: h.Config.MaintenanceNote,
		strBetapages:       h.Config.BetaPages,
		strCspnonce:        nonce,
		strCsrftoken:       csrfToken,
		strActivepage:      mapKeyInvestigate,
		strShowform:        true,
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, investigateTemplate, data)
}

func (h *InvestigateHandler) renderInvestigateError(c *gin.Context, category, msg, domain, ip string, statusCode int) {
	nonce, _ := c.Get(mapKeyCspNonce)
	csrfToken, _ := c.Get(mapKeyCsrfToken)
	data := gin.H{
		strAppversion:      h.Config.AppVersion,
		strMaintenancenote: h.Config.MaintenanceNote,
		strBetapages:       h.Config.BetaPages,
		strCspnonce:        nonce,
		strCsrftoken:       csrfToken,
		strActivepage:      mapKeyInvestigate,
		strShowform:        true,
		"FlashMessages":    []FlashMessage{{Category: category, Message: msg}},
		"FormDomain":       domain,
		"FormIP":           ip,
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(statusCode, investigateTemplate, data)
}

func (h *InvestigateHandler) Investigate(c *gin.Context) {
	nonce, _ := c.Get(mapKeyCspNonce)
	csrfToken, _ := c.Get(mapKeyCsrfToken)

	domain := strings.TrimSpace(c.PostForm("domain"))
	ip := strings.TrimSpace(c.PostForm("ip_address"))

	if domain == "" || ip == "" {
		h.renderInvestigateError(c, mapKeyDanger, "Please enter both a domain name and an IP address.", domain, ip, http.StatusOK)
		return
	}

	if !dnsclient.ValidateDomain(domain) {
		h.renderInvestigateError(c, mapKeyDanger, "Invalid domain name. Enter a domain like example.com.", domain, ip, http.StatusOK)
		return
	}

	if !analyzer.ValidateIPAddress(ip) {
		h.renderInvestigateError(c, mapKeyDanger, "Invalid IP address. Enter a valid IPv4 or IPv6 address.", domain, ip, http.StatusOK)
		return
	}

	if analyzer.IsPrivateIP(ip) {
		h.renderInvestigateError(c, "warning", "Private, loopback, and link-local IP addresses cannot be investigated. Enter a public IP address.", domain, ip, http.StatusOK)
		return
	}

	asciiDomain, err := dnsclient.DomainToASCII(domain)
	if err != nil {
		asciiDomain = domain
	}

	securityTrailsKey := strings.TrimSpace(c.PostForm("securitytrails_api_key"))
	ipInfoToken := strings.TrimSpace(c.PostForm("ipinfo_access_token"))

	results := h.Analyzer.InvestigateIP(c.Request.Context(), asciiDomain, ip)

	stError := fetchSecurityTrails(c, ip, securityTrailsKey, domain, asciiDomain, results)
	ipInfoData, ipInfoError := fetchIPInfo(c, ip, ipInfoToken)

	resultsData := gin.H{
		strAppversion:      h.Config.AppVersion,
		strMaintenancenote: h.Config.MaintenanceNote,
		strBetapages:       h.Config.BetaPages,
		strCspnonce:        nonce,
		strCsrftoken:       csrfToken,
		strActivepage:      mapKeyInvestigate,
		strShowform:        false,
		"ShowResults":      true,
		"Domain":           domain,
		"AsciiDomain":      asciiDomain,
		"IPAddress":        ip,
		"Results":          results,
		"IPInfo":           ipInfoData,
		"STError":          stError,
		"IPInfoError":      ipInfoError,
	}
	mergeAuthData(c, h.Config, resultsData)
	c.HTML(http.StatusOK, investigateTemplate, resultsData)
}

func fetchSecurityTrails(c *gin.Context, ip, apiKey, domain, asciiDomain string, results map[string]any) string {
	if apiKey == "" {
		return ""
	}
	stDomains, stErr := analyzer.FetchDomainsByIPWithKey(c.Request.Context(), ip, apiKey)
	if stErr != nil {
		return securityTrailsErrorMessage(stErr)
	}
	if len(stDomains) > 0 {
		applySecurityTrailsNeighborhood(stDomains, domain, asciiDomain, results)
	}
	return ""
}

func securityTrailsErrorMessage(err error) string {
	switch err.Error() {
	case "rate_limited":
		return "SecurityTrails: Your API key has exceeded its rate limit. Free keys allow 50 requests per month. Try again next month or upgrade your plan at securitytrails.com."
	case "auth_failed":
		return "SecurityTrails: API key was rejected. Please check that your key is correct and hasn't expired."
	case "connection_error":
		return "SecurityTrails: Could not connect to SecurityTrails. The service may be temporarily unavailable."
	default:
		return "SecurityTrails: An unexpected error occurred. The API may be temporarily unavailable."
	}
}

func applySecurityTrailsNeighborhood(stDomains []string, domain, asciiDomain string, results map[string]any) {
	neighborhood := make([]map[string]any, 0, len(stDomains))
	for _, d := range stDomains {
		if !strings.EqualFold(d, domain) && !strings.EqualFold(d, asciiDomain) {
			neighborhood = append(neighborhood, map[string]any{
				"domain": d,
				"source": "securitytrails",
			})
		}
	}
	cap := 10
	if len(neighborhood) > cap {
		neighborhood = neighborhood[:cap]
	}
	results["neighborhood"] = neighborhood
	results["neighborhood_total"] = len(stDomains)
	results["neighborhood_source"] = "SecurityTrails"
	results["st_enabled"] = true
}

func fetchIPInfo(c *gin.Context, ip, token string) (map[string]any, string) {
	if token == "" {
		return nil, ""
	}
	ipInfo, ipInfoErr := analyzer.FetchIPInfo(c.Request.Context(), ip, token)
	if ipInfoErr != nil {
		return nil, ipInfoErrorMessage(ipInfoErr)
	}
	if ipInfo == nil {
		return nil, ""
	}
	return map[string]any{
		"ip":       ipInfo.IP,
		"hostname": ipInfo.Hostname,
		"city":     ipInfo.City,
		"region":   ipInfo.Region,
		"country":  ipInfo.Country,
		"loc":      ipInfo.Loc,
		"org":      ipInfo.Org,
		"postal":   ipInfo.Postal,
		"timezone": ipInfo.Timezone,
		"anycast":  ipInfo.Anycast,
		"bogon":    ipInfo.Bogon,
	}, ""
}

func ipInfoErrorMessage(err error) string {
	errMsg := err.Error()
	if strings.Contains(errMsg, "rate limit") {
		return "IPinfo.io: Your token has exceeded its rate limit. Free tokens allow 50,000 lookups per month."
	}
	if strings.Contains(errMsg, "invalid") || strings.Contains(errMsg, "expired") {
		return "IPinfo.io: Token was rejected. Please check that your token is correct and hasn't expired."
	}
	return "IPinfo.io: Could not retrieve data. The service may be temporarily unavailable."
}
