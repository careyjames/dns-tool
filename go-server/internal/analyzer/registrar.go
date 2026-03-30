// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	registrarRe  = regexp.MustCompile(`(?im)^(?:registrar|sponsoring registrar|registrar[- ]name)\s*:\s*(.+)$`)
	registrantRe = regexp.MustCompile(`(?im)^(?:registrant organization|registrant name|registrant)\s*:\s*(.+)$`)
)

var directRDAPEndpoints = map[string]string{
	"com":    "https://rdap.verisign.com/com/v1/",
	"net":    "https://rdap.verisign.com/net/v1/",
	"org":    "https://rdap.publicinterestregistry.net/rdap/",
	"io":     "https://rdap.nic.io/",
	"dev":    "https://rdap.nic.google/",
	"app":    "https://rdap.nic.google/",
	"uk":     "https://rdap.nominet.uk/uk/",
	"eu":     "https://rdap.eu/",
	"nl":     "https://rdap.sidn.nl/rdap/",
	"au":     "https://rdap.auda.org.au/rdap/",
	"cc":     "https://rdap.verisign.com/cc/v1/",
	"tv":     "https://rdap.verisign.com/tv/v1/",
	"xyz":    "https://rdap.centralnic.com/xyz/",
	"co":     "https://rdap.nic.co/",
	"me":     "https://rdap.nic.me/",
	"ai":     "https://rdap.nic.ai/",
	"tech":   "https://rdap.centralnic.com/tech/",
	"site":   "https://rdap.centralnic.com/site/",
	"store":  "https://rdap.centralnic.com/store/",
	"info":   "https://rdap.afilias.net/rdap/info/",
	"biz":    "https://rdap.nic.biz/",
	"mobi":   "https://rdap.nic.mobi/",
	"name":   "https://rdap.verisign.com/name/v1/",
	"pro":    "https://rdap.nic.pro/",
	"cloud":  "https://rdap.centralnic.com/cloud/",
	"online": "https://rdap.centralnic.com/online/",
	"live":   "https://rdap.centralnic.com/live/",
	"space":  "https://rdap.centralnic.com/space/",
	"fun":    "https://rdap.centralnic.com/fun/",
	"top":    "https://rdap.nic.top/",
}

var whoisServers = map[string]string{
	"com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
	"org": "whois.pir.org", "io": "whois.nic.io",
	"dev": "whois.nic.google", "app": "whois.nic.google",
	"co": "whois.nic.co", "me": "whois.nic.me",
	"uk": "whois.nic.uk", "us": "whois.nic.us",
	"ca": "whois.cira.ca", "au": "whois.auda.org.au",
	"de": "whois.denic.de", "fr": "whois.nic.fr",
	"nl": "whois.sidn.nl", "eu": "whois.eu",
	"it": "whois.nic.it", "ch": "whois.nic.ch",
	"se": "whois.iis.se", "pl": "whois.dns.pl",
	"xyz": "whois.nic.xyz", "tech": "whois.nic.tech",
	"site": "whois.nic.site", "store": "whois.nic.store",
	"info": "whois.afilias.net", "biz": "whois.nic.biz",
	"mobi": "whois.nic.mobi", "pro": "whois.nic.pro",
	"cloud": "whois.nic.cloud", "online": "whois.nic.online",
	"live": "whois.nic.live", "space": "whois.nic.space",
	"top": "whois.nic.top",
}

const (
	providerMicrosoftAzureDNS = "Microsoft Azure DNS"

	mapKeySource    = "source"
	statusSuccess   = "success"
	mapKeyEntities  = "entities"
	mapKeyAttempt   = "attempt"
	fmtAttemptTotal = "%d/%d"

	strIonos  = "IONOS"
	mapKeyUrl = "url"
	mapKeyTld = "tld"
)

var nsRegistrarPatterns = map[string]string{
	"awsdns":                "Amazon Registrar",
	"gandi.net":             "Gandi SAS",
	"ovh.net":               "OVHcloud",
	"ovh.com":               "OVHcloud",
	"domaincontrol.com":     "GoDaddy",
	"registrar-servers.com": "Namecheap",
	"name-services.com":     "Enom / Tucows",
	"ionos.com":             strIonos,
	"ui-dns.com":            strIonos,
	"ui-dns.de":             strIonos,
	"strato.de":             "Strato",
	"hetzner.com":           "Hetzner",
	"inwx.de":               "INWX",
	"porkbun.com":           "Porkbun",
	"dynadot.com":           "Dynadot",
	"squarespace.com":       "Squarespace Domains",
	"wixdns.net":            "Wix",
	"wordpress.com":         "WordPress.com",
	"aruba.it":              "Aruba S.p.A.",
	"infomaniak.ch":         "Infomaniak",
	"hostpoint.ch":          "Hostpoint",
	"bluehost.com":          "Bluehost",
	"dreamhost.com":         "DreamHost",
	"googledomains.com":     "Google Domains",
	"google.com":            "Google Domains",
	"cloudflare.com":        "Cloudflare Registrar",
	"digitalocean.com":      "DigitalOcean",
	"linode.com":            "Linode (Akamai)",
	"vultr.com":             "Vultr",
	"hostgator.com":         "HostGator",
	"siteground.com":        "SiteGround",
	"hover.com":             "Hover (Tucows)",
	"dnsimple.com":          "DNSimple",
	"dnsmadeeasy.com":       "DNS Made Easy",
	"he.net":                "Hurricane Electric",
	"nsone.net":             "NS1 (IBM)",
	"ultradns.com":          "UltraDNS (Neustar)",
	"azure-dns.com":         providerMicrosoftAzureDNS,
	"azure-dns.net":         providerMicrosoftAzureDNS,
	"azure-dns.org":         providerMicrosoftAzureDNS,
	"azure-dns.info":        providerMicrosoftAzureDNS,
}

var whoisRestrictedIndicators = []string{
	"not authorised", "not authorized", "access denied",
	"authorization required", "ip address used to perform",
	"exceeded the established limit", "access restricted",
	"query rate limit exceeded", "too many queries",
}

func (a *Analyzer) GetRegistrarInfo(ctx context.Context, domain string) map[string]any {
	slog.Info("Getting registrar info", mapKeyDomain, domain)

	if cached, ok := a.RDAPCache.Get(domain); ok {
		slog.Info("RDAP cache hit", mapKeyDomain, domain)
		cached["cache_hit"] = true
		return cached
	}

	result := a.getRegistrarInfoUncached(ctx, domain)

	if result[mapKeyStatus] == statusSuccess {
		a.RDAPCache.Set(domain, result)
	}

	return result
}

func buildRestrictedResult(restricted bool, restrictedTLD string) map[string]any {
	if !restricted {
		return map[string]any{
			mapKeyStatus:    "error",
			mapKeySource:    nil,
			mapKeyRegistrar: nil,
			"message":       "Registry data unavailable (RDAP/WHOIS services unreachable or rate-limited)",
		}
	}

	registryName := knownRestrictedTLDs[restrictedTLD]
	if registryName == "" {
		registryName = fmt.Sprintf(".%s registry", restrictedTLD)
	}
	return map[string]any{
		mapKeyStatus:              "restricted",
		mapKeySource:              "WHOIS",
		mapKeyRegistrar:           nil,
		"registry_restricted":     true,
		"registry_restricted_tld": restrictedTLD,
		"message":                 fmt.Sprintf("%s restricts public WHOIS/RDAP access — registrar data requires authorized IP", registryName),
	}
}

func (a *Analyzer) getRegistrarInfoUncached(ctx context.Context, domain string) map[string]any {
	if result := a.tryRDAPLookup(ctx, domain); result != nil {
		return result
	}

	whoisResult, restricted, restrictedTLD := a.whoisLookup(ctx, domain)
	if whoisResult != "" {
		return map[string]any{mapKeyStatus: statusSuccess, mapKeySource: "WHOIS", mapKeyRegistrar: whoisResult, mapKeyConfidence: ConfidenceObservedMap(MethodWHOIS)}
	}

	if result := a.tryParentZoneLookup(ctx, domain); result != nil {
		return result
	}

	return a.tryNSInference(ctx, domain, restricted, restrictedTLD)
}

func (a *Analyzer) tryRDAPLookup(ctx context.Context, domain string) map[string]any {
	rdapResult := a.rdapLookup(ctx, domain)
	if rdapResult == nil {
		slog.Info("RDAP lookup returned nil", mapKeyDomain, domain)
		return nil
	}
	registrar := extractRegistrarFromRDAP(rdapResult)
	if registrar == "" || isDigits(registrar) {
		slog.Info("RDAP registrar extraction failed", mapKeyDomain, domain, "raw_registrar", registrar)
		return nil
	}
	registrant := extractRegistrantFromRDAP(rdapResult)
	regStr := formatRegistrarWithRegistrant(registrar, registrant)
	slog.Info("RDAP lookup succeeded", mapKeyDomain, domain, mapKeyRegistrar, regStr)
	return map[string]any{mapKeyStatus: statusSuccess, mapKeySource: "RDAP", mapKeyRegistrar: regStr, mapKeyConfidence: ConfidenceObservedMap(MethodRDAP)}
}

func formatRegistrarWithRegistrant(registrar, registrant string) string {
	if registrant != "" {
		return registrar + fmt.Sprintf(" (Registrant: %s)", registrant)
	}
	return registrar
}

func (a *Analyzer) tryParentZoneLookup(ctx context.Context, domain string) map[string]any {
	parentZone := findParentZone(a.DNS, ctx, domain)
	if parentZone == "" || parentZone == domain {
		return nil
	}
	parentResult := a.GetRegistrarInfo(ctx, parentZone)
	if parentResult[mapKeyStatus] == statusSuccess {
		parentResult["subdomain_of"] = parentZone
		return parentResult
	}
	return nil
}

func (a *Analyzer) tryNSInference(ctx context.Context, domain string, restricted bool, restrictedTLD string) map[string]any {
	parentZone := findParentZone(a.DNS, ctx, domain)
	lookupDomain := domain
	if parentZone != "" && parentZone != domain {
		lookupDomain = parentZone
	}

	nsResult := a.inferRegistrarFromNS(ctx, lookupDomain)
	if nsResult != nil {
		if lookupDomain != domain {
			nsResult["subdomain_of"] = lookupDomain
		}
		if restricted {
			nsResult["registry_restricted"] = true
			nsResult["registry_restricted_tld"] = restrictedTLD
		}
		return nsResult
	}

	return buildRestrictedResult(restricted, restrictedTLD)
}

func (a *Analyzer) rdapLookup(ctx context.Context, domain string) map[string]any {
	tld := getTLD(domain)
	providerName := "rdap:" + tld

	endpoints := a.buildRDAPEndpoints(tld)
	slog.Info("RDAP lookup starting", mapKeyDomain, domain, mapKeyTld, tld, "endpoint_count", len(endpoints))

	type rdapResult struct {
		data     map[string]any
		endpoint string
	}

	resultCh := make(chan rdapResult, len(endpoints))
	rdapCtx, rdapCancel := context.WithTimeout(ctx, 30*time.Second)
	defer rdapCancel()

	var wg sync.WaitGroup
	for i, endpoint := range endpoints {
		wg.Add(1)
		go func(ep string, idx int) {
			defer wg.Done()
			data := a.tryRDAPEndpointWithRetry(rdapCtx, domain, ep, providerName, idx+1, len(endpoints))
			if data != nil {
				resultCh <- rdapResult{data: data, endpoint: ep}
			}
		}(endpoint, i)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	if result, ok := <-resultCh; ok {
		rdapCancel()
		slog.Info("RDAP parallel lookup succeeded", mapKeyDomain, domain, "winning_endpoint", result.endpoint)
		return result.data
	}

	slog.Warn("RDAP lookup exhausted all endpoints", mapKeyDomain, domain, "endpoints_tried", len(endpoints))
	a.Telemetry.RecordFailure(providerName, "all endpoints exhausted")
	return nil
}

func (a *Analyzer) tryRDAPEndpointWithRetry(ctx context.Context, domain, endpoint, providerName string, attempt, total int) map[string]any {
	const maxRetries = 2
	for retry := 0; retry <= maxRetries; retry++ {
		if ctx.Err() != nil {
			return nil
		}
		if retry > 0 {
			backoff := time.Duration(retry*200) * time.Millisecond
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil
			}
			slog.Info("RDAP retry", mapKeyDomain, domain, "endpoint", endpoint, "retry", retry)
		}
		data := a.tryRDAPEndpoint(ctx, domain, endpoint, providerName, attempt, total)
		if data != nil {
			return data
		}
	}
	return nil
}

func (a *Analyzer) buildRDAPEndpoints(tld string) []string {
	var endpoints []string
	seen := make(map[string]bool)

	if ep, ok := directRDAPEndpoints[tld]; ok && ep != "" {
		appendValidEndpoint(&endpoints, seen, ep, tld, "direct")
	}

	if ianaEps, ok := a.GetRDAPEndpoints(tld); ok {
		for _, ep := range ianaEps {
			if ep != "" && !seen[ep] {
				appendValidEndpoint(&endpoints, seen, ep, tld, "IANA")
			}
		}
	}

	const rdapFallback = "https://rdap.org/"
	if !seen[rdapFallback] {
		endpoints = append(endpoints, rdapFallback)
	}

	return endpoints
}

func appendValidEndpoint(endpoints *[]string, seen map[string]bool, ep, tld, source string) {
	if isValidRDAPEndpoint(ep) {
		*endpoints = append(*endpoints, ep)
		seen[ep] = true
	} else {
		slog.Warn("RDAP endpoint rejected (not HTTPS)", "endpoint", ep, mapKeyTld, tld, mapKeySource, source)
	}
}

func isValidRDAPEndpoint(endpoint string) bool {
	return strings.HasPrefix(endpoint, "https://")
}

func (a *Analyzer) tryRDAPEndpoint(ctx context.Context, domain, endpoint, providerName string, attempt, total int) map[string]any {
	rdapURL := fmt.Sprintf("%sdomain/%s", strings.TrimRight(endpoint, "/")+"/", domain)
	slog.Info("RDAP trying endpoint", mapKeyUrl, rdapURL, mapKeyAttempt, fmt.Sprintf(fmtAttemptTotal, attempt, total))

	start := time.Now()
	resp, err := a.RDAPHTTP.GetDirect(ctx, rdapURL)
	if err != nil {
		slog.Warn("RDAP endpoint failed", mapKeyDomain, domain, mapKeyUrl, rdapURL, mapKeyError, err, mapKeyElapsedMs, time.Since(start).Milliseconds(), mapKeyAttempt, fmt.Sprintf(fmtAttemptTotal, attempt, total))
		return nil
	}

	body, err := a.RDAPHTTP.ReadBody(resp, 1<<20)
	if err != nil {
		slog.Warn("RDAP body read failed", mapKeyUrl, rdapURL, mapKeyError, err)
		return nil
	}

	slog.Info("RDAP response received", mapKeyUrl, rdapURL, mapKeyStatus, resp.StatusCode, "body_len", len(body), mapKeyElapsedMs, time.Since(start).Milliseconds())

	if resp.StatusCode >= 400 {
		return nil
	}

	var data map[string]any
	if json.Unmarshal(body, &data) != nil {
		slog.Warn("RDAP JSON parse failed", mapKeyUrl, rdapURL, "body_preview", string(body[:min(200, len(body))]))
		return nil
	}

	if _, hasError := data["errorCode"]; hasError {
		slog.Warn("RDAP error in response", mapKeyUrl, rdapURL, "error_code", data["errorCode"])
		return nil
	}

	a.Telemetry.RecordSuccess(providerName, time.Since(start))
	slog.Info("RDAP lookup succeeded", mapKeyDomain, domain, mapKeyUrl, rdapURL, mapKeyAttempt, fmt.Sprintf(fmtAttemptTotal, attempt, total), mapKeyElapsedMs, time.Since(start).Milliseconds())
	return data
}

func extractRegistrarFromRDAP(data map[string]any) string {
	entities, ok := data[mapKeyEntities].([]any)
	if !ok {
		return ""
	}
	return findRegistrarEntity(entities)
}

func findRegistrarEntity(entities []any) string {
	for _, e := range entities {
		entity, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if !entityHasRole(entity, mapKeyRegistrar) {
			if result := findRegistrarInSubEntities(entity); result != "" {
				return result
			}
			continue
		}
		if name := extractFNFromVCard(entity); name != "" {
			return name
		}
		if name := extractEntityName(entity); name != "" {
			return name
		}
		if result := findRegistrarInSubEntities(entity); result != "" {
			return result
		}
	}
	return ""
}

func findRegistrarInSubEntities(entity map[string]any) string {
	subEntities, ok := entity[mapKeyEntities].([]any)
	if !ok {
		return ""
	}
	return findRegistrarEntity(subEntities)
}

func extractEntityName(entity map[string]any) string {
	if name, ok := entity["name"].(string); ok && name != "" && !isDigits(name) {
		return name
	}
	if handle, ok := entity["handle"].(string); ok && handle != "" && !isDigits(handle) {
		return handle
	}
	return ""
}

func extractRegistrantFromRDAP(data map[string]any) string {
	entities, ok := data[mapKeyEntities].([]any)
	if !ok {
		return ""
	}
	return findRegistrantEntity(entities)
}

var redactedValues = map[string]bool{
	"redacted": true, "data protected": true,
	"not disclosed": true, "withheld": true,
}

func findRegistrantEntity(entities []any) string {
	for _, e := range entities {
		entity, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if !entityHasRole(entity, "registrant") {
			if result := findRegistrantInSubEntities(entity); result != "" {
				return result
			}
			continue
		}
		if name := extractFNFromVCard(entity); name != "" && !redactedValues[strings.ToLower(name)] {
			return name
		}
		if result := findRegistrantInSubEntities(entity); result != "" {
			return result
		}
	}
	return ""
}

func findRegistrantInSubEntities(entity map[string]any) string {
	subEntities, ok := entity[mapKeyEntities].([]any)
	if !ok {
		return ""
	}
	return findRegistrantEntity(subEntities)
}

func entityHasRole(entity map[string]any, role string) bool {
	roles, ok := entity["roles"].([]any)
	if !ok {
		return false
	}
	for _, r := range roles {
		if strings.ToLower(fmt.Sprint(r)) == role {
			return true
		}
	}
	return false
}

func extractFNFromVCard(entity map[string]any) string {
	vcard, ok := entity["vcardArray"].([]any)
	if !ok || len(vcard) != 2 {
		return ""
	}
	items, ok := vcard[1].([]any)
	if !ok {
		return ""
	}
	for _, item := range items {
		arr, ok := item.([]any)
		if !ok || len(arr) < 4 {
			continue
		}
		if fmt.Sprint(arr[0]) == "fn" {
			return fmt.Sprint(arr[3])
		}
	}
	return ""
}

func (a *Analyzer) whoisLookup(ctx context.Context, domain string) (string, bool, string) {
	tld := getTLD(domain)
	server, ok := whoisServers[tld]
	if !ok {
		return "", false, ""
	}

	conn, err := net.DialTimeout("tcp", server+":43", 3*time.Second)
	if err != nil {
		return "", false, ""
	}
	defer safeClose(conn, "whois connection")
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = conn.Write([]byte(domain + "\r\n"))
	if err != nil {
		return "", false, ""
	}

	var buf [8192]byte
	var response []byte
	for {
		n, err := conn.Read(buf[:])
		if n > 0 {
			response = append(response, buf[:n]...)
		}
		if err != nil {
			break
		}
		if len(response) > 32768 {
			break
		}
	}

	output := string(response)

	restricted, empty := isWhoisRestricted(output, tld)
	if empty && !restricted {
		slog.Info("WHOIS returned empty/minimal response (not a known restricted TLD)", mapKeyDomain, domain, mapKeyTld, tld, "response_len", len(strings.TrimSpace(output)))
		return "", false, ""
	}
	if restricted {
		return "", true, tld
	}

	registrar := parseWhoisRegistrar(output)
	registrant := parseWhoisRegistrant(output)

	return formatWhoisResult(registrar, registrant)
}

var knownRestrictedTLDs = map[string]string{
	"es": "Red.es (Spain)", "br": "Registro.br (Brazil)",
	"kr": "KISA (South Korea)", "cn": "CNNIC (China)", "ru": "RIPN (Russia)",
}

func isWhoisRestricted(output, tld string) (bool, bool) {
	trimmed := strings.TrimSpace(output)
	if len(trimmed) < 50 {
		if _, known := knownRestrictedTLDs[tld]; known {
			return true, true
		}
		return false, true
	}
	outputLower := strings.ToLower(output)
	for _, indicator := range whoisRestrictedIndicators {
		if strings.Contains(outputLower, indicator) {
			return true, false
		}
	}
	return false, false
}

func parseWhoisRegistrar(output string) string {
	m := registrarRe.FindStringSubmatch(output)
	if m == nil {
		return ""
	}
	val := strings.TrimSpace(m[1])
	if val == "" || strings.HasPrefix(strings.ToLower(val), "http") || strings.ToLower(val) == "not available" {
		return ""
	}
	return val
}

func parseWhoisRegistrant(output string) string {
	m := registrantRe.FindStringSubmatch(output)
	if m == nil {
		return ""
	}
	val := strings.TrimSpace(m[1])
	if val == "" || redactedValues[strings.ToLower(val)] {
		return ""
	}
	return val
}

func formatWhoisResult(registrar, registrant string) (string, bool, string) {
	if registrar != "" && registrant != "" {
		return fmt.Sprintf("%s (Registrant: %s)", registrar, registrant), false, ""
	}
	if registrar != "" {
		return registrar, false, ""
	}
	if registrant != "" {
		return registrant, false, ""
	}
	return "", false, ""
}

func (a *Analyzer) inferRegistrarFromNS(ctx context.Context, domain string) map[string]any {
	nsRecords := a.DNS.QueryDNS(ctx, "NS", domain)
	if len(nsRecords) == 0 {
		return nil
	}

	nsStr := strings.ToLower(strings.Join(nsRecords, " "))

	for pattern, registrarName := range nsRegistrarPatterns {
		if strings.Contains(nsStr, pattern) {
			slog.Info("Inferred registrar from NS", mapKeyRegistrar, registrarName, "pattern", pattern, mapKeyDomain, domain)
			return map[string]any{
				mapKeyStatus:     statusSuccess,
				mapKeySource:     "NS inference",
				mapKeyRegistrar:  registrarName,
				"ns_inferred":    true,
				"caveat":         "Inferred from nameserver records — indicates DNS hosting provider, which for integrated registrars typically matches the registrar.",
				mapKeyConfidence: ConfidenceInferredMap(MethodNSInference),
			}
		}
	}

	return nil
}

func getTLD(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	return domain
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
