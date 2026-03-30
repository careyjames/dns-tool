// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "encoding/json"
        "fmt"
        "log/slog"
        "sort"
        "strings"
        "sync"
        "time"
)

const (
        mapKeyCertCount        = "cert_count"
        mapKeyCnameCount       = "cname_count"
        mapKeyCtAvailable      = "ct_available"
        mapKeyCurrentCount     = "current_count"
        mapKeyDisplayedCount   = "displayed_count"
        mapKeyExpiredCount     = "expired_count"
        mapKeyFirstSeen        = "first_seen"
        mapKeyIsCurrent        = "is_current"
        mapKeyIssuers          = "issuers"
        mapKeyUniqueSubdomains = "unique_subdomains"
        mapKeyName             = "name"
        mapKeyDns              = "dns"
)

type ctEntry struct {
        NameValue    string `json:"name_value"`
        CommonName   string `json:"common_name"`
        NotBefore    string `json:"not_before"`
        NotAfter     string `json:"not_after"`
        IssuerName   string `json:"issuer_name"`
        SerialNumber string `json:"serial_number"`
}

var commonSubdomainProbes = []string{
        "www", "www1", "www2", "www3", "web", "web1", "web2", "m", "mobile",
        "mail", "mail1", "mail2", "mail3", "email", "webmail", "smtp", "smtp1", "smtp2",
        "pop", "pop3", "imap", "mx", "mx1", "mx2", "mx3", "mx4", "mx5", "relay", "relay1", "mta",
        "autodiscover", "autoconfig", "owa", "exchange", "outlook",
        "ftp", "ftp1", "ftp2", "sftp", "ssh", "scp",
        "vpn", "vpn1", "vpn2", "vpn3", "remote", "ra", "gateway", "gw", "gw1", "gw2",
        "api", "api1", "api2", "api3", "apis", "rest", "graphql", "ws",
        "app", "app1", "app2", "apps", "portal", "portal2", "hub",
        "admin", "admin1", "admin2", "panel", "cpanel", "whm", "plesk",
        "dashboard", "console", "manage", "management", "manager",
        "server", "server1", "server2", "server3", "srv", "srv1", "srv2",
        "blog", "news", "press", "media", "wiki", "docs", "doc", "documentation",
        "help", "helpdesk", "support", "support2", "kb", "faq",
        "shop", "store", "ecommerce", "cart", "billing", "pay", "payment", "payments",
        "checkout", "invoice", "orders", "order",
        "sso", "auth", "oauth", "login", "signin", "id", "identity",
        "accounts", "account", "myaccount", "my", "profile", "signup", "register",
        "dev", "dev1", "dev2", "develop", "developer", "developers",
        "staging", "stg", "stage", "test", "test1", "test2", "testing",
        "demo", "sandbox", "beta", "alpha", "preview", "uat", "qa", "preprod", "pre",
        "cdn", "cdn1", "cdn2", "cdn3", "static", "static1", "static2",
        "assets", "media", "img", "images", "image", "photos", "video", "videos",
        "ns", "ns1", "ns2", "ns3", "ns4", "ns5", "ns6", mapKeyDns, "dns1", "dns2",
        "cloud", "host", "hosting", "vps", "dedicated",
        "db", "db1", "db2", "database", "sql", "mysql", "postgres", "mongo", "mongodb",
        "monitor", "monitoring", mapKeyStatus, "uptime", "health", "healthcheck",
        "grafana", "prometheus", "nagios", "zabbix", "kibana", "datadog",
        "git", "gitlab", "github", "repo", "repos", "bitbucket", "svn", "code",
        "ci", "cd", "jenkins", "build", "builds", "deploy", "deployment", "releases",
        "calendar", "cal", "meet", "meeting", "video", "chat", "conference",
        "webinar", "live", "stream", "streaming",
        "crm", "erp", "hr", "hris", "payroll", "finance", "accounting",
        "intranet", "internal", "corp", "corporate", "hq",
        "proxy", "proxy1", "proxy2", "lb", "loadbalancer", "haproxy", "nginx",
        "secure", "ssl", "tls", "ocsp", "crl", "pki", "ca", "cert", "certs",
        "files", "file", "download", "downloads", "upload", "uploads", "backup", "share",
        "forum", "forums", "community", "discuss", "discussions",
        "office", "o365", "work", "connect", "workspace",
        "analytics", "stats", "statistics", "metrics", "logs", "log", "tracking",
        "search", "es", "elastic", "elasticsearch", "solr",
        "cache", "redis", "memcached", "varnish",
        "queue", "mq", "rabbitmq", "kafka", "broker",
        "s3", "storage", "bucket", "blob", "object",
        "map", "maps", "geo", "location", "gis",
        "confluence", "jira", "ticket", "tickets", "servicedesk", "itsm",
        "slack", "teams", "zoom", "webex",
        "reports", "report", "reporting", "bi",
        "schedule", "booking", "appointments", "reservations",
        "tools", "tool", "utility",
        "client", "clients", "partner", "partners", "vendor", "vendors",
        "training", "learn", "learning", "lms", "academy", "courses", "education",
        "inventory", "catalog", "products", "product",
        "notify", "notifications", "alerts", "alert",
        "print", "printer", "scan", "scanner",
        "backup1", "backup2", "archive", "archives",
        "voip", "sip", "phone", "pbx", "tel", "telecom",
        "mdm", "devices", "endpoint",
        "edge", "edge1", "edge2", "waf", "firewall", "fw",
        "data", "data1", "data2", "bigdata", "warehouse", "etl",
        "service", "services", "svc", "microservices",
        "gateway", "apigw", "kong",
        "registry", "docker", "k8s", "kubernetes", "containers", "rancher",
        "vault", "secrets", "config", "configuration",
        "auth0", "okta", "adfs", "ldap", "ad", "directory",
        "cms", "content", "drupal", "wordpress", "wp",
        "marketing", "campaign", "campaigns", "promo",
        "feedback", "survey", "surveys", "forms",
        "careers", "jobs", "recruit", "hiring", "talent",
        "legal", "compliance", "policy", "policies", "terms", "privacy",
        "investor", "investors", "ir",
        "events", "event", "webinars",
        "network", "net", "lan", "wan",
        "it", "itsupport", "techsupport",
        "cname", "redirect",
        "origin", "origin1", "origin2",
        "primary", "secondary",
        "a", "b", "c", "d", "e", "f",
        "node1", "node2", "node3", "worker", "worker1", "worker2",
        "us", "eu", "ap", "asia", "na", "emea", "apac",
        "us-east", "us-west", "eu-west", "ap-south",
        "int", "ext", "public", "private",
        "go", "swift", "link", "links", "url", "r",
        "feeds", "feed", "rss", "atom", "xml",
        "websocket", "socket", "realtime", "rt",
        "metrics", "trace", "tracing", "apm",
        "sandbox1", "sandbox2", "lab", "labs",
        "dnstool", "webtool", "webtools", "nettools", "nettool", "syslog",
        "mailgw", "mailrelay", "mailserver", "mailhost",
        "webhost", "webserver", "webproxy", "webapp", "webapi",
        "devops", "sysadmin", "netadmin",
        "speedtest", "pingdom", "uptime", "statuspage",
        "lookup", "whois", "dnscheck", "mxtoolbox",
}

type ctFetchResult struct {
        entries       []ctEntry
        available     bool
        failureReason string
        fallback      bool
}

func (a *Analyzer) fetchCTEntriesWithFallback(ctx context.Context, domain string) ctFetchResult {
        ctProvider := "ct:crt.sh"
        inCooldown := a.Telemetry.InCooldown(ctProvider)
        if !inCooldown {
                entries, available, failReason := a.fetchCTWithRetry(ctx, domain, ctProvider)
                if available && len(entries) > 0 {
                        return ctFetchResult{entries: entries, available: true}
                }
                if failReason != "" {
                        slog.Info("CT primary provider failed, trying fallback", mapKeyDomain, domain, "reason", failReason)
                }
        } else {
                slog.Info("CT provider in cooldown, trying certspotter", mapKeyDomain, domain)
        }
        csEntries, csOK := a.fetchCertspotter(ctx, domain)
        if csOK && len(csEntries) > 0 {
                slog.Info("Certspotter fallback succeeded", mapKeyDomain, domain, "entries", len(csEntries))
                return ctFetchResult{entries: csEntries, available: true, fallback: true}
        }
        if inCooldown {
                return ctFetchResult{failureReason: "cooldown"}
        }
        return ctFetchResult{available: false, failureReason: "both_providers_failed"}
}

func populateCTResults(result map[string]any, ctEntries, dedupedEntries []ctEntry, domain string, ctAvailable bool) {
        if !ctAvailable {
                return
        }
        result["total_certs"] = len(ctEntries)
        result["unique_certs"] = len(dedupedEntries)
        result["ca_summary"] = buildCASummary(dedupedEntries)
}

func (a *Analyzer) DiscoverSubdomains(ctx context.Context, domain string) map[string]any {
        result := map[string]any{
                mapKeyStatus:           "success",
                mapKeySubdomains:       []map[string]any{},
                mapKeyUniqueSubdomains: 0,
                "total_certs":          0,
                mapKeySource:           "Certificate Transparency + DNS Intelligence",
                "caveat":               "Subdomains discovered via CT logs (RFC 6962), DNS probing of common service names, and CNAME chain traversal.",
                mapKeyCurrentCount:     "0",
                mapKeyExpiredCount:     "0",
                mapKeyCnameCount:       0.0,
                "providers_found":      0.0,
                mapKeyCtAvailable:      true,
        }

        if cached, ok := a.getCTCache(domain); ok {
                return returnCachedSubdomains(result, cached)
        }

        if a.CTStore != nil {
                if dbCached, ok := a.CTStore.Get(ctx, domain); ok && len(dbCached) > 0 {
                        a.setCTCache(domain, dbCached)
                        result["ct_source"] = "database"
                        return returnCachedSubdomains(result, dbCached)
                }
        }

        ct := a.fetchCTEntriesWithFallback(ctx, domain)
        if ct.fallback {
                result["ct_source_fallback"] = "certspotter"
        }

        dedupedEntries := deduplicateCTEntries(ct.entries)
        populateCTResults(result, ct.entries, dedupedEntries, domain, ct.available)

        wildcardInfo := detectWildcardCerts(dedupedEntries, domain)
        if wildcardInfo != nil {
                result["wildcard_certs"] = wildcardInfo
        }

        subdomainSet := make(map[string]map[string]any)
        if ct.available {
                processCTEntries(ct.entries, domain, subdomainSet)
        }

        a.probeCommonSubdomains(ctx, domain, subdomainSet)

        extResults := RunExternalTools(ctx, domain)
        for _, fqdn := range extResults {
                if _, exists := subdomainSet[fqdn]; !exists {
                        subdomainSet[fqdn] = map[string]any{
                                mapKeyName:      fqdn,
                                mapKeySource:    "external_tools",
                                mapKeyIsCurrent: true,
                                mapKeyCertCount: "—",
                                mapKeyFirstSeen: "—",
                                mapKeyIssuers:   []string{},
                        }
                }
        }

        if ct.available && len(dedupedEntries) > 0 {
                enrichDNSWithCTData(dedupedEntries, domain, subdomainSet)
        }

        result["cname_discovered_count"] = 0.0
        subdomains, cnameCount := collectSubdomains(subdomainSet)
        result[mapKeyCnameCount] = float64(cnameCount)

        if len(subdomains) > 0 {
                a.enrichSubdomainsV2(ctx, domain, subdomains)
        }

        subdomains = a.applyNmapEnrichment(ctx, domain, subdomains, result)
        subdomains = a.finalizeSubdomains(ctx, domain, subdomains, ct, result)

        return result
}

func (a *Analyzer) applyNmapEnrichment(ctx context.Context, domain string, subdomains []map[string]any, result map[string]any) []map[string]any {
        if len(a.Probes) == 0 || len(subdomains) == 0 {
                return subdomains
        }
        newSANs, nmapEnriched := a.enrichSubdomainsWithNmap(ctx, domain, subdomains)
        if len(newSANs) > 0 {
                subdomains = append(subdomains, newSANs...)
                result["nmap_san_discovered"] = len(newSANs)
        }
        if nmapEnriched > 0 {
                result["nmap_enriched"] = nmapEnriched
        }
        return subdomains
}

func (a *Analyzer) finalizeSubdomains(ctx context.Context, domain string, subdomains []map[string]any, ct ctFetchResult, result map[string]any) []map[string]any {
        currentCount, expiredCount := countSubdomainStats(subdomains)
        result[mapKeyCurrentCount] = fmt.Sprintf("%d", currentCount)
        result[mapKeyExpiredCount] = fmt.Sprintf("%d", expiredCount)

        subdomains = sortSubdomainsSmartOrder(subdomains)
        if ct.available {
                a.setCTCache(domain, subdomains)

                if a.CTStore != nil && len(subdomains) > 0 {
                        ctSource := "crt.sh"
                        if ct.fallback {
                                ctSource = "certspotter"
                        }
                        go func() {
                                storeCtx, storeCancel := context.WithTimeout(context.Background(), 10*time.Second)
                                defer storeCancel()
                                a.CTStore.Set(storeCtx, domain, subdomains, ctSource)
                        }()
                }
        }

        result[mapKeyUniqueSubdomains] = len(subdomains)
        result["ct_source"] = "live"
        result[mapKeyCtAvailable] = ct.available
        if !ct.available {
                result["ct_failure_reason"] = ct.failureReason
        }
        applySubdomainDisplayCap(result, subdomains, currentCount)
        return subdomains
}

func returnCachedSubdomains(result map[string]any, cached []map[string]any) map[string]any {
        result[mapKeyUniqueSubdomains] = len(cached)
        result["ct_source"] = "cache"
        result[mapKeyCtAvailable] = true

        currentCount, expiredCount := countSubdomainStats(cached)
        cnameCount := 0
        for _, sd := range cached {
                if _, hasCname := sd[mapKeyCnameTarget]; hasCname {
                        cnameCount++
                }
        }
        result[mapKeyCurrentCount] = fmt.Sprintf("%d", currentCount)
        result[mapKeyExpiredCount] = fmt.Sprintf("%d", expiredCount)
        result[mapKeyCnameCount] = float64(cnameCount)

        sorted := sortSubdomainsSmartOrder(cached)
        applySubdomainDisplayCap(result, sorted, currentCount)
        return result
}

func collectSubdomains(subdomainSet map[string]map[string]any) ([]map[string]any, int) {
        var subdomains []map[string]any
        cnameCount := 0
        for _, sd := range subdomainSet {
                subdomains = append(subdomains, sd)
                if _, hasCname := sd[mapKeyCnameTarget]; hasCname {
                        cnameCount++
                }
        }
        return subdomains, cnameCount
}

func countSubdomainStats(subdomains []map[string]any) (int, int) {
        currentCount := 0
        expiredCount := 0
        for _, sd := range subdomains {
                if isCurrent, ok := sd[mapKeyIsCurrent].(bool); ok && isCurrent {
                        currentCount++
                } else {
                        expiredCount++
                }
        }
        return currentCount, expiredCount
}

func (a *Analyzer) fetchCTWithRetry(ctx context.Context, domain, ctProvider string) ([]ctEntry, bool, string) {
        const maxAttempts = 2
        ctURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json&exclude=expired", domain)

        totalBudget, totalCancel := context.WithTimeout(ctx, 90*time.Second)
        defer totalCancel()

        var lastErr string
        for attempt := 1; attempt <= maxAttempts; attempt++ {
                if totalBudget.Err() != nil {
                        break
                }
                entries, done, failReason, errMsg := a.attemptCTFetch(totalBudget, ctURL, domain, ctProvider, attempt, maxAttempts)
                if done {
                        return a.handleCTSuccess(totalBudget, entries, failReason, domain, ctProvider)
                }
                lastErr = errMsg
        }

        return nil, false, classifyCTFailure(lastErr)
}

func (a *Analyzer) handleCTSuccess(totalBudget context.Context, entries []ctEntry, failReason, domain, ctProvider string) ([]ctEntry, bool, string) {
        if failReason != "" {
                return nil, false, failReason
        }
        if len(entries) == 0 && totalBudget.Err() == nil {
                if fallback, ok := a.fetchCTFallback(totalBudget, domain, ctProvider); ok {
                        return fallback, true, ""
                }
        }
        return entries, true, ""
}

func classifyCTFailure(lastErr string) string {
        if lastErr != "" && !strings.Contains(lastErr, "deadline") && !strings.Contains(lastErr, "timeout") {
                return mapKeyError
        }
        return "timeout"
}

func retryBackoff(attempt, maxAttempts int) {
        if attempt < maxAttempts {
                time.Sleep(time.Duration(attempt*2) * time.Second)
        }
}

func (a *Analyzer) attemptCTFetch(totalBudget context.Context, ctURL, domain, ctProvider string, attempt, maxAttempts int) ([]ctEntry, bool, string, string) {
        ctCtx, ctCancel := context.WithTimeout(totalBudget, 75*time.Second)
        start := time.Now()
        resp, err := a.SlowHTTP.Get(ctCtx, ctURL)
        if err != nil {
                lastErr := err.Error()
                a.Telemetry.RecordFailure(ctProvider, lastErr)
                slog.Warn("CT log query failed", mapKeyDomain, domain, "attempt", attempt, mapKeyError, err, "elapsed_ms", time.Since(start).Milliseconds())
                ctCancel()
                retryBackoff(attempt, maxAttempts)
                return nil, false, "", lastErr
        }

        body, err := a.HTTP.ReadBody(resp, 20<<20)
        if err != nil {
                lastErr := err.Error()
                a.Telemetry.RecordFailure(ctProvider, lastErr)
                ctCancel()
                retryBackoff(attempt, maxAttempts)
                return nil, false, "", lastErr
        }
        if resp.StatusCode != 200 {
                lastErr := fmt.Sprintf("HTTP %d", resp.StatusCode)
                a.Telemetry.RecordFailure(ctProvider, lastErr)
                ctCancel()
                if resp.StatusCode >= 400 && resp.StatusCode < 500 {
                        return nil, true, mapKeyError, lastErr
                }
                retryBackoff(attempt, maxAttempts)
                return nil, false, "", lastErr
        }

        var entries []ctEntry
        if json.Unmarshal(body, &entries) != nil {
                ctCancel()
                return nil, true, mapKeyError, "JSON parse error"
        }

        elapsed := time.Since(start)
        a.Telemetry.RecordSuccess(ctProvider, elapsed)
        slog.Info("CT log query succeeded", mapKeyDomain, domain, "attempt", attempt, "entries", len(entries), "elapsed_ms", elapsed.Milliseconds())
        ctCancel()

        return entries, true, "", ""
}

func (a *Analyzer) fetchCTFallback(totalBudget context.Context, domain, ctProvider string) ([]ctEntry, bool) {
        ctURL2 := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
        ctCtx2, ctCancel2 := context.WithTimeout(totalBudget, 75*time.Second)
        defer ctCancel2()
        start2 := time.Now()
        resp2, err2 := a.SlowHTTP.Get(ctCtx2, ctURL2)
        if err2 == nil {
                body2, err3 := a.HTTP.ReadBody(resp2, 20<<20)
                if err3 == nil && resp2.StatusCode == 200 {
                        var allEntries []ctEntry
                        if json.Unmarshal(body2, &allEntries) == nil && len(allEntries) > 0 {
                                a.Telemetry.RecordSuccess(ctProvider, time.Since(start2))
                                return allEntries, true
                        }
                }
        }
        return nil, false
}

type certspotterEntry struct {
        ID        string   `json:"id"`
        DNSNames  []string `json:"dns_names"`
        NotBefore string   `json:"not_before"`
        NotAfter  string   `json:"not_after"`
}

type certspotterPageResult struct {
        entries  []certspotterEntry
        cursor   string
        hasMore  bool
        hardFail bool
}

func (a *Analyzer) fetchCertspotterPage(budgetCtx context.Context, domain, cursor string, page int) certspotterPageResult {
        csURL := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
        if cursor != "" {
                csURL += "&after=" + cursor
        }

        pageCtx, pageCancel := context.WithTimeout(budgetCtx, 15*time.Second)
        resp, err := a.HTTP.Get(pageCtx, csURL)
        if err != nil {
                slog.Warn("Certspotter query failed", mapKeyDomain, domain, "page", page, mapKeyError, err)
                pageCancel()
                return certspotterPageResult{hardFail: page == 0}
        }
        body, err := a.HTTP.ReadBody(resp, 10<<20)
        pageCancel()
        if err != nil || resp.StatusCode != 200 {
                slog.Warn("Certspotter bad response", mapKeyDomain, domain, "page", page, mapKeyStatus, resp.StatusCode)
                return certspotterPageResult{hardFail: page == 0}
        }

        var csEntries []certspotterEntry
        if json.Unmarshal(body, &csEntries) != nil {
                return certspotterPageResult{hardFail: page == 0}
        }

        nextCursor := ""
        hasMore := len(csEntries) >= 100
        if hasMore {
                nextCursor = csEntries[len(csEntries)-1].ID
        }
        return certspotterPageResult{entries: csEntries, cursor: nextCursor, hasMore: hasMore}
}

func convertCertspotterEntries(csEntries []certspotterEntry) []ctEntry {
        entries := make([]ctEntry, 0, len(csEntries))
        for _, cs := range csEntries {
                entries = append(entries, ctEntry{
                        NameValue: strings.Join(cs.DNSNames, "\n"),
                        NotBefore: cs.NotBefore,
                        NotAfter:  cs.NotAfter,
                })
        }
        return entries
}

func (a *Analyzer) fetchCertspotter(ctx context.Context, domain string) ([]ctEntry, bool) {
        const maxPages = 25
        budgetCtx, budgetCancel := context.WithTimeout(ctx, 60*time.Second)
        defer budgetCancel()

        var allEntries []ctEntry
        cursor := ""

        for page := 0; page < maxPages; page++ {
                if budgetCtx.Err() != nil {
                        break
                }
                pr := a.fetchCertspotterPage(budgetCtx, domain, cursor, page)
                if pr.hardFail {
                        return nil, false
                }
                if pr.entries == nil {
                        break
                }
                allEntries = append(allEntries, convertCertspotterEntries(pr.entries)...)
                if !pr.hasMore {
                        break
                }
                cursor = pr.cursor
                slog.Info("Certspotter pagination", mapKeyDomain, domain, "page", page+1, "entries_so_far", len(allEntries))
        }

        if len(allEntries) == 0 {
                return nil, false
        }

        slog.Info("Certspotter query succeeded", mapKeyDomain, domain, "total_entries", len(allEntries))
        return allEntries, true
}

func sortSubdomainsSmartOrder(subdomains []map[string]any) []map[string]any {
        var current, historical []map[string]any
        for _, sd := range subdomains {
                if isCur, ok := sd[mapKeyIsCurrent].(bool); ok && isCur {
                        current = append(current, sd)
                } else {
                        historical = append(historical, sd)
                }
        }

        sort.Slice(current, func(i, j int) bool {
                return current[i][mapKeyName].(string) < current[j][mapKeyName].(string)
        })

        sort.Slice(historical, func(i, j int) bool {
                di, _ := historical[i][mapKeyFirstSeen].(string)
                dj, _ := historical[j][mapKeyFirstSeen].(string)
                return di > dj
        })

        result := make([]map[string]any, 0, len(current)+len(historical))
        result = append(result, current...)
        result = append(result, historical...)
        return result
}

func applySubdomainDisplayCap(result map[string]any, subdomains []map[string]any, currentCount int) {
        const softCap = 200
        const historicalOverflow = 25

        total := len(subdomains)

        if total <= softCap {
                result[mapKeySubdomains] = subdomains
                result[mapKeyDisplayedCount] = total
                return
        }

        var displayLimit int
        if currentCount > softCap {
                displayLimit = currentCount + historicalOverflow
        } else {
                displayLimit = softCap
        }

        if displayLimit >= total {
                result[mapKeySubdomains] = subdomains
                result[mapKeyDisplayedCount] = total
                return
        }

        result[mapKeySubdomains] = subdomains[:displayLimit]
        result[mapKeyDisplayedCount] = displayLimit
        result["display_capped"] = true
        result["was_truncated"] = true
        result["display_current_count"] = currentCount
        result["display_historical_omitted"] = total - displayLimit
}

func deduplicateCTEntries(entries []ctEntry) []ctEntry {
        seen := make(map[string]bool, len(entries))
        deduped := make([]ctEntry, 0, len(entries))
        for _, e := range entries {
                if e.SerialNumber == "" || !seen[e.SerialNumber] {
                        if e.SerialNumber != "" {
                                seen[e.SerialNumber] = true
                        }
                        deduped = append(deduped, e)
                }
        }
        return deduped
}

type wildcardAccum struct {
        hasWildcard       bool
        isCurrent         bool
        certCount         int
        latestNotAfter    time.Time
        earliestNotBefore time.Time
        issuers           []string
        issuerSeen        map[string]bool
        sanSet            map[string]bool
}

func detectWildcardCerts(ctEntries []ctEntry, domain string) map[string]any {
        wildcardPattern := "*." + domain
        now := time.Now()

        acc := &wildcardAccum{
                issuerSeen: make(map[string]bool),
                sanSet:     make(map[string]bool),
        }

        for _, entry := range ctEntries {
                processWildcardEntry(entry, wildcardPattern, domain, now, acc)
        }

        if !acc.hasWildcard {
                return nil
        }

        var explicitSANs []string
        for san := range acc.sanSet {
                explicitSANs = append(explicitSANs, san)
        }
        sort.Strings(explicitSANs)

        result := map[string]any{
                "present":       true,
                "pattern":       wildcardPattern,
                "current":       acc.isCurrent,
                mapKeyCertCount: acc.certCount,
                mapKeyIssuers:   acc.issuers,
        }

        if len(explicitSANs) > 0 {
                result["explicit_sans"] = explicitSANs
                result["san_count"] = len(explicitSANs)
        }
        if !acc.earliestNotBefore.IsZero() {
                result["earliest"] = acc.earliestNotBefore.Format(dateFormatISO)
        }
        if !acc.latestNotAfter.IsZero() {
                result["latest_expiry"] = acc.latestNotAfter.Format(dateFormatISO)
        }

        return result
}

func processWildcardEntry(entry ctEntry, wildcardPattern, domain string, now time.Time, acc *wildcardAccum) {
        if !isWildcardCertEntry(entry, wildcardPattern) {
                return
        }

        acc.hasWildcard = true
        acc.certCount++
        notAfter := parseCertDate(entry.NotAfter)
        notBefore := parseCertDate(entry.NotBefore)
        if notAfter.After(now) {
                acc.isCurrent = true
        }
        if notAfter.After(acc.latestNotAfter) {
                acc.latestNotAfter = notAfter
        }
        if acc.earliestNotBefore.IsZero() || notBefore.Before(acc.earliestNotBefore) {
                acc.earliestNotBefore = notBefore
        }

        trackWildcardIssuer(simplifyIssuer(entry.IssuerName), acc)
        collectWildcardSANs(entry.NameValue, wildcardPattern, domain, acc)
}

func isWildcardCertEntry(entry ctEntry, wildcardPattern string) bool {
        for _, name := range strings.Split(entry.NameValue, "\n") {
                if strings.TrimSpace(strings.ToLower(name)) == wildcardPattern {
                        return true
                }
        }
        return false
}

func trackWildcardIssuer(issuer string, acc *wildcardAccum) {
        if acc.issuerSeen[issuer] {
                return
        }
        acc.issuerSeen[issuer] = true
        if len(acc.issuers) < 10 {
                acc.issuers = append(acc.issuers, issuer)
        }
}

func collectWildcardSANs(nameValue, wildcardPattern, domain string, acc *wildcardAccum) {
        for _, name := range strings.Split(nameValue, "\n") {
                name = strings.TrimSpace(strings.ToLower(name))
                if name == "" || name == wildcardPattern || name == domain {
                        continue
                }
                if strings.HasSuffix(name, "."+domain) || name == domain {
                        acc.sanSet[name] = true
                }
        }
}

func buildCASummary(entries []ctEntry) []map[string]any {
        type caStats struct {
                name        string
                certCount   int
                firstSeen   time.Time
                lastSeen    time.Time
                hasCurrents bool
        }

        now := time.Now()
        caMap := make(map[string]*caStats)
        var caOrder []string

        for _, entry := range entries {
                issuer := simplifyIssuer(entry.IssuerName)
                notBefore := parseCertDate(entry.NotBefore)
                notAfter := parseCertDate(entry.NotAfter)

                stats, exists := caMap[issuer]
                if !exists {
                        stats = &caStats{name: issuer, firstSeen: notBefore, lastSeen: notBefore}
                        caMap[issuer] = stats
                        caOrder = append(caOrder, issuer)
                }
                stats.certCount++
                if !notBefore.IsZero() && notBefore.Before(stats.firstSeen) {
                        stats.firstSeen = notBefore
                }
                if !notBefore.IsZero() && notBefore.After(stats.lastSeen) {
                        stats.lastSeen = notBefore
                }
                if notAfter.After(now) {
                        stats.hasCurrents = true
                }
        }

        sort.Slice(caOrder, func(i, j int) bool {
                return caMap[caOrder[i]].certCount > caMap[caOrder[j]].certCount
        })

        maxCAs := 8
        if len(caOrder) < maxCAs {
                maxCAs = len(caOrder)
        }

        summary := make([]map[string]any, 0, maxCAs)
        for _, name := range caOrder[:maxCAs] {
                s := caMap[name]
                entry := map[string]any{
                        mapKeyName:      s.name,
                        mapKeyCertCount: s.certCount,
                        mapKeyFirstSeen: s.firstSeen.Format(dateFormatISO),
                        "last_seen":     s.lastSeen.Format(dateFormatISO),
                        "active":        s.hasCurrents,
                }
                summary = append(summary, entry)
        }

        return summary
}

func parseCertDate(s string) time.Time {
        s = strings.TrimSpace(s)
        if s == "" {
                return time.Time{}
        }
        formats := []string{
                "2006-01-02T15:04:05",
                "2006-01-02 15:04:05",
                dateFormatISO,
        }
        for _, fmt := range formats {
                if t, err := time.Parse(fmt, s); err == nil {
                        return t
                }
        }
        if len(s) >= 10 {
                if t, err := time.Parse(dateFormatISO, s[:10]); err == nil {
                        return t
                }
        }
        return time.Time{}
}

func processCTEntries(ctEntries []ctEntry, domain string, subdomainSet map[string]map[string]any) {
        now := time.Now()
        for _, entry := range ctEntries {
                processSingleCTEntry(entry, domain, now, subdomainSet)
        }
}

func processSingleCTEntry(entry ctEntry, domain string, now time.Time, subdomainSet map[string]map[string]any) {
        isCurrent := parseCertDate(entry.NotAfter).After(now)
        issuer := simplifyIssuer(entry.IssuerName)
        for _, name := range strings.Split(entry.NameValue, "\n") {
                name = normalizeCTName(name, domain)
                if name == "" {
                        continue
                }
                if existing, exists := subdomainSet[name]; exists {
                        mergeCTSubdomain(existing, isCurrent, issuer)
                } else {
                        subdomainSet[name] = map[string]any{
                                mapKeyName:      name,
                                mapKeySource:    "ct",
                                mapKeyIsCurrent: isCurrent,
                                mapKeyCertCount: "1",
                                mapKeyFirstSeen: entry.NotBefore,
                                mapKeyIssuers:   []string{issuer},
                        }
                }
        }
}

func mergeCTSubdomain(existing map[string]any, isCurrent bool, issuer string) {
        existing[mapKeyCertCount] = fmt.Sprintf("%d", atoi(existing[mapKeyCertCount].(string))+1)
        if isCurrent {
                existing[mapKeyIsCurrent] = true
        }
        if issuers, ok := existing[mapKeyIssuers].([]string); ok {
                if !containsString(issuers, issuer) && len(issuers) < 5 {
                        existing[mapKeyIssuers] = append(issuers, issuer)
                }
        }
}

func containsString(ss []string, target string) bool {
        for _, s := range ss {
                if s == target {
                        return true
                }
        }
        return false
}

func enrichDNSWithCTData(ctEntries []ctEntry, domain string, subdomainSet map[string]map[string]any) {
        now := time.Now()
        for name, entry := range subdomainSet {
                src, _ := entry[mapKeySource].(string)
                if src != mapKeyDns {
                        continue
                }
                enrichSingleDNSEntry(name, entry, ctEntries, now)
        }
}

type ctMatchResult struct {
        certCount int
        firstSeen time.Time
        isCurrent bool
        issuers   []string
}

func matchCTForName(name string, ctEntries []ctEntry, now time.Time) ctMatchResult {
        var result ctMatchResult
        issuersMap := make(map[string]bool)
        for _, ct := range ctEntries {
                if !ctEntryCoversName(ct, name) {
                        continue
                }
                result.certCount++
                notBefore := parseCertDate(ct.NotBefore)
                if !notBefore.IsZero() && (result.firstSeen.IsZero() || notBefore.Before(result.firstSeen)) {
                        result.firstSeen = notBefore
                }
                if parseCertDate(ct.NotAfter).After(now) {
                        result.isCurrent = true
                }
                issuer := simplifyIssuer(ct.IssuerName)
                if issuer != "" && !issuersMap[issuer] && len(result.issuers) < 5 {
                        issuersMap[issuer] = true
                        result.issuers = append(result.issuers, issuer)
                }
        }
        return result
}

func enrichSingleDNSEntry(name string, entry map[string]any, ctEntries []ctEntry, now time.Time) {
        match := matchCTForName(name, ctEntries, now)
        if match.certCount == 0 {
                return
        }
        entry[mapKeyCertCount] = fmt.Sprintf("%d", match.certCount)
        if match.isCurrent {
                entry[mapKeyIsCurrent] = true
        }
        if !match.firstSeen.IsZero() {
                entry[mapKeyFirstSeen] = match.firstSeen.Format(dateFormatISO)
        }
        if len(match.issuers) > 0 {
                entry[mapKeyIssuers] = match.issuers
        }
}

func ctEntryCoversName(ct ctEntry, name string) bool {
        names := strings.Split(ct.NameValue, "\n")
        for _, n := range names {
                n = strings.TrimSpace(strings.ToLower(n))
                if n == name {
                        return true
                }
                if strings.HasPrefix(n, "*.") && strings.HasSuffix(name, n[1:]) {
                        return true
                }
        }
        return false
}

func (a *Analyzer) probeCommonSubdomains(ctx context.Context, domain string, subdomainSet map[string]map[string]any) int {
        probeCtx, probeCancel := context.WithTimeout(ctx, 25*time.Second)
        defer probeCancel()

        found := 0
        var mu sync.Mutex
        var wg sync.WaitGroup

        sem := make(chan struct{}, 30)

        for _, prefix := range commonSubdomainProbes {
                fqdn := prefix + "." + domain

                mu.Lock()
                _, alreadyFound := subdomainSet[fqdn]
                mu.Unlock()
                if alreadyFound {
                        continue
                }

                wg.Add(1)
                sem <- struct{}{}
                go func(name string) {
                        defer wg.Done()
                        defer func() { <-sem }()

                        exists, cnameTarget := a.DNS.ProbeExists(probeCtx, name)
                        if !exists {
                                return
                        }

                        entry := map[string]any{
                                mapKeyName:      name,
                                mapKeySource:    mapKeyDns,
                                mapKeyIsCurrent: true,
                                mapKeyCertCount: "—",
                                mapKeyFirstSeen: "—",
                                mapKeyIssuers:   []string{},
                        }

                        if cnameTarget != "" {
                                entry[mapKeyCnameTarget] = cnameTarget
                        }

                        mu.Lock()
                        subdomainSet[name] = entry
                        found++
                        mu.Unlock()
                }(fqdn)
        }

        wg.Wait()
        return found
}

func (a *Analyzer) enrichSubdomainsV2(ctx context.Context, baseDomain string, subdomains []map[string]any) {
        enrichCtx, enrichCancel := context.WithTimeout(ctx, 10*time.Second)
        defer enrichCancel()

        maxEnrich := 50
        if len(subdomains) < maxEnrich {
                maxEnrich = len(subdomains)
        }

        var wg sync.WaitGroup
        var mu sync.Mutex
        sem := make(chan struct{}, 20)

        for i := 0; i < maxEnrich; i++ {
                wg.Add(1)
                sem <- struct{}{}
                go func(idx int) {
                        defer wg.Done()
                        defer func() { <-sem }()

                        sd := subdomains[idx]
                        name := sd[mapKeyName].(string)

                        if sd[mapKeySource] == mapKeyDns {
                                return
                        }

                        exists, cnameTarget := a.DNS.ProbeExists(enrichCtx, name)

                        mu.Lock()
                        if exists {
                                sd[mapKeyIsCurrent] = true
                                if cnameTarget != "" {
                                        sd[mapKeyCnameTarget] = cnameTarget
                                }
                        }
                        mu.Unlock()
                }(i)
        }
        wg.Wait()
}

func parseDNAttributes(dn string) []string {
        var parts []string
        var current strings.Builder
        inQuote := false
        for i := 0; i < len(dn); i++ {
                ch := dn[i]
                if ch == '"' {
                        inQuote = !inQuote
                        continue
                }
                if ch == ',' && !inQuote {
                        parts = append(parts, current.String())
                        current.Reset()
                        continue
                }
                current.WriteByte(ch)
        }
        if current.Len() > 0 {
                parts = append(parts, current.String())
        }
        return parts
}

func simplifyIssuer(issuer string) string {
        parts := parseDNAttributes(issuer)
        for _, part := range parts {
                part = strings.TrimSpace(part)
                if strings.HasPrefix(part, "O=") {
                        return strings.TrimSpace(part[2:])
                }
        }
        for _, part := range parts {
                part = strings.TrimSpace(part)
                if strings.HasPrefix(part, "CN=") {
                        return strings.TrimSpace(part[3:])
                }
        }
        if len(issuer) > 40 {
                return issuer[:40] + "..."
        }
        return issuer
}

func atoi(s string) int {
        n := 0
        for _, c := range s {
                if c >= '0' && c <= '9' {
                        n = n*10 + int(c-'0')
                }
        }
        return n
}

func normalizeCTName(name, domain string) string {
        name = strings.TrimSpace(strings.ToLower(name))
        if name == "" || name == domain {
                return ""
        }
        if !strings.HasSuffix(name, "."+domain) {
                return ""
        }
        if strings.HasPrefix(name, "*.") {
                name = name[2:]
        }
        if name == domain {
                return ""
        }
        return name
}
