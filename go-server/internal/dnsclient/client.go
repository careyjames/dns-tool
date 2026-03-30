// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package dnsclient

import (
        "context"
        "encoding/json"
        "fmt"
        "io"
        "log/slog"
        "net"
        "net/http"
        "net/url"
        "sort"
        "strings"
        "sync"
        "time"

        "codeberg.org/miekg/dns"
        "codeberg.org/miekg/dns/dnsutil"
)

type ResolverConfig struct {
        Name string
        IP   string
        DoH  string
}

// S1313 suppressed: these are well-known public DNS resolver IPs — intentional
// hardcoded constants for the multi-resolver consensus architecture (RFC-documented services).
// SECINTENT-003: Hardcoded DNS resolver IPs
var DefaultResolvers = []ResolverConfig{
        {Name: "Cloudflare", IP: resolverCloudflare, DoH: "https://cloudflare-dns.com/dns-query"},
        {Name: "Google", IP: resolverGoogle, DoH: "https://dns.google/resolve"},
        {Name: "Quad9", IP: "9.9.9.9"},
        {Name: "OpenDNS", IP: "208.67.222.222"},
        {Name: "DNS4EU", IP: "86.54.11.100", DoH: "https://unfiltered.joindns4.eu/dns-query"},
}

var UserAgent = "DNSTool-DomainSecurityAudit/1.0 (+https://dnstool.it-help.tech)"

func SetUserAgentVersion(version string) {
        UserAgent = fmt.Sprintf("DNSTool-DomainSecurityAudit/%s (+https://dnstool.it-help.tech)", version)
}

const (
        dohGoogleURL    = "https://dns.google/resolve"
        defaultTimeout  = 2 * time.Second
        defaultLifetime = 4 * time.Second
        consensusWait   = 5 * time.Second

        resolverCloudflare = "1.1.1.1"
        resolverGoogle     = "8.8.8.8"

        dnsPort      = "53"
        protoUDP     = "udp"
        dohTypeRRSIG = 46

        mapKeyDiscrepancies = "discrepancies"
        mapKeyError         = "error"
        mapKeyDomain        = "domain"
        mapKeyResolver      = "resolver"
        dnsTypeTXT          = "TXT"
)

type ConsensusResult struct {
        Records         []string            `json:"records"`
        Consensus       bool                `json:"consensus"`
        ResolverCount   int                 `json:"resolver_count"`
        Discrepancies   []string            `json:"discrepancies"`
        ResolverResults map[string][]string `json:"resolver_results"`
}

type RecordWithTTL struct {
        Records       []string
        TTL           *uint32
        Authenticated bool
}

type ADFlagResult struct {
        ADFlag       bool    `json:"ad_flag"`
        Validated    bool    `json:"validated"`
        ResolverUsed *string `json:"resolver_used"`
        Error        *string `json:"error"`
}

type Client struct {
        resolvers  []ResolverConfig
        httpClient *http.Client
        timeout    time.Duration
        lifetime   time.Duration

        cacheMu  sync.RWMutex
        cache    map[string]cacheEntry
        cacheTTL time.Duration
        cacheMax int
}

type cacheEntry struct {
        data      []string
        timestamp time.Time
}

type Option func(*Client)

func WithResolvers(r []ResolverConfig) Option {
        return func(c *Client) { c.resolvers = r }
}

func WithHTTPClient(h *http.Client) Option {
        return func(c *Client) { c.httpClient = h }
}

func WithTimeout(t time.Duration) Option {
        return func(c *Client) { c.timeout = t }
}

func WithCacheTTL(t time.Duration) Option {
        return func(c *Client) { c.cacheTTL = t }
}

func New(opts ...Option) *Client {
        c := &Client{
                resolvers: DefaultResolvers,
                httpClient: &http.Client{
                        Timeout: 10 * time.Second,
                        Transport: &http.Transport{
                                MaxIdleConns:        20,
                                IdleConnTimeout:     30 * time.Second,
                                DisableKeepAlives:   false,
                                MaxIdleConnsPerHost: 5,
                        },
                },
                timeout:  defaultTimeout,
                lifetime: defaultLifetime,
                cache:    make(map[string]cacheEntry),
                cacheTTL: 0,
                cacheMax: 0,
        }
        for _, o := range opts {
                o(c)
        }
        return c
}

func (c *Client) cacheGet(key string) ([]string, bool) {
        c.cacheMu.RLock()
        defer c.cacheMu.RUnlock()
        entry, ok := c.cache[key]
        if !ok {
                return nil, false
        }
        if time.Since(entry.timestamp) > c.cacheTTL {
                return nil, false
        }
        return entry.data, true
}

func (c *Client) cacheSet(key string, data []string) {
        c.cacheMu.Lock()
        defer c.cacheMu.Unlock()
        c.cache[key] = cacheEntry{data: data, timestamp: time.Now()}
        if len(c.cache) > c.cacheMax {
                cutoff := time.Now().Add(-c.cacheTTL)
                for k, v := range c.cache {
                        if v.timestamp.Before(cutoff) {
                                delete(c.cache, k)
                        }
                }
        }
}

func dnsTypeFromString(recordType string) (uint16, error) {
        switch strings.ToUpper(recordType) {
        case "A":
                return dns.TypeA, nil
        case "AAAA":
                return dns.TypeAAAA, nil
        case "MX":
                return dns.TypeMX, nil
        case dnsTypeTXT:
                return dns.TypeTXT, nil
        case "NS":
                return dns.TypeNS, nil
        case "CNAME":
                return dns.TypeCNAME, nil
        case "CAA":
                return dns.TypeCAA, nil
        case "SOA":
                return dns.TypeSOA, nil
        case "SRV":
                return dns.TypeSRV, nil
        case "TLSA":
                return dns.TypeTLSA, nil
        case "DNSKEY":
                return dns.TypeDNSKEY, nil
        case "DS":
                return dns.TypeDS, nil
        case "RRSIG":
                return dns.TypeRRSIG, nil
        case "NSEC":
                return dns.TypeNSEC, nil
        case "NSEC3":
                return dns.TypeNSEC3, nil
        case "PTR":
                return dns.TypePTR, nil
        default:
                return 0, fmt.Errorf("unsupported record type: %s", recordType)
        }
}

func rrToString(rr dns.RR) string {
        switch v := rr.(type) {
        case *dns.A:
                return v.A.Addr.String()
        case *dns.AAAA:
                return v.AAAA.Addr.String()
        case *dns.MX:
                return fmt.Sprintf("%d %s", v.MX.Preference, v.MX.Mx)
        case *dns.TXT:
                return strings.Join(v.TXT.Txt, "")
        case *dns.NS:
                return v.NS.Ns
        case *dns.CNAME:
                return v.CNAME.Target
        case *dns.CAA:
                return fmt.Sprintf("%d %s \"%s\"", v.CAA.Flag, v.CAA.Tag, v.CAA.Value)
        case *dns.SOA:
                return fmt.Sprintf("%s %s %d %d %d %d %d", v.SOA.Ns, v.SOA.Mbox, v.SOA.Serial, v.SOA.Refresh, v.SOA.Retry, v.SOA.Expire, v.SOA.Minttl)
        case *dns.SRV:
                return fmt.Sprintf("%d %d %d %s", v.SRV.Priority, v.SRV.Weight, v.SRV.Port, v.SRV.Target)
        case *dns.TLSA:
                return fmt.Sprintf("%d %d %d %s", v.TLSA.Usage, v.TLSA.Selector, v.TLSA.MatchingType, v.TLSA.Certificate)
        case *dns.DNSKEY:
                return v.String()
        case *dns.DS:
                return v.String()
        case *dns.RRSIG:
                return v.String()
        default:
                hdr := rr.Header()
                full := rr.String()
                prefix := hdr.String()
                return strings.TrimPrefix(full, prefix)
        }
}

func (c *Client) QueryDNS(ctx context.Context, recordType, domain string) []string {
        if domain == "" || recordType == "" {
                return nil
        }

        cacheKey := fmt.Sprintf("%s:%s", strings.ToUpper(recordType), strings.ToLower(domain))
        if cached, ok := c.cacheGet(cacheKey); ok {
                return cached
        }

        results := c.dohQuery(ctx, domain, recordType)
        if len(results) > 0 {
                c.cacheSet(cacheKey, results)
                return results
        }

        results = c.parallelUDPQuery(ctx, domain, recordType)
        if len(results) > 0 {
                c.cacheSet(cacheKey, results)
        }
        return results
}

func (c *Client) parallelUDPQuery(ctx context.Context, domain, recordType string) []string {
        type udpResult struct {
                records []string
        }
        ch := make(chan udpResult, len(c.resolvers))
        qctx, cancel := context.WithTimeout(ctx, defaultLifetime)
        defer cancel()

        for _, resolver := range c.resolvers {
                go func(ip string) {
                        ch <- udpResult{records: c.udpQuery(qctx, domain, recordType, ip)}
                }(resolver.IP)
        }

        for range c.resolvers {
                r := <-ch
                if len(r.records) > 0 {
                        return r.records
                }
        }
        return nil
}

func (c *Client) QueryDNSWithTTL(ctx context.Context, recordType, domain string) RecordWithTTL {
        if domain == "" || recordType == "" {
                return RecordWithTTL{}
        }

        result := c.dohQueryWithTTL(ctx, domain, recordType)
        if len(result.Records) > 0 {
                return result
        }

        return c.parallelUDPQueryWithTTL(ctx, domain, recordType)
}

func (c *Client) parallelUDPQueryWithTTL(ctx context.Context, domain, recordType string) RecordWithTTL {
        ch := make(chan RecordWithTTL, len(c.resolvers))
        qctx, cancel := context.WithTimeout(ctx, defaultLifetime)
        defer cancel()

        for _, resolver := range c.resolvers {
                go func(ip string) {
                        ch <- c.udpQueryWithTTL(qctx, domain, recordType, ip)
                }(resolver.IP)
        }

        for range c.resolvers {
                r := <-ch
                if len(r.Records) > 0 {
                        return r
                }
        }
        return RecordWithTTL{}
}

func (c *Client) querySingleResolver(ctx context.Context, domain, recordType, resolverIP string) (string, []string, string) {
        qtype, err := dnsTypeFromString(recordType)
        if err != nil {
                return resolverIP, nil, err.Error()
        }

        fqdn := dnsutil.Fqdn(domain)
        msg := dns.NewMsg(fqdn, qtype)
        msg.RecursionDesired = true

        client := newDNSClient(c.timeout)

        r, _, err := client.Exchange(ctx, msg, protoUDP, net.JoinHostPort(resolverIP, dnsPort))
        if err != nil {
                return resolverIP, nil, err.Error()
        }

        if r.Rcode == dns.RcodeNameError {
                return resolverIP, nil, "NXDOMAIN"
        }

        var results []string
        for _, rr := range r.Answer {
                s := rrToString(rr)
                if s != "" {
                        results = append(results, s)
                }
        }
        sort.Strings(results)
        return resolverIP, results, ""
}

func (c *Client) QueryWithConsensus(ctx context.Context, recordType, domain string) ConsensusResult {
        if domain == "" || recordType == "" {
                return ConsensusResult{Consensus: true}
        }

        type resolverResult struct {
                name    string
                results []string
                err     string
        }

        ch := make(chan resolverResult, len(c.resolvers))
        ctx2, cancel := context.WithTimeout(ctx, consensusWait)
        defer cancel()

        for _, r := range c.resolvers {
                go func(resolver ResolverConfig) {
                        _, results, errStr := c.querySingleResolver(ctx2, domain, recordType, resolver.IP)
                        ch <- resolverResult{name: resolver.Name, results: results, err: errStr}
                }(r)
        }

        resolverResults := make(map[string][]string)
        for i := 0; i < len(c.resolvers); i++ {
                select {
                case rr := <-ch:
                        if rr.err == "" {
                                resolverResults[rr.name] = rr.results
                        } else {
                                slog.Debug("resolver error", mapKeyResolver, rr.name, "record_type", recordType, mapKeyDomain, domain, mapKeyError, rr.err)
                        }
                case <-ctx2.Done():
                        break
                }
        }

        if len(resolverResults) == 0 {
                dohResults := c.dohQuery(ctx, domain, recordType)
                return ConsensusResult{
                        Records:         dohResults,
                        Consensus:       true,
                        ResolverCount:   boolToInt(len(dohResults) > 0),
                        ResolverResults: map[string][]string{"DoH": dohResults},
                }
        }

        consensusRecords, allSame, discrepancies := findConsensus(resolverResults)
        if !allSame {
                slog.Warn("DNS discrepancy", mapKeyDomain, domain, "record_type", recordType, mapKeyDiscrepancies, discrepancies)
        }

        return ConsensusResult{
                Records:         consensusRecords,
                Consensus:       allSame,
                ResolverCount:   len(resolverResults),
                Discrepancies:   discrepancies,
                ResolverResults: resolverResults,
        }
}

func findConsensus(resolverResults map[string][]string) (records []string, allSame bool, discrepancies []string) {
        resultSets := make(map[string]int)
        for _, results := range resolverResults {
                key := strings.Join(results, "|")
                resultSets[key]++
        }

        var mostCommonKey string
        var mostCommonCount int
        for key, count := range resultSets {
                if count > mostCommonCount {
                        mostCommonKey = key
                        mostCommonCount = count
                }
        }

        if mostCommonKey != "" {
                records = strings.Split(mostCommonKey, "|")
                if len(records) == 1 && records[0] == "" {
                        records = nil
                }
        }

        allSame = len(resultSets) <= 1
        if !allSame {
                for name, results := range resolverResults {
                        key := strings.Join(results, "|")
                        if key != mostCommonKey {
                                discrepancies = append(discrepancies, fmt.Sprintf("%s returned different results: %v", name, results))
                        }
                }
        }
        return
}

func (c *Client) ValidateResolverConsensus(ctx context.Context, domain string) map[string]any {
        criticalTypes := []string{"A", "MX", "NS", dnsTypeTXT}
        result := map[string]any{
                "consensus_reached":    true,
                "resolvers_queried":    len(c.resolvers),
                "checks_performed":     0,
                mapKeyDiscrepancies:    []string{},
                "per_record_consensus": map[string]any{},
        }

        type checkResult struct {
                recordType string
                consensus  ConsensusResult
                err        error
        }

        ch := make(chan checkResult, len(criticalTypes))
        ctx2, cancel := context.WithTimeout(ctx, 8*time.Second)
        defer cancel()

        for _, rt := range criticalTypes {
                go func(recordType string) {
                        cr := c.QueryWithConsensus(ctx2, recordType, domain)
                        ch <- checkResult{recordType: recordType, consensus: cr}
                }(rt)
        }

        perRecord := make(map[string]any)
        var allDisc []string
        checksPerformed := 0
        consensusReached := true

        for i := 0; i < len(criticalTypes); i++ {
                select {
                case cr := <-ch:
                        checksPerformed++
                        perRecord[cr.recordType] = map[string]any{
                                "consensus":         cr.consensus.Consensus,
                                "resolver_count":    cr.consensus.ResolverCount,
                                mapKeyDiscrepancies: cr.consensus.Discrepancies,
                        }
                        if !cr.consensus.Consensus {
                                consensusReached = false
                                for _, d := range cr.consensus.Discrepancies {
                                        allDisc = append(allDisc, fmt.Sprintf("%s: %s", cr.recordType, d))
                                }
                        }
                case <-ctx2.Done():
                        break
                }
        }

        result["consensus_reached"] = consensusReached
        result["checks_performed"] = checksPerformed
        result[mapKeyDiscrepancies] = allDisc
        result["per_record_consensus"] = perRecord
        return result
}

func (c *Client) CheckDNSSECADFlag(ctx context.Context, domain string) ADFlagResult {
        result := ADFlagResult{}
        validatingResolvers := []string{resolverGoogle, resolverCloudflare}

        for _, resolverIP := range validatingResolvers {
                fqdn := dnsutil.Fqdn(domain)
                msg := dns.NewMsg(fqdn, dns.TypeA)
                msg.RecursionDesired = true
                msg.UDPSize, msg.Security = 4096, true

                dnsClient := newDNSClient(3 * time.Second)

                r, _, err := dnsClient.Exchange(ctx, msg, protoUDP, net.JoinHostPort(resolverIP, dnsPort))
                if err != nil {
                        if isNXDomain(r) {
                                errStr := "Domain not found"
                                result.Error = &errStr
                                return result
                        }
                        slog.Debug("AD flag check failed", mapKeyResolver, resolverIP, mapKeyError, err)
                        continue
                }

                if r.Rcode == dns.RcodeNameError {
                        errStr := "Domain not found"
                        result.Error = &errStr
                        return result
                }

                if len(r.Answer) == 0 {
                        msg2 := dns.NewMsg(fqdn, dns.TypeSOA)
                        msg2.RecursionDesired = true
                        msg2.UDPSize, msg2.Security = 4096, true
                        r2, _, err2 := dnsClient.Exchange(ctx, msg2, protoUDP, net.JoinHostPort(resolverIP, dnsPort))
                        if err2 == nil {
                                r = r2
                        }
                }

                if r.AuthenticatedData {
                        result.ADFlag = true
                        result.Validated = true
                        result.ResolverUsed = &resolverIP
                        return result
                }
                result.ADFlag = false
                result.Validated = false
                result.ResolverUsed = &resolverIP
                return result
        }

        errStr := "Could not verify AD flag"
        result.Error = &errStr
        return result
}

func (c *Client) ExchangeContext(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
        resolverAddr := net.JoinHostPort(c.resolvers[0].IP, dnsPort)
        return c.exchangeWithFallback(ctx, msg, resolverAddr)
}

func (c *Client) exchangeWithFallback(ctx context.Context, msg *dns.Msg, resolverAddr string) (*dns.Msg, error) {
        client := newDNSClient(c.timeout)
        r, _, err := client.Exchange(ctx, msg, protoUDP, resolverAddr)
        if err == nil {
                return r, nil
        }

        slog.Debug("UDP query failed, falling back to TCP", mapKeyResolver, resolverAddr, mapKeyError, err)
        r, _, err = client.Exchange(ctx, msg, "tcp", resolverAddr)
        return r, err
}

func (c *Client) QuerySpecificResolver(ctx context.Context, recordType, domain, resolverIP string) ([]string, error) {
        qtype, err := dnsTypeFromString(recordType)
        if err != nil {
                return nil, err
        }

        fqdn := dnsutil.Fqdn(domain)
        msg := dns.NewMsg(fqdn, qtype)
        msg.RecursionDesired = false

        resolverAddr := net.JoinHostPort(resolverIP, dnsPort)
        r, err := c.exchangeWithFallback(ctx, msg, resolverAddr)
        if err != nil {
                return nil, err
        }

        if r.Rcode == dns.RcodeNameError {
                return nil, nil
        }

        var results []string
        for _, rr := range r.Answer {
                s := rrToString(rr)
                if s != "" {
                        results = append(results, s)
                }
        }
        return results, nil
}

func (c *Client) QueryWithTTLFromResolver(ctx context.Context, recordType, domain, resolverIP string) RecordWithTTL {
        qtype, err := dnsTypeFromString(recordType)
        if err != nil {
                return RecordWithTTL{}
        }

        fqdn := dnsutil.Fqdn(domain)
        msg := dns.NewMsg(fqdn, qtype)
        msg.RecursionDesired = false

        resolverAddr := net.JoinHostPort(resolverIP, dnsPort)
        r, err := c.exchangeWithFallback(ctx, msg, resolverAddr)
        if err != nil {
                return RecordWithTTL{}
        }

        if r.Rcode == dns.RcodeNameError {
                return RecordWithTTL{}
        }

        var results []string
        var ttl *uint32
        for _, rr := range r.Answer {
                s := rrToString(rr)
                if s != "" {
                        results = append(results, s)
                        if ttl == nil {
                                t := rr.Header().TTL
                                ttl = &t
                        }
                }
        }
        return RecordWithTTL{Records: results, TTL: ttl}
}

func (c *Client) dohQuery(ctx context.Context, domain, recordType string) []string {
        result := c.dohQueryWithTTL(ctx, domain, recordType)
        return result.Records
}

type dohResponse struct {
        Status int  `json:"Status"`
        AD     bool `json:"AD"`
        Answer []struct {
                Data string `json:"data"`
                TTL  uint32 `json:"TTL"`
                Type int    `json:"type"`
        } `json:"Answer"`
}

func (c *Client) dohQueryWithTTL(ctx context.Context, domain, recordType string) RecordWithTTL {
        req, err := http.NewRequestWithContext(ctx, "GET", dohGoogleURL, nil)
        if err != nil {
                return RecordWithTTL{}
        }

        q := url.Values{}
        q.Set("name", domain)
        q.Set("type", strings.ToUpper(recordType))
        q.Set("do", "1")
        req.URL.RawQuery = q.Encode()
        req.Header.Set("Accept", "application/dns-json")
        req.Header.Set("User-Agent", UserAgent)

        resp, err := c.httpClient.Do(req)
        if err != nil {
                slog.Debug("DoH query failed", mapKeyDomain, domain, "type", recordType, mapKeyError, err)
                return RecordWithTTL{}
        }
        defer safeClose(resp.Body, "doh-response")

        if resp.StatusCode != http.StatusOK {
                return RecordWithTTL{}
        }

        body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
        if err != nil {
                return RecordWithTTL{}
        }

        return parseDohResponse(body, recordType)
}

func parseDohResponse(body []byte, recordType string) RecordWithTTL {
        var data dohResponse
        if json.Unmarshal(body, &data) != nil {
                return RecordWithTTL{}
        }

        if data.Status != 0 {
                return RecordWithTTL{}
        }

        if len(data.Answer) == 0 {
                return RecordWithTTL{}
        }

        requestedRRSIG := strings.ToUpper(recordType) == "RRSIG"
        var results []string
        var ttl *uint32
        seen := make(map[string]bool)
        for _, answer := range data.Answer {
                if answer.Type == dohTypeRRSIG && !requestedRRSIG {
                        continue
                }
                rd := strings.TrimSpace(answer.Data)
                if rd == "" {
                        continue
                }
                if strings.ToUpper(recordType) == dnsTypeTXT {
                        rd = strings.Trim(rd, "\"")
                }
                if !seen[rd] {
                        results = append(results, rd)
                        seen[rd] = true
                }
                if ttl == nil {
                        t := answer.TTL
                        ttl = &t
                }
        }

        return RecordWithTTL{Records: results, TTL: ttl, Authenticated: data.AD}
}

func (c *Client) ProbeExists(ctx context.Context, domain string) (exists bool, cname string) {
        fqdn := dnsutil.Fqdn(domain)
        msg := dns.NewMsg(fqdn, dns.TypeA)
        msg.RecursionDesired = true

        dnsClient := newDNSClient(3 * time.Second)

        resolverIP := resolverGoogle
        r, _, err := dnsClient.Exchange(ctx, msg, protoUDP, net.JoinHostPort(resolverIP, dnsPort))
        if err != nil {
                resolverIP = resolverCloudflare
                r, _, err = dnsClient.Exchange(ctx, msg, protoUDP, net.JoinHostPort(resolverIP, dnsPort))
                if err != nil {
                        return false, ""
                }
        }

        if r.Rcode == dns.RcodeNameError {
                return false, ""
        }

        hasA := false
        cnameTarget := ""
        for _, rr := range r.Answer {
                switch v := rr.(type) {
                case *dns.A:
                        hasA = true
                case *dns.CNAME:
                        if cnameTarget == "" {
                                cnameTarget = strings.TrimSuffix(v.CNAME.Target, ".")
                        }
                }
        }

        if hasA || cnameTarget != "" {
                return true, cnameTarget
        }
        return false, ""
}

func (c *Client) udpQuery(ctx context.Context, domain, recordType, resolverIP string) []string {
        result := c.udpQueryWithTTL(ctx, domain, recordType, resolverIP)
        return result.Records
}

func (c *Client) udpQueryWithTTL(ctx context.Context, domain, recordType, resolverIP string) RecordWithTTL {
        qtype, err := dnsTypeFromString(recordType)
        if err != nil {
                return RecordWithTTL{}
        }

        fqdn := dnsutil.Fqdn(domain)
        msg := dns.NewMsg(fqdn, qtype)
        msg.RecursionDesired = true
        msg.UDPSize, msg.Security = 4096, true

        dnsClient := newDNSClient(c.timeout)

        r, _, err := dnsClient.Exchange(ctx, msg, protoUDP, net.JoinHostPort(resolverIP, dnsPort))
        if err != nil {
                return RecordWithTTL{}
        }

        if r.Rcode == dns.RcodeNameError {
                return RecordWithTTL{}
        }

        var results []string
        var ttl *uint32
        for _, rr := range r.Answer {
                if _, isRRSIG := rr.(*dns.RRSIG); isRRSIG && qtype != dns.TypeRRSIG {
                        continue
                }
                s := rrToString(rr)
                if s != "" {
                        results = append(results, s)
                        if ttl == nil {
                                t := rr.Header().TTL
                                ttl = &t
                        }
                }
        }

        return RecordWithTTL{Records: results, TTL: ttl, Authenticated: r.AuthenticatedData}
}

func newDNSClient(timeout time.Duration) *dns.Client {
        return &dns.Client{
                Transport: &dns.Transport{
                        Dialer: &net.Dialer{
                                Timeout: timeout,
                        },
                        ReadTimeout:  timeout,
                        WriteTimeout: timeout,
                },
        }
}

func isNXDomain(r *dns.Msg) bool {
        return r != nil && r.Rcode == dns.RcodeNameError
}

func boolToInt(b bool) int {
        if b {
                return 1
        }
        return 0
}
