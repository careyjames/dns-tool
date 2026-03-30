// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "dnstool/go-server/internal/dnsclient"
        "fmt"
        "io"
        "regexp"
        "strings"
        "time"
)

const (
        mapKeyWeb3Analysis = "web3_analysis"

        web3StatusDetected    = "detected"
        web3StatusNotDetected = "not_detected"

        indicatorTypeDNSLink      = "dnslink"
        indicatorTypeCryptoWallet = "crypto_wallet"
        indicatorTypeENSRecord    = "ens_record"
        indicatorTypeIPFSHash     = "ipfs_hash"
        indicatorTypeIPNSName     = "ipns_name"

        ipfsGatewayDwebLink = "https://dweb.link"
        ipfsGatewayIPFSIO   = "https://ipfs.io"

        ipfsProbeTimeout = 5 * time.Second
        ipfsProbeBodyMax = 1024

        trustModeGatewayTrusted = "gateway_trusted"
        trustModeCIDVerified    = "cid_verified"
)

var (
        dnslinkIPFSRe = regexp.MustCompile(`(?i)^dnslink=/ipfs/([a-zA-Z0-9]+)`)
        dnslinkIPNSRe = regexp.MustCompile(`(?i)^dnslink=/ipns/(.+)$`)
        cidV0Re       = regexp.MustCompile(`^Qm[1-9A-HJ-NP-Za-km-z]{44}$`)
        cidV1Re       = regexp.MustCompile(`^b[a-z2-7]{58,}$`)
        ethAddressRe  = regexp.MustCompile(`(?i)^(?:(?:ETH|eth\.addr|addr)[=:]\s*)?0x[0-9a-fA-F]{40}$`)
        btcAddressRe  = regexp.MustCompile(`(?i)^(?:(?:BTC|btc\.addr|addr)[=:]\s*)?([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})$`)
        ensContentRe  = regexp.MustCompile(`(?i)(contenthash|_ens|eth\.addr)`)
)

var walletPatterns = []struct {
        name    string
        pattern *regexp.Regexp
}{
        {"Ethereum Address", ethAddressRe},
        {"Bitcoin Address", btcAddressRe},
}

type Web3Indicator struct {
        Type          string `json:"type"`
        Value         string `json:"value"`
        Description   string `json:"description"`
        Link          string `json:"link,omitempty"`
        EvidenceClass string `json:"evidence_class"`
}

type Web3DNSSECTrust struct {
        Present bool   `json:"dnssec_present"`
        Valid   bool   `json:"dnssec_valid"`
        Status  string `json:"status"`
}

type IPFSProbe struct {
        Namespace          string   `json:"namespace"`
        CIDOrName          string   `json:"cid_or_name"`
        ReachableViaAny    bool     `json:"reachable_via_any"`
        ReachableViaAll    bool     `json:"reachable_via_all"`
        GatewaysTested     []string `json:"gateways_tested"`
        GatewaysReachable  []string `json:"gateways_reachable"`
        ContentType        string   `json:"content_type,omitempty"`
        TrustMode          string   `json:"trust_mode"`
        PersistenceUnproven bool   `json:"persistence_unproven"`
        Error              string   `json:"error,omitempty"`
}

type Web3Analysis struct {
        Detected       bool             `json:"detected"`
        Status         string           `json:"status"`
        Indicators     []Web3Indicator  `json:"indicators"`
        DNSLinkCID     string           `json:"dnslink_cid,omitempty"`
        DNSLinkIPNS    string           `json:"dnslink_ipns,omitempty"`
        DNSLinkSource  string           `json:"dnslink_source,omitempty"`
        IPFSProbe      *IPFSProbe       `json:"ipfs_probe,omitempty"`
        DNSSECTrust    Web3DNSSECTrust  `json:"dnssec_trust"`
        ResolutionInfo map[string]any   `json:"resolution_info,omitempty"`
        IndicatorCount int              `json:"indicator_count"`

        IPFSReachable  *bool  `json:"-"`
        IPFSGatewayURL string `json:"-"`
        IPFSError      string `json:"-"`
}

func DefaultWeb3Analysis() map[string]any {
        return map[string]any{
                "detected":        false,
                "status":          web3StatusNotDetected,
                "indicators":      []Web3Indicator{},
                "indicator_count": 0,
                "dnssec_trust": map[string]any{
                        "dnssec_present": false,
                        "dnssec_valid":   false,
                        "status":         "unknown",
                },
        }
}

func (a *Analyzer) AnalyzeWeb3(ctx context.Context, domain string, txtRecords []string, dnssecResult map[string]any) map[string]any {
        analysis := &Web3Analysis{
                Status:     web3StatusNotDetected,
                Indicators: []Web3Indicator{},
        }

        dnslinkRecords := a.queryDNSLinkSubdomain(ctx, domain)
        if len(dnslinkRecords) > 0 {
                analysis.detectDNSLink(dnslinkRecords)
                if analysis.DNSLinkCID != "" || analysis.DNSLinkIPNS != "" {
                        analysis.DNSLinkSource = "_dnslink"
                }
        }

        if analysis.DNSLinkCID == "" && analysis.DNSLinkIPNS == "" {
                analysis.detectDNSLink(txtRecords)
                if analysis.DNSLinkCID != "" || analysis.DNSLinkIPNS != "" {
                        analysis.DNSLinkSource = "root_txt"
                }
        }

        analysis.detectCryptoWallets(txtRecords)
        analysis.detectENSRecords(txtRecords)
        analysis.assessDNSSECTrust(dnssecResult)

        if len(analysis.Indicators) > 0 {
                analysis.Detected = true
                analysis.Status = web3StatusDetected
        }

        if analysis.DNSLinkCID != "" {
                analysis.verifyIPFSReachability(ctx)
        }

        analysis.IndicatorCount = len(analysis.Indicators)
        return analysis.toMap()
}

func AnalyzeWeb3Static(txtRecords []string, dnssecResult map[string]any) map[string]any {
        analysis := &Web3Analysis{
                Status:     web3StatusNotDetected,
                Indicators: []Web3Indicator{},
        }

        analysis.detectDNSLink(txtRecords)
        if analysis.DNSLinkCID != "" || analysis.DNSLinkIPNS != "" {
                analysis.DNSLinkSource = "root_txt"
        }
        analysis.detectCryptoWallets(txtRecords)
        analysis.detectENSRecords(txtRecords)
        analysis.assessDNSSECTrust(dnssecResult)

        if len(analysis.Indicators) > 0 {
                analysis.Detected = true
                analysis.Status = web3StatusDetected
        }

        analysis.IndicatorCount = len(analysis.Indicators)
        return analysis.toMap()
}

func (a *Analyzer) queryDNSLinkSubdomain(ctx context.Context, domain string) []string {
        dnslinkDomain := "_dnslink." + domain
        records := a.DNS.QueryDNS(ctx, "TXT", dnslinkDomain)
        return records
}

func (w *Web3Analysis) detectDNSLink(txtRecords []string) {
        for _, txt := range txtRecords {
                txt = strings.TrimSpace(txt)

                if m := dnslinkIPFSRe.FindStringSubmatch(txt); m != nil {
                        cid := m[1]
                        w.DNSLinkCID = cid
                        gatewayURL := fmt.Sprintf("%s/ipfs/%s", ipfsGatewayDwebLink, cid)
                        w.IPFSGatewayURL = gatewayURL
                        w.Indicators = append(w.Indicators, Web3Indicator{
                                Type:          indicatorTypeDNSLink,
                                Value:         txt,
                                Description:   fmt.Sprintf("IPFS content-addressed hosting via DNSLink (CID: %s)", truncateCID(cid)),
                                Link:          gatewayURL,
                                EvidenceClass: "protocol_binding",
                        })
                        continue
                }

                if m := dnslinkIPNSRe.FindStringSubmatch(txt); m != nil {
                        ipnsName := m[1]
                        w.DNSLinkIPNS = ipnsName
                        gatewayURL := fmt.Sprintf("%s/ipns/%s", ipfsGatewayDwebLink, ipnsName)
                        w.Indicators = append(w.Indicators, Web3Indicator{
                                Type:          indicatorTypeIPNSName,
                                Value:         txt,
                                Description:   fmt.Sprintf("IPNS mutable naming via DNSLink (name: %s)", truncateStr(ipnsName, 40)),
                                Link:          gatewayURL,
                                EvidenceClass: "protocol_binding",
                        })
                }
        }
}

func (w *Web3Analysis) detectCryptoWallets(txtRecords []string) {
        for _, txt := range txtRecords {
                txt = strings.TrimSpace(txt)
                for _, wp := range walletPatterns {
                        if wp.pattern.MatchString(txt) {
                                w.Indicators = append(w.Indicators, Web3Indicator{
                                        Type:          indicatorTypeCryptoWallet,
                                        Value:         redactWalletAddress(txt),
                                        Description:   fmt.Sprintf("%s found in DNS TXT record", wp.name),
                                        EvidenceClass: "identity_metadata",
                                })
                                break
                        }
                }
        }
}

func (w *Web3Analysis) detectENSRecords(txtRecords []string) {
        for _, txt := range txtRecords {
                txt = strings.TrimSpace(txt)
                if ensContentRe.MatchString(txt) {
                        w.Indicators = append(w.Indicators, Web3Indicator{
                                Type:          indicatorTypeENSRecord,
                                Value:         truncateStr(txt, 80),
                                Description:   "ENS-related record detected in DNS TXT",
                                EvidenceClass: "protocol_binding",
                        })
                }
        }
}

func (w *Web3Analysis) assessDNSSECTrust(dnssecResult map[string]any) {
        if dnssecResult == nil {
                w.DNSSECTrust = Web3DNSSECTrust{
                        Present: false,
                        Valid:   false,
                        Status:  "unknown",
                }
                return
        }

        status, _ := dnssecResult["status"].(string)
        switch status {
        case "success":
                w.DNSSECTrust = Web3DNSSECTrust{
                        Present: true,
                        Valid:   true,
                        Status:  "validated",
                }
        case "warning":
                w.DNSSECTrust = Web3DNSSECTrust{
                        Present: true,
                        Valid:   false,
                        Status:  "partial",
                }
        default:
                w.DNSSECTrust = Web3DNSSECTrust{
                        Present: false,
                        Valid:   false,
                        Status:  "not_configured",
                }
        }
}

func (w *Web3Analysis) verifyIPFSReachability(ctx context.Context) {
        if w.DNSLinkCID == "" {
                return
        }

        if !IsValidCID(w.DNSLinkCID) {
                f := false
                w.IPFSReachable = &f
                w.IPFSError = "Invalid IPFS CID format"
                w.IPFSProbe = &IPFSProbe{
                        Namespace:           "ipfs",
                        CIDOrName:           w.DNSLinkCID,
                        TrustMode:           trustModeGatewayTrusted,
                        PersistenceUnproven: true,
                        Error:               "Invalid IPFS CID format",
                }
                return
        }

        gateways := []string{ipfsGatewayDwebLink, ipfsGatewayIPFSIO}
        probe := &IPFSProbe{
                Namespace:           "ipfs",
                CIDOrName:           w.DNSLinkCID,
                GatewaysTested:      gateways,
                GatewaysReachable:   []string{},
                TrustMode:           trustModeGatewayTrusted,
                PersistenceUnproven: true,
        }

        for _, gw := range gateways {
                probeURL := fmt.Sprintf("%s/ipfs/%s", gw, w.DNSLinkCID)
                reachable, errMsg := probeIPFSGateway(ctx, probeURL)
                if reachable {
                        probe.GatewaysReachable = append(probe.GatewaysReachable, gw)
                        if w.IPFSGatewayURL == "" {
                                w.IPFSGatewayURL = probeURL
                        }
                } else if errMsg != "" && probe.Error == "" {
                        probe.Error = errMsg
                }
        }

        probe.ReachableViaAny = len(probe.GatewaysReachable) > 0
        probe.ReachableViaAll = len(probe.GatewaysReachable) == len(gateways)

        if probe.ReachableViaAny {
                t := true
                w.IPFSReachable = &t
        } else {
                f := false
                w.IPFSReachable = &f
                if probe.Error == "" {
                        probe.Error = "Content not reachable via public IPFS gateways"
                }
                w.IPFSError = probe.Error
        }

        w.IPFSProbe = probe
}

func probeIPFSGateway(ctx context.Context, url string) (bool, string) {
        probeCtx, cancel := context.WithTimeout(ctx, ipfsProbeTimeout)
        defer cancel()

        client := dnsclient.NewSafeHTTPClientWithTimeout(ipfsProbeTimeout)

        resp, err := client.GetWithHeaders(probeCtx, url, map[string]string{
                "User-Agent": "DNS-Tool-Web3-Probe/1.0",
        })
        if err != nil {
                return false, fmt.Sprintf("Gateway unreachable: %s", classifyWeb3HTTPError(err))
        }
        defer func() {
                _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, ipfsProbeBodyMax))
                resp.Body.Close()
        }()

        if resp.StatusCode >= 200 && resp.StatusCode < 400 {
                return true, ""
        }
        return false, fmt.Sprintf("Gateway returned HTTP %d", resp.StatusCode)
}

func classifyWeb3HTTPError(err error) string {
        errStr := err.Error()
        switch {
        case strings.Contains(errStr, "timeout"):
                return "timeout"
        case strings.Contains(errStr, "refused"):
                return "connection refused"
        case strings.Contains(errStr, "no such host"):
                return "DNS resolution failed"
        default:
                return "connection error"
        }
}

func IsValidCID(cid string) bool {
        if cid == "" {
                return false
        }
        return cidV0Re.MatchString(cid) || cidV1Re.MatchString(cid)
}

func truncateCID(cid string) string {
        if len(cid) <= 16 {
                return cid
        }
        return cid[:8] + "..." + cid[len(cid)-4:]
}

func truncateStr(s string, maxLen int) string {
        if len(s) <= maxLen {
                return s
        }
        return s[:maxLen-3] + "..."
}

func redactWalletAddress(addr string) string {
        if len(addr) <= 12 {
                return addr
        }
        return addr[:6] + "..." + addr[len(addr)-4:]
}

func renderDNSSECTrustNote(trust Web3DNSSECTrust) string {
        switch trust.Status {
        case "validated":
                return "DNSSEC validated — DNS records are cryptographically signed, supporting trustless Web3 resolution"
        case "partial":
                return "DNSSEC partially configured — Web3 resolution trust is degraded without full chain validation"
        case "not_configured":
                return "DNSSEC not configured — DNS records can be spoofed, undermining Web3 resolution trust"
        default:
                return "DNSSEC status unknown — trustless Web3 resolution requires DNSSEC for DNS-based discovery"
        }
}

func (w *Web3Analysis) toMap() map[string]any {
        indicators := make([]map[string]any, len(w.Indicators))
        for i, ind := range w.Indicators {
                m := map[string]any{
                        "type":           ind.Type,
                        "value":          ind.Value,
                        "description":    ind.Description,
                        "evidence_class": ind.EvidenceClass,
                }
                if ind.Link != "" {
                        m["link"] = ind.Link
                }
                indicators[i] = m
        }

        result := map[string]any{
                "detected":        w.Detected,
                "status":          w.Status,
                "indicators":      indicators,
                "indicator_count": w.IndicatorCount,
                "dnssec_trust": map[string]any{
                        "dnssec_present": w.DNSSECTrust.Present,
                        "dnssec_valid":   w.DNSSECTrust.Valid,
                        "status":         w.DNSSECTrust.Status,
                },
                "dnssec_trust_note": renderDNSSECTrustNote(w.DNSSECTrust),
        }

        if w.DNSLinkCID != "" {
                result["dnslink_cid"] = w.DNSLinkCID
        }
        if w.DNSLinkIPNS != "" {
                result["dnslink_ipns"] = w.DNSLinkIPNS
        }
        if w.DNSLinkSource != "" {
                result["dnslink_source"] = w.DNSLinkSource
        }

        if w.IPFSReachable != nil {
                result["ipfs_reachable"] = *w.IPFSReachable
        }
        if w.IPFSGatewayURL != "" {
                result["ipfs_gateway_url"] = w.IPFSGatewayURL
        }
        if w.IPFSError != "" {
                result["ipfs_error"] = w.IPFSError
        }

        if w.IPFSProbe != nil {
                probe := map[string]any{
                        "namespace":            w.IPFSProbe.Namespace,
                        "cid_or_name":          w.IPFSProbe.CIDOrName,
                        "reachable_via_any":    w.IPFSProbe.ReachableViaAny,
                        "reachable_via_all":    w.IPFSProbe.ReachableViaAll,
                        "gateways_tested":      w.IPFSProbe.GatewaysTested,
                        "gateways_reachable":   w.IPFSProbe.GatewaysReachable,
                        "trust_mode":           w.IPFSProbe.TrustMode,
                        "persistence_unproven": w.IPFSProbe.PersistenceUnproven,
                }
                if w.IPFSProbe.ContentType != "" {
                        probe["content_type"] = w.IPFSProbe.ContentType
                }
                if w.IPFSProbe.Error != "" {
                        probe["error"] = w.IPFSProbe.Error
                }
                result["ipfs_probe"] = probe
        }

        if w.ResolutionInfo != nil {
                result["resolution_info"] = w.ResolutionInfo
        }

        return result
}

func ExtractTXTFromBasicRecords(basic map[string]any) []string {
        if basic == nil {
                return nil
        }
        switch v := basic["TXT"].(type) {
        case []string:
                return v
        case []any:
                result := make([]string, 0, len(v))
                for _, item := range v {
                        if s, ok := item.(string); ok {
                                result = append(result, s)
                        }
                }
                return result
        }
        return nil
}
