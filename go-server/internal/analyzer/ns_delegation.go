// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "fmt"
        "sort"
        "strings"
)

const (
        mapKeyEnterpriseDetail  = "enterprise_detail"
        mapKeyEnterpriseLabel   = "enterprise_label"
        mapKeyEnterprisePattern = "enterprise_pattern"
)

func normalizeNSList(records []string) []string {
        var result []string
        for _, ns := range records {
                if ns != "" {
                        result = append(result, strings.ToLower(strings.TrimRight(ns, ".")))
                }
        }
        sort.Strings(result)
        return result
}

func (a *Analyzer) queryChildNS(ctx context.Context, domain string) []string {
        childResult := a.DNS.QueryDNS(ctx, "NS", domain)
        if len(childResult) == 0 {
                return nil
        }
        return normalizeNSList(childResult)
}

func parentZoneFromDomain(domain string) string {
        parts := strings.Split(domain, ".")
        if len(parts) < 2 {
                return ""
        }
        if len(parts) > 2 {
                return strings.Join(parts[1:], ".")
        }
        return parts[len(parts)-1]
}

func (a *Analyzer) queryParentNS(ctx context.Context, domain string) []string {
        parentZone := parentZoneFromDomain(domain)
        if parentZone == "" {
                return nil
        }

        parentNSServers := a.DNS.QueryDNS(ctx, "NS", parentZone)
        if len(parentNSServers) == 0 {
                return nil
        }

        parentServer := strings.TrimRight(parentNSServers[0], ".")
        parentIPs := a.DNS.QueryDNS(ctx, "A", parentServer)
        if len(parentIPs) == 0 {
                return nil
        }

        delegation, err := a.DNS.QuerySpecificResolver(ctx, "NS", domain, parentIPs[0])
        if err != nil || len(delegation) == 0 {
                return nil
        }

        return normalizeNSList(delegation)
}

func nsDelegationResult(status, message string, childNS, parentNS []string, match any, delegationOK bool, extras map[string]any) map[string]any {
        if childNS == nil {
                childNS = []string{}
        }
        if parentNS == nil {
                parentNS = []string{}
        }
        result := map[string]any{
                "status":        status,
                "message":       message,
                "child_ns":      childNS,
                "parent_ns":     parentNS,
                "ns_count":      float64(len(childNS)),
                "nameservers":   childNS,
                "match":         match,
                "delegation_ok": delegationOK,
        }
        for k, v := range extras {
                result[k] = v
        }
        return result
}

func (a *Analyzer) handleNoChildNS(ctx context.Context, domain string) map[string]any {
        parentZone := findParentZone(a.DNS, ctx, domain)
        if parentZone == "" {
                return nsDelegationResult("error", "Could not retrieve NS records", nil, nil, false, false, nil)
        }

        var parentZoneNS []string
        pzResult := a.DNS.QueryDNS(ctx, "NS", parentZone)
        if len(pzResult) > 0 {
                parentZoneNS = normalizeNSList(pzResult)
        }
        return nsDelegationResult(mapKeySuccess,
                fmt.Sprintf("Subdomain within %s zone - no separate delegation needed", parentZone),
                nil, parentZoneNS, nil, true,
                map[string]any{"is_subdomain": true, "parent_zone": parentZone},
        )
}

var knownDNSProviders = map[string]string{
        "awsdns":            "Amazon Route 53",
        "cloudflare":        "Cloudflare",
        "ultradns":          "UltraDNS (Neustar/Vercara)",
        "dynect":            "Dyn (Oracle)",
        "azure-dns":         "Microsoft Azure DNS",
        "googledomains":     "Google Domains",
        "google":            "Google Cloud DNS",
        "domaincontrol":     "GoDaddy",
        "registrar-servers": "Namecheap",
        "nsone":             "NS1 (IBM)",
        "akamai":            "Akamai",
        "akam.net":          "Akamai",
        "dnsmadeeasy":       "DNS Made Easy",
}

func classifyNSProvider(ns string) string {
        lower := strings.ToLower(ns)
        for pattern, provider := range knownDNSProviders {
                if strings.Contains(lower, pattern) {
                        return provider
                }
        }
        return ""
}

var knownMultiLabelTLDs = map[string]bool{
        "co.uk": true, "org.uk": true, "gov.uk": true, "ac.uk": true, "me.uk": true,
        "com.au": true, "org.au": true, "gov.au": true, "edu.au": true, "net.au": true,
        "co.nz": true, "org.nz": true, "govt.nz": true, "net.nz": true,
        "co.jp": true, "or.jp": true, "go.jp": true, "ne.jp": true, "ac.jp": true,
        "co.kr": true, "or.kr": true, "go.kr": true,
        "com.br": true, "org.br": true, "gov.br": true, "net.br": true,
        "com.cn": true, "org.cn": true, "gov.cn": true, "net.cn": true,
        "co.in": true, "org.in": true, "gov.in": true, "net.in": true,
        "co.za": true, "org.za": true, "gov.za": true, "net.za": true,
        "com.mx": true, "org.mx": true, "gob.mx": true,
        "co.il": true, "org.il": true, "gov.il": true,
        "com.sg": true, "org.sg": true, "gov.sg": true,
        "com.hk": true, "org.hk": true, "gov.hk": true,
        "com.tw": true, "org.tw": true, "gov.tw": true,
        "co.id": true, "or.id": true, "go.id": true,
        "com.ar": true, "org.ar": true, "gov.ar": true,
}

func registrableDomain(domain string) string {
        parts := strings.Split(strings.ToLower(domain), ".")
        if len(parts) < 2 {
                return ""
        }
        if len(parts) >= 3 {
                twoLabel := strings.Join(parts[len(parts)-2:], ".")
                if knownMultiLabelTLDs[twoLabel] {
                        return strings.Join(parts[len(parts)-3:], ".")
                }
        }
        return strings.Join(parts[len(parts)-2:], ".")
}

type nsClassification struct {
        dedicated   int
        managed     int
        providers   map[string]int
        dedicatedNS []string
        managedNS   []string
}

func classifyNameservers(nameservers []string, domainBase string) nsClassification {
        c := nsClassification{providers: map[string]int{}}
        for _, ns := range nameservers {
                provider := classifyNSProvider(ns)
                if provider != "" {
                        c.managed++
                        c.providers[provider]++
                        c.managedNS = append(c.managedNS, ns)
                } else if domainBase != "" && strings.HasSuffix(strings.ToLower(ns), "."+domainBase) {
                        c.dedicated++
                        c.dedicatedNS = append(c.dedicatedNS, ns)
                } else {
                        c.managed++
                        c.managedNS = append(c.managedNS, ns)
                }
        }
        return c
}

func determineEnterprisePattern(c nsClassification, total int, domainBase string) map[string]any {
        result := map[string]any{}
        if c.dedicated > 0 && c.managed > 0 {
                result[mapKeyEnterprisePattern] = "mixed"
                result[mapKeyEnterpriseLabel] = "Enterprise DNS (Mixed Configuration)"
                result[mapKeyEnterpriseDetail] = fmt.Sprintf(
                        "%d of %d nameservers are dedicated (%s-branded), %d use external provider(s). "+
                                "This pattern is common in large organizations using split-horizon DNS or "+
                                "maintaining redundancy across internal and external infrastructure.",
                        c.dedicated, total, domainBase, c.managed)
                result["dedicated_ns"] = c.dedicatedNS
                result["managed_ns"] = c.managedNS
                return result
        }
        if c.dedicated == total {
                result[mapKeyEnterprisePattern] = "dedicated"
                result[mapKeyEnterpriseLabel] = "Enterprise DNS (Dedicated Infrastructure)"
                result[mapKeyEnterpriseDetail] = fmt.Sprintf(
                        "All %d nameservers are %s-branded, indicating organization-operated DNS infrastructure. "+
                                "This is typical of large enterprises, government agencies, and organizations "+
                                "that maintain full control of their DNS resolution chain.",
                        total, domainBase)
                return result
        }
        if len(c.providers) > 1 {
                providerNames := sortedProviderNames(c.providers)
                result[mapKeyEnterprisePattern] = "multi-provider"
                result[mapKeyEnterpriseLabel] = "Enterprise DNS (Multi-Provider Redundancy)"
                result[mapKeyEnterpriseDetail] = fmt.Sprintf(
                        "Nameservers span %d providers (%s). Multi-provider DNS provides resilience "+
                                "against single-provider outages — an enterprise best practice for critical domains.",
                        len(c.providers), strings.Join(providerNames, ", "))
                return result
        }
        if len(c.providers) == 1 {
                for p := range c.providers {
                        result[mapKeyEnterprisePattern] = "managed"
                        result[mapKeyEnterpriseLabel] = "Managed DNS"
                        result[mapKeyEnterpriseDetail] = fmt.Sprintf(
                                "All %d nameservers hosted by %s. Managed DNS provides reliable "+
                                        "resolution with provider-maintained infrastructure.",
                                total, p)
                }
        }
        return result
}

func sortedProviderNames(providers map[string]int) []string {
        names := make([]string, 0, len(providers))
        for p := range providers {
                names = append(names, p)
        }
        sort.Strings(names)
        return names
}

func classifyEnterpriseDNS(domain string, nameservers []string) map[string]any {
        if len(nameservers) == 0 {
                return nil
        }

        domainBase := registrableDomain(domain)
        c := classifyNameservers(nameservers, domainBase)
        result := determineEnterprisePattern(c, len(nameservers), domainBase)

        if len(c.providers) > 0 {
                providerList := sortedProviderNames(c.providers)
                result["dns_providers"] = providerList
        }

        return result
}

func (a *Analyzer) AnalyzeNSDelegation(ctx context.Context, domain string) map[string]any {
        childNS := a.queryChildNS(ctx, domain)
        parentNS := a.queryParentNS(ctx, domain)

        if len(childNS) == 0 {
                return a.handleNoChildNS(ctx, domain)
        }

        enterprise := classifyEnterpriseDNS(domain, childNS)

        if len(parentNS) == 0 {
                extras := map[string]any{"note": "Parent zone delegation could not be verified"}
                for k, v := range enterprise {
                        extras[k] = v
                }
                return nsDelegationResult(mapKeySuccess,
                        fmt.Sprintf("%d nameserver(s) configured", len(childNS)),
                        childNS, nil, nil, true,
                        extras,
                )
        }

        if stringSetEqual(childNS, parentNS) {
                return nsDelegationResult(mapKeySuccess,
                        fmt.Sprintf("NS delegation verified - %d nameserver(s) match parent zone", len(childNS)),
                        childNS, parentNS, true, true, enterprise,
                )
        }

        extras := map[string]any{"note": "This may indicate a recent change still propagating"}
        for k, v := range enterprise {
                extras[k] = v
        }
        return nsDelegationResult("warning",
                "NS delegation mismatch - child and parent zone have different NS records",
                childNS, parentNS, false, false,
                extras,
        )
}

func stringSetEqual(a, b []string) bool {
        if len(a) != len(b) {
                return false
        }
        set := make(map[string]bool, len(a))
        for _, s := range a {
                set[s] = true
        }
        for _, s := range b {
                if !set[s] {
                        return false
                }
        }
        return true
}
