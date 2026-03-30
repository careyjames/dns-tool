// Copyright (c) 2024-2026 IT Help San Diego Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL — See LICENSE for terms.
// This file is part of the DNS Tool Intelligence Module.
package analyzer

import (
        "strings"
)

var cdnASNs = map[string]string{
        "13335":  "Cloudflare",
        "209242": "Cloudflare",
        "19551":  "Incapsula/Imperva",
        "20940":  "Akamai",
        "16625":  "Akamai",
        "12222":  "Akamai",
        "54113":  "Fastly",
        "62785":  "Fastly",
        "2635":   "Automattic/WordPress.com",
        "13238":  "Yandex",
        "47541":  "Vk.com",
        "60068":  "CDN77",
        "30148":  "Sucuri",
        "394536": "Sucuri",
        "209101": "Sucuri",
}

var cloudASNs = map[string]string{
        "16509":  "AWS",
        "14618":  "AWS",
        "8075":   "Microsoft Azure",
        "15169":  "Google Cloud",
        "396982": "Google Cloud",
        "14061":  "DigitalOcean",
}

var cloudCDNPTRPatterns = map[string]string{
        "cloudfront.net":    "AWS CloudFront",
        "awsglobalaccelerator.com": "AWS Global Accelerator",
}

var cdnCNAMEPatterns = map[string]string{
        "cloudflare":        "Cloudflare",
        "cloudfront.net":    "AWS CloudFront",
        "akamaiedge.net":    "Akamai",
        "akamai.net":        "Akamai",
        "edgekey.net":       "Akamai",
        "fastly.net":        "Fastly",
        "global.fastly.net": "Fastly",
        "azureedge.net":     "Azure CDN",
        "azurefd.net":       "Azure Front Door",
        "edgecastcdn.net":   "Edgecast/Verizon",
        "stackpathdns.com":  "StackPath",
        "stackpathcdn.com":  "StackPath",
        "cdn77.org":         "CDN77",
        "incapdns.net":      "Imperva/Incapsula",
        "sucuri.net":        "Sucuri WAF",
        "netlify.app":       "Netlify CDN",
        "vercel-dns.com":    "Vercel",
        "dualstack.":        "AWS ELB/CloudFront",
        "elb.amazonaws.com": "AWS ELB",
        "ghproxy":           "GitHub CDN",
}

func DetectEdgeCDN(results map[string]any) map[string]any {
        result := map[string]any{
                "status":         "success",
                "is_behind_cdn":  false,
                "cdn_provider":   "",
                "cdn_indicators": []string{},
                "origin_visible": true,
                "issues":         []string{},
        }

        var indicators []string
        var cdnProvider string

        cdnProvider, indicators = checkASNForCDN(results, indicators)
        if cdnProvider == "" {
                cdnProvider, indicators = checkCNAMEForCDN(results, indicators)
        }

        if cdnProvider != "" {
                result["is_behind_cdn"] = true
                result["cdn_provider"] = cdnProvider
                result["origin_visible"] = false
                result["cdn_indicators"] = indicators
                result["message"] = "Domain is behind " + cdnProvider + " edge network"
                result["confidence"] = ConfidenceInferredMap(MethodASNMatch)
        } else {
                result["message"] = "Domain appears to use direct origin hosting"
                result["origin_visible"] = true
        }

        return result
}

func checkASNForCDN(results map[string]any, indicators []string) (string, []string) {
        asnData, _ := results["asn_info"].(map[string]any)
        if asnData == nil {
                return "", indicators
        }

        provider, indicators := matchASNEntries(asnData, "ipv4_asn", indicators)
        if provider != "" {
                return provider, indicators
        }
        return matchASNEntries(asnData, "ipv6_asn", indicators)
}

func matchASNEntries(asnData map[string]any, key string, indicators []string) (string, []string) {
        entries, _ := asnData[key].([]map[string]any)
        for _, entry := range entries {
                asn, _ := entry["asn"].(string)
                if cdn, ok := cdnASNs[asn]; ok {
                        indicators = append(indicators, "ASN "+asn+" belongs to "+cdn)
                        return cdn, indicators
                }
                if cloud, ok := cloudASNs[asn]; ok {
                        indicators = append(indicators, "ASN "+asn+" belongs to "+cloud+" (cloud infrastructure)")
                        return cloud, indicators
                }
        }
        return "", indicators
}

func checkCNAMEForCDN(results map[string]any, indicators []string) (string, []string) {
        basicRecords, _ := results["basic_records"].(map[string]any)
        if basicRecords == nil {
                return "", indicators
        }

        cnameRecords, _ := basicRecords["CNAME"].([]string)
        for _, cname := range cnameRecords {
                cnameLower := strings.ToLower(cname)
                for pattern, provider := range cdnCNAMEPatterns {
                        if strings.Contains(cnameLower, pattern) {
                                indicators = append(indicators, "CNAME contains "+pattern)
                                return provider, indicators
                        }
                }
        }

        return "", indicators
}

func classifyCloudIP(asn string, ptrRecords []string) (provider string, isCDN bool) {
        cloud, ok := cloudASNs[asn]
        if !ok {
                return "", false
        }

        for _, ptr := range ptrRecords {
                ptrLower := strings.ToLower(ptr)
                for pattern, cdnName := range cloudCDNPTRPatterns {
                        if strings.Contains(ptrLower, pattern) {
                                return cdnName, true
                        }
                }
        }

        return cloud, false
}
