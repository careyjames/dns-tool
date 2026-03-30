// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"strings"
)

const (
	mapKeyCnameTarget = "cname_target"
	mapKeyConfidence  = "confidence"
	mapKeyIssues      = "issues"
	mapKeyReason      = "reason"
	mapKeyService     = "service"
	mapKeySubdomain   = "subdomain"
	mapKeyRisk        = "risk"
)

var takeoverFingerprints = map[string]string{
	".s3.amazonaws.com":     "AWS S3",
	".s3-website":           "AWS S3",
	".herokuapp.com":        "Heroku",
	".herokudns.com":        "Heroku",
	".github.io":            "GitHub Pages",
	".azurewebsites.net":    "Azure App Service",
	".cloudapp.azure.com":   "Azure Cloud",
	".trafficmanager.net":   "Azure Traffic Manager",
	".azure-api.net":        "Azure API Management",
	".azurefd.net":          "Azure Front Door",
	".netlify.app":          "Netlify",
	".netlify.com":          "Netlify",
	".firebaseapp.com":      "Firebase",
	".web.app":              "Firebase",
	".fly.dev":              "Fly.io",
	".ghost.io":             "Ghost",
	".myshopify.com":        "Shopify",
	".shopifypreview.com":   "Shopify",
	".pantheonsite.io":      "Pantheon",
	".surge.sh":             "Surge.sh",
	".bitbucket.io":         "Bitbucket",
	".zendesk.com":          "Zendesk",
	".teamwork.com":         "Teamwork",
	".helpjuice.com":        "HelpJuice",
	".helpscoutdocs.com":    "HelpScout",
	".cargo.site":           "Cargo",
	".statuspage.io":        "Statuspage",
	".tumblr.com":           "Tumblr",
	".wordpress.com":        "WordPress.com",
	".smugmug.com":          "SmugMug",
	".strikingly.com":       "Strikingly",
	".webflow.io":           "Webflow",
	".squarespace.com":      "Squarespace",
	".unbounce.com":         "Unbounce",
	".landingi.com":         "Landingi",
	".cloudfront.net":       "AWS CloudFront",
	".elasticbeanstalk.com": "AWS Elastic Beanstalk",
	".appspot.com":          "Google App Engine",
	".readthedocs.io":       "ReadTheDocs",
}

func (a *Analyzer) DetectDanglingDNS(ctx context.Context, domain string, subdomains []map[string]any) map[string]any {
	result := map[string]any{
		"status":           "success",
		"checked":          true,
		"dangling_count":   0,
		"dangling_records": []map[string]any{},
		mapKeyIssues:       []string{},
	}

	var danglingRecords []map[string]any

	for _, sd := range subdomains {
		dr := checkSubdomainDangling(sd)
		if dr != nil {
			danglingRecords = append(danglingRecords, dr)
		}
	}

	danglingRecords = append(danglingRecords, a.checkBaseDomainDangling(ctx, domain)...)

	result["dangling_count"] = len(danglingRecords)
	result["dangling_records"] = danglingRecords

	if len(danglingRecords) > 0 {
		result["status"] = "warning"
		result["message"] = buildDanglingMessage(len(danglingRecords))
		var issues []string
		for _, dr := range danglingRecords {
			issues = append(issues, buildDanglingIssue(dr))
		}
		result[mapKeyIssues] = issues
	} else {
		result["message"] = "No dangling DNS records detected"
		result[mapKeyIssues] = []string{}
	}

	return result
}

func buildDanglingMessage(count int) string {
	if count == 1 {
		return "1 potential subdomain takeover risk detected"
	}
	return strings.Join([]string{itoa(count), " potential subdomain takeover risks detected"}, "")
}

func buildDanglingIssue(dr map[string]any) string {
	name, _ := dr[mapKeySubdomain].(string)
	target, _ := dr[mapKeyCnameTarget].(string)
	service, _ := dr[mapKeyService].(string)
	reason, _ := dr[mapKeyReason].(string)
	return strings.Join([]string{name, " → ", target, " (", service, ": ", reason, ")"}, "")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func checkSubdomainDangling(sd map[string]any) map[string]any {
	cname, _ := sd["cname"].(string)
	if cname == "" {
		return nil
	}

	hasDNS, _ := sd["has_dns"].(bool)
	subdomain, _ := sd[mapKeySubdomain].(string)
	cnameLower := strings.ToLower(strings.TrimRight(cname, "."))

	if !hasDNS {
		service := matchTakeoverService(cnameLower)
		if service != "" {
			return map[string]any{
				mapKeySubdomain:   subdomain,
				mapKeyCnameTarget: cnameLower,
				mapKeyService:     service,
				mapKeyReason:      "CNAME points to unclaimed service",
				mapKeyRisk:        "high",
				mapKeyConfidence:  ConfidenceObservedMap(MethodDNSRecord),
			}
		}
		return map[string]any{
			mapKeySubdomain:   subdomain,
			mapKeyCnameTarget: cnameLower,
			mapKeyService:     "Unknown",
			mapKeyReason:      "CNAME target has no DNS resolution (potential NXDOMAIN)",
			mapKeyRisk:        "medium",
			mapKeyConfidence:  ConfidenceObservedMap(MethodDNSRecord),
		}
	}

	return nil
}

func (a *Analyzer) checkBaseDomainDangling(ctx context.Context, domain string) []map[string]any {
	cnames := a.DNS.QueryDNS(ctx, "CNAME", domain)
	if len(cnames) == 0 {
		return nil
	}

	var results []map[string]any
	for _, cname := range cnames {
		cnameLower := strings.ToLower(strings.TrimRight(cname, "."))
		aRecs := a.DNS.QueryDNS(ctx, "A", cnameLower)
		if len(aRecs) == 0 {
			service := matchTakeoverService(cnameLower)
			if service == "" {
				service = "Unknown"
			}
			results = append(results, map[string]any{
				mapKeySubdomain:   domain,
				mapKeyCnameTarget: cnameLower,
				mapKeyService:     service,
				mapKeyReason:      "Base domain CNAME target unresolvable",
				mapKeyRisk:        "critical",
				mapKeyConfidence:  ConfidenceObservedMap(MethodDNSRecord),
			})
		}
	}
	return results
}

func matchTakeoverService(cname string) string {
	for suffix, service := range takeoverFingerprints {
		if strings.HasSuffix(cname, suffix) || strings.Contains(cname, suffix+".") {
			return service
		}
	}
	return ""
}
