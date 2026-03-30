// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// saas_txt.go — Framework: types, constants, commodity patterns. Always compiled.
// The intel build (_intel.go) adds proprietary/rare patterns on top of these.
// dns-tool:scrutiny science
package analyzer

import (
	"fmt"
	"regexp"
	"strings"
)

type saasPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

// commoditySaaSPatterns — well-known SaaS TXT verification patterns.
// These are public knowledge with no competitive advantage in keeping private.
// The intel build adds deeper/rarer patterns via saasPatterns in _intel.go.
var commoditySaaSPatterns = []saasPattern{
	{Name: "Google Workspace", Pattern: regexp.MustCompile(`^google-site-verification=`)},
	{Name: "Microsoft 365", Pattern: regexp.MustCompile(`^MS=`)},
	{Name: "Facebook / Meta", Pattern: regexp.MustCompile(`^facebook-domain-verification=`)},
	{Name: "Apple", Pattern: regexp.MustCompile(`^apple-domain-verification=`)},
	{Name: "DocuSign", Pattern: regexp.MustCompile(`(?i)^docusign=`)},
	{Name: "Atlassian", Pattern: regexp.MustCompile(`^atlassian-domain-verification=`)},
	{Name: "Slack", Pattern: regexp.MustCompile(`^slack-domain-verification=`)},
	{Name: "Zoom", Pattern: regexp.MustCompile(`^zoom-verification=`)},
	{Name: "GitHub", Pattern: regexp.MustCompile(`^_github-challenge-`)},
	{Name: "Adobe", Pattern: regexp.MustCompile(`^adobe-idp-site-verification=`)},
	{Name: "HubSpot", Pattern: regexp.MustCompile(`^hubspot-developer-verification=`)},
	{Name: "Dropbox", Pattern: regexp.MustCompile(`^dropbox-domain-verification=`)},
	{Name: "Zendesk", Pattern: regexp.MustCompile(`^zendeskverification=`)},
	{Name: "Webex", Pattern: regexp.MustCompile(`^webexdomainverification`)},
	{Name: "Citrix", Pattern: regexp.MustCompile(`^citrix-verification-code=`)},
	{Name: "Twilio / SendGrid", Pattern: regexp.MustCompile(`^sendgrid-verification=`)},
	{Name: "Mailchimp", Pattern: regexp.MustCompile(`^mailchimp-domain-verification=`)},
	{Name: "Salesforce", Pattern: regexp.MustCompile(`^salesforce-domainkey=`)},
	{Name: "Stripe", Pattern: regexp.MustCompile(`^stripe-verification=`)},
	{Name: "Pinterest", Pattern: regexp.MustCompile(`^pinterest-site-verification=`)},
	{Name: "Yandex", Pattern: regexp.MustCompile(`^yandex-verification:`)},
	{Name: "Brave", Pattern: regexp.MustCompile(`^brave-ledger-verification=`)},
	{Name: "Sophos", Pattern: regexp.MustCompile(`^sophos-domain-verification=`)},
	{Name: "Miro", Pattern: regexp.MustCompile(`^miro-verification=`)},
	{Name: "1Password", Pattern: regexp.MustCompile(`^1password-site-verification=`)},
	{Name: "Canva", Pattern: regexp.MustCompile(`^canva-site-verification=`)},
	{Name: "Notion", Pattern: regexp.MustCompile(`^notion-domain-verification=`)},
	{Name: "Linear", Pattern: regexp.MustCompile(`^linear-domain-verification=`)},
	{Name: "Loom", Pattern: regexp.MustCompile(`^loom-site-verification=`)},
	{Name: "Cisco Umbrella", Pattern: regexp.MustCompile(`^cisco-ci-domain-verification=`)},
	{Name: "MongoDB Atlas", Pattern: regexp.MustCompile(`^mongodb-site-verification=`)},
	{Name: "Dynatrace", Pattern: regexp.MustCompile(`^dynatrace-site-verification=`)},
	{Name: "Amazon SES", Pattern: regexp.MustCompile(`^amazonses:`)},
	{Name: "Postmark", Pattern: regexp.MustCompile(`^postmark-domain-verification=`)},
	{Name: "Statuspage", Pattern: regexp.MustCompile(`^statuspage-domain-verification=`)},
	{Name: "Knowbe4", Pattern: regexp.MustCompile(`^knowbe4-site-verification=`)},
	{Name: "Cloudflare", Pattern: regexp.MustCompile(`^cloudflare-domain-verification=`)},
}

func truncateRecord(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// extractSaaSTXTFromRecords scans TXT records against a pattern list.
// Used by both OSS (commodity only) and intel (commodity + proprietary) builds.
func extractSaaSTXTFromRecords(txtRecords []any, patterns []saasPattern) map[string]any {
	seen := make(map[string]bool)
	var services []map[string]any

	for _, rec := range txtRecords {
		txt, ok := rec.(string)
		if !ok {
			continue
		}
		txt = strings.TrimSpace(txt)
		for _, p := range patterns {
			if p.Pattern.MatchString(txt) && !seen[p.Name] {
				seen[p.Name] = true
				services = append(services, map[string]any{
					"name":   p.Name,
					"record": truncateRecord(txt, 80),
				})
			}
		}
	}

	count := len(services)
	msg := "No SaaS services detected"
	if count > 0 {
		msg = fmt.Sprintf("%d SaaS service%s detected via DNS TXT verification records", count, pluralS(count))
	}

	if services == nil {
		services = []map[string]any{}
	}

	return map[string]any{
		"status":        "success",
		"services":      services,
		"service_count": count,
		"issues":        []string{},
		"message":       msg,
	}
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
