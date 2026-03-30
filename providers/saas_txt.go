// Copyright (c) 2024-2026 IT Help San Diego Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL — See LICENSE for terms.
// This file is part of the DNS Tool Intelligence Module.
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

var saasPatterns = []saasPattern{
	{Name: "Google Workspace", Pattern: regexp.MustCompile(`(?i)^google-site-verification=`)},
	{Name: "Microsoft 365", Pattern: regexp.MustCompile(`(?i)^MS=`)},
	{Name: "Facebook", Pattern: regexp.MustCompile(`(?i)^facebook-domain-verification=`)},
	{Name: "Adobe", Pattern: regexp.MustCompile(`(?i)^adobe-idp-site-verification=`)},
	{Name: "Adobe Sign", Pattern: regexp.MustCompile(`(?i)^adobe-sign-verification=`)},
	{Name: "DocuSign", Pattern: regexp.MustCompile(`(?i)^docusign=`)},
	{Name: "Atlassian", Pattern: regexp.MustCompile(`(?i)^atlassian-domain-verification=`)},
	{Name: "Salesforce", Pattern: regexp.MustCompile(`(?i)^salesforce-`)},
	{Name: "Hubspot", Pattern: regexp.MustCompile(`(?i)^hubspot-developer-verification=`)},
	{Name: "Stripe", Pattern: regexp.MustCompile(`(?i)^stripe-verification=`)},
	{Name: "Slack", Pattern: regexp.MustCompile(`(?i)^slack-domain-verification=`)},
	{Name: "Zoom", Pattern: regexp.MustCompile(`(?i)^ZOOM_verify_`)},
	{Name: "Webex", Pattern: regexp.MustCompile(`(?i)^webexdomainverification`)},
	{Name: "Cisco", Pattern: regexp.MustCompile(`(?i)^cisco-ci-domain-verification=`)},
	{Name: "Apple", Pattern: regexp.MustCompile(`(?i)^apple-domain-verification=`)},
	{Name: "Amazon SES", Pattern: regexp.MustCompile(`(?i)^amazonses:`)},
	{Name: "Postmark", Pattern: regexp.MustCompile(`(?i)^postmark-domain-verification=`)},
	{Name: "Mailgun", Pattern: regexp.MustCompile(`(?i)^mailgun-`)},
	{Name: "SendGrid", Pattern: regexp.MustCompile(`(?i)^sendgrid-`)},
	{Name: "Mimecast", Pattern: regexp.MustCompile(`(?i)^mimecast`)},
	{Name: "Proofpoint", Pattern: regexp.MustCompile(`(?i)^proofpoint-`)},
	{Name: "Globalsign", Pattern: regexp.MustCompile(`(?i)^globalsign-domain-verification=`)},
	{Name: "DigiCert", Pattern: regexp.MustCompile(`(?i)^_?digicert`)},
	{Name: "Sectigo", Pattern: regexp.MustCompile(`(?i)^sectigo-domain-verification=`)},
	{Name: "Let's Encrypt", Pattern: regexp.MustCompile(`(?i)^_acme-challenge`)},
	{Name: "Duo Security", Pattern: regexp.MustCompile(`(?i)^duo_sso_verification=`)},
	{Name: "Dropbox", Pattern: regexp.MustCompile(`(?i)^dropbox-domain-verification=`)},
	{Name: "Citrix", Pattern: regexp.MustCompile(`(?i)^citrix-verification-code=`)},
	{Name: "Statuspage", Pattern: regexp.MustCompile(`(?i)^status-page-domain-verification=`)},
	{Name: "Workplace", Pattern: regexp.MustCompile(`(?i)^workplace-domain-verification=`)},
	{Name: "Pinterest", Pattern: regexp.MustCompile(`(?i)^pinterest-site-verification=`)},
	{Name: "Yandex", Pattern: regexp.MustCompile(`(?i)^yandex-verification:`)},
	{Name: "Bing/Microsoft", Pattern: regexp.MustCompile(`(?i)^msvalidate\.01=`)},
	{Name: "Brave", Pattern: regexp.MustCompile(`(?i)^brave-ledger-verification=`)},
	{Name: "Have I Been Pwned", Pattern: regexp.MustCompile(`(?i)^have-i-been-pwned-verification=`)},
	{Name: "Keybase", Pattern: regexp.MustCompile(`(?i)^keybase-site-verification=`)},
	{Name: "Bluesky", Pattern: regexp.MustCompile(`(?i)^did=did:`)},
	{Name: "Fastly", Pattern: regexp.MustCompile(`(?i)^fastly-domain-delegation-`)},
	{Name: "Sophos", Pattern: regexp.MustCompile(`(?i)^sophos-domain-verification=`)},
	{Name: "1Password", Pattern: regexp.MustCompile(`(?i)^1password-site-verification=`)},
	{Name: "TeamViewer", Pattern: regexp.MustCompile(`(?i)^teamviewer-sso-verification=`)},
	{Name: "Okta", Pattern: regexp.MustCompile(`(?i)^okta-domain-verification=`)},
	{Name: "Notion", Pattern: regexp.MustCompile(`(?i)^notion-domain-verification=`)},
	{Name: "Canva", Pattern: regexp.MustCompile(`(?i)^canva-site-verification=`)},
	{Name: "Twilio", Pattern: regexp.MustCompile(`(?i)^twilio-domain-verification=`)},
	{Name: "MongoDB", Pattern: regexp.MustCompile(`(?i)^mongodb-site-verification=`)},
	{Name: "Dynatrace", Pattern: regexp.MustCompile(`(?i)^dynatrace-site-verification=`)},
	{Name: "Ahrefs", Pattern: regexp.MustCompile(`(?i)^ahrefs-site-verification_`)},
}

func ExtractSaaSTXTFootprint(results map[string]any) map[string]any {
	result := map[string]any{
		"status":          "success",
		"services":        []map[string]any{},
		"service_count":   0,
		"issues":          []string{},
	}

	basicRecords, _ := results["basic_records"].(map[string]any)
	if basicRecords == nil {
		result["message"] = "No TXT records available"
		return result
	}

	txtRecords, _ := basicRecords["TXT"].([]string)
	if len(txtRecords) == 0 {
		result["message"] = "No TXT records found"
		return result
	}

	seen := make(map[string]bool)
	var services []map[string]any

	for _, txt := range txtRecords {
		matchSaaSPatterns(txt, seen, &services)
	}

	result["services"] = services
	result["service_count"] = len(services)

	if len(services) > 0 {
		result["message"] = fmt.Sprintf("%d SaaS service(s) detected via TXT record verification", len(services))
	} else {
		result["message"] = "No SaaS verification records detected"
	}

	return result
}

func matchSaaSPatterns(txt string, seen map[string]bool, services *[]map[string]any) {
	trimmed := strings.TrimSpace(txt)
	for _, sp := range saasPatterns {
		if seen[sp.Name] {
			continue
		}
		if sp.Pattern.MatchString(trimmed) {
			seen[sp.Name] = true
			*services = append(*services, map[string]any{
				"name":       sp.Name,
				"record":     truncateRecord(trimmed, 80),
				"confidence": ConfidenceObservedMap(MethodTXTPattern),
			})
		}
	}
}

func truncateRecord(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
