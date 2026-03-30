// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Proprietary — All rights reserved.
// This file provides the real implementation of isKnownDKIMProvider.
// It overrides the stub in the public repo (providers.go).
package analyzer

import "strings"

var knownDKIMProviders = map[string]bool{
	"google":           true,
	"google workspace": true,
	"microsoft":        true,
	"microsoft 365":    true,
	"protonmail":       true,
	"zoho":             true,
	"zoho mail":        true,
	"fastmail":         true,
	"yahoo":            true,
	"mailgun":          true,
	"sendgrid":         true,
	"amazonses":        true,
	"amazon ses":       true,
	"postmark":         true,
	"sparkpost":        true,
	"mailchimp":        true,
	"mandrill":         true,
	"sendinblue":       true,
	"brevo":            true,
	"constantcontact":  true,
	"mimecast":         true,
	"proofpoint":       true,
	"barracuda":        true,
	"cloudflare email": true,
	"hornetsecurity":   true,
}

func isKnownDKIMProvider(provider interface{}) bool {
	s, ok := provider.(string)
	if !ok || s == "" || s == "Unknown" {
		return false
	}
	return knownDKIMProviders[strings.ToLower(s)]
}
