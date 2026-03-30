// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Proprietary — All rights reserved.
// Real implementations of isHostedEmailProvider and isBIMICapableProvider.
// These override the stubs in the public repo (providers.go).
package analyzer

import "strings"

var hostedEmailProviders = map[string]bool{
	"google workspace":    true,
	"microsoft 365":       true,
	"zoho mail":           true,
	"fastmail":            true,
	"protonmail":          true,
	"yahoo mail":          true,
	"amazon ses":          true,
	"amazon workmail":     true,
	"rackspace email":     true,
	"godaddy email":       true,
	"namecheap email":     true,
	"ionos email":         true,
	"ovh email":           true,
	"hostinger email":     true,
	"bluehost email":      true,
	"dreamhost email":     true,
	"mimecast":            true,
	"barracuda":           true,
	"proofpoint":          true,
	"hornetsecurity":      true,
	"cloudflare email":    true,
	"forcepoint email":    true,
	"trend micro email":   true,
	"cisco email security": true,
}

var bimiCapableProviders = map[string]bool{
	"google workspace": true,
	"microsoft 365":    true,
	"yahoo mail":       true,
	"fastmail":         true,
	"apple mail":       true,
	"zoho mail":        true,
	"cloudflare email": true,
}

func isHostedEmailProvider(provider string) bool {
	if provider == "" {
		return false
	}
	return hostedEmailProviders[strings.ToLower(provider)]
}

func isBIMICapableProvider(provider string) bool {
	if provider == "" {
		return true
	}
	lower := strings.ToLower(provider)
	if bimiCapableProviders[lower] {
		return true
	}
	return false
}
