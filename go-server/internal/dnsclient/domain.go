// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package dnsclient

import (
	"context"
	"regexp"
	"strings"

	"golang.org/x/net/idna"
)

var (
	labelRegex = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)
	tldRegex   = regexp.MustCompile(`^[a-zA-Z]{2,}$`)
)

func DomainToASCII(domain string) (string, error) {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimRight(domain, ".")

	p := idna.New(idna.MapForLookup(), idna.Transitional(false))
	ascii, err := p.ToASCII(domain)
	if err != nil {
		if regexp.MustCompile(`^[a-zA-Z0-9.-]+$`).MatchString(domain) {
			labels := strings.Split(domain, ".")
			for _, label := range labels {
				if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
					return "", err
				}
			}
			return domain, nil
		}
		return "", err
	}
	return ascii, nil
}

const maxLabelDepth = 10

func ValidateDomain(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}

	domain = strings.TrimSpace(domain)
	domain = strings.TrimLeft(domain, ".")
	domain = strings.TrimRight(domain, ".")
	if domain == "" {
		return false
	}

	ascii, err := DomainToASCII(domain)
	if err != nil {
		return false
	}

	if strings.Contains(ascii, "..") || strings.HasPrefix(ascii, ".") || strings.HasPrefix(ascii, "-") {
		return false
	}

	labels := strings.Split(ascii, ".")

	if len(labels) == 1 {
		return validateTLD(labels[0])
	}

	if len(labels) > maxLabelDepth {
		return false
	}

	if !validateLabels(labels) {
		return false
	}

	return validateTLD(labels[len(labels)-1])
}

func IsTLDInput(domain string) bool {
	d := strings.TrimSpace(domain)
	d = strings.TrimLeft(d, ".")
	d = strings.TrimRight(d, ".")
	if d == "" {
		return false
	}
	return !strings.Contains(d, ".") && validateTLD(d)
}

func validateLabels(labels []string) bool {
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		if !labelRegex.MatchString(label) {
			return false
		}
	}
	return true
}

func validateTLD(tld string) bool {
	return tldRegex.MatchString(tld) || strings.HasPrefix(tld, "xn--")
}

func GetTLD(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return ""
	}
	return strings.ToLower(parts[len(parts)-1])
}

func FindParentZone(c *Client, ctx context.Context, domain string) string {
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		candidate := strings.Join(parts[i:], ".")
		results := c.QueryDNS(ctx, "NS", candidate)
		if len(results) > 0 {
			return candidate
		}
	}
	return ""
}
