// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	mapKeyExpired    = "expired"
	mapKeyExpires    = "expires"
	mapKeyFetchError = "fetch_error"
	mapKeyLanguages  = "languages"
)

var (
	secTxtContactRe = regexp.MustCompile(`(?i)^Contact:\s*(.+)$`)
	secTxtExpiresRe = regexp.MustCompile(`(?i)^Expires:\s*(.+)$`)
	secTxtEncryptRe = regexp.MustCompile(`(?i)^Encryption:\s*(.+)$`)
	secTxtPolicyRe  = regexp.MustCompile(`(?i)^Policy:\s*(.+)$`)
	secTxtAckRe     = regexp.MustCompile(`(?i)^Acknowledgments:\s*(.+)$`)
	secTxtHiringRe  = regexp.MustCompile(`(?i)^Hiring:\s*(.+)$`)
	secTxtCanonRe   = regexp.MustCompile(`(?i)^Canonical:\s*(.+)$`)
	secTxtLangRe    = regexp.MustCompile(`(?i)^Preferred-Languages:\s*(.+)$`)
)

type securityTxtFields struct {
	contacts  []string
	expires   string
	encrypt   []string
	policy    []string
	ack       []string
	hiring    []string
	canonical []string
	languages string
	signed    bool
}

func parseSecurityTxt(body string) securityTxtFields {
	var f securityTxtFields
	if strings.Contains(body, "-----BEGIN PGP SIGNED MESSAGE-----") {
		f.signed = true
	}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parseSecurityTxtLine(line, &f)
	}
	return f
}

func parseSecurityTxtLine(line string, f *securityTxtFields) {
	if m := secTxtContactRe.FindStringSubmatch(line); m != nil {
		f.contacts = append(f.contacts, strings.TrimSpace(m[1]))
	} else if m := secTxtExpiresRe.FindStringSubmatch(line); m != nil {
		f.expires = strings.TrimSpace(m[1])
	} else if m := secTxtEncryptRe.FindStringSubmatch(line); m != nil {
		f.encrypt = append(f.encrypt, strings.TrimSpace(m[1]))
	} else if m := secTxtPolicyRe.FindStringSubmatch(line); m != nil {
		f.policy = append(f.policy, strings.TrimSpace(m[1]))
	} else if m := secTxtAckRe.FindStringSubmatch(line); m != nil {
		f.ack = append(f.ack, strings.TrimSpace(m[1]))
	} else if m := secTxtHiringRe.FindStringSubmatch(line); m != nil {
		f.hiring = append(f.hiring, strings.TrimSpace(m[1]))
	} else if m := secTxtCanonRe.FindStringSubmatch(line); m != nil {
		f.canonical = append(f.canonical, strings.TrimSpace(m[1]))
	} else if m := secTxtLangRe.FindStringSubmatch(line); m != nil {
		f.languages = strings.TrimSpace(m[1])
	}
}

func evaluateSecurityTxtExpiry(expiresStr string) (bool, string) {
	if expiresStr == "" {
		return false, ""
	}
	t, err := time.Parse(time.RFC3339, expiresStr)
	if err != nil {
		t2, err2 := time.Parse("2006-01-02T15:04:05Z", expiresStr)
		if err2 != nil {
			return false, "unparseable"
		}
		t = t2
	}
	if time.Now().After(t) {
		return true, t.Format("2006-01-02")
	}
	return false, t.Format("2006-01-02")
}

func determineSecurityTxtStatus(fields securityTxtFields) (string, string, []string) {
	var issues []string

	if len(fields.contacts) == 0 {
		issues = append(issues, "Missing required Contact field (RFC 9116 §2.5.3)")
	}
	if fields.expires == "" {
		issues = append(issues, "Missing required Expires field (RFC 9116 §2.5.5)")
	}

	expired, expiryDate := evaluateSecurityTxtExpiry(fields.expires)
	if expired {
		issues = append(issues, fmt.Sprintf("File expired on %s (RFC 9116 §2.5.5)", expiryDate))
	}

	if len(issues) > 0 && len(fields.contacts) == 0 {
		return mapKeyWarning, "security.txt found but missing required fields", issues
	}
	if expired {
		return mapKeyWarning, "security.txt found but expired", issues
	}
	if len(issues) > 0 {
		return mapKeyWarning, "security.txt found with issues", issues
	}
	return "success", "security.txt properly configured", issues
}

func (a *Analyzer) AnalyzeSecurityTxt(ctx context.Context, domain string) map[string]any {
	baseResult := map[string]any{
		"status":         "info",
		mapKeyMessage:    "No security.txt found",
		"found":          false,
		"url":            nil,
		"contacts":       []string{},
		mapKeyExpires:    nil,
		mapKeyExpired:    false,
		"encryption":     []string{},
		"policy":         []string{},
		"ack":            []string{},
		"hiring":         []string{},
		"canonical":      []string{},
		mapKeyLanguages:  nil,
		"signed":         false,
		"issues":         []string{},
		mapKeyFetchError: nil,
	}

	wellKnownURL := fmt.Sprintf("https://%s/.well-known/security.txt", domain)
	rootURL := fmt.Sprintf("https://%s/security.txt", domain)

	body, fetchURL, fetchErr := a.tryFetchSecurityTxt(ctx, wellKnownURL, rootURL)
	if fetchErr != nil {
		baseResult[mapKeyFetchError] = classifyHTTPError(fetchErr, 80)
		baseResult[mapKeyMessage] = "Could not fetch security.txt"
		return baseResult
	}
	if body == "" {
		return baseResult
	}

	fields := parseSecurityTxt(body)
	status, message, issues := determineSecurityTxtStatus(fields)

	expired, expiryDate := evaluateSecurityTxtExpiry(fields.expires)

	result := map[string]any{
		"status":         status,
		mapKeyMessage:    message,
		"found":          true,
		"url":            fetchURL,
		"contacts":       fields.contacts,
		"encryption":     fields.encrypt,
		"policy":         fields.policy,
		"ack":            fields.ack,
		"hiring":         fields.hiring,
		"canonical":      fields.canonical,
		"signed":         fields.signed,
		"issues":         issues,
		mapKeyFetchError: nil,
	}

	if fields.expires != "" {
		result[mapKeyExpires] = expiryDate
		result[mapKeyExpired] = expired
	} else {
		result[mapKeyExpires] = nil
		result[mapKeyExpired] = false
	}

	if fields.languages != "" {
		result[mapKeyLanguages] = fields.languages
	} else {
		result[mapKeyLanguages] = nil
	}

	return result
}

func (a *Analyzer) tryFetchSecurityTxt(ctx context.Context, wellKnownURL, rootURL string) (string, string, error) {
	body, err := a.fetchSecurityTxtURL(ctx, wellKnownURL)
	if err == nil && body != "" {
		return body, wellKnownURL, nil
	}

	body, err2 := a.fetchSecurityTxtURL(ctx, rootURL)
	if err2 == nil && body != "" {
		return body, rootURL, nil
	}

	if err != nil {
		return "", "", err
	}
	return "", "", nil
}

func (a *Analyzer) fetchSecurityTxtURL(ctx context.Context, url string) (string, error) {
	resp, err := a.HTTP.Get(ctx, url)
	if err != nil {
		return "", err
	}

	body, err := a.HTTP.ReadBody(resp, 1<<20)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", nil
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(strings.ToLower(ct), "text/plain") && !strings.Contains(strings.ToLower(ct), "text/") {
		return "", nil
	}

	return string(body), nil
}
