// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package dnsclient

import (
	"testing"
	"time"
)

func TestNewSafeHTTPClient(t *testing.T) {
	c := NewSafeHTTPClient()
	if c == nil {
		t.Fatal("NewSafeHTTPClient returned nil")
	}
	if c.client == nil {
		t.Fatal("client should not be nil")
	}
}

func TestNewSafeHTTPClientWithTimeout(t *testing.T) {
	c := NewSafeHTTPClientWithTimeout(30 * time.Second)
	if c == nil {
		t.Fatal("NewSafeHTTPClientWithTimeout returned nil")
	}
}

func TestValidateURLTarget_InvalidURL(t *testing.T) {
	if ValidateURLTarget("://invalid") {
		t.Error("expected false for invalid URL")
	}
}

func TestValidateURLTarget_EmptyHost(t *testing.T) {
	if ValidateURLTarget("https://") {
		t.Error("expected false for empty host")
	}
}

func TestValidateURLTarget_PrivateIP(t *testing.T) {
	if ValidateURLTarget("https://127.0.0.1/test") {
		t.Error("expected false for localhost")
	}
	if ValidateURLTarget("https://10.0.0.1/test") {
		t.Error("expected false for private IP 10.x")
	}
	if ValidateURLTarget("https://192.168.1.1/test") {
		t.Error("expected false for private IP 192.168.x")
	}
}

func TestIsRDAPAllowedHost_AllEntries(t *testing.T) {
	allowed := []string{
		"rdap.verisign.com",
		"rdap.publicinterestregistry.net",
		"rdap.nic.io",
		"rdap.nic.google",
		"rdap.nominet.uk",
		"rdap.eu",
		"rdap.sidn.nl",
		"rdap.auda.org.au",
		"rdap.centralnic.com",
		"rdap.nic.co",
		"rdap.nic.me",
		"rdap.nic.ai",
		"rdap.afilias.net",
		"rdap.nic.biz",
		"rdap.nic.mobi",
		"rdap.nic.pro",
		"rdap.nic.top",
		"rdap.org",
	}
	for _, h := range allowed {
		if !IsRDAPAllowedHost(h) {
			t.Errorf("expected %q to be allowed", h)
		}
	}
}
