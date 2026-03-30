//go:build !intel

package analyzer

import (
        "testing"
)

func TestIsHostedEmailProvider_OSSAlwaysTrue(t *testing.T) {
        providers := []string{
                "google.com",
                "outlook.com",
                "yahoo.com",
                "fastmail.com",
                "",
        }
        for _, p := range providers {
                if !isHostedEmailProvider(p) {
                        t.Errorf("isHostedEmailProvider(%q) = false, OSS should return true", p)
                }
        }
}

func TestIsBIMICapableProvider_OSSVariants(t *testing.T) {
        providers := []string{"google.com", "yahoo.com", "fastmail.com", ""}
        for _, p := range providers {
                if isBIMICapableProvider(p) {
                        t.Errorf("isBIMICapableProvider(%q) = true, OSS should return false", p)
                }
        }
}

func TestIsKnownDKIMProvider_OSSVariants(t *testing.T) {
        values := []interface{}{
                "selector1._domainkey.example.com",
                42,
                nil,
                "",
        }
        for _, v := range values {
                if isKnownDKIMProvider(v) {
                        t.Errorf("isKnownDKIMProvider(%v) = true, OSS should return false", v)
                }
        }
}
