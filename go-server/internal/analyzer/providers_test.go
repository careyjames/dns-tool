package analyzer

import (
        "testing"
)

func TestIsHostedEmailProvider_VariousInputs(t *testing.T) {
        inputs := []string{
                "google.com",
                "microsoft.com",
                "protonmail.com",
                "",
                "unknown.example.com",
        }
        for _, input := range inputs {
                result := isHostedEmailProvider(input)
                if !result {
                        t.Errorf("isHostedEmailProvider(%q) = false, OSS always returns true", input)
                }
        }
}

func TestIsBIMICapableProvider_AlwaysFalseOSS(t *testing.T) {
        inputs := []string{
                "google.com",
                "microsoft.com",
                "",
                "bimi.example.com",
        }
        for _, input := range inputs {
                if isBIMICapableProvider(input) {
                        t.Errorf("isBIMICapableProvider(%q) = true, OSS should return false", input)
                }
        }
}

func TestIsKnownDKIMProvider_AlwaysFalseOSS(t *testing.T) {
        inputs := []interface{}{
                "selector1-example-com._domainkey.example.onmicrosoft.com",
                "google._domainkey.example.com",
                "",
                nil,
                42,
        }
        for _, input := range inputs {
                if isKnownDKIMProvider(input) {
                        t.Errorf("isKnownDKIMProvider(%v) = true, OSS should return false", input)
                }
        }
}

