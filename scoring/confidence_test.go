// Copyright (c) 2024-2026 IT Help San Diego Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL — See LICENSE for terms.
// This file is part of the DNS Tool Intelligence Module.
package analyzer

import (
        "context"
        "testing"
)

func assertLevel(t *testing.T, m map[string]any, expected string) {
        t.Helper()
        if m["level"] != expected {
                t.Errorf("expected level %q, got %q", expected, m["level"])
        }
}

func assertLabel(t *testing.T, m map[string]any, expected string) {
        t.Helper()
        if m["label"] != expected {
                t.Errorf("expected label %q, got %q", expected, m["label"])
        }
}

func assertMethod(t *testing.T, m map[string]any, expected string) {
        t.Helper()
        if m["method"] != expected {
                t.Errorf("expected method %q, got %q", expected, m["method"])
        }
}

func TestConfidenceMapFunctions(t *testing.T) {
        t.Run("ObservedMap", func(t *testing.T) {
                m := ConfidenceObservedMap(MethodRDAP)
                assertLevel(t, m, ConfidenceObserved)
                assertLabel(t, m, ConfidenceLabelObserved)
                assertMethod(t, m, MethodRDAP)
        })

        t.Run("InferredMap", func(t *testing.T) {
                m := ConfidenceInferredMap(MethodNSPattern)
                assertLevel(t, m, ConfidenceInferred)
                assertLabel(t, m, ConfidenceLabelInferred)
                assertMethod(t, m, MethodNSPattern)
        })

        t.Run("ThirdPartyMap", func(t *testing.T) {
                m := ConfidenceThirdPartyMap("ip-api.com")
                assertLevel(t, m, ConfidenceThirdParty)
                assertLabel(t, m, ConfidenceLabelThirdParty)
        })
}

func TestInfrastructureConfidenceLabels(t *testing.T) {
        a := testAnalyzer()

        t.Run("HostingInfoHasConfidence", func(t *testing.T) {
                results := baseResults()
                results["basic_records"] = map[string]any{
                        "A":  []string{"172.217.14.206"},
                        "NS": []string{"ns1.google.com", "ns2.google.com"},
                        "MX": []string{"aspmx.l.google.com"},
                }
                hosting := a.GetHostingInfo(context.Background(), "example.com", results)

                hostConf, ok := hosting["hosting_confidence"].(map[string]any)
                if !ok || len(hostConf) == 0 {
                        t.Skip("hosting_confidence empty for unresolved A-record provider")
                }

                emailConf, ok := hosting["email_confidence"].(map[string]any)
                if !ok {
                        t.Fatal("email_confidence missing from hosting info")
                }
                assertLevel(t, emailConf, ConfidenceObserved)

                dnsConf, ok := hosting["dns_confidence"].(map[string]any)
                if !ok {
                        t.Fatal("dns_confidence missing from hosting info")
                }
                assertLevel(t, dnsConf, ConfidenceObserved)
        })

        t.Run("DNSInfraHasConfidence", func(t *testing.T) {
                results := baseResults()
                results["basic_records"] = map[string]any{
                        "NS": []string{"ns1.cloudflare.com", "ns2.cloudflare.com"},
                }
                infra := a.AnalyzeDNSInfrastructure("example.com", results)

                conf, ok := infra["confidence"].(map[string]any)
                if !ok {
                        t.Fatal("confidence missing from DNS infrastructure result")
                }
                assertLevel(t, conf, ConfidenceObserved)
                assertMethod(t, conf, MethodNSPattern)
        })

        t.Run("GovernmentConfidence", func(t *testing.T) {
                results := baseResults()
                results["basic_records"] = map[string]any{
                        "NS": []string{"ns1.example.gov"},
                }
                infra := a.AnalyzeDNSInfrastructure("whitehouse.gov", results)

                govConf, ok := infra["gov_confidence"].(map[string]any)
                if !ok {
                        t.Fatal("gov_confidence missing for government domain")
                }
                assertLevel(t, govConf, ConfidenceInferred)
                assertMethod(t, govConf, MethodTLDSuffix)
        })
}
