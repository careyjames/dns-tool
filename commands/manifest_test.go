// Copyright (c) 2024-2026 IT Help San Diego Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL — See LICENSE for terms.
// This file is part of the DNS Tool Intelligence Module.
package analyzer

import (
        "sort"
        "testing"
)

func assertNoMissingKeys(t *testing.T, missing []string, context string) {
        t.Helper()
        if len(missing) == 0 {
                return
        }
        sort.Strings(missing)
        t.Errorf("Manifest schema keys %s:\n", context)
        for _, k := range missing {
                t.Errorf("  - %s", k)
        }
}

func TestManifestSchemaKeysInActiveResult(t *testing.T) {
        a := newTestAnalyzer()

        result := a.buildNonExistentResult("test.example", "undelegated", nil)

        var missing []string
        for _, key := range RequiredSchemaKeys {
                if key == "_data_freshness" {
                        continue
                }
                if _, ok := result[key]; !ok {
                        missing = append(missing, key)
                }
        }

        assertNoMissingKeys(t, missing, "missing from buildNonExistentResult output")
        if len(missing) > 0 {
                t.Errorf("\nEvery schema key in the manifest MUST be present in analysis output.")
                t.Errorf("If you added a new feature, add its schema key to FeatureParityManifest in manifest.go.")
                t.Errorf("If you removed a feature, remove it from FeatureParityManifest with documented rationale.")
        }
}

func TestManifestSchemaKeysInLiveResultMap(t *testing.T) {
        liveKeys := map[string]bool{
                "domain_exists":          true,
                "domain_status":          true,
                "domain_status_message":  true,
                "section_status":         true,
                "basic_records":          true,
                "authoritative_records":  true,
                "auth_query_status":      true,
                "resolver_ttl":           true,
                "auth_ttl":               true,
                "propagation_status":     true,
                "spf_analysis":           true,
                "dmarc_analysis":         true,
                "dkim_analysis":          true,
                "mta_sts_analysis":       true,
                "tlsrpt_analysis":        true,
                "bimi_analysis":          true,
                "dane_analysis":          true,
                "caa_analysis":           true,
                "dnssec_analysis":        true,
                "ns_delegation_analysis": true,
                "registrar_info":         true,
                "resolver_consensus":     true,
                "ct_subdomains":          true,
                "smtp_transport":         true,
                "has_null_mx":            true,
                "is_no_mail_domain":      true,
                "hosting_summary":        true,
                "dns_infrastructure":     true,
                "email_security_mgmt":    true,
                "dmarc_report_auth":      true,
                "dangling_dns":           true,
                "https_svcb":             true,
                "asn_info":               true,
                "edge_cdn":               true,
                "saas_txt":               true,
                "cds_cdnskey":            true,
                "smimea_openpgpkey":      true,
                "security_txt":          true,
                "ai_surface":            true,
                "posture":                true,
                "remediation":            true,
                "mail_posture":           true,
        }

        missing := findMissingSchemaKeys(liveKeys)
        assertNoMissingKeys(t, missing, "not in AnalyzeDomain live result map")
        if len(missing) > 0 {
                t.Errorf("\nUpdate liveKeys in this test AND AnalyzeDomain() when adding new features.")
        }

        extra := findExtraKeys(liveKeys)
        if len(extra) > 0 {
                sort.Strings(extra)
                t.Errorf("Keys in AnalyzeDomain output but NOT in manifest (add them to manifest.go):\n")
                for _, k := range extra {
                        t.Errorf("  + %s", k)
                }
        }
}

func findMissingSchemaKeys(liveKeys map[string]bool) []string {
        var missing []string
        for _, key := range RequiredSchemaKeys {
                if key == "_data_freshness" {
                        continue
                }
                if !liveKeys[key] {
                        missing = append(missing, key)
                }
        }
        return missing
}

func findExtraKeys(liveKeys map[string]bool) []string {
        var extra []string
        for key := range liveKeys {
                found := false
                for _, mk := range RequiredSchemaKeys {
                        if mk == key {
                                found = true
                                break
                        }
                }
                if !found {
                        extra = append(extra, key)
                }
        }
        return extra
}

func TestManifestCompleteness(t *testing.T) {
        if len(FeatureParityManifest) < 33 {
                t.Errorf("Manifest has %d entries, expected at least 33 (the original migration baseline). "+
                        "Features should never be silently removed.", len(FeatureParityManifest))
        }
}

func TestManifestNoDuplicateSchemaKeys(t *testing.T) {
        seen := make(map[string]int)
        for _, entry := range FeatureParityManifest {
                seen[entry.SchemaKey]++
        }

        for key, count := range seen {
                if count > 1 {
                        t.Errorf("Duplicate schema key %q appears %d times in manifest", key, count)
                }
        }
}

func TestManifestEntriesHaveRequiredFields(t *testing.T) {
        for i, entry := range FeatureParityManifest {
                if entry.Feature == "" {
                        t.Errorf("Entry %d: missing Feature name", i)
                }
                if entry.Category == "" {
                        t.Errorf("Entry %d (%s): missing Category", i, entry.Feature)
                }
                if entry.Description == "" {
                        t.Errorf("Entry %d (%s): missing Description", i, entry.Feature)
                }
                if entry.SchemaKey == "" {
                        t.Errorf("Entry %d (%s): missing SchemaKey", i, entry.Feature)
                }
                if len(entry.DetectionMethods) == 0 {
                        t.Errorf("Entry %d (%s): missing DetectionMethods", i, entry.Feature)
                }

                validCategories := map[string]bool{
                        "analysis": true, "infrastructure": true,
                        "detection": true, "assessment": true,
                }
                if !validCategories[entry.Category] {
                        t.Errorf("Entry %d (%s): invalid category %q", i, entry.Feature, entry.Category)
                }
        }
}

func TestManifestCategories(t *testing.T) {
        categories := map[string]int{}
        for _, entry := range FeatureParityManifest {
                categories[entry.Category]++
        }

        if categories["analysis"] < 10 {
                t.Errorf("Expected at least 10 analysis features, got %d", categories["analysis"])
        }
        if categories["infrastructure"] < 10 {
                t.Errorf("Expected at least 10 infrastructure features, got %d", categories["infrastructure"])
        }
        if categories["detection"] < 3 {
                t.Errorf("Expected at least 3 detection features, got %d", categories["detection"])
        }
        if categories["assessment"] < 2 {
                t.Errorf("Expected at least 2 assessment features, got %d", categories["assessment"])
        }
}
