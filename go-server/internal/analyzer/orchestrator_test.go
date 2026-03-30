// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
        "testing"
        "time"

        "dnstool/go-server/internal/icuae"
)

func TestBuildRecordCurrencies(t *testing.T) {
        ttlMap := map[string]uint32{
                "A":    300,
                "AAAA": 600,
                "MX":   3600,
        }

        records := buildRecordCurrencies(ttlMap)

        if len(records) != 3 {
                t.Fatalf("expected 3 records, got %d", len(records))
        }

        found := map[string]bool{}
        for _, r := range records {
                found[r.RecordType] = true
                if r.ObservedTTL != ttlMap[r.RecordType] {
                        t.Errorf("record %s: expected TTL %d, got %d", r.RecordType, ttlMap[r.RecordType], r.ObservedTTL)
                }
                if r.TypicalTTL != icuae.TypicalTTLFor(r.RecordType) {
                        t.Errorf("record %s: expected typical TTL %d, got %d", r.RecordType, icuae.TypicalTTLFor(r.RecordType), r.TypicalTTL)
                }
        }

        for rt := range ttlMap {
                if !found[rt] {
                        t.Errorf("missing record type %s", rt)
                }
        }
}

func TestBuildRecordCurrencies_Empty(t *testing.T) {
        records := buildRecordCurrencies(map[string]uint32{})
        if len(records) != 0 {
                t.Errorf("expected 0 records, got %d", len(records))
        }
}

func TestBuildObservedTypes(t *testing.T) {
        resolver := map[string]uint32{"A": 300, "MX": 3600}
        auth := map[string]uint32{"A": 300, "AAAA": 600}

        observed := buildObservedTypes(resolver, auth)

        if len(observed) != 3 {
                t.Fatalf("expected 3 observed types, got %d", len(observed))
        }
        for _, rt := range []string{"A", "MX", "AAAA"} {
                if !observed[rt] {
                        t.Errorf("expected %s to be observed", rt)
                }
        }
}

func TestBuildObservedTypes_BothEmpty(t *testing.T) {
        observed := buildObservedTypes(map[string]uint32{}, map[string]uint32{})
        if len(observed) != 0 {
                t.Errorf("expected 0 observed types, got %d", len(observed))
        }
}

func TestBuildObservedTypes_Overlap(t *testing.T) {
        resolver := map[string]uint32{"A": 300}
        auth := map[string]uint32{"A": 300}

        observed := buildObservedTypes(resolver, auth)
        if len(observed) != 1 {
                t.Errorf("expected 1 observed type (deduplicated), got %d", len(observed))
        }
}

func TestExtractResolverAgreements_Valid(t *testing.T) {
        consensus := map[string]any{
                "resolvers_queried": 3,
                "per_record_consensus": map[string]any{
                        "A": map[string]any{
                                "consensus":      true,
                                "resolver_count": 3,
                        },
                        "MX": map[string]any{
                                "consensus":      false,
                                "resolver_count": 3,
                        },
                },
        }

        agreements, resolverCount := extractResolverAgreements(consensus)

        if resolverCount != 3 {
                t.Errorf("expected resolver count 3, got %d", resolverCount)
        }
        if len(agreements) != 2 {
                t.Fatalf("expected 2 agreements, got %d", len(agreements))
        }

        for _, a := range agreements {
                switch a.RecordType {
                case "A":
                        if !a.Unanimous {
                                t.Error("expected A to be unanimous")
                        }
                        if a.AgreeCount != 3 {
                                t.Errorf("A: expected agree count 3, got %d", a.AgreeCount)
                        }
                case "MX":
                        if a.Unanimous {
                                t.Error("expected MX not unanimous")
                        }
                        if a.AgreeCount != 2 {
                                t.Errorf("MX: expected agree count 2, got %d", a.AgreeCount)
                        }
                }
        }
}

func TestExtractResolverAgreements_NoPerRecord(t *testing.T) {
        consensus := map[string]any{
                "resolvers_queried": 4,
        }

        agreements, resolverCount := extractResolverAgreements(consensus)

        if resolverCount != 4 {
                t.Errorf("expected resolver count 4, got %d", resolverCount)
        }
        if agreements != nil {
                t.Errorf("expected nil agreements, got %v", agreements)
        }
}

func TestExtractResolverAgreements_DefaultResolverCount(t *testing.T) {
        consensus := map[string]any{
                "per_record_consensus": map[string]any{},
        }

        _, resolverCount := extractResolverAgreements(consensus)

        if resolverCount != 5 {
                t.Errorf("expected default resolver count 5, got %d", resolverCount)
        }
}

func TestExtractResolverAgreements_ZeroResolverCount(t *testing.T) {
        consensus := map[string]any{
                "per_record_consensus": map[string]any{
                        "A": map[string]any{
                                "consensus":      false,
                                "resolver_count": 0,
                        },
                },
        }

        agreements, _ := extractResolverAgreements(consensus)

        for _, a := range agreements {
                if a.RecordType == "A" && a.AgreeCount != 0 {
                        t.Errorf("expected agree count 0 when resolver_count=0 and no consensus, got %d", a.AgreeCount)
                }
        }
}

func TestEnrichCurrencyInput(t *testing.T) {
        input := &icuae.CurrencyReportInput{}
        results := map[string]any{
                "ns": map[string]any{
                        "dns_providers": []string{"Cloudflare", "Route53"},
                },
                "basic_records": map[string]any{
                        "NS":  []string{"ns1.example.com", "ns2.example.com"},
                        "SOA": []string{"ns1.example.com admin.example.com 2024010101 3600 900 604800 86400"},
                },
        }

        enrichCurrencyInput(input, results)

        if len(input.DNSProviders) != 2 {
                t.Errorf("expected 2 DNS providers, got %d", len(input.DNSProviders))
        }
        if len(input.NSRecords) != 2 {
                t.Errorf("expected 2 NS records, got %d", len(input.NSRecords))
        }
        if input.SOARaw == "" {
                t.Error("expected SOARaw to be populated")
        }
}

func TestEnrichCurrencyInput_MissingData(t *testing.T) {
        input := &icuae.CurrencyReportInput{}
        results := map[string]any{}

        enrichCurrencyInput(input, results)

        if len(input.DNSProviders) != 0 {
                t.Errorf("expected 0 DNS providers, got %d", len(input.DNSProviders))
        }
        if len(input.NSRecords) != 0 {
                t.Errorf("expected 0 NS records, got %d", len(input.NSRecords))
        }
        if input.SOARaw != "" {
                t.Error("expected empty SOARaw")
        }
}

func TestEnrichCurrencyInput_EmptySOA(t *testing.T) {
        input := &icuae.CurrencyReportInput{}
        results := map[string]any{
                "basic_records": map[string]any{
                        "SOA": []string{},
                },
        }

        enrichCurrencyInput(input, results)

        if input.SOARaw != "" {
                t.Error("expected empty SOARaw for empty SOA slice")
        }
}

func TestEnrichBasicRecords(t *testing.T) {
        basic := map[string]any{}
        resultsMap := map[string]any{
                "dmarc": map[string]any{
                        "status":        "success",
                        "valid_records": []string{"v=DMARC1; p=reject"},
                },
                "mta_sts": map[string]any{
                        "record": "_mta-sts.example.com v=STSv1; id=20240101",
                },
                "tlsrpt": map[string]any{
                        "record": "v=TLSRPTv1; rua=mailto:tls@example.com",
                },
        }

        enrichBasicRecords(basic, resultsMap)

        if dmarc, ok := basic["DMARC"].([]string); !ok || len(dmarc) != 1 {
                t.Error("expected DMARC record in basic")
        }
        if mtaSts, ok := basic["MTA-STS"].([]string); !ok || len(mtaSts) != 1 {
                t.Error("expected MTA-STS record in basic")
        }
        if tlsrpt, ok := basic["TLS-RPT"].([]string); !ok || len(tlsrpt) != 1 {
                t.Error("expected TLS-RPT record in basic")
        }
}

func TestEnrichBasicRecords_EmptyResults(t *testing.T) {
        basic := map[string]any{}
        resultsMap := map[string]any{}

        enrichBasicRecords(basic, resultsMap)

        if _, ok := basic["DMARC"]; ok {
                t.Error("expected no DMARC in basic")
        }
        if _, ok := basic["MTA-STS"]; ok {
                t.Error("expected no MTA-STS in basic")
        }
        if _, ok := basic["TLS-RPT"]; ok {
                t.Error("expected no TLS-RPT in basic")
        }
}

func TestEnrichBasicRecords_ErrorStatus(t *testing.T) {
        basic := map[string]any{}
        resultsMap := map[string]any{
                "dmarc": map[string]any{
                        "status": "error",
                },
        }

        enrichBasicRecords(basic, resultsMap)

        if _, ok := basic["DMARC"]; ok {
                t.Error("expected no DMARC in basic when status is error")
        }
}

func TestEnrichMisplacedDMARC_Detected(t *testing.T) {
        basic := map[string]any{
                "TXT": []string{"v=DMARC1; p=reject"},
        }
        resultsMap := map[string]any{
                "dmarc": map[string]any{
                        "status": "warning",
                        "issues": []string{},
                },
        }

        enrichMisplacedDMARC(basic, resultsMap)

        dmarcResult := resultsMap["dmarc"].(map[string]any)
        if dmarcResult["misplaced_dmarc"] == nil {
                t.Error("expected misplaced_dmarc to be set")
        }
}

func TestEnrichMisplacedDMARC_NotDetected(t *testing.T) {
        basic := map[string]any{
                "TXT": []string{"v=spf1 include:_spf.google.com ~all"},
        }
        resultsMap := map[string]any{
                "dmarc": map[string]any{
                        "status": "success",
                },
        }

        enrichMisplacedDMARC(basic, resultsMap)

        dmarcResult := resultsMap["dmarc"].(map[string]any)
        if dmarcResult["misplaced_dmarc"] != nil {
                t.Error("expected misplaced_dmarc not to be set")
        }
}

func TestEnrichMisplacedDMARC_NoDmarcInResults(t *testing.T) {
        basic := map[string]any{
                "TXT": []string{"v=DMARC1; p=reject"},
        }
        resultsMap := map[string]any{}

        enrichMisplacedDMARC(basic, resultsMap)
}

func TestBuildPropagationStatus_Synchronized(t *testing.T) {
        basic := map[string]any{
                "A": []string{"1.2.3.4"},
        }
        auth := map[string]any{
                "A": []string{"1.2.3.4"},
        }

        propagation := buildPropagationStatus(basic, auth)

        entry, ok := propagation["A"].(map[string]any)
        if !ok {
                t.Fatal("expected A entry in propagation")
        }
        if entry["status"] != "synchronized" {
                t.Errorf("expected synchronized, got %v", entry["status"])
        }
        if entry["synced"] != true {
                t.Error("expected synced=true")
        }
}

func TestBuildPropagationStatus_Propagating(t *testing.T) {
        basic := map[string]any{
                "A": []string{"1.2.3.4"},
        }
        auth := map[string]any{
                "A": []string{"5.6.7.8"},
        }

        propagation := buildPropagationStatus(basic, auth)

        entry, ok := propagation["A"].(map[string]any)
        if !ok {
                t.Fatal("expected A entry in propagation")
        }
        if entry["status"] != "propagating" {
                t.Errorf("expected propagating, got %v", entry["status"])
        }
        if entry["mismatch"] != true {
                t.Error("expected mismatch=true")
        }
}

func TestBuildPropagationStatus_Unknown(t *testing.T) {
        basic := map[string]any{
                "A": []string{"1.2.3.4"},
        }
        auth := map[string]any{
                "A": []string{},
        }

        propagation := buildPropagationStatus(basic, auth)

        entry, ok := propagation["A"].(map[string]any)
        if !ok {
                t.Fatal("expected A entry in propagation")
        }
        if entry["status"] != "unknown" {
                t.Errorf("expected unknown, got %v", entry["status"])
        }
}

func TestBuildPropagationStatus_SkipsTTLKeys(t *testing.T) {
        basic := map[string]any{
                "_ttl":          map[string]uint32{"A": 300},
                "_query_status": "ok",
                "A":             []string{"1.2.3.4"},
        }
        auth := map[string]any{
                "A": []string{"1.2.3.4"},
        }

        propagation := buildPropagationStatus(basic, auth)

        if _, ok := propagation["_ttl"]; ok {
                t.Error("expected _ttl to be skipped")
        }
        if _, ok := propagation["_query_status"]; ok {
                t.Error("expected _query_status to be skipped")
        }
        if _, ok := propagation["A"]; !ok {
                t.Error("expected A entry")
        }
}

func TestPopulateTTLReports_NilMaps(t *testing.T) {
        results := map[string]any{}

        populateTTLReports(results)

        if results["freshness_matrix"] == nil {
                t.Error("expected freshness_matrix to be populated")
        }
        if results["currency_report"] == nil {
                t.Error("expected currency_report to be populated")
        }
}

func TestPopulateTTLReports_WithData(t *testing.T) {
        results := map[string]any{
                "resolver_ttl": map[string]uint32{"A": 300, "MX": 3600},
                "auth_ttl":     map[string]uint32{"A": 300},
        }

        populateTTLReports(results)

        if results["freshness_matrix"] == nil {
                t.Error("expected freshness_matrix to be populated")
        }
        if results["currency_report"] == nil {
                t.Error("expected currency_report to be populated")
        }
}

func TestBuildICuAEReport_Basic(t *testing.T) {
        resolverTTL := map[string]uint32{"A": 300}
        authTTL := map[string]uint32{"A": 300}
        results := map[string]any{}

        report := buildICuAEReport(resolverTTL, authTTL, results)

        if report.OverallGrade == "" {
                t.Error("expected non-empty overall grade")
        }
}

func TestBuildICuAEReport_WithConsensus(t *testing.T) {
        resolverTTL := map[string]uint32{"A": 300}
        authTTL := map[string]uint32{"A": 300}
        results := map[string]any{
                "resolver_consensus": map[string]any{
                        "resolvers_queried": 3,
                        "per_record_consensus": map[string]any{
                                "A": map[string]any{
                                        "consensus":      true,
                                        "resolver_count": 3,
                                },
                        },
                },
        }

        report := buildICuAEReport(resolverTTL, authTTL, results)

        if report.OverallGrade == "" {
                t.Error("expected non-empty overall grade")
        }
}

func TestBuildSectionStatus_TimeoutStatus(t *testing.T) {
        resultsMap := map[string]any{
                "spf": map[string]any{"status": "timeout"},
        }
        status := buildSectionStatus(resultsMap)
        spf, ok := status["spf"].(map[string]any)
        if !ok {
                t.Fatal("expected spf entry")
        }
        if spf["status"] != "timeout" {
                t.Errorf("expected status=timeout, got %v", spf["status"])
        }
        if spf["message"] != "Query timed out" {
                t.Errorf("expected 'Query timed out' message, got %v", spf["message"])
        }
}

func TestBuildSectionStatus_ErrorWithMessage(t *testing.T) {
        resultsMap := map[string]any{
                "dmarc": map[string]any{"status": "error", "message": "DNS failure"},
        }
        status := buildSectionStatus(resultsMap)
        dmarc, ok := status["dmarc"].(map[string]any)
        if !ok {
                t.Fatal("expected dmarc entry")
        }
        if dmarc["status"] != "error" {
                t.Errorf("expected status=error, got %v", dmarc["status"])
        }
        if dmarc["message"] != "DNS failure" {
                t.Errorf("expected 'DNS failure', got %v", dmarc["message"])
        }
}

func TestBuildSectionStatus_ErrorNoMessage(t *testing.T) {
        resultsMap := map[string]any{
                "dkim": map[string]any{"status": "error"},
        }
        status := buildSectionStatus(resultsMap)
        dkim, ok := status["dkim"].(map[string]any)
        if !ok {
                t.Fatal("expected dkim entry")
        }
        if dkim["message"] != "Lookup failed" {
                t.Errorf("expected default 'Lookup failed', got %v", dkim["message"])
        }
}

func TestBuildSectionStatus_NonMapResult(t *testing.T) {
        resultsMap := map[string]any{
                "something": "not a map",
        }
        status := buildSectionStatus(resultsMap)
        entry, ok := status["something"].(map[string]any)
        if !ok {
                t.Fatal("expected something entry")
        }
        if entry["status"] != "ok" {
                t.Errorf("expected status=ok for non-map result, got %v", entry["status"])
        }
}

func TestBuildSectionStatus_SuccessStatus(t *testing.T) {
        resultsMap := map[string]any{
                "caa": map[string]any{"status": "success"},
        }
        status := buildSectionStatus(resultsMap)
        caa, ok := status["caa"].(map[string]any)
        if !ok {
                t.Fatal("expected caa entry")
        }
        if caa["status"] != "ok" {
                t.Errorf("expected status=ok for success, got %v", caa["status"])
        }
}

func TestAdjustHostingSummary_NotAMap(t *testing.T) {
        results := map[string]any{
                "hosting_summary": "not a map",
        }
        adjustHostingSummary(results)
        if results["hosting_summary"] != "not a map" {
                t.Error("expected hosting_summary to remain unchanged when not a map")
        }
}

func TestAdjustHostingSummary_KnownEmailProvider(t *testing.T) {
        results := map[string]any{
                "is_no_mail_domain": false,
                "has_null_mx":       false,
                "hosting_summary":   map[string]any{"email_hosting": "Google Workspace"},
        }
        adjustHostingSummary(results)
        hs := results["hosting_summary"].(map[string]any)
        if hs["email_hosting"] != "Google Workspace" {
                t.Errorf("expected email_hosting to remain 'Google Workspace', got %v", hs["email_hosting"])
        }
}

func TestAdjustHostingSummary_UnknownNotNoMail(t *testing.T) {
        results := map[string]any{
                "is_no_mail_domain": false,
                "has_null_mx":       false,
                "hosting_summary":   map[string]any{"email_hosting": "Unknown"},
                "dkim_analysis": map[string]any{
                        "primary_provider": "Microsoft 365",
                },
        }
        adjustHostingSummary(results)
        hs := results["hosting_summary"].(map[string]any)
        if hs["email_hosting"] != "Microsoft 365" {
                t.Errorf("expected email_hosting inferred to 'Microsoft 365', got %v", hs["email_hosting"])
        }
}

func TestInferEmailFromDKIM_NoDKIMKey(t *testing.T) {
        hs := map[string]any{"email_hosting": "Unknown"}
        results := map[string]any{}
        inferEmailFromDKIM(hs, results)
        if hs["email_hosting"] != "Unknown" {
                t.Errorf("expected unchanged when no dkim_analysis, got %v", hs["email_hosting"])
        }
}

func TestInferEmailFromDKIM_EmptyProvider(t *testing.T) {
        hs := map[string]any{"email_hosting": "Unknown"}
        results := map[string]any{
                "dkim_analysis": map[string]any{
                        "primary_provider": "",
                },
        }
        inferEmailFromDKIM(hs, results)
        if hs["email_hosting"] != "Unknown" {
                t.Errorf("expected unchanged for empty provider, got %v", hs["email_hosting"])
        }
}

func TestInferEmailFromDKIM_PreservesExistingConfidence(t *testing.T) {
        existingConfidence := map[string]any{
                "level":  "confirmed",
                "label":  "Confirmed",
                "method": "MX record match",
        }
        hs := map[string]any{
                "email_hosting":    "Unknown",
                "email_confidence": existingConfidence,
        }
        results := map[string]any{
                "dkim_analysis": map[string]any{
                        "primary_provider": "Google Workspace",
                },
        }
        inferEmailFromDKIM(hs, results)
        if hs["email_hosting"] != "Google Workspace" {
                t.Errorf("expected 'Google Workspace', got %v", hs["email_hosting"])
        }
        ec := hs["email_confidence"].(map[string]any)
        if ec["level"] != "confirmed" {
                t.Error("expected existing email_confidence to be preserved")
        }
}

func TestDetectNullMX_MultipleWithOneNull(t *testing.T) {
        basic := map[string]any{
                "MX": []string{"10 mail.example.com.", "0 ."},
        }
        if !detectNullMX(basic) {
                t.Error("expected null MX detection when one record is null")
        }
}

func TestEnrichMisplacedDMARC_NilIssuesList(t *testing.T) {
        basic := map[string]any{
                "TXT": []string{"v=DMARC1; p=reject"},
        }
        resultsMap := map[string]any{
                "dmarc": map[string]any{
                        "status": "warning",
                },
        }

        enrichMisplacedDMARC(basic, resultsMap)

        dmarcResult := resultsMap["dmarc"].(map[string]any)
        if dmarcResult["misplaced_dmarc"] == nil {
                t.Error("expected misplaced_dmarc to be set")
        }
        issues, ok := dmarcResult["issues"].([]string)
        if !ok {
                t.Fatal("expected issues to be a string slice")
        }
        if len(issues) == 0 {
                t.Error("expected at least one issue appended")
        }
}

func TestBuildPropagationStatus_EmptyMaps(t *testing.T) {
        propagation := buildPropagationStatus(map[string]any{}, map[string]any{})
        if len(propagation) != 0 {
                t.Errorf("expected empty propagation for empty inputs, got %d entries", len(propagation))
        }
}

func TestExtractResolverAgreements_InvalidPerRecordEntry(t *testing.T) {
        consensus := map[string]any{
                "per_record_consensus": map[string]any{
                        "A": "not a map",
                },
        }

        agreements, _ := extractResolverAgreements(consensus)
        if len(agreements) != 0 {
                t.Errorf("expected 0 agreements for invalid per_record entry, got %d", len(agreements))
        }
}

func TestMakeStringSet_Empty(t *testing.T) {
        set := makeStringSet([]string{})
        if len(set) != 0 {
                t.Errorf("expected empty set, got %d", len(set))
        }
}

func TestMakeStringSet_Nil(t *testing.T) {
        set := makeStringSet(nil)
        if len(set) != 0 {
                t.Errorf("expected empty set for nil input, got %d", len(set))
        }
}

func TestKeysOf_Empty(t *testing.T) {
        keys := keysOf(map[string]bool{})
        if len(keys) != 0 {
                t.Errorf("expected empty keys, got %d", len(keys))
        }
}

func TestTimedTask(t *testing.T) {
        ch := make(chan namedResult, 1)
        fn := timedTask(ch, "test_key", time.Now(), func() any {
                return map[string]any{"status": "ok"}
        })

        fn()

        nr := <-ch
        if nr.key != "test_key" {
                t.Errorf("expected key 'test_key', got %q", nr.key)
        }
        if nr.elapsed <= 0 {
                t.Error("expected positive elapsed duration")
        }
        result, ok := nr.result.(map[string]any)
        if !ok {
                t.Fatal("expected map result")
        }
        if result["status"] != "ok" {
                t.Errorf("expected status=ok, got %v", result["status"])
        }
}

func TestTimedTask_NilResult(t *testing.T) {
        ch := make(chan namedResult, 1)
        fn := timedTask(ch, "nil_key", time.Now(), func() any {
                return nil
        })

        fn()

        nr := <-ch
        if nr.key != "nil_key" {
                t.Errorf("expected key 'nil_key', got %q", nr.key)
        }
        if nr.result != nil {
                t.Error("expected nil result")
        }
}

func TestPopulateExtendedResults_Defaults(t *testing.T) {
        results := map[string]any{}
        resultsMap := map[string]any{}

        populateExtendedResults(results, resultsMap)

        expectedKeys := []string{
                "https_svcb", "cds_cdnskey", "smimea_openpgpkey",
                "security_txt", "ai_surface", "secret_exposure",
                "nmap_dns", "delegation_consistency", "ns_fleet", "dnssec_ops",
        }
        for _, key := range expectedKeys {
                if results[key] == nil {
                        t.Errorf("expected key %q to be populated with default", key)
                }
        }
}

func TestPopulateExtendedResults_ExistingValues(t *testing.T) {
        results := map[string]any{}
        customVal := map[string]any{"status": "custom", "custom_field": true}
        resultsMap := map[string]any{
                "https_svcb": customVal,
        }

        populateExtendedResults(results, resultsMap)

        got, ok := results["https_svcb"].(map[string]any)
        if !ok {
                t.Fatal("expected map for https_svcb")
        }
        if got["status"] != "custom" {
                t.Errorf("expected custom status, got %v", got["status"])
        }
        if got["custom_field"] != true {
                t.Error("expected custom_field=true")
        }
}

func TestBuildCoreResults(t *testing.T) {
        domain := "example.com"
        domainStatus := "active"
        msg := "All good"
        domainStatusMessage := &msg
        basic := map[string]any{"A": []string{"1.2.3.4"}}
        auth := map[string]any{"A": []string{"1.2.3.4"}}
        resolverTTL := map[string]uint32{"A": 300}
        authTTL := map[string]uint32{"A": 300}
        authQueryStatus := "ok"
        resultsMap := map[string]any{
                "spf":   map[string]any{"status": "success", "no_mail_intent": false},
                "dmarc": map[string]any{"status": "success"},
        }
        spfAnalysis := map[string]any{"no_mail_intent": false}

        results := buildCoreResults(domain, domainStatus, domainStatusMessage, basic, auth, resolverTTL, authTTL, authQueryStatus, resultsMap, spfAnalysis)

        if results["domain"] != "example.com" {
                t.Errorf("expected domain=example.com, got %v", results["domain"])
        }
        if results["domain_exists"] != true {
                t.Error("expected domain_exists=true")
        }
        if results["domain_status"] != "active" {
                t.Errorf("expected domain_status=active, got %v", results["domain_status"])
        }
        if results["auth_query_status"] != "ok" {
                t.Errorf("expected auth_query_status=ok, got %v", results["auth_query_status"])
        }
        if results["has_null_mx"] == nil {
                t.Error("expected has_null_mx to be set")
        }
        if results["section_status"] == nil {
                t.Error("expected section_status to be set")
        }
}

func TestBuildCoreResults_NilStatusMessage(t *testing.T) {
        results := buildCoreResults("test.com", "active", nil, map[string]any{}, map[string]any{}, nil, nil, nil, map[string]any{}, map[string]any{})

        if _, exists := results["domain_status_message"]; !exists {
                t.Error("expected domain_status_message key to exist")
        }
}

func TestBuildCoreResults_NoMailIntent(t *testing.T) {
        spfAnalysis := map[string]any{"no_mail_intent": true}
        results := buildCoreResults("test.com", "active", nil, map[string]any{}, map[string]any{}, nil, nil, nil, map[string]any{}, spfAnalysis)

        if results["is_no_mail_domain"] != true {
                t.Error("expected is_no_mail_domain=true when spf has no_mail_intent")
        }
}

func TestBuildCoreResults_DefaultAnalyses(t *testing.T) {
        results := buildCoreResults("test.com", "active", nil, map[string]any{}, map[string]any{}, nil, nil, nil, map[string]any{}, map[string]any{})

        analysisKeys := []string{
                "spf_analysis", "dmarc_analysis", "dkim_analysis",
                "mta_sts_analysis", "tlsrpt_analysis", "bimi_analysis",
                "dane_analysis", "caa_analysis", "dnssec_analysis",
                "ns_delegation_analysis", "registrar_info",
                "resolver_consensus", "ct_subdomains",
        }
        for _, key := range analysisKeys {
                if results[key] == nil {
                        t.Errorf("expected %q to have a default value", key)
                }
        }
}

func TestDetectNullMX_ZeroOnly(t *testing.T) {
        basic := map[string]any{
                "MX": []string{"0"},
        }
        if !detectNullMX(basic) {
                t.Error("expected null MX detection for '0'")
        }
}

func TestDetectNullMX_NonStringSlice(t *testing.T) {
        basic := map[string]any{
                "MX": "not a slice",
        }
        if detectNullMX(basic) {
                t.Error("expected no null MX for non-slice MX value")
        }
}

func TestGetMapResult_NonMap(t *testing.T) {
        m := map[string]any{
                "test": "string value",
        }
        result := getMapResult(m, "test")
        if len(result) != 0 {
                t.Error("expected empty map for non-map value")
        }
}

func TestGetOrDefault_NonMapValue(t *testing.T) {
        m := map[string]any{
                "test": "string value",
        }
        defaultVal := map[string]any{"status": "default"}
        result := getOrDefault(m, "test", defaultVal)
        if result != "string value" {
                t.Errorf("expected string value, got %v", result)
        }
}

func TestBuildPropagationStatus_MultipleRecordTypes(t *testing.T) {
        basic := map[string]any{
                "A":    []string{"1.2.3.4"},
                "AAAA": []string{"2001:db8::1"},
                "MX":   []string{"10 mail.example.com."},
        }
        auth := map[string]any{
                "A":    []string{"1.2.3.4"},
                "AAAA": []string{},
                "MX":   []string{"10 mail2.example.com."},
        }

        propagation := buildPropagationStatus(basic, auth)

        aEntry := propagation["A"].(map[string]any)
        if aEntry["status"] != "synchronized" {
                t.Errorf("expected A synchronized, got %v", aEntry["status"])
        }

        aaaaEntry := propagation["AAAA"].(map[string]any)
        if aaaaEntry["status"] != "unknown" {
                t.Errorf("expected AAAA unknown, got %v", aaaaEntry["status"])
        }

        mxEntry := propagation["MX"].(map[string]any)
        if mxEntry["status"] != "propagating" {
                t.Errorf("expected MX propagating, got %v", mxEntry["status"])
        }
}
