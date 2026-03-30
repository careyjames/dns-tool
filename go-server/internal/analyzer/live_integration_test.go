// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
//
// Live integration tests — these query real DNS infrastructure and HTTP endpoints.
// Run manually: cd go-server && GIT_DIR=/dev/null go test -tags=integration -run TestLive ./internal/analyzer/ -v -timeout 120s
// These tests are NOT part of the default test suite and never run in CI.
// They validate end-to-end pipeline behavior against real domains.
//
// Design principles:
//   - Assert STRUCTURAL properties, not exact record values
//   - Use owner-controlled domain (it-help.tech) as primary target
//   - Failures here may indicate domain config changes, not code bugs
//   - Test the shape of results: "SPF exists" not "SPF equals X"
//   - Full orchestrator scans may time out in constrained environments — t.Skip gracefully

//go:build integration

package analyzer

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"dnstool/go-server/internal/analyzer/ai_surface"
)

const (
	ownerDomain    = "it-help.tech"
	ownerDomainWWW = "www.it-help.tech"
	toolDomain     = "dnstool.it-help.tech"
)

func newLiveAnalyzer(t *testing.T) *Analyzer {
	t.Helper()
	a := New(WithMaxConcurrent(4))
	time.Sleep(2 * time.Second)
	return a
}

func requireMapKey(t *testing.T, m map[string]any, key string) any {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Fatalf("result missing required key %q", key)
	}
	return v
}

func requireMapStringKey(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	v := requireMapKey(t, m, key)
	s, ok := v.(string)
	if !ok {
		t.Fatalf("key %q is not a string: %T", key, v)
	}
	return s
}

func requireSubMap(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	v, ok := m[key].(map[string]any)
	if !ok {
		t.Fatalf("%s missing or not a map", key)
	}
	return v
}

func TestLiveFullScanOwnerDomain(t *testing.T) {
	a := newLiveAnalyzer(t)
	ctx := context.Background()

	start := time.Now()
	results := a.AnalyzeDomain(ctx, ownerDomain, nil)
	elapsed := time.Since(start)

	success, _ := results["analysis_success"].(bool)
	if !success {
		if elapsed > 55*time.Second {
			t.Skipf("AnalyzeDomain timed out (%s) — orchestrator 60s limit hit; individual protocol tests validate correctness separately", elapsed)
		}
		t.Fatalf("AnalyzeDomain returned analysis_success=false for %s (took %s)", ownerDomain, elapsed)
	}

	domain := requireMapStringKey(t, results, "domain")
	if domain != ownerDomain {
		t.Errorf("domain mismatch: expected %s, got %s", ownerDomain, domain)
	}

	t.Run("SPF_exists", func(t *testing.T) {
		spf := requireSubMap(t, results, "spf_analysis")
		status := requireMapStringKey(t, spf, "status")
		if status == "not_found" || status == "error" || status == "n/a" {
			t.Errorf("SPF should be configured, got status=%s", status)
		}
		if record, ok := spf["record"].(string); ok {
			if !strings.HasPrefix(record, "v=spf1") {
				t.Errorf("SPF record should start with v=spf1, got: %s", record)
			}
		}
	})

	t.Run("DMARC_exists", func(t *testing.T) {
		dmarc := requireSubMap(t, results, "dmarc_analysis")
		status := requireMapStringKey(t, dmarc, "status")
		if status == "not_found" || status == "error" || status == "n/a" {
			t.Errorf("DMARC should be configured, got status=%s", status)
		}
		if policy, ok := dmarc["policy"].(string); ok {
			validPolicies := map[string]bool{"none": true, "quarantine": true, "reject": true}
			if !validPolicies[policy] {
				t.Errorf("DMARC policy should be none/quarantine/reject, got: %s", policy)
			}
		}
	})

	t.Run("DNS_infrastructure_classified", func(t *testing.T) {
		infra := requireSubMap(t, results, "dns_infrastructure")
		tier := requireMapStringKey(t, infra, "provider_tier")
		if tier == "" || tier == "N/A" {
			t.Error("should have a provider tier classification")
		}
		provider := requireMapStringKey(t, infra, "provider")
		if provider == "" || provider == "N/A" {
			t.Error("should identify a provider")
		}
		t.Logf("Detected: provider=%s, tier=%s", provider, tier)
	})

	t.Run("mail_posture_classified", func(t *testing.T) {
		posture := requireSubMap(t, results, "mail_posture")
		classification := requireMapStringKey(t, posture, "classification")
		if classification == "" || classification == "unknown" {
			t.Error("mail posture should have a classification")
		}
		t.Logf("Mail posture: %s", classification)
	})

	t.Run("remediation_generated", func(t *testing.T) {
		remediation := requireSubMap(t, results, "remediation")
		_ = requireMapKey(t, remediation, "top_fixes")
	})

	t.Run("basic_records_populated", func(t *testing.T) {
		basic := requireSubMap(t, results, "basic_records")
		nsRecords, _ := basic["NS"].([]string)
		if len(nsRecords) == 0 {
			t.Error("domain should have NS records")
		}
		t.Logf("NS records: %v", nsRecords)
	})

	t.Run("DNSSEC_analyzed", func(t *testing.T) {
		dnssec := requireSubMap(t, results, "dnssec_analysis")
		status := requireMapStringKey(t, dnssec, "status")
		if status == "" || status == "error" {
			t.Errorf("DNSSEC should return a definitive status, got: %s", status)
		}
		t.Logf("DNSSEC status: %s", status)
	})

	t.Run("CAA_analyzed", func(t *testing.T) {
		caa := requireSubMap(t, results, "caa_analysis")
		status := requireMapStringKey(t, caa, "status")
		if status == "" || status == "error" {
			t.Errorf("CAA should return a status, got: %s", status)
		}
		t.Logf("CAA status: %s", status)
	})

	t.Run("AI_surface_present", func(t *testing.T) {
		aiSurface, ok := results["ai_surface"].(map[string]any)
		if !ok {
			t.Fatal("ai_surface missing from full scan results")
		}
		status := requireMapStringKey(t, aiSurface, "status")
		if status == "" {
			t.Error("AI surface should have a status")
		}
		t.Logf("AI surface status: %s", status)
	})

	t.Run("security_txt_present", func(t *testing.T) {
		secTxt, ok := results["security_txt"].(map[string]any)
		if !ok {
			t.Fatal("security_txt missing from full scan results")
		}
		status := requireMapStringKey(t, secTxt, "status")
		if status == "" {
			t.Error("security_txt should have a status")
		}
		t.Logf("security.txt status: %s, found: %v", status, secTxt["found"])
	})

	t.Run("NS_delegation_present", func(t *testing.T) {
		nsDel, ok := results["ns_delegation_analysis"].(map[string]any)
		if !ok {
			t.Fatal("ns_delegation_analysis missing from full scan results")
		}
		status := requireMapStringKey(t, nsDel, "status")
		if status == "" || status == "error" {
			t.Errorf("NS delegation should return a status, got: %s", status)
		}
		t.Logf("NS delegation status: %s", status)
	})

	t.Run("all_protocol_sections_present", func(t *testing.T) {
		requiredSections := []string{
			"spf_analysis", "dmarc_analysis", "dkim_analysis",
			"mta_sts_analysis", "tlsrpt_analysis", "bimi_analysis",
			"dane_analysis", "caa_analysis", "dnssec_analysis",
			"ns_delegation_analysis", "ai_surface", "security_txt",
			"dns_infrastructure", "mail_posture", "remediation",
		}
		for _, section := range requiredSections {
			if _, ok := results[section].(map[string]any); !ok {
				t.Errorf("missing section %s in full scan results", section)
			}
		}
	})
}

func TestLiveIndividualProtocols(t *testing.T) {
	a := newLiveAnalyzer(t)
	ctx := context.Background()

	t.Run("SPF_analysis", func(t *testing.T) {
		result := a.AnalyzeSPF(ctx, ownerDomain)
		status := requireMapStringKey(t, result, "status")
		t.Logf("SPF status: %s", status)
		if status == "error" {
			t.Error("SPF analysis returned error — DNS query may have failed")
		}
	})

	t.Run("DMARC_analysis", func(t *testing.T) {
		result := a.AnalyzeDMARC(ctx, ownerDomain)
		status := requireMapStringKey(t, result, "status")
		t.Logf("DMARC status: %s", status)
		if status == "error" {
			t.Error("DMARC analysis returned error — DNS query may have failed")
		}
	})

	t.Run("DKIM_analysis", func(t *testing.T) {
		result := a.AnalyzeDKIM(ctx, ownerDomain, nil, nil)
		status := requireMapStringKey(t, result, "status")
		t.Logf("DKIM status: %s", status)
	})

	t.Run("MTA_STS_analysis", func(t *testing.T) {
		result := a.AnalyzeMTASTS(ctx, ownerDomain)
		status := requireMapStringKey(t, result, "status")
		t.Logf("MTA-STS status: %s", status)
		if status == "error" {
			t.Error("MTA-STS analysis returned error")
		}
	})

	t.Run("DNSSEC_analysis", func(t *testing.T) {
		result := a.AnalyzeDNSSEC(ctx, ownerDomain)
		status := requireMapStringKey(t, result, "status")
		t.Logf("DNSSEC status: %s", status)
		if status == "error" {
			t.Error("DNSSEC analysis returned error")
		}
	})

	t.Run("CAA_analysis", func(t *testing.T) {
		result := a.AnalyzeCAA(ctx, ownerDomain)
		status := requireMapStringKey(t, result, "status")
		t.Logf("CAA status: %s", status)
		if status == "error" {
			t.Error("CAA analysis returned error")
		}
	})

	t.Run("TLS_RPT_analysis", func(t *testing.T) {
		result := a.AnalyzeTLSRPT(ctx, ownerDomain)
		status := requireMapStringKey(t, result, "status")
		t.Logf("TLS-RPT status: %s", status)
		if status == "error" {
			t.Error("TLS-RPT analysis returned error")
		}
	})

	t.Run("BIMI_analysis", func(t *testing.T) {
		result := a.AnalyzeBIMI(ctx, ownerDomain)
		status := requireMapStringKey(t, result, "status")
		t.Logf("BIMI status: %s", status)
	})

	t.Run("NS_delegation_analysis", func(t *testing.T) {
		result := a.AnalyzeNSDelegation(ctx, ownerDomain)
		status := requireMapStringKey(t, result, "status")
		t.Logf("NS delegation status: %s", status)
		if status == "error" {
			t.Error("NS delegation analysis returned error")
		}
	})
}

func TestLiveAISurfaceScanner(t *testing.T) {
	a := newLiveAnalyzer(t)
	ctx := context.Background()

	t.Run("owner_domain_AI_surface", func(t *testing.T) {
		result := a.AnalyzeAISurface(ctx, ownerDomainWWW)

		status := requireMapStringKey(t, result, "status")
		if status == "" {
			t.Error("AI surface scan should return a status")
		}
		t.Logf("AI surface status: %s", status)

		message := requireMapStringKey(t, result, "message")
		if message == "" {
			t.Error("AI surface scan should return a message")
		}
		t.Logf("AI surface message: %s", message)

		llms := requireSubMap(t, result, "llms_txt")
		_ = requireMapKey(t, llms, "found")
		t.Logf("llms.txt found: %v, url: %v", llms["found"], llms["url"])

		robots := requireSubMap(t, result, "robots_txt")
		_ = requireMapKey(t, robots, "found")
		_ = requireMapKey(t, robots, "blocks_ai_crawlers")
		_ = requireMapKey(t, robots, "allows_ai_crawlers")
		t.Logf("robots.txt found: %v, blocks_ai: %v, allows_ai: %v",
			robots["found"], robots["blocks_ai_crawlers"], robots["allows_ai_crawlers"])

		if blocked, ok := robots["blocked_crawlers"].([]string); ok && len(blocked) > 0 {
			t.Logf("Blocked crawlers: %v", blocked)
		}
		if allowed, ok := robots["allowed_crawlers"].([]string); ok && len(allowed) > 0 {
			t.Logf("Allowed crawlers: %v", allowed)
		}

		poisoning := requireSubMap(t, result, "poisoning")
		_ = requireMapKey(t, poisoning, "status")
		_ = requireMapKey(t, poisoning, "ioc_count")
		t.Logf("Poisoning: status=%v, ioc_count=%v", poisoning["status"], poisoning["ioc_count"])

		hidden := requireSubMap(t, result, "hidden_prompts")
		_ = requireMapKey(t, hidden, "status")
		_ = requireMapKey(t, hidden, "artifact_count")
		t.Logf("Hidden prompts: status=%v, artifact_count=%v", hidden["status"], hidden["artifact_count"])

		summary := requireSubMap(t, result, "summary")
		_ = requireMapKey(t, summary, "status")
		_ = requireMapKey(t, summary, "has_llms_txt")
		_ = requireMapKey(t, summary, "blocks_ai")
		_ = requireMapKey(t, summary, "allows_ai")
		_ = requireMapKey(t, summary, "poisoning_count")
		_ = requireMapKey(t, summary, "hidden_count")
		_ = requireMapKey(t, summary, "total_evidence")
		t.Logf("Summary: has_llms_txt=%v, blocks_ai=%v, allows_ai=%v, evidence=%v",
			summary["has_llms_txt"], summary["blocks_ai"], summary["allows_ai"], summary["total_evidence"])

		evidence, ok := result["evidence"].([]map[string]any)
		if !ok {
			t.Log("evidence not a []map[string]any — may be empty or different type")
		} else {
			for i, e := range evidence {
				t.Logf("Evidence[%d]: type=%v, source=%v, confidence=%v", i, e["type"], e["source"], e["confidence"])
			}
		}
	})

	t.Run("tool_domain_AI_surface", func(t *testing.T) {
		result := a.AnalyzeAISurface(ctx, toolDomain)

		status := requireMapStringKey(t, result, "status")
		t.Logf("AI surface status for %s: %s", toolDomain, status)

		llms := requireSubMap(t, result, "llms_txt")
		t.Logf("llms.txt found: %v", llms["found"])

		robots := requireSubMap(t, result, "robots_txt")
		robotsFound, _ := robots["found"].(bool)
		if robotsFound {
			t.Logf("robots.txt found, blocks_ai: %v, allows_ai: %v",
				robots["blocks_ai_crawlers"], robots["allows_ai_crawlers"])
		}
	})

	t.Run("AI_surface_result_shape", func(t *testing.T) {
		result := a.AnalyzeAISurface(ctx, "example.com")

		requiredKeys := []string{
			"status", "message", "llms_txt", "robots_txt",
			"poisoning", "hidden_prompts", "evidence", "summary",
		}
		for _, key := range requiredKeys {
			if _, ok := result[key]; !ok {
				t.Errorf("AI surface result missing required key %q", key)
			}
		}
	})
}

func TestLiveAISurfaceScannerDirect(t *testing.T) {
	a := newLiveAnalyzer(t)
	scanner := ai_surface.NewScanner(a.HTTP)
	ctx := context.Background()

	t.Run("llms_txt_detection_www", func(t *testing.T) {
		result := scanner.Scan(ctx, ownerDomainWWW)
		llms := requireSubMap(t, result, "llms_txt")

		found, _ := llms["found"].(bool)
		t.Logf("llms.txt found on %s: %v", ownerDomainWWW, found)

		if found {
			url, _ := llms["url"].(string)
			if url == "" {
				t.Error("llms.txt found but url is empty")
			}
			t.Logf("llms.txt URL: %s", url)

			if fields, ok := llms["fields"].(map[string]any); ok && len(fields) > 0 {
				t.Logf("llms.txt fields: %v", fields)
			}
		}
	})

	t.Run("llms_txt_detection_tool", func(t *testing.T) {
		result := scanner.Scan(ctx, toolDomain)
		llms := requireSubMap(t, result, "llms_txt")

		found, _ := llms["found"].(bool)
		t.Logf("llms.txt found on %s: %v", toolDomain, found)
		if found {
			url, _ := llms["url"].(string)
			t.Logf("llms.txt URL: %s", url)
		}
	})

	t.Run("robots_txt_AI_crawlers_www", func(t *testing.T) {
		result := scanner.Scan(ctx, ownerDomainWWW)
		robots := requireSubMap(t, result, "robots_txt")

		robotsFound, _ := robots["found"].(bool)
		if !robotsFound {
			t.Skipf("robots.txt not found on %s — cannot verify AI crawler detection", ownerDomainWWW)
		}

		url, _ := robots["url"].(string)
		t.Logf("robots.txt URL: %s", url)

		blocksAI, _ := robots["blocks_ai_crawlers"].(bool)
		allowsAI, _ := robots["allows_ai_crawlers"].(bool)
		t.Logf("blocks_ai_crawlers: %v, allows_ai_crawlers: %v", blocksAI, allowsAI)

		if !blocksAI && !allowsAI {
			t.Error("robots.txt found but neither blocks_ai nor allows_ai is set — parser may have failed")
		}
	})

	t.Run("robots_txt_AI_crawlers_tool", func(t *testing.T) {
		result := scanner.Scan(ctx, toolDomain)
		robots := requireSubMap(t, result, "robots_txt")

		robotsFound, _ := robots["found"].(bool)
		if !robotsFound {
			t.Skipf("robots.txt not found on %s", toolDomain)
		}

		blocksAI, _ := robots["blocks_ai_crawlers"].(bool)
		allowsAI, _ := robots["allows_ai_crawlers"].(bool)
		t.Logf("%s: blocks_ai=%v, allows_ai=%v", toolDomain, blocksAI, allowsAI)
	})

	t.Run("poisoning_scan_clean_domain", func(t *testing.T) {
		result := scanner.Scan(ctx, ownerDomainWWW)
		poisoning := requireSubMap(t, result, "poisoning")

		status, _ := poisoning["status"].(string)
		iocCount := 0
		if v, ok := poisoning["ioc_count"].(int); ok {
			iocCount = v
		}

		t.Logf("Poisoning scan: status=%s, ioc_count=%d", status, iocCount)

		if iocCount > 0 {
			t.Logf("WARNING: Poisoning indicators found on owner domain — investigate immediately")
			if iocs, ok := poisoning["iocs"].([]map[string]any); ok {
				for _, ioc := range iocs {
					t.Logf("  IOC: %v", ioc["detail"])
				}
			}
		}
	})

	t.Run("hidden_prompts_scan_clean_domain", func(t *testing.T) {
		result := scanner.Scan(ctx, ownerDomainWWW)
		hidden := requireSubMap(t, result, "hidden_prompts")

		status, _ := hidden["status"].(string)
		artifactCount := 0
		if v, ok := hidden["artifact_count"].(int); ok {
			artifactCount = v
		}

		t.Logf("Hidden prompts scan: status=%s, artifact_count=%d", status, artifactCount)

		if artifactCount > 0 {
			t.Logf("WARNING: Hidden prompt artifacts found on owner domain — investigate immediately")
			if artifacts, ok := hidden["artifacts"].([]map[string]any); ok {
				for _, a := range artifacts {
					t.Logf("  Artifact: method=%v, detail=%v", a["method"], a["detail"])
				}
			}
		}
	})

	t.Run("summary_coherent", func(t *testing.T) {
		result := scanner.Scan(ctx, ownerDomainWWW)
		summary := requireSubMap(t, result, "summary")

		status := requireMapStringKey(t, summary, "status")
		validStatuses := map[string]bool{"success": true, "info": true, "warning": true}
		if !validStatuses[status] {
			t.Errorf("summary status should be success/info/warning, got: %s", status)
		}

		hasLLMS, _ := summary["has_llms_txt"].(bool)
		blocksAI, _ := summary["blocks_ai"].(bool)
		allowsAI, _ := summary["allows_ai"].(bool)
		evidenceCount, _ := summary["total_evidence"].(int)
		t.Logf("Summary: status=%s, has_llms=%v, blocks_ai=%v, allows_ai=%v, evidence=%d",
			status, hasLLMS, blocksAI, allowsAI, evidenceCount)

		if hasLLMS || blocksAI {
			if status != "success" && status != "warning" {
				t.Errorf("domain with llms.txt or AI blocks should have success/warning status, got: %s", status)
			}
		}
	})
}

func TestLiveSecurityTxt(t *testing.T) {
	a := newLiveAnalyzer(t)
	ctx := context.Background()

	t.Run("owner_domain_www", func(t *testing.T) {
		result := a.AnalyzeSecurityTxt(ctx, ownerDomainWWW)
		status := requireMapStringKey(t, result, "status")
		t.Logf("security.txt status: %s", status)

		found, _ := result["found"].(bool)
		t.Logf("security.txt found: %v", found)

		if found {
			if contacts, ok := result["contacts"].([]string); ok {
				if len(contacts) == 0 {
					t.Error("security.txt found but no contacts extracted")
				}
				t.Logf("Contacts: %v", contacts)
			}
		}
	})

	t.Run("tool_domain", func(t *testing.T) {
		result := a.AnalyzeSecurityTxt(ctx, toolDomain)
		status := requireMapStringKey(t, result, "status")
		t.Logf("security.txt status for %s: %s, found: %v", toolDomain, status, result["found"])
	})

	t.Run("result_shape", func(t *testing.T) {
		result := a.AnalyzeSecurityTxt(ctx, "example.com")
		requiredKeys := []string{"status", "found"}
		for _, key := range requiredKeys {
			if _, ok := result[key]; !ok {
				t.Errorf("security_txt result missing required key %q", key)
			}
		}
	})
}

func TestLiveAdvancedProtocols(t *testing.T) {
	a := newLiveAnalyzer(t)
	ctx := context.Background()

	t.Run("HTTPS_SVCB", func(t *testing.T) {
		result := a.AnalyzeHTTPSSVCB(ctx, ownerDomain)
		status := requireMapStringKey(t, result, "status")
		t.Logf("HTTPS/SVCB status: %s", status)

		hasHTTPS, _ := result["has_https"].(bool)
		hasSVCB, _ := result["has_svcb"].(bool)
		t.Logf("has_https: %v, has_svcb: %v", hasHTTPS, hasSVCB)
	})

	t.Run("CDS_CDNSKEY", func(t *testing.T) {
		result := a.AnalyzeCDSCDNSKEY(ctx, ownerDomain)
		status := requireMapStringKey(t, result, "status")
		t.Logf("CDS/CDNSKEY status: %s", status)

		hasCDS, _ := result["has_cds"].(bool)
		hasCDNSKEY, _ := result["has_cdnskey"].(bool)
		t.Logf("has_cds: %v, has_cdnskey: %v", hasCDS, hasCDNSKEY)
	})

	t.Run("SMIMEA_OPENPGPKEY", func(t *testing.T) {
		result := a.AnalyzeSMIMEA(ctx, ownerDomain)
		status := requireMapStringKey(t, result, "status")
		t.Logf("SMIMEA/OPENPGPKEY status: %s", status)
	})

	t.Run("DANE_analysis", func(t *testing.T) {
		result := a.AnalyzeDANE(ctx, ownerDomain, nil)
		status := requireMapStringKey(t, result, "status")
		t.Logf("DANE status: %s", status)

		hasDANE, _ := result["has_dane"].(bool)
		t.Logf("has_dane: %v", hasDANE)
	})
}

func TestLiveResultsShape(t *testing.T) {
	a := newLiveAnalyzer(t)
	ctx := context.Background()

	t.Run("nonexistent_domain", func(t *testing.T) {
		results := a.AnalyzeDomain(ctx, "this-domain-definitely-does-not-exist-xyzzy-12345.com", nil)
		exists, _ := results["domain_exists"].(bool)
		if exists {
			t.Error("nonexistent domain should return domain_exists=false")
		}
		success, _ := results["analysis_success"].(bool)
		if success {
			t.Error("nonexistent domain should return analysis_success=false")
		}

		aiSurface, ok := results["ai_surface"].(map[string]any)
		if !ok {
			t.Error("even nonexistent domain should have ai_surface section")
		} else {
			llms, _ := aiSurface["llms_txt"].(map[string]any)
			if llms != nil {
				found, _ := llms["found"].(bool)
				if found {
					t.Error("nonexistent domain should not have llms.txt found")
				}
			}
		}
	})

	t.Run("well_known_domain_google", func(t *testing.T) {
		start := time.Now()
		results := a.AnalyzeDomain(ctx, "google.com", nil)
		elapsed := time.Since(start)
		success, _ := results["analysis_success"].(bool)
		if !success {
			if elapsed > 55*time.Second {
				t.Skipf("google.com analysis timed out (%s)", elapsed)
			}
			t.Fatal("google.com should analyze successfully")
		}

		spf, _ := results["spf_analysis"].(map[string]any)
		spfStatus, _ := spf["status"].(string)
		if spfStatus == "not_found" {
			t.Error("google.com should have SPF — if this fails, google removed their SPF record (unlikely)")
		}

		dmarc, _ := results["dmarc_analysis"].(map[string]any)
		dmarcStatus, _ := dmarc["status"].(string)
		if dmarcStatus == "not_found" {
			t.Error("google.com should have DMARC — if this fails, google removed their DMARC record (unlikely)")
		}

		infra, _ := results["dns_infrastructure"].(map[string]any)
		provider, _ := infra["provider"].(string)
		t.Logf("google.com provider: %s", provider)
	})
}

func TestLiveAnalysisTimingReasonable(t *testing.T) {
	a := newLiveAnalyzer(t)
	ctx := context.Background()

	start := time.Now()
	results := a.AnalyzeDomain(ctx, ownerDomain, nil)
	elapsed := time.Since(start)

	success, _ := results["analysis_success"].(bool)
	if !success {
		if elapsed > 55*time.Second {
			t.Skipf("analysis timed out (%s) — orchestrator limit; timing test not applicable", elapsed)
		}
		t.Fatal("analysis failed — cannot assess timing")
	}

	t.Logf("Full analysis completed in %s", elapsed)

	if elapsed > 90*time.Second {
		t.Errorf("analysis took %s — exceeds 90s timeout, something may be hanging", elapsed)
	}

	if elapsed < 500*time.Millisecond {
		t.Log("WARNING: analysis completed suspiciously fast — may indicate cached or stubbed results")
	}

	scanTime, _ := results["scan_time"].(string)
	if scanTime != "" {
		t.Logf("Reported scan_time: %s", scanTime)
	}

	fmt.Printf("\n=== LIVE INTEGRATION TEST SUMMARY ===\n")
	fmt.Printf("Domain: %s\n", ownerDomain)
	fmt.Printf("Analysis time: %s\n", elapsed)
	if posture, ok := results["mail_posture"].(map[string]any); ok {
		fmt.Printf("Mail posture: %v\n", posture["classification"])
	}
	if infra, ok := results["dns_infrastructure"].(map[string]any); ok {
		fmt.Printf("Provider: %v (tier: %v)\n", infra["provider"], infra["provider_tier"])
	}
	if ai, ok := results["ai_surface"].(map[string]any); ok {
		fmt.Printf("AI surface: status=%v\n", ai["status"])
		if summary, ok := ai["summary"].(map[string]any); ok {
			fmt.Printf("  llms.txt: %v, blocks_ai: %v, allows_ai: %v\n",
				summary["has_llms_txt"], summary["blocks_ai"], summary["allows_ai"])
		}
	}
	fmt.Printf("=====================================\n")
}
