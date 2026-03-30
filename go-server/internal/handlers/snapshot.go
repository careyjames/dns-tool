// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/sha3"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/db"

	"github.com/gin-gonic/gin"
)

const (
	snapshotSeparator      = "; ============================================================\n"
	snapshotNoneDiscovered = "; (none discovered)\n"
)

type SnapshotHandler struct {
	DB     *db.Database
	Config *config.Config
}

func NewSnapshotHandler(database *db.Database, cfg *config.Config) *SnapshotHandler {
	return &SnapshotHandler{DB: database, Config: cfg}
}

func (h *SnapshotHandler) Snapshot(c *gin.Context) {
	domain := strings.TrimSpace(strings.ToLower(c.Param(mapKeyDomain)))
	if domain == "" {
		c.String(http.StatusBadRequest, "Domain is required")
		return
	}

	ctx := c.Request.Context()
	analysis, err := h.DB.Queries.GetRecentAnalysisByDomain(ctx, domain)
	if err != nil {
		slog.Warn("Snapshot: no analysis found", mapKeyDomain, domain, "error", err)
		c.String(http.StatusNotFound, "No analysis found for domain: %s", domain)
		return
	}

	if analysis.Private {
		c.String(http.StatusNotFound, "No analysis found for domain: %s", domain)
		return
	}

	if len(analysis.FullResults) == 0 || string(analysis.FullResults) == "null" {
		c.String(http.StatusNotFound, "No results available for domain: %s", domain)
		return
	}

	var results map[string]any
	if err := json.Unmarshal(analysis.FullResults, &results); err != nil {
		slog.Error("Snapshot: failed to unmarshal results", mapKeyDomain, domain, "error", err)
		c.String(http.StatusInternalServerError, "Failed to process analysis results")
		return
	}

	snapshot := GenerateObservedSnapshot(domain, results, h.Config.AppVersion)

	hash := sha3.Sum512([]byte(snapshot))
	hashHex := fmt.Sprintf("%x", hash)

	snapshot += fmt.Sprintf(snapshotSeparator)
	snapshot += fmt.Sprintf("; END OF OBSERVED RECORDS SNAPSHOT\n")
	snapshot += fmt.Sprintf("; Integrity: SHA-3-512 hash of this document: %s\n", hashHex)
	snapshot += fmt.Sprintf(snapshotSeparator)

	timestamp := time.Now().UTC().Format("20060102_150405")
	safeDomain := strings.ReplaceAll(domain, ".", "_")
	filename := fmt.Sprintf("observed_records_%s_%s.txt", safeDomain, timestamp)

	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.String(http.StatusOK, snapshot)
}

func GenerateObservedSnapshot(domain string, results map[string]any, appVersion string) string {
	now := time.Now().UTC().Format(time.RFC3339)

	var sb strings.Builder

	sb.WriteString(snapshotSeparator)
	sb.WriteString("; OBSERVED RECORDS SNAPSHOT (RECONSTRUCTED)\n")
	sb.WriteString(snapshotSeparator)
	sb.WriteString(fmt.Sprintf("; Domain:     %s\n", domain))
	sb.WriteString(fmt.Sprintf("; Generated:  %s\n", now))
	sb.WriteString(fmt.Sprintf("; Tool:       DNS Tool v%s\n", appVersion))
	sb.WriteString("; Source:     Public DNS resolution (not authoritative zone transfer)\n")
	sb.WriteString(";\n")
	sb.WriteString("; IMPORTANT DISCLAIMERS:\n")
	sb.WriteString("; - This is NOT an authoritative zone file\n")
	sb.WriteString("; - Records were observed via public DNS queries, not zone transfer\n")
	sb.WriteString("; - This snapshot may be incomplete — only queried record types are shown\n")
	sb.WriteString("; - TTL values reflect resolver cache state at query time\n")
	sb.WriteString("; - Internal/unpublished records will not appear\n")
	sb.WriteString("; - Use for comparison and documentation purposes only\n")
	sb.WriteString(snapshotSeparator)
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("$ORIGIN %s.\n", domain))
	sb.WriteString("\n")

	basic := extractMapSafe(results, "basic_records")
	auth := extractMapSafe(results, "authoritative_records")
	ttls := extractTTLMap(results)

	fqdn := domain + "."

	writeRecordSection(&sb, "A Records", fqdn, extractStringSlice(basic, "A"), ttls, "A")
	writeRecordSection(&sb, "AAAA Records", fqdn, extractStringSlice(basic, "AAAA"), ttls, "AAAA")

	writeRecordSection(&sb, "MX Records", fqdn, extractStringSlice(basic, "MX"), ttls, "MX")
	writeRecordSection(&sb, "NS Records", fqdn, extractStringSlice(basic, "NS"), ttls, "NS")

	writeTXTSection(&sb, fqdn, basic, auth, results, domain, ttls)

	writeRecordSection(&sb, "SOA Record", fqdn, extractStringSlice(basic, "SOA"), ttls, "SOA")
	writeRecordSection(&sb, "CAA Records", fqdn, extractStringSlice(basic, "CAA"), ttls, "CAA")

	writeSRVSection(&sb, fqdn, extractStringSlice(basic, "SRV"))
	writeRecordSection(&sb, "CNAME Records", fqdn, extractStringSlice(basic, "CNAME"), ttls, "CNAME")

	return sb.String()
}

func writeTXTSection(sb *strings.Builder, fqdn string, basic, auth, results map[string]any, domain string, ttls map[string]uint32) {
	txtRecords := extractStringSlice(basic, "TXT")
	dmarcRecords := extractEmailSubdomainRecords(auth, results, "DMARC", "_dmarc", domain)
	mtaStsRecords := extractEmailSubdomainRecords(auth, results, "MTA-STS", "_mta-sts", domain)
	tlsRptRecords := extractEmailSubdomainRecords(auth, results, "TLS-RPT", "_smtp._tls", domain)

	hasTXT := len(txtRecords) > 0 || len(dmarcRecords) > 0 || len(mtaStsRecords) > 0 || len(tlsRptRecords) > 0
	if !hasTXT {
		return
	}
	sb.WriteString("; --- TXT Records (SPF, DMARC, DKIM, etc.) ---\n")
	ttl := getTTL(ttls, "TXT")
	for _, rec := range txtRecords {
		sb.WriteString(fmt.Sprintf("%s    %s    IN    TXT    \"%s\"\n", fqdn, ttl, escapeTXT(rec)))
	}
	for _, rec := range dmarcRecords {
		sb.WriteString(fmt.Sprintf("_dmarc.%s    3600    IN    TXT    \"%s\"\n", fqdn, escapeTXT(rec)))
	}
	for _, rec := range mtaStsRecords {
		sb.WriteString(fmt.Sprintf("_mta-sts.%s    3600    IN    TXT    \"%s\"\n", fqdn, escapeTXT(rec)))
	}
	for _, rec := range tlsRptRecords {
		sb.WriteString(fmt.Sprintf("_smtp._tls.%s    3600    IN    TXT    \"%s\"\n", fqdn, escapeTXT(rec)))
	}
	sb.WriteString("\n")
}

func writeSRVSection(sb *strings.Builder, fqdn string, srvRecords []string) {
	sb.WriteString("; --- SRV Records ---\n")
	if len(srvRecords) > 0 {
		for _, rec := range srvRecords {
			parts := strings.SplitN(rec, ": ", 2)
			if len(parts) == 2 {
				sb.WriteString(fmt.Sprintf("%s.%s    300    IN    SRV    %s\n", parts[0], fqdn, parts[1]))
			} else {
				sb.WriteString(fmt.Sprintf("%s    300    IN    SRV    %s\n", fqdn, rec))
			}
		}
	} else {
		sb.WriteString(snapshotNoneDiscovered)
	}
	sb.WriteString("\n")
}

func writeRecordSection(sb *strings.Builder, label, fqdn string, records []string, ttls map[string]uint32, rtype string) {
	sb.WriteString(fmt.Sprintf("; --- %s ---\n", label))
	if len(records) > 0 {
		ttl := getTTL(ttls, rtype)
		for _, rec := range records {
			sb.WriteString(fmt.Sprintf("%s    %s    IN    %s    %s\n", fqdn, ttl, rtype, rec))
		}
	} else {
		sb.WriteString(snapshotNoneDiscovered)
	}
	sb.WriteString("\n")
}

func extractMapSafe(results map[string]any, key string) map[string]any {
	if v, ok := results[key]; ok {
		if m, ok := v.(map[string]any); ok {
			return m
		}
	}
	return map[string]any{}
}

func extractTTLMap(results map[string]any) map[string]uint32 {
	ttls := make(map[string]uint32)

	rttl := results["resolver_ttl"]
	if rttl != nil {
		if m, ok := rttl.(map[string]any); ok {
			mergeTTLValues(ttls, m, false)
		}
	}

	basic := extractMapSafe(results, "basic_records")
	if ttlRaw, ok := basic["_ttl"]; ok {
		if m, ok := ttlRaw.(map[string]any); ok {
			mergeTTLValues(ttls, m, true)
		}
	}

	return ttls
}

func mergeTTLValues(ttls map[string]uint32, m map[string]any, skipExisting bool) {
	for k, v := range m {
		if skipExisting {
			if _, exists := ttls[k]; exists {
				continue
			}
		}
		switch val := v.(type) {
		case float64:
			ttls[k] = uint32(val)
		case json.Number:
			if n, err := val.Int64(); err == nil {
				ttls[k] = uint32(n)
			}
		}
	}
}

func extractStringSlice(m map[string]any, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	switch val := v.(type) {
	case []string:
		return val
	case []any:
		var result []string
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

func extractEmailSubdomainRecords(auth map[string]any, results map[string]any, authKey, prefix, domain string) []string {
	if recs := extractStringSlice(auth, authKey); len(recs) > 0 {
		return recs
	}

	var analysisKey string
	switch authKey {
	case "DMARC":
		analysisKey = "dmarc_analysis"
	case "MTA-STS":
		analysisKey = "mta_sts_analysis"
	case "TLS-RPT":
		analysisKey = "tlsrpt_analysis"
	default:
		return nil
	}

	analysisData := extractMapSafe(results, analysisKey)
	if rec, ok := analysisData["record"].(string); ok && rec != "" {
		return []string{rec}
	}
	if recs := extractStringSlice(analysisData, "valid_records"); len(recs) > 0 {
		return recs
	}

	return nil
}

func getTTL(ttls map[string]uint32, rtype string) string {
	if v, ok := ttls[rtype]; ok {
		return fmt.Sprintf("%d", v)
	}
	return "; TTL unknown"
}

func escapeTXT(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}
