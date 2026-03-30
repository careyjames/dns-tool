// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	mapKeyRfcNum = "rfc"
)

type RFCMetadata struct {
	Number      string    `json:"number"`
	Title       string    `json:"title"`
	Status      string    `json:"status"`
	Stream      string    `json:"stream"`
	ObsoletedBy []string  `json:"obsoleted_by,omitempty"`
	UpdatedBy   []string  `json:"updated_by,omitempty"`
	IsObsolete  bool      `json:"is_obsolete"`
	FetchedAt   time.Time `json:"fetched_at"`
}

type ietfDocResponse struct {
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	Stream      string   `json:"stream"`
	StdLevel    string   `json:"std_level"`
	States      []string `json:"states"`
	ObsoletedBy []string `json:"obsoleted_by"`
	UpdatedBy   []string `json:"updated_by"`
}

var (
	rfcCache            map[string]*RFCMetadata
	rfcCacheMu          sync.RWMutex
	rfcCacheTTL         = 24 * time.Hour
	rfcCacheLastRefresh time.Time

	ietfHTTPClient = &http.Client{
		Timeout: 15 * time.Second,
	}

	referencedRFCs = []string{
		"1035", "3596", "3207",
		"4033", "4034", "4035",
		"5321",
		"6376",
		"6698", "6962",
		"7208", "7489", "7672",
		"8078", "8301", "8460", "8461", "8659",
		"9083", "9460", "9495",
	}
)

func InitIETFMetadata() {
	rfcCacheMu.Lock()
	rfcCache = make(map[string]*RFCMetadata)
	rfcCacheMu.Unlock()

	go refreshRFCCache()
}

func refreshRFCCache() {
	slog.Info("IETF metadata: starting bulk RFC metadata fetch", "count", len(referencedRFCs))

	fetched := 0
	for _, rfc := range referencedRFCs {
		meta := fetchSingleRFC(rfc)
		if meta != nil {
			rfcCacheMu.Lock()
			rfcCache[rfc] = meta
			rfcCacheMu.Unlock()
			fetched++
		}
		time.Sleep(200 * time.Millisecond)
	}

	rfcCacheMu.Lock()
	rfcCacheLastRefresh = time.Now()
	rfcCacheMu.Unlock()

	slog.Info("IETF metadata: bulk fetch complete", "fetched", fetched, "total", len(referencedRFCs))
}

func fetchSingleRFC(number string) *RFCMetadata {
	docName := fmt.Sprintf("rfc%s", number)
	url := fmt.Sprintf("https://datatracker.ietf.org/api/v1/doc/document/%s/?format=json", docName)

	resp, err := ietfHTTPClient.Get(url)
	if err != nil {
		slog.Debug("IETF metadata: fetch failed", mapKeyRfcNum, number, "error", err)
		return nil
	}
	defer safeClose(resp.Body, "ietf-metadata")

	if resp.StatusCode != http.StatusOK {
		slog.Debug("IETF metadata: unexpected status", mapKeyRfcNum, number, mapKeyStatus, resp.StatusCode)
		return nil
	}

	var doc ietfDocResponse
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		slog.Debug("IETF metadata: parse failed", mapKeyRfcNum, number, "error", err)
		return nil
	}

	status := classifyRFCStatus(doc)
	isObsolete := len(doc.ObsoletedBy) > 0

	obsoletedBy := extractRFCNumbers(doc.ObsoletedBy)
	updatedBy := extractRFCNumbers(doc.UpdatedBy)

	return &RFCMetadata{
		Number:      number,
		Title:       doc.Title,
		Status:      status,
		Stream:      doc.Stream,
		ObsoletedBy: obsoletedBy,
		UpdatedBy:   updatedBy,
		IsObsolete:  isObsolete,
		FetchedAt:   time.Now(),
	}
}

func classifyRFCStatus(doc ietfDocResponse) string {
	if doc.StdLevel != "" {
		switch {
		case strings.Contains(doc.StdLevel, "/std/"):
			return "Internet Standard"
		case strings.Contains(doc.StdLevel, "/ds/"):
			return "Draft Standard"
		case strings.Contains(doc.StdLevel, "/ps/"):
			return "Proposed Standard"
		case strings.Contains(doc.StdLevel, "/bcp/"):
			return "Best Current Practice"
		case strings.Contains(doc.StdLevel, "/inf/"):
			return "Informational"
		case strings.Contains(doc.StdLevel, "/exp/"):
			return "Experimental"
		case strings.Contains(doc.StdLevel, "/hist/"):
			return "Historic"
		}
	}

	return "Published"
}

func extractRFCNumbers(refs []string) []string {
	var numbers []string
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if strings.Contains(ref, mapKeyRfcNum) {
			parts := strings.Split(ref, "/")
			for _, p := range parts {
				if strings.HasPrefix(p, mapKeyRfcNum) {
					num := strings.TrimPrefix(p, mapKeyRfcNum)
					num = strings.TrimSuffix(num, "/")
					if num != "" {
						numbers = append(numbers, num)
					}
				}
			}
		}
	}
	return numbers
}

func GetRFCMetadata(number string) *RFCMetadata {
	number = strings.TrimPrefix(strings.ToLower(number), mapKeyRfcNum)
	number = strings.TrimSpace(number)

	rfcCacheMu.RLock()
	meta, ok := rfcCache[number]
	rfcCacheMu.RUnlock()

	if ok {
		return meta
	}

	return nil
}

func GetAllRFCMetadata() map[string]map[string]any {
	rfcCacheMu.RLock()
	defer rfcCacheMu.RUnlock()

	result := make(map[string]map[string]any, len(rfcCache))
	for k, v := range rfcCache {
		entry := map[string]any{
			"number":      v.Number,
			"title":       v.Title,
			mapKeyStatus:  v.Status,
			"is_obsolete": v.IsObsolete,
		}
		if len(v.ObsoletedBy) > 0 {
			entry["obsoleted_by"] = v.ObsoletedBy
		}
		if len(v.UpdatedBy) > 0 {
			entry["updated_by"] = v.UpdatedBy
		}
		result[k] = entry
	}
	return result
}

func GetObsoleteWarnings() []map[string]any {
	rfcCacheMu.RLock()
	defer rfcCacheMu.RUnlock()

	var warnings []map[string]any
	for _, meta := range rfcCache {
		if meta.IsObsolete {
			warnings = append(warnings, map[string]any{
				mapKeyRfcNum:   fmt.Sprintf("RFC %s", meta.Number),
				"title":        meta.Title,
				"obsoleted_by": meta.ObsoletedBy,
				mapKeyStatus:   meta.Status,
			})
		}
	}
	return warnings
}

func EnrichRemediationWithRFCMeta(remediation map[string]any) map[string]any {
	allFixes, ok := remediation["all_fixes"].([]map[string]any)
	if !ok {
		return remediation
	}

	enrichFixesWithRFCMeta(allFixes)

	topFixes, ok := remediation["top_fixes"].([]map[string]any)
	if ok {
		enrichFixesWithRFCMeta(topFixes)
	}

	remediation["rfc_metadata_enriched"] = true
	return remediation
}

func enrichFixesWithRFCMeta(fixes []map[string]any) {
	for i, fix := range fixes {
		rfcRef, _ := fix[mapKeyRfcNum].(string)
		if rfcRef == "" {
			continue
		}
		number := extractRFCNumberFromRef(rfcRef)
		if number == "" {
			continue
		}
		meta := GetRFCMetadata(number)
		if meta == nil {
			continue
		}
		applyRFCMetaToFix(fixes[i], meta)
	}
}

func applyRFCMetaToFix(fix map[string]any, meta *RFCMetadata) {
	fix["rfc_title"] = meta.Title
	fix["rfc_status"] = meta.Status
	fix["rfc_obsolete"] = meta.IsObsolete
	if meta.IsObsolete && len(meta.ObsoletedBy) > 0 {
		fix["rfc_obsoleted_by"] = meta.ObsoletedBy
	}
}

func extractRFCNumberFromRef(ref string) string {
	ref = strings.TrimSpace(ref)
	ref = strings.TrimPrefix(ref, "RFC ")
	ref = strings.TrimPrefix(ref, mapKeyRfcNum)

	parts := strings.Fields(ref)
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

func ScheduleRFCRefresh() {
	go func() {
		ticker := time.NewTicker(rfcCacheTTL)
		defer ticker.Stop()
		for range ticker.C {
			refreshRFCCache()
		}
	}()
}
