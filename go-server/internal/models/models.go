// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package models

import (
	"encoding/json"
	"time"
)

const (
	mapKeyStatus               = "status"
	mapKeyDomain               = "domain"
	mapKeyASCIIDomain          = "ascii_domain"
	mapKeyBasicRecords         = "basic_records"
	mapKeyAuthoritativeRecords = "authoritative_records"
	mapKeyAnalysisSuccess      = "analysis_success"
	mapKeyAnalysisDuration     = "analysis_duration"
	mapKeyErrorMessage         = "error_message"
	mapKeyCreatedAt            = "created_at"
	mapKeyUpdatedAt            = "updated_at"
)

type DomainAnalysis struct {
	ID                   int             `json:"id" db:"id"`
	Domain               string          `json:"domain" db:"domain"`
	ASCIIDomain          string          `json:"ascii_domain" db:"ascii_domain"`
	BasicRecords         json.RawMessage `json:"basic_records" db:"basic_records"`
	AuthoritativeRecords json.RawMessage `json:"authoritative_records" db:"authoritative_records"`
	SPFStatus            *string         `json:"spf_status" db:"spf_status"`
	SPFRecords           json.RawMessage `json:"spf_records" db:"spf_records"`
	DMARCStatus          *string         `json:"dmarc_status" db:"dmarc_status"`
	DMARCPolicy          *string         `json:"dmarc_policy" db:"dmarc_policy"`
	DMARCRecords         json.RawMessage `json:"dmarc_records" db:"dmarc_records"`
	DKIMStatus           *string         `json:"dkim_status" db:"dkim_status"`
	DKIMSelectors        json.RawMessage `json:"dkim_selectors" db:"dkim_selectors"`
	RegistrarName        *string         `json:"registrar_name" db:"registrar_name"`
	RegistrarSource      *string         `json:"registrar_source" db:"registrar_source"`
	CountryCode          *string         `json:"country_code" db:"country_code"`
	CountryName          *string         `json:"country_name" db:"country_name"`
	CTSubdomains         json.RawMessage `json:"ct_subdomains" db:"ct_subdomains"`
	FullResults          json.RawMessage `json:"full_results" db:"full_results"`
	AnalysisSuccess      bool            `json:"analysis_success" db:"analysis_success"`
	ErrorMessage         *string         `json:"error_message" db:"error_message"`
	AnalysisDuration     *float64        `json:"analysis_duration" db:"analysis_duration"`
	CreatedAt            time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt            *time.Time      `json:"updated_at" db:"updated_at"`
}

const SchemaVersion = 2

var RequiredSections = []string{
	mapKeyBasicRecords, "spf_analysis", "dmarc_analysis",
	"dkim_analysis", "registrar_info", "posture",
	"dane_analysis", "mta_sts_analysis", "tlsrpt_analysis",
	"bimi_analysis", "caa_analysis", "dnssec_analysis",
}

type AnalysisStats struct {
	ID                 int        `json:"id" db:"id"`
	Date               time.Time  `json:"date" db:"date"`
	TotalAnalyses      int        `json:"total_analyses" db:"total_analyses"`
	SuccessfulAnalyses int        `json:"successful_analyses" db:"successful_analyses"`
	FailedAnalyses     int        `json:"failed_analyses" db:"failed_analyses"`
	UniqueDomains      int        `json:"unique_domains" db:"unique_domains"`
	AvgAnalysisTime    float64    `json:"avg_analysis_time" db:"avg_analysis_time"`
	CreatedAt          time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt          *time.Time `json:"updated_at" db:"updated_at"`
}

func (da *DomainAnalysis) ToDict() map[string]interface{} {
	result := map[string]interface{}{
		"id":                       da.ID,
		mapKeyDomain:               da.Domain,
		mapKeyASCIIDomain:          da.ASCIIDomain,
		mapKeyBasicRecords:         da.BasicRecords,
		mapKeyAuthoritativeRecords: da.AuthoritativeRecords,
		"spf_analysis": map[string]interface{}{
			mapKeyStatus: da.SPFStatus,
			"records":    da.SPFRecords,
		},
		"dmarc_analysis": map[string]interface{}{
			mapKeyStatus: da.DMARCStatus,
			"policy":     da.DMARCPolicy,
			"records":    da.DMARCRecords,
		},
		"dkim_analysis": map[string]interface{}{
			mapKeyStatus: da.DKIMStatus,
			"selectors":  da.DKIMSelectors,
		},
		"registrar_info": map[string]interface{}{
			"registrar": da.RegistrarName,
			"source":    da.RegistrarSource,
		},
		mapKeyAnalysisSuccess:  da.AnalysisSuccess,
		mapKeyErrorMessage:     da.ErrorMessage,
		mapKeyAnalysisDuration: da.AnalysisDuration,
	}
	if !da.CreatedAt.IsZero() {
		result[mapKeyCreatedAt] = da.CreatedAt.Format(time.RFC3339)
	}
	if da.UpdatedAt != nil {
		result[mapKeyUpdatedAt] = da.UpdatedAt.Format(time.RFC3339)
	}
	return result
}
