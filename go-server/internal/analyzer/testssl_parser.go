// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny science
package analyzer

import (
        "encoding/json"
        "strings"
)

const (
        strCritical = "CRITICAL"
        strHigh     = "HIGH"
)

type TestSSLFinding struct {
        ID       string `json:"id"`
        Severity string `json:"severity"`
        Finding  string `json:"finding"`
        CWE      string `json:"cwe,omitempty"`
        CVE      string `json:"cve,omitempty"`
}

type TestSSLResult struct {
        Protocols       []TestSSLFinding `json:"protocols"`
        Ciphers         []TestSSLFinding `json:"ciphers"`
        Vulnerabilities []TestSSLFinding `json:"vulnerabilities"`
        CertInfo        []TestSSLFinding `json:"cert_info"`
        HSTS            *TestSSLFinding  `json:"hsts,omitempty"`
        OCSP            *TestSSLFinding  `json:"ocsp,omitempty"`

        TLS13Supported bool     `json:"tls13_supported"`
        TLS12Supported bool     `json:"tls12_supported"`
        TLS11Supported bool     `json:"tls11_supported"`
        TLS10Supported bool     `json:"tls10_supported"`
        SSL3Supported  bool     `json:"ssl3_supported"`
        SSL2Supported  bool     `json:"ssl2_supported"`
        VulnIDs        []string `json:"vuln_ids"`
        OverallRating  string   `json:"overall_rating"`
        Issues         []string `json:"issues"`
}

func ParseTestSSLJSON(data []byte) (*TestSSLResult, error) {
        var raw []TestSSLFinding
        if err := json.Unmarshal(data, &raw); err != nil {
                var single TestSSLFinding
                if err2 := json.Unmarshal(data, &single); err2 != nil {
                        return nil, err
                }
                raw = []TestSSLFinding{single}
        }

        result := &TestSSLResult{}
        classifyFindings(result, raw)
        analyzeProtocols(result)
        analyzeVulnerabilities(result)
        rateOverall(result)
        return result, nil
}

func classifyFindings(result *TestSSLResult, findings []TestSSLFinding) {
        for _, f := range findings {
                id := strings.ToLower(f.ID)
                switch {
                case strings.HasPrefix(id, "sslv2") || strings.HasPrefix(id, "sslv3") ||
                        strings.HasPrefix(id, "tls1") || strings.HasPrefix(id, "tls1_1") ||
                        strings.HasPrefix(id, "tls1_2") || strings.HasPrefix(id, "tls1_3"):
                        result.Protocols = append(result.Protocols, f)
                case strings.Contains(id, "cipher") || strings.HasPrefix(id, "cipherorder") ||
                        strings.HasPrefix(id, "cipher_") || strings.HasPrefix(id, "fs"):
                        result.Ciphers = append(result.Ciphers, f)
                case strings.HasPrefix(id, "cert") || strings.HasPrefix(id, "cert_") ||
                        strings.Contains(id, "certificate"):
                        result.CertInfo = append(result.CertInfo, f)
                case strings.HasPrefix(id, "hsts"):
                        result.HSTS = &f
                case strings.HasPrefix(id, "ocsp"):
                        result.OCSP = &f
                case isVulnerability(id):
                        result.Vulnerabilities = append(result.Vulnerabilities, f)
                default:
                        if f.Severity == strCritical || f.Severity == strHigh || f.Severity == "MEDIUM" {
                                result.Vulnerabilities = append(result.Vulnerabilities, f)
                        }
                }
        }
}

func isVulnerability(id string) bool {
        vulnPrefixes := []string{
                "heartbleed", "ccs", "ticketbleed", "robot", "secure_renego",
                "secure_client_renego", "crime", "breach", "poodle", "sweet32",
                "freak", "drown", "logjam", "beast", "lucky13", "rc4",
                "fallback_scsv", "cve-", "winshock",
        }
        for _, prefix := range vulnPrefixes {
                if strings.HasPrefix(id, prefix) || strings.Contains(id, prefix) {
                        return true
                }
        }
        return false
}

func analyzeProtocols(result *TestSSLResult) {
        for _, p := range result.Protocols {
                id := strings.ToLower(p.ID)
                finding := strings.ToLower(p.Finding)
                offered := strings.Contains(finding, "offered") && !strings.Contains(finding, "not offered")

                switch {
                case strings.Contains(id, "tls1_3"):
                        result.TLS13Supported = offered
                case strings.Contains(id, "tls1_2"):
                        result.TLS12Supported = offered
                case strings.Contains(id, "tls1_1"):
                        result.TLS11Supported = offered
                case id == "tls1" || strings.HasSuffix(id, "tls1_0"):
                        result.TLS10Supported = offered
                case strings.Contains(id, "sslv3"):
                        result.SSL3Supported = offered
                case strings.Contains(id, "sslv2"):
                        result.SSL2Supported = offered
                }
        }
}

func analyzeVulnerabilities(result *TestSSLResult) {
        for _, v := range result.Vulnerabilities {
                sev := strings.ToUpper(v.Severity)
                finding := strings.ToLower(v.Finding)
                vulnerable := strings.Contains(finding, "vulnerable") ||
                        strings.Contains(finding, "offered") ||
                        sev == strCritical || sev == strHigh

                if vulnerable && !strings.Contains(finding, "not vulnerable") &&
                        !strings.Contains(finding, "not offered") {
                        result.VulnIDs = append(result.VulnIDs, v.ID)
                        issue := v.ID
                        if v.CVE != "" {
                                issue += " (" + v.CVE + ")"
                        }
                        issue += ": " + v.Finding
                        result.Issues = append(result.Issues, issue)
                }
        }

        if result.SSL2Supported {
                result.Issues = append(result.Issues, "SSLv2 supported — obsolete and insecure (RFC 6176)")
        }
        if result.SSL3Supported {
                result.Issues = append(result.Issues, "SSLv3 supported — vulnerable to POODLE (RFC 7568)")
        }
        if result.TLS10Supported {
                result.Issues = append(result.Issues, "TLS 1.0 supported — deprecated (RFC 8996)")
        }
        if result.TLS11Supported {
                result.Issues = append(result.Issues, "TLS 1.1 supported — deprecated (RFC 8996)")
        }
}

func rateOverall(result *TestSSLResult) {
        if result.SSL2Supported || result.SSL3Supported {
                result.OverallRating = "critical"
                return
        }

        critCount := 0
        highCount := 0
        for _, v := range result.Vulnerabilities {
                sev := strings.ToUpper(v.Severity)
                if sev == strCritical {
                        critCount++
                }
                if sev == strHigh {
                        highCount++
                }
        }

        if critCount > 0 {
                result.OverallRating = "critical"
        } else if highCount > 0 || len(result.VulnIDs) > 0 {
                result.OverallRating = "warning"
        } else if !result.TLS13Supported && !result.TLS12Supported {
                result.OverallRating = "warning"
        } else {
                result.OverallRating = "good"
        }
}
