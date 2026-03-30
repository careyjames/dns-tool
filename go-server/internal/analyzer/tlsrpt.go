// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

const (
	mapKeyRecord = "record"
	mapKeyRua    = "rua"
)

var tlsrptRUARe = regexp.MustCompile(`(?i)rua=([^;\s]+)`)

func (a *Analyzer) AnalyzeTLSRPT(ctx context.Context, domain string) map[string]any {
	tlsrptDomain := fmt.Sprintf("_smtp._tls.%s", domain)
	records := a.DNS.QueryDNS(ctx, dnsTypeTXT, tlsrptDomain)

	if len(records) == 0 {
		return map[string]any{
			mapKeyStatus:  "warning",
			mapKeyMessage: "No TLS-RPT record found",
			mapKeyRecord:  nil,
			mapKeyRua:     nil,
		}
	}

	var validRecords []string
	for _, r := range records {
		if strings.HasPrefix(strings.ToLower(r), "v=tlsrptv1") {
			validRecords = append(validRecords, r)
		}
	}

	if len(validRecords) == 0 {
		return map[string]any{
			mapKeyStatus:  "warning",
			mapKeyMessage: "No valid TLS-RPT record found",
			mapKeyRecord:  nil,
			mapKeyRua:     nil,
		}
	}

	record := validRecords[0]
	var rua *string
	if m := tlsrptRUARe.FindStringSubmatch(record); m != nil {
		rua = &m[1]
	}

	return map[string]any{
		mapKeyStatus:  "success",
		mapKeyMessage: "TLS-RPT configured - receiving TLS delivery reports",
		mapKeyRecord:  record,
		mapKeyRua:     derefStr(rua),
	}
}
