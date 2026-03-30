// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package zoneparse

import (
        "fmt"
        "golang.org/x/crypto/sha3"
        "io"
        "sort"
        "strings"

        "codeberg.org/miekg/dns"
        "codeberg.org/miekg/dns/dnsutil"
)

type ParsedRecord struct {
        Name  string `json:"name"`
        TTL   uint32 `json:"ttl"`
        Class string `json:"class"`
        Type  string `json:"type"`
        RData string `json:"rdata"`
}

type ParseResult struct {
        Domain        string         `json:"domain"`
        Records       []ParsedRecord `json:"records"`
        RecordCount   int            `json:"record_count"`
        IntegrityHash string         `json:"sha3_512"`
        ParseErrors   []string       `json:"parse_errors,omitempty"`
}

func detectDomain(origin string, records []ParsedRecord) string {
        domain := strings.TrimSuffix(origin, ".")
        if domain != "" || len(records) == 0 {
                return domain
        }
        for _, r := range records {
                if r.Type == "SOA" {
                        return strings.TrimSuffix(r.Name, ".")
                }
        }
        return strings.TrimSuffix(records[0].Name, ".")
}

func ParseZoneFile(r io.Reader, origin string) (*ParseResult, []byte, error) {
        raw, err := io.ReadAll(r)
        if err != nil {
                return nil, nil, fmt.Errorf("failed to read zone file: %w", err)
        }

        hash := sha3.Sum512(raw)
        hashHex := fmt.Sprintf("%x", hash)

        if origin != "" && !strings.HasSuffix(origin, ".") {
                origin = origin + "."
        }

        zp := dns.NewZoneParser(strings.NewReader(string(raw)), origin, "")

        var records []ParsedRecord
        var parseErrors []string

        for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
                hdr := rr.Header()
                rrtype := dns.RRToType(rr)
                rec := ParsedRecord{
                        Name:  strings.ToLower(hdr.Name),
                        TTL:   hdr.TTL,
                        Class: dns.ClassToString[hdr.Class],
                        Type:  dnsutil.TypeToString(rrtype),
                }
                if rr.Data() != nil {
                        rec.RData = rr.Data().String()
                }
                records = append(records, rec)
        }

        if err := zp.Err(); err != nil {
                parseErrors = append(parseErrors, err.Error())
        }

        domain := detectDomain(origin, records)

        sort.Slice(records, func(i, j int) bool {
                if records[i].Type != records[j].Type {
                        return records[i].Type < records[j].Type
                }
                return records[i].Name < records[j].Name
        })

        result := &ParseResult{
                Domain:        domain,
                Records:       records,
                RecordCount:   len(records),
                IntegrityHash: hashHex,
                ParseErrors:   parseErrors,
        }

        return result, raw, nil
}
