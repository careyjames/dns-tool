// dns-tool:scrutiny science
package citation

import (
        "fmt"
        "os"
        "regexp"
        "strings"
)

type ValidationResult struct {
        Missing  []string
        Extra    []string
        OK       bool
        Messages []string
}

var rfcNumberRe = regexp.MustCompile(`\b(\d{3,5})\b`)

func ValidateAuthoritiesMD(path string) (*ValidationResult, error) {
        data, err := os.ReadFile(path)
        if err != nil {
                return nil, fmt.Errorf("read AUTHORITIES.md: %w", err)
        }

        content := string(data)
        reg := Global()
        result := &ValidationResult{OK: true}

        registryRFCIDs := checkRegistryMissing(reg, content, result)
        mdRFCNums := extractMDRFCNumbers(content)
        checkExtraRFCs(reg, registryRFCIDs, mdRFCNums, result)

        return result, nil
}

func checkRegistryMissing(reg *Registry, content string, result *ValidationResult) map[string]bool {
        registryRFCIDs := make(map[string]bool)
        for _, e := range reg.All() {
                if e.Type != "rfc" && e.Type != "draft" {
                        continue
                }
                rfcNum := strings.TrimPrefix(e.ID, "rfc:")
                rfcNum = strings.TrimPrefix(rfcNum, "draft:")
                registryRFCIDs[rfcNum] = true

                if !strings.Contains(content, rfcNum) {
                        result.Missing = append(result.Missing, e.ID)
                        result.Messages = append(result.Messages,
                                fmt.Sprintf("MISSING: %s (%s) not found in AUTHORITIES.md", e.ID, e.Title))
                        result.OK = false
                }
        }
        return registryRFCIDs
}

func extractMDRFCNumbers(content string) map[string]bool {
        lines := strings.Split(content, "\n")
        mdRFCNums := make(map[string]bool)
        for _, line := range lines {
                if !strings.Contains(line, "|") {
                        continue
                }
                cols := strings.Split(line, "|")
                if len(cols) < 3 {
                        continue
                }
                cell := strings.TrimSpace(cols[1])
                if cell == "RFC" || cell == "Draft" || strings.Contains(cell, "---") {
                        continue
                }
                parts := strings.Split(cell, "/")
                for _, part := range parts {
                        part = strings.TrimSpace(part)
                        matches := rfcNumberRe.FindAllString(part, -1)
                        for _, m := range matches {
                                mdRFCNums[m] = true
                        }
                }
        }
        return mdRFCNums
}

func checkExtraRFCs(reg *Registry, registryRFCIDs, mdRFCNums map[string]bool, result *ValidationResult) {
        for num := range mdRFCNums {
                if registryRFCIDs[num] {
                        continue
                }
                rfcID := "rfc:" + num
                draftID := "draft:" + num
                _, rfcExists := reg.Lookup(rfcID)
                _, draftExists := reg.Lookup(draftID)
                if !rfcExists && !draftExists {
                        result.Extra = append(result.Extra, rfcID)
                        result.Messages = append(result.Messages,
                                fmt.Sprintf("EXTRA: RFC %s found in AUTHORITIES.md but not in citation registry", num))
                        result.OK = false
                }
        }
}
