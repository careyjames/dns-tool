// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package icuae

type TestCategory struct {
        Name     string
        Standard string
        Cases    int
        Icon     string
}

type TestInventory struct {
        TotalCases      int
        TotalDimensions int
        Categories      []TestCategory
}

func GetTestInventory() *TestInventory {
        categories := []TestCategory{
                {Name: "Score-to-Grade Boundaries", Standard: "All Standards", Cases: 1, Icon: "ruler-combined"},
                {Name: "Currentness", Standard: "ISO/IEC 25012", Cases: 6, Icon: "clock"},
                {Name: "TTL Compliance", Standard: "RFC 8767", Cases: 5, Icon: "check-circle"},
                {Name: "Completeness", Standard: StandardNIST80053SI7, Cases: 4, Icon: "th"},
                {Name: "Source Credibility", Standard: "ISO/IEC 25012 + SPJ", Cases: 3, Icon: "users"},
                {Name: "TTL Relevance", Standard: StandardNIST80053SI7, Cases: 6, Icon: "balance-scale"},
                {Name: "Integration & Constants", Standard: "All Standards", Cases: 4, Icon: "cogs"},
        }

        total := 0
        for _, c := range categories {
                total += c.Cases
        }

        return &TestInventory{
                TotalCases:      total,
                TotalDimensions: 5,
                Categories:      categories,
        }
}
