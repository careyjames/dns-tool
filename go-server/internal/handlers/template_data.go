// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

const (
        keyAppVersion      = "AppVersion"
        keyMaintenanceNote = "MaintenanceNote"
        keyBetaPages       = "BetaPages"
        keyCspNonce        = "CspNonce"
        keyActivePage      = "ActivePage"
)

type FlashMessage struct {
        Category string
        Message  string
}

type PaginationData struct {
        CurrentPage int
        TotalPages  int
        HasPrev     bool
        HasNext     bool
        PrevPage    int
        NextPage    int
        Pages       []PageItem
        Total       int64
}

type PageItem struct {
        Number   int
        IsActive bool
        IsGap    bool
}

func BuildPagination(currentPage, totalPages int, total int64) PaginationData {
        pd := PaginationData{
                CurrentPage: currentPage,
                TotalPages:  totalPages,
                HasPrev:     currentPage > 1,
                HasNext:     currentPage < totalPages,
                PrevPage:    currentPage - 1,
                NextPage:    currentPage + 1,
                Total:       total,
        }

        pd.Pages = iterPages(currentPage, totalPages)
        return pd
}

func iterPages(currentPage, totalPages int) []PageItem {
        var pages []PageItem
        leftEdge := 2
        rightEdge := 2
        leftCurrent := 2
        rightCurrent := 5

        lastWasGap := false
        for i := 1; i <= totalPages; i++ {
                if i <= leftEdge || i > totalPages-rightEdge ||
                        (i >= currentPage-leftCurrent && i <= currentPage+rightCurrent) {
                        pages = append(pages, PageItem{Number: i, IsActive: i == currentPage})
                        lastWasGap = false
                } else if !lastWasGap {
                        pages = append(pages, PageItem{IsGap: true})
                        lastWasGap = true
                }
        }
        return pages
}

type AnalysisItem struct {
        ID               int32
        Domain           string
        AsciiDomain      string
        SpfStatus        string
        DmarcStatus      string
        DkimStatus       string
        AnalysisSuccess  bool
        AnalysisDuration float64
        CreatedAt        string
        CreatedDate      string
        CreatedTime      string
        ToolVersion      string
        FullResults      map[string]interface{}
}

type CountryStat struct {
        Code  string
        Name  string
        Count int64
        Flag  string
}

type PopularDomain struct {
        Domain string
        Count  int64
}

type DailyStat struct {
        Date               string
        TotalAnalyses      int32
        SuccessfulAnalyses int32
        FailedAnalyses     int32
        UniqueDomains      int32
        AvgAnalysisTime    float64
        HasAvgTime         bool
}

type DiffItem struct {
        Label         string
        Icon          string
        Changed       bool
        StatusA       string
        StatusB       string
        DetailChanges []DiffChange
}

type DiffChange struct {
        Field  string
        Old    interface{}
        New    interface{}
        OldStr string
        NewStr string
        IsMap  bool
}

type CompareAnalysis struct {
        CreatedAt        string
        ToolVersion      string
        AnalysisDuration string
        HasToolVersion   bool
        HasDuration      bool
}
