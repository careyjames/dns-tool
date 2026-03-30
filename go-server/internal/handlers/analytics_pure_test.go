package handlers

import (
        "context"
        "testing"
)

func TestTopN(t *testing.T) {
        t.Run("empty map", func(t *testing.T) {
                result := topN(nil, 5)
                if len(result) != 0 {
                        t.Errorf("expected 0, got %d", len(result))
                }
        })

        t.Run("fewer than n", func(t *testing.T) {
                m := map[string]int{"google": 10, "bing": 5}
                result := topN(m, 5)
                if len(result) != 2 {
                        t.Fatalf("expected 2, got %d", len(result))
                }
                if result[0].Source != "google" || result[0].Count != 10 {
                        t.Errorf("first entry = %+v, want google/10", result[0])
                }
                if result[1].Source != "bing" || result[1].Count != 5 {
                        t.Errorf("second entry = %+v, want bing/5", result[1])
                }
        })

        t.Run("more than n truncates", func(t *testing.T) {
                m := map[string]int{
                        "a": 100, "b": 90, "c": 80, "d": 70, "e": 60,
                        "f": 50, "g": 40, "h": 30, "i": 20, "j": 10, "k": 5,
                }
                result := topN(m, 3)
                if len(result) != 3 {
                        t.Fatalf("expected 3, got %d", len(result))
                }
                if result[0].Count != 100 {
                        t.Errorf("first count = %d, want 100", result[0].Count)
                }
                if result[1].Count != 90 {
                        t.Errorf("second count = %d, want 90", result[1].Count)
                }
                if result[2].Count != 80 {
                        t.Errorf("third count = %d, want 80", result[2].Count)
                }
        })

        t.Run("sorted descending", func(t *testing.T) {
                m := map[string]int{"z": 1, "y": 50, "x": 25}
                result := topN(m, 10)
                for i := 1; i < len(result); i++ {
                        if result[i].Count > result[i-1].Count {
                                t.Errorf("not sorted: %d > %d at index %d", result[i].Count, result[i-1].Count, i)
                        }
                }
        })
}

func TestTopNPages(t *testing.T) {
        t.Run("empty map", func(t *testing.T) {
                result := topNPages(nil, 5)
                if len(result) != 0 {
                        t.Errorf("expected 0, got %d", len(result))
                }
        })

        t.Run("fewer than n", func(t *testing.T) {
                m := map[string]int{"/home": 100, "/about": 50}
                result := topNPages(m, 5)
                if len(result) != 2 {
                        t.Fatalf("expected 2, got %d", len(result))
                }
                if result[0].Path != "/home" || result[0].Count != 100 {
                        t.Errorf("first = %+v, want /home/100", result[0])
                }
        })

        t.Run("more than n truncates", func(t *testing.T) {
                m := map[string]int{
                        "/a": 10, "/b": 20, "/c": 30, "/d": 40, "/e": 50,
                }
                result := topNPages(m, 3)
                if len(result) != 3 {
                        t.Fatalf("expected 3, got %d", len(result))
                }
                if result[0].Count != 50 {
                        t.Errorf("top count = %d, want 50", result[0].Count)
                }
        })

        t.Run("sorted descending", func(t *testing.T) {
                m := map[string]int{"/x": 5, "/y": 500, "/z": 50}
                result := topNPages(m, 10)
                for i := 1; i < len(result); i++ {
                        if result[i].Count > result[i-1].Count {
                                t.Errorf("not sorted: %d > %d at index %d", result[i].Count, result[i-1].Count, i)
                        }
                }
        })
}

func TestNewAnalyticsHandler(t *testing.T) {
        h := NewAnalyticsHandler(nil, nil)
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
        if h.DB != nil {
                t.Error("expected nil DB when constructed with nil")
        }
        if h.Config != nil {
                t.Error("expected nil Config when constructed with nil")
        }
}

func TestComputeSummary_EmptyDays(t *testing.T) {
        h := NewAnalyticsHandler(nil, nil)
        s := h.computeSummary(context.Background(), nil)
        if s.DaysTracked != 0 {
                t.Errorf("DaysTracked = %d, want 0", s.DaysTracked)
        }
        if s.TotalPageviews != 0 {
                t.Errorf("TotalPageviews = %d, want 0", s.TotalPageviews)
        }
        if s.AvgDailyPageviews != 0 {
                t.Errorf("AvgDailyPageviews = %d, want 0", s.AvgDailyPageviews)
        }
}

func TestComputeSummary_AggregatesCorrectly(t *testing.T) {
        h := NewAnalyticsHandler(nil, nil)
        days := []AnalyticsDay{
                {
                        Date:                  "2024-01-01",
                        Pageviews:             100,
                        UniqueVisitors:        40,
                        AnalysesRun:           10,
                        UniqueDomainsAnalyzed: 5,
                        ReferrerSources:       map[string]int{"google": 20, "bing": 5},
                        TopPages:              map[string]int{"/": 60, "/about": 30},
                },
                {
                        Date:                  "2024-01-02",
                        Pageviews:             200,
                        UniqueVisitors:        60,
                        AnalysesRun:           20,
                        UniqueDomainsAnalyzed: 15,
                        ReferrerSources:       map[string]int{"google": 30, "duckduckgo": 10},
                        TopPages:              map[string]int{"/": 100, "/contact": 50},
                },
        }
        s := h.computeSummary(context.Background(), days)

        if s.DaysTracked != 2 {
                t.Errorf("DaysTracked = %d, want 2", s.DaysTracked)
        }
        if s.TotalPageviews != 300 {
                t.Errorf("TotalPageviews = %d, want 300", s.TotalPageviews)
        }
        if s.TotalUniqueVisitors != 100 {
                t.Errorf("TotalUniqueVisitors = %d, want 100", s.TotalUniqueVisitors)
        }
        if s.TotalAnalyses != 30 {
                t.Errorf("TotalAnalyses = %d, want 30", s.TotalAnalyses)
        }
        if s.TotalUniqueDomains != 20 {
                t.Errorf("TotalUniqueDomains = %d, want 20", s.TotalUniqueDomains)
        }
        if s.AvgDailyPageviews != 150 {
                t.Errorf("AvgDailyPageviews = %d, want 150", s.AvgDailyPageviews)
        }
        if s.AvgDailyVisitors != 50 {
                t.Errorf("AvgDailyVisitors = %d, want 50", s.AvgDailyVisitors)
        }
        if len(s.TopReferrers) != 3 {
                t.Fatalf("TopReferrers count = %d, want 3", len(s.TopReferrers))
        }
        if s.TopReferrers[0].Source != "google" || s.TopReferrers[0].Count != 50 {
                t.Errorf("top referrer = %+v, want google/50", s.TopReferrers[0])
        }
        if len(s.TopPages) != 3 {
                t.Fatalf("TopPages count = %d, want 3", len(s.TopPages))
        }
        if s.TopPages[0].Path != "/" || s.TopPages[0].Count != 160 {
                t.Errorf("top page = %+v, want //160", s.TopPages[0])
        }
}

func TestComputeSummary_SingleDay(t *testing.T) {
        h := NewAnalyticsHandler(nil, nil)
        days := []AnalyticsDay{
                {
                        Date:                  "2024-06-15",
                        Pageviews:             500,
                        UniqueVisitors:        200,
                        AnalysesRun:           50,
                        UniqueDomainsAnalyzed: 30,
                        ReferrerSources:       map[string]int{"twitter": 100},
                        TopPages:              map[string]int{"/pricing": 300},
                },
        }
        s := h.computeSummary(context.Background(), days)
        if s.AvgDailyPageviews != 500 {
                t.Errorf("AvgDailyPageviews = %d, want 500 for single day", s.AvgDailyPageviews)
        }
        if s.AvgDailyVisitors != 200 {
                t.Errorf("AvgDailyVisitors = %d, want 200 for single day", s.AvgDailyVisitors)
        }
}
