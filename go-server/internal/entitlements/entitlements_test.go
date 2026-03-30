// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny plumbing
package entitlements

import "testing"

func TestResolvePlan(t *testing.T) {
        tests := []struct {
                name               string
                authenticated      bool
                role               string
                subscriptionActive bool
                want               Plan
        }{
                {"anonymous visitor", false, "", false, PlanAnonymous},
                {"anonymous ignores subscription", false, "", true, PlanAnonymous},
                {"registered user", true, "user", false, PlanRegistered},
                {"premium subscriber", true, "user", true, PlanPremium},
                {"admin always premium", true, "admin", false, PlanPremium},
                {"admin with subscription", true, "admin", true, PlanPremium},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := ResolvePlan(tt.authenticated, tt.role, tt.subscriptionActive)
                        if got != tt.want {
                                t.Errorf("ResolvePlan(%v, %q, %v) = %q, want %q",
                                        tt.authenticated, tt.role, tt.subscriptionActive, got, tt.want)
                        }
                })
        }
}

func TestHasAccess(t *testing.T) {
        tests := []struct {
                name    string
                plan    Plan
                feature Feature
                want    bool
        }{
                {"anonymous can't access personal history", PlanAnonymous, FeaturePersonalHistory, false},
                {"anonymous can't access watchlist", PlanAnonymous, FeatureWatchlist, false},
                {"anonymous can't access bulk scan", PlanAnonymous, FeatureBulkScan, false},
                {"registered can access personal history", PlanRegistered, FeaturePersonalHistory, true},
                {"registered can access watchlist", PlanRegistered, FeatureWatchlist, true},
                {"registered can access dossier", PlanRegistered, FeatureDossier, true},
                {"registered can access zone upload", PlanRegistered, FeatureZoneUpload, true},
                {"registered can't access bulk scan", PlanRegistered, FeatureBulkScan, false},
                {"registered can't access API keys", PlanRegistered, FeatureAPIKeys, false},
                {"registered can't access bulk export", PlanRegistered, FeatureBulkExport, false},
                {"premium can access personal history", PlanPremium, FeaturePersonalHistory, true},
                {"premium can access bulk scan", PlanPremium, FeatureBulkScan, true},
                {"premium can access API keys", PlanPremium, FeatureAPIKeys, true},
                {"premium can access bulk export", PlanPremium, FeatureBulkExport, true},
                {"premium can access priority queue", PlanPremium, FeaturePriorityQueue, true},
                {"premium can access webhook scale", PlanPremium, FeatureWebhookScale, true},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := HasAccess(tt.plan, tt.feature)
                        if got != tt.want {
                                t.Errorf("HasAccess(%q, %q) = %v, want %v",
                                        tt.plan, tt.feature, got, tt.want)
                        }
                })
        }
}

func TestHasAccessUnregisteredFeature(t *testing.T) {
        got := HasAccess(PlanAnonymous, Feature("nonexistent_feature"))
        if !got {
                t.Error("unregistered features should be open to all plans")
        }
}

func TestMinimumPlan(t *testing.T) {
        if p := MinimumPlan(FeaturePersonalHistory); p != PlanRegistered {
                t.Errorf("MinimumPlan(FeaturePersonalHistory) = %q, want %q", p, PlanRegistered)
        }
        if p := MinimumPlan(FeatureBulkScan); p != PlanPremium {
                t.Errorf("MinimumPlan(FeatureBulkScan) = %q, want %q", p, PlanPremium)
        }
        if p := MinimumPlan(Feature("open_feature")); p != PlanAnonymous {
                t.Errorf("MinimumPlan(open_feature) = %q, want %q", p, PlanAnonymous)
        }
}

func TestAllFeatures(t *testing.T) {
        all := AllFeatures()
        if len(all) != len(Registry) {
                t.Errorf("AllFeatures() returned %d features, Registry has %d", len(all), len(Registry))
        }
        all[FeaturePersonalHistory] = PlanPremium
        if Registry[FeaturePersonalHistory] != PlanRegistered {
                t.Error("AllFeatures() must return a copy, not the original registry")
        }
}

func TestPlanHierarchyCompleteness(t *testing.T) {
        plans := []Plan{PlanAnonymous, PlanRegistered, PlanPremium}
        for _, p := range plans {
                if _, ok := planHierarchy[p]; !ok {
                        t.Errorf("plan %q missing from planHierarchy", p)
                }
        }
}
