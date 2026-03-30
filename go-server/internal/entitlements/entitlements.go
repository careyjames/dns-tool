// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny plumbing
package entitlements

// Plan represents a user's access tier.
type Plan string

const (
        PlanAnonymous  Plan = "anonymous"
        PlanRegistered Plan = "registered"
        PlanPremium    Plan = "premium"
)

var planHierarchy = map[Plan]int{
        PlanAnonymous:  0,
        PlanRegistered: 1,
        PlanPremium:    2,
}

// Feature represents a gated product capability.
type Feature string

const (
        // FeaturePersonalHistory gates the future "My History" feature (scans saved to account).
        // The public history page (/history) showing all domain analyses is Tier 1 (open).
        FeaturePersonalHistory Feature = "personal_history"
        FeatureWatchlist       Feature = "watchlist"
        FeatureDossier         Feature = "dossier"
        FeatureZoneUpload      Feature = "zone_upload"
        FeatureBulkScan        Feature = "bulk_scan"
        FeatureAPIKeys         Feature = "api_keys"
        FeatureBulkExport      Feature = "bulk_export"
        FeaturePriorityQueue   Feature = "priority_queue"
        FeatureWebhookScale    Feature = "webhook_scale"
        FeatureWeb3Analysis    Feature = "web3_analysis"
)

// Registry maps each gated feature to its minimum required plan.
// Features not listed here are open (Tier 1) and require no gating.
var Registry = map[Feature]Plan{
        FeaturePersonalHistory: PlanRegistered,
        FeatureWatchlist:       PlanRegistered,
        FeatureDossier:         PlanRegistered,
        FeatureZoneUpload:      PlanRegistered,
        FeatureBulkScan:        PlanPremium,
        FeatureAPIKeys:         PlanPremium,
        FeatureBulkExport:      PlanPremium,
        FeaturePriorityQueue:   PlanPremium,
        FeatureWebhookScale:    PlanPremium,
}

// ResolvePlan determines a user's plan from session state.
// Admin users always resolve to PlanPremium (full access).
func ResolvePlan(authenticated bool, role string, subscriptionActive bool) Plan {
        if !authenticated {
                return PlanAnonymous
        }
        if role == "admin" {
                return PlanPremium
        }
        if subscriptionActive {
                return PlanPremium
        }
        return PlanRegistered
}

// HasAccess checks whether a plan meets the minimum requirement for a feature.
func HasAccess(userPlan Plan, feature Feature) bool {
        required, exists := Registry[feature]
        if !exists {
                return true
        }
        return planHierarchy[userPlan] >= planHierarchy[required]
}

// MinimumPlan returns the minimum plan required for a feature.
// Returns PlanAnonymous for unregistered (open) features.
func MinimumPlan(feature Feature) Plan {
        if p, ok := Registry[feature]; ok {
                return p
        }
        return PlanAnonymous
}

// AllFeatures returns all registered features and their minimum plans.
func AllFeatures() map[Feature]Plan {
        result := make(map[Feature]Plan, len(Registry))
        for k, v := range Registry {
                result[k] = v
        }
        return result
}
