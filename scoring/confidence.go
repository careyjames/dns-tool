// Copyright (c) 2024-2026 IT Help San Diego Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL — See LICENSE for terms.
// This file is part of the DNS Tool Intelligence Module.
package analyzer

const (
        ConfidenceObserved  = "observed"
        ConfidenceInferred  = "inferred"
        ConfidenceThirdParty = "third_party"

        ConfidenceLabelObserved  = "Observed"
        ConfidenceLabelInferred  = "Inferred"
        ConfidenceLabelThirdParty = "Third-party data"

        MethodDNSRecord       = "Direct DNS record query"
        MethodNSPattern       = "Authoritative NS record query"
        MethodMXPattern       = "MX record query"
        MethodARecordPattern  = "A/AAAA record query"
        MethodSPFInclude      = "SPF include mechanism analysis"
        MethodCNAMETarget     = "CNAME target pattern matching"
        MethodTLDSuffix       = "TLD suffix rule"
        MethodRDAP            = "RDAP registry lookup"
        MethodWHOIS           = "WHOIS registry lookup"
        MethodNSInference     = "NS record inference"
        MethodDKIMSelector    = "DKIM selector pattern matching"
        MethodDMARCRua        = "DMARC rua/ruf domain matching"
        MethodSPFFlattening   = "SPF flattening include pattern"
        MethodMTASTSCNAME     = "MTA-STS hosting CNAME"
        MethodDKIMCNAME       = "DKIM CNAME delegation"
        MethodTeamCymru       = "Team Cymru DNS-based ASN lookup"
        MethodASNMatch        = "ASN and CNAME pattern matching"
        MethodTXTPattern      = "TXT record pattern matching"
        MethodPTRRecord       = "Reverse DNS (PTR) record lookup"
)

func confidenceMap(level, label, method string) map[string]any {
        return map[string]any{
                "level":  level,
                "label":  label,
                "method": method,
        }
}

func ConfidenceObservedMap(method string) map[string]any {
        return confidenceMap(ConfidenceObserved, ConfidenceLabelObserved, method)
}

func ConfidenceInferredMap(method string) map[string]any {
        return confidenceMap(ConfidenceInferred, ConfidenceLabelInferred, method)
}

func ConfidenceThirdPartyMap(method string) map[string]any {
        return confidenceMap(ConfidenceThirdParty, ConfidenceLabelThirdParty, method)
}
