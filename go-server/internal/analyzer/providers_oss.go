//go:build !intel

// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Stub implementations. See the corresponding _intel.go file (requires -tags intel build).
// dns-tool:scrutiny science
package analyzer

const (
        nameOnDMARC       = "OnDMARC"
        nameDMARCReport   = "DMARC Report"
        nameDMARCLY       = "DMARCLY"
        nameDmarcian      = "Dmarcian"
        nameSendmarc      = "Sendmarc"
        nameProofpoint    = "Proofpoint"
        nameValimailEnf   = "Valimail Enforce"
        nameProofpointEFD = "Proofpoint EFD"
        namePowerDMARC    = "PowerDMARC"
        nameMailhardener  = "Mailhardener"
        nameFraudmarc     = "Fraudmarc"
        nameEasyDMARC     = "EasyDMARC"
        nameDMARCAdvisor  = "DMARC Advisor"
        nameRedSift       = "Red Sift"

        vendorRedSift    = "Red Sift"
        vendorValimail   = "Valimail"
        vendorDmarcian   = "Dmarcian"
        vendorSendmarc   = "Sendmarc"
        vendorProofpoint = "Proofpoint"
        vendorDMARCLY    = "DMARCLY"
        vendorPowerDMARC = "PowerDMARC"
        vendorFraudmarc  = "Fraudmarc"
        vendorEasyDMARC  = "EasyDMARC"
        vendorDMARCAdv   = "DMARC Advisor"
        vendorMailharden = "Mailhardener"
        vendorDMARCRpt   = "DMARC Report"
        vendorFortra     = "Fortra"
        vendorMimecast   = "Mimecast"
        vendorActiveCamp = "ActiveCampaign"

        nameAkamai     = "Akamai"
        nameSalesforce = "Salesforce"
        nameHubSpot    = "HubSpot"
        nameHeroku     = "Heroku"

        domainOndmarc  = "ondmarc.com"
        domainRedsift  = "redsift.cloud"
        domainDmarcian = "dmarcian.com"
        domainSendmarc = "sendmarc.com"
)

var dmarcMonitoringProviders = map[string]managementProviderInfo{}

var spfFlatteningProviders = map[string]spfFlatteningInfo{}

var hostedDKIMProviders = map[string]hostedDKIMInfo{}

var dynamicServicesProviders = map[string]dynamicServiceInfo{}

var dynamicServicesZones = map[string]string{}

var cnameProviderMap = map[string]cnameProviderInfo{}

func isHostedEmailProvider(_ string) bool {
        return true
}

func isBIMICapableProvider(_ string) bool {
        return false
}

func isKnownDKIMProvider(_ interface{}) bool {
        return false
}
