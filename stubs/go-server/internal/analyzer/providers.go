// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// This file contains stub implementations. See the corresponding _intel.go file (requires -tags intel build).
package analyzer

type managementProviderInfo struct {
	Name         string
	Vendor       string
	Capabilities []string
}

type spfFlatteningInfo struct {
	Name   string
	Vendor string
}

type hostedDKIMInfo struct {
	Name   string
	Vendor string
}

type dynamicServiceInfo struct {
	Name   string
	Vendor string
}

type cnameProviderInfo struct {
	Name     string
	Category string
}

const (
	capDMARCReporting   = "DMARC reporting"
	capDMARCAnalytics   = "DMARC analytics"
	capDMARCEnforcement = "DMARC enforcement"
	capSPFManagement    = "SPF management"
	capTLSRPTReporting  = "TLS-RPT reporting"
	capMTASTSHosting    = "MTA-STS hosting"
	capBrandProtection  = "brand protection"
	capEmailFraudDef    = "email fraud defense"
	capEmailSecurity    = "email security"
	capDeliverability   = "deliverability testing"
	capAIAnalysis       = "AI-assisted analysis"

	catEcommerce     = "E-commerce"
	catWebsite       = "Website"
	catMarketing     = "Marketing"
	catEmail         = "Email"
	catSupport       = "Support"
	catCRM           = "CRM"
	catCDN           = "CDN"
	catCloud         = "Cloud"
	catPaaS          = "PaaS"
	catSecurity      = "Security"
	catCollaboration = "Collaboration"
	catIdentity      = "Identity"
	catMonitoring    = "Monitoring"
	catAnalytics     = "Analytics"
	catPayments      = "Payments"
	catHosting       = "Hosting"
	catHR            = "HR"
	catLiveChat      = "Live Chat"
	catStorage       = "Storage"
	catDocuments     = "Documents"
	catLandingPages  = "Landing Pages"
	catRecruiting    = "Recruiting"
	catScheduling    = "Scheduling"
	catForms         = "Forms"
	catLearning      = "Learning"
	catCommunity     = "Community"
	catStatusPage    = "Status Page"
	catDocumentation = "Documentation"
	catDesign        = "Design"
	catEvents        = "Events"
	catVideo         = "Video"
	catITSM          = "ITSM"
	catDevOps        = "DevOps"

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
	nameAgari         = "Agari"
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
