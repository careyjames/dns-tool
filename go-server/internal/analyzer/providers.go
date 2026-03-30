// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
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
)
