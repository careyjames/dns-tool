// Copyright (c) 2024-2026 IT Help San Diego Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL — See LICENSE for terms.
// This file is part of the DNS Tool Intelligence Module.
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

        domainOndmarc      = "ondmarc.com"
        domainRedsift      = "redsift.cloud"
        domainDmarcian     = "dmarcian.com"
        domainSendmarc     = "sendmarc.com"
)

var dmarcMonitoringProviders = map[string]managementProviderInfo{
        domainOndmarc:                   {Name: nameOnDMARC, Vendor: vendorRedSift, Capabilities: []string{capDMARCReporting, capTLSRPTReporting, capSPFManagement, capMTASTSHosting}},
        "valimail.com":                  {Name: nameValimailEnf, Vendor: vendorValimail, Capabilities: []string{capDMARCReporting, capDMARCEnforcement, capSPFManagement}},
        domainDmarcian:                  {Name: nameDmarcian, Vendor: vendorDmarcian, Capabilities: []string{capDMARCReporting, capDMARCAnalytics}},
        "easydmarc.com":                 {Name: nameEasyDMARC, Vendor: vendorEasyDMARC, Capabilities: []string{capDMARCReporting, capDMARCAnalytics, capSPFManagement}},
        "powerdmarc.com":                {Name: namePowerDMARC, Vendor: vendorPowerDMARC, Capabilities: []string{capDMARCReporting, capDMARCEnforcement, capSPFManagement}},
        "agari.com":                     {Name: nameAgari, Vendor: "Fortra (HelpSystems)", Capabilities: []string{capDMARCReporting, capBrandProtection}},
        "dmarc-analyzer.com":            {Name: "DMARC Analyzer", Vendor: vendorMimecast, Capabilities: []string{capDMARCReporting, capDMARCAnalytics}},
        "postmarkapp.com":               {Name: "Postmark DMARC", Vendor: vendorActiveCamp, Capabilities: []string{capDMARCReporting}},
        "uriports.com":                  {Name: "URIports", Vendor: "URIports", Capabilities: []string{capDMARCReporting, capTLSRPTReporting}},
        "fraudmarc.com":                 {Name: nameFraudmarc, Vendor: vendorFraudmarc, Capabilities: []string{capDMARCReporting, capSPFManagement}},
        "mxtoolbox.com":                 {Name: "MxToolbox", Vendor: "MxToolbox", Capabilities: []string{capDMARCReporting}},
        domainSendmarc:                  {Name: nameSendmarc, Vendor: vendorSendmarc, Capabilities: []string{capDMARCReporting, capDMARCEnforcement}},
        "proofpoint.com":                {Name: nameProofpointEFD, Vendor: vendorProofpoint, Capabilities: []string{capDMARCReporting, capEmailFraudDef}},
        "redsift.com":                   {Name: nameRedSift, Vendor: vendorRedSift, Capabilities: []string{capDMARCReporting}},
        "mailhardener.com":              {Name: nameMailhardener, Vendor: vendorMailharden, Capabilities: []string{capDMARCReporting, capMTASTSHosting}},
        "dmarc.postmarkapp.com":         {Name: "Postmark DMARC", Vendor: vendorActiveCamp, Capabilities: []string{capDMARCReporting}},
        "emailsecuritycheck.net":        {Name: nameDMARCReport, Vendor: vendorDMARCRpt, Capabilities: []string{capDMARCReporting}},
        "app.dmarcdigests.com":          {Name: "DMARC Digests", Vendor: "DMARC Digests", Capabilities: []string{capDMARCReporting}},
        "dmarc.report":                  {Name: nameDMARCReport, Vendor: vendorDMARCRpt, Capabilities: []string{capDMARCReporting}},
        "ag.dmarcly.com":                {Name: nameDMARCLY, Vendor: vendorDMARCLY, Capabilities: []string{capDMARCReporting, capDMARCAnalytics}},
        "dmarcly.com":                   {Name: nameDMARCLY, Vendor: vendorDMARCLY, Capabilities: []string{capDMARCReporting, capDMARCAnalytics}},
        "dmarc-reports.cloudflare.net":  {Name: "Cloudflare DMARC", Vendor: nameCloudflare, Capabilities: []string{capDMARCReporting, capDMARCAnalytics}},
        "cloudflare.net":                {Name: "Cloudflare DMARC", Vendor: nameCloudflare, Capabilities: []string{capDMARCReporting, capDMARCAnalytics}},
        "glockapps.com":                 {Name: "GlockApps", Vendor: "GlockApps", Capabilities: []string{capDMARCReporting, capDeliverability}},
        "dmarcadvisor.com":              {Name: nameDMARCAdvisor, Vendor: vendorDMARCAdv, Capabilities: []string{capDMARCReporting, capDMARCAnalytics}},
        "dmarcmanager.app":              {Name: nameDMARCAdvisor, Vendor: vendorDMARCAdv, Capabilities: []string{capDMARCReporting, capDMARCAnalytics}},
        "dmarcduty.com":                 {Name: "DynamicSPF", Vendor: "Dmarcduty", Capabilities: []string{capDMARCReporting, capSPFManagement}},
        "dmarcreport.com":               {Name: nameDMARCReport, Vendor: vendorDMARCRpt, Capabilities: []string{capDMARCReporting, capAIAnalysis}},
        "ironscales.com":                {Name: "IRONSCALES", Vendor: "IRONSCALES", Capabilities: []string{capDMARCReporting, capEmailSecurity}},
        domainRedsift:                   {Name: nameOnDMARC, Vendor: vendorRedSift, Capabilities: []string{capDMARCReporting, capTLSRPTReporting, capSPFManagement, capMTASTSHosting}},
}

var spfFlatteningProviders = map[string]spfFlatteningInfo{
        domainOndmarc:       {Name: nameOnDMARC, Vendor: vendorRedSift},
        "smart.ondmarc.com": {Name: nameOnDMARC, Vendor: vendorRedSift},
        domainRedsift:       {Name: nameOnDMARC, Vendor: vendorRedSift},
        "vali.email":        {Name: nameValimailEnf, Vendor: vendorValimail},
        "valimail.com":      {Name: nameValimailEnf, Vendor: vendorValimail},
        "autospf.com":       {Name: "AutoSPF", Vendor: "AutoSPF"},
        domainSendmarc:      {Name: nameSendmarc, Vendor: vendorSendmarc},
        "fraudmarc.com":     {Name: nameFraudmarc, Vendor: vendorFraudmarc},
        domainDmarcian:      {Name: nameDmarcian, Vendor: vendorDmarcian},
        "easydmarc.pro":     {Name: "EasySPF", Vendor: vendorEasyDMARC},
        "easydmarc.com":     {Name: "EasySPF", Vendor: vendorEasyDMARC},
        "powerspf.com":      {Name: "PowerSPF", Vendor: vendorPowerDMARC},
        "powerdmarc.com":    {Name: "PowerSPF", Vendor: vendorPowerDMARC},
        "dmarcly.com":       {Name: nameDMARCLY, Vendor: vendorDMARCLY},
        "dmarcduty.com":     {Name: "DynamicSPF", Vendor: "Dmarcduty"},
        "spf.has.gpphosted.com": {Name: "Proofpoint EFD (Gov)", Vendor: vendorProofpoint},
        "spf.has.pphosted.com":  {Name: nameProofpointEFD, Vendor: vendorProofpoint},
}

var hostedDKIMProviders = map[string]hostedDKIMInfo{
        "gpphosted.com":             {Name: "Proofpoint EFD (Gov)", Vendor: vendorProofpoint},
        "pphosted.com":              {Name: nameProofpointEFD, Vendor: vendorProofpoint},
        "proofpoint.com":            {Name: nameProofpointEFD, Vendor: vendorProofpoint},
        "dkim.mimecast.com":         {Name: "Mimecast DMARC Analyzer", Vendor: vendorMimecast},
        "mimecast.com":              {Name: "Mimecast DMARC Analyzer", Vendor: vendorMimecast},
        "agari.com":                 {Name: nameAgari, Vendor: vendorFortra},
        "emailsecurity.fortra.com":  {Name: nameAgari, Vendor: vendorFortra},
        domainSendmarc:              {Name: nameSendmarc, Vendor: vendorSendmarc},
        domainDmarcian:              {Name: nameDmarcian, Vendor: vendorDmarcian},
}

var dynamicServicesProviders = map[string]dynamicServiceInfo{
        domainOndmarc:      {Name: nameOnDMARC, Vendor: vendorRedSift},
        domainRedsift:      {Name: nameOnDMARC, Vendor: vendorRedSift},
        "mailhardener.com": {Name: nameMailhardener, Vendor: vendorMailharden},
        "vali.email":       {Name: nameValimailEnf, Vendor: vendorValimail},
}

var dynamicServicesZones = map[string]string{
        "_dmarc":     "Dynamic DMARC",
        "_domainkey": "Dynamic DKIM",
        "_mta-sts":   "Dynamic MTA-STS",
        "_smtp._tls": "Dynamic TLS-RPT",
}

var cnameProviderMap = map[string]cnameProviderInfo{
        "shopify.com":               {Name: "Shopify", Category: catEcommerce},
        "myshopify.com":             {Name: "Shopify", Category: catEcommerce},
        "bigcommerce.com":           {Name: "BigCommerce", Category: catEcommerce},
        "squarespace.com":           {Name: "Squarespace", Category: catWebsite},
        "wixdns.net":                {Name: "Wix", Category: catWebsite},
        "wix.com":                   {Name: "Wix", Category: catWebsite},
        "wordpress.com":             {Name: "WordPress.com", Category: catWebsite},
        "wpengine.com":              {Name: "WP Engine", Category: catWebsite},
        "pantheonsite.io":           {Name: "Pantheon", Category: catWebsite},
        "netlify.app":               {Name: "Netlify", Category: catWebsite},
        "netlify.com":               {Name: "Netlify", Category: catWebsite},
        "vercel.app":                {Name: "Vercel", Category: catWebsite},
        "vercel-dns.com":            {Name: "Vercel", Category: catWebsite},
        "webflow.io":                {Name: "Webflow", Category: catWebsite},
        "ghost.io":                  {Name: "Ghost", Category: catWebsite},
        "cargo.site":                {Name: "Cargo", Category: catWebsite},
        "strikingly.com":            {Name: "Strikingly", Category: catWebsite},
        "hubspot.net":               {Name: nameHubSpot, Category: catMarketing},
        "hubspot.com":               {Name: nameHubSpot, Category: catMarketing},
        "hs-sites.com":              {Name: nameHubSpot, Category: catMarketing},
        "marketo.com":               {Name: "Marketo (Adobe)", Category: catMarketing},
        "mktoweb.com":               {Name: "Marketo (Adobe)", Category: catMarketing},
        "pardot.com":                {Name: "Pardot (Salesforce)", Category: catMarketing},
        "mailchimp.com":             {Name: "Mailchimp", Category: catMarketing},
        "mailgun.org":               {Name: "Mailgun", Category: catEmail},
        "sendgrid.net":              {Name: "SendGrid (Twilio)", Category: catEmail},
        "postmarkapp.com":           {Name: "Postmark", Category: catEmail},
        "mandrillapp.com":           {Name: "Mandrill (Mailchimp)", Category: catEmail},
        "zendesk.com":               {Name: "Zendesk", Category: catSupport},
        "zendeskhost.com":           {Name: "Zendesk", Category: catSupport},
        "freshdesk.com":             {Name: "Freshdesk", Category: catSupport},
        "freshservice.com":          {Name: "Freshservice", Category: catSupport},
        "intercom.io":               {Name: "Intercom", Category: catSupport},
        "helpscout.com":             {Name: "Help Scout", Category: catSupport},
        "helpscout.net":             {Name: "Help Scout", Category: catSupport},
        "salesforce.com":            {Name: nameSalesforce, Category: catCRM},
        "force.com":                 {Name: nameSalesforce, Category: catCRM},
        "salesforceliveagent.com":   {Name: nameSalesforce, Category: catCRM},
        "zoho.com":                  {Name: "Zoho", Category: catCRM},
        "zoho.eu":                   {Name: "Zoho", Category: catCRM},
        "pipedrive.com":             {Name: "Pipedrive", Category: catCRM},
        "cloudfront.net":            {Name: "AWS CloudFront", Category: catCDN},
        "amazonaws.com":             {Name: "AWS", Category: catCloud},
        "awsglobalaccelerator.com":  {Name: "AWS Global Accelerator", Category: catCloud},
        "elasticbeanstalk.com":      {Name: "AWS Elastic Beanstalk", Category: catCloud},
        "s3.amazonaws.com":          {Name: "AWS S3", Category: catCloud},
        "azurewebsites.net":         {Name: "Azure App Service", Category: catCloud},
        "azure-api.net":             {Name: "Azure API Management", Category: catCloud},
        "azurefd.net":               {Name: "Azure Front Door", Category: catCDN},
        "azureedge.net":             {Name: "Azure CDN", Category: catCDN},
        "trafficmanager.net":        {Name: "Azure Traffic Manager", Category: catCloud},
        "cloudapp.azure.com":        {Name: "Azure", Category: catCloud},
        "blob.core.windows.net":     {Name: "Azure Blob Storage", Category: catCloud},
        "windows.net":               {Name: "Azure", Category: catCloud},
        "googleapis.com":            {Name: "Google Cloud", Category: catCloud},
        "appspot.com":               {Name: "Google App Engine", Category: catCloud},
        "googleplex.com":            {Name: "Google", Category: catCloud},
        "run.app":                   {Name: "Google Cloud Run", Category: catCloud},
        "web.app":                   {Name: "Firebase Hosting", Category: catCloud},
        "firebaseapp.com":           {Name: "Firebase", Category: catCloud},
        "cdn.cloudflare.net":        {Name: nameCloudflare, Category: catCDN},
        "cloudflare.net":            {Name: nameCloudflare, Category: catCDN},
        "cdn77.org":                 {Name: "CDN77", Category: catCDN},
        "fastly.net":                {Name: "Fastly", Category: catCDN},
        "edgekey.net":               {Name: nameAkamai, Category: catCDN},
        "akamaiedge.net":            {Name: nameAkamai, Category: catCDN},
        "akadns.net":                {Name: nameAkamai, Category: catCDN},
        "akamaized.net":             {Name: nameAkamai, Category: catCDN},
        "edgesuite.net":             {Name: nameAkamai, Category: catCDN},
        "stackpathdns.com":          {Name: "StackPath", Category: catCDN},
        "stackpathcdn.com":          {Name: "StackPath", Category: catCDN},
        "sucuri.net":                {Name: "Sucuri", Category: catSecurity},
        "incapdns.net":              {Name: "Imperva (Incapsula)", Category: catSecurity},
        "impervadns.net":            {Name: "Imperva", Category: catSecurity},
        "heroku.com":                {Name: nameHeroku, Category: catPaaS},
        "herokuapp.com":             {Name: nameHeroku, Category: catPaaS},
        "herokudns.com":             {Name: nameHeroku, Category: catPaaS},
        "render.com":                {Name: "Render", Category: catPaaS},
        "onrender.com":              {Name: "Render", Category: catPaaS},
        "fly.dev":                   {Name: "Fly.io", Category: catPaaS},
        "digitaloceanspaces.com":    {Name: "DigitalOcean Spaces", Category: catCloud},
        "ondigitalocean.app":        {Name: "DigitalOcean App Platform", Category: catCloud},
        "github.io":                 {Name: "GitHub Pages", Category: catWebsite},
        "githubusercontents.com":    {Name: "GitHub", Category: catDevOps},
        "gitlab.io":                 {Name: "GitLab Pages", Category: catWebsite},
        "bitbucket.io":              {Name: "Bitbucket", Category: catDevOps},
        "atlassian.net":             {Name: "Atlassian", Category: catCollaboration},
        "statuspage.io":             {Name: "Statuspage (Atlassian)", Category: catStatusPage},
        "status.io":                 {Name: "Status.io", Category: catStatusPage},
        "readthedocs.io":            {Name: "Read the Docs", Category: catDocumentation},
        "gitbook.io":                {Name: "GitBook", Category: catDocumentation},
        "readme.io":                 {Name: "ReadMe", Category: catDocumentation},
        "outlook.com":               {Name: "Microsoft 365", Category: catEmail},
        "protection.outlook.com":    {Name: "Microsoft 365 (Exchange Online)", Category: catEmail},
        "mx.microsoft":              {Name: "Microsoft 365 (DANE)", Category: catEmail},
        "office365.com":             {Name: "Microsoft 365", Category: catEmail},
        "sharepoint.com":            {Name: "SharePoint Online", Category: catCollaboration},
        "lync.com":                  {Name: "Skype for Business", Category: catCollaboration},
        "microsoftonline.com":       {Name: "Microsoft Entra ID", Category: catIdentity},
        "msappproxy.net":            {Name: "Azure AD App Proxy", Category: catIdentity},
        "aspmx.l.google.com":        {Name: "Google Workspace", Category: catEmail},
        "googlemail.com":            {Name: "Google Workspace", Category: catEmail},
        "ghs.googlehosted.com":      {Name: "Google Sites", Category: catWebsite},
        "googlehosted.com":          {Name: "Google", Category: catCloud},
        "stripe.com":                {Name: "Stripe", Category: catPayments},
        "chargebee.com":             {Name: "Chargebee", Category: catPayments},
        "recurly.com":               {Name: "Recurly", Category: catPayments},
        "braintreegateway.com":      {Name: "Braintree (PayPal)", Category: catPayments},
        "squareup.com":              {Name: "Square", Category: catPayments},
        "typeform.com":              {Name: "Typeform", Category: catForms},
        "wufoo.com":                 {Name: "Wufoo", Category: catForms},
        "surveygizmo.com":           {Name: "Alchemer", Category: catForms},
        "unbounce.com":              {Name: "Unbounce", Category: catLandingPages},
        "instapage.com":             {Name: "Instapage", Category: catLandingPages},
        "leadpages.net":             {Name: "Leadpages", Category: catLandingPages},
        "canva.com":                 {Name: "Canva", Category: catDesign},
        "calendly.com":              {Name: "Calendly", Category: catScheduling},
        "acuityscheduling.com":      {Name: "Acuity Scheduling", Category: catScheduling},
        "eventbrite.com":            {Name: "Eventbrite", Category: catEvents},
        "zoom.us":                   {Name: "Zoom", Category: catVideo},
        "webex.com":                 {Name: "Webex (Cisco)", Category: catVideo},
        "auth0.com":                 {Name: "Auth0 (Okta)", Category: catIdentity},
        "okta.com":                  {Name: "Okta", Category: catIdentity},
        "onelogin.com":              {Name: "OneLogin", Category: catIdentity},
        "duosecurity.com":           {Name: "Duo (Cisco)", Category: catIdentity},
        "greenhouse.io":             {Name: "Greenhouse", Category: catRecruiting},
        "lever.co":                  {Name: "Lever", Category: catRecruiting},
        "workday.com":               {Name: "Workday", Category: catHR},
        "bamboohr.com":              {Name: "BambooHR", Category: catHR},
        "namely.com":                {Name: "Namely", Category: catHR},
        "gusto.com":                 {Name: "Gusto", Category: catHR},
        "slack.com":                 {Name: "Slack", Category: catCollaboration},
        "notion.so":                 {Name: "Notion", Category: catCollaboration},
        "monday.com":                {Name: "monday.com", Category: catCollaboration},
        "asana.com":                 {Name: "Asana", Category: catCollaboration},
        "pagerduty.com":             {Name: "PagerDuty", Category: catMonitoring},
        "datadoghq.com":             {Name: "Datadog", Category: catMonitoring},
        "datadoghq.eu":              {Name: "Datadog", Category: catMonitoring},
        "sentry.io":                 {Name: "Sentry", Category: catMonitoring},
        "newrelic.com":              {Name: "New Relic", Category: catMonitoring},
        "sumologic.com":             {Name: "Sumo Logic", Category: catMonitoring},
        "grafana.net":               {Name: "Grafana Cloud", Category: catMonitoring},
        "docusign.com":              {Name: "DocuSign", Category: catDocuments},
        "docusign.net":              {Name: "DocuSign", Category: catDocuments},
        "hellosign.com":             {Name: "HelloSign (Dropbox)", Category: catDocuments},
        "box.com":                   {Name: "Box", Category: catStorage},
        "dropbox.com":               {Name: "Dropbox", Category: catStorage},
        "egnyte.com":                {Name: "Egnyte", Category: catStorage},
        "teachable.com":             {Name: "Teachable", Category: catLearning},
        "thinkific.com":             {Name: "Thinkific", Category: catLearning},
        "kajabi.com":                {Name: "Kajabi", Category: catLearning},
        "discourse.org":             {Name: "Discourse", Category: catCommunity},
        "discourse.cloud":           {Name: "Discourse", Category: catCommunity},
        "mattermost.com":            {Name: "Mattermost", Category: catCollaboration},
        "tawk.to":                   {Name: "tawk.to", Category: catLiveChat},
        "crisp.chat":                {Name: "Crisp", Category: catLiveChat},
        "drift.com":                 {Name: "Drift", Category: catLiveChat},
        "livechatinc.com":           {Name: "LiveChat", Category: catLiveChat},
        "segment.com":               {Name: "Segment (Twilio)", Category: catAnalytics},
        "segment.io":                {Name: "Segment (Twilio)", Category: catAnalytics},
        "amplitude.com":             {Name: "Amplitude", Category: catAnalytics},
        "mixpanel.com":              {Name: "Mixpanel", Category: catAnalytics},
        "hotjar.com":                {Name: "Hotjar", Category: catAnalytics},
        "optimizely.com":            {Name: "Optimizely", Category: catAnalytics},
        "crazyegg.com":              {Name: "Crazy Egg", Category: catAnalytics},
        "wpenginepowered.com":       {Name: "WP Engine", Category: catWebsite},
        "flywheel.io":               {Name: "Flywheel", Category: catWebsite},
        "kinsta.cloud":              {Name: "Kinsta", Category: catWebsite},
        "cloudwaysapps.com":         {Name: "Cloudways", Category: catWebsite},
        "siteground.net":            {Name: "SiteGround", Category: catHosting},
        "bluehost.com":              {Name: "Bluehost", Category: catHosting},
        "godaddysites.com":          {Name: "GoDaddy", Category: catHosting},
        "secureserver.net":          {Name: "GoDaddy", Category: catHosting},
        "hostgator.com":             {Name: "HostGator", Category: catHosting},
        "dreamhost.com":             {Name: "DreamHost", Category: catHosting},
        "wpcomstaging.com":          {Name: "WordPress.com", Category: catWebsite},
        "service-now.com":           {Name: "ServiceNow", Category: catITSM},
        "servicenow.com":            {Name: "ServiceNow", Category: catITSM},
}
