// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny plumbing
package providers

const (
	catEcommerce    = "E-commerce"
	catWebsite      = "Website"
	catMarketing    = "Marketing"
	catEmail        = "Email"
	catSupport      = "Support"
	catCRM          = "CRM"
	catCDN          = "CDN"
	catCloud        = "Cloud"
	catPaaS         = "PaaS"
	catSecurity     = "Security"
	catMonitoring   = "Monitoring"
	catLandingPages = "Landing Pages"
	catLiveChat     = "Live Chat"
	catDynamicDNS   = "Dynamic DNS"

	capDMARCReporting   = "DMARC reporting"
	capDMARCAnalytics   = "DMARC analytics"
	capDMARCEnforcement = "DMARC enforcement"
	capSPFManagement    = "SPF management"
	capTLSRPTReporting  = "TLS-RPT reporting"

	altMTASTS = "MTA-STS"

	nameRedSiftOnDMARC = "Red Sift OnDMARC"
	nameAkamai         = "Akamai"
	nameHubSpot        = "HubSpot"
	nameSalesforce     = "Salesforce"
	nameNoIP           = "No-IP"

	domainOndmarc   = "ondmarc.com"
	domainRedsift   = "redsift.cloud"
	domainDmarcian  = "dmarcian.com"
	domainValimail  = "valimail.com"
	domainEasydmarc = "easydmarc.com"
	domainNsupdate  = "nsupdate.info"
)

type ProviderInfo struct {
	Name     string
	Category string
}

type DANECapability struct {
	Name         string
	DANEInbound  bool
	DANEOutbound bool
	Reason       string
	Alternative  string
	Patterns     []string
}

type MonitoringProvider struct {
	Name         string
	Capabilities []string
}

type SPFFlatteningProvider struct {
	Name     string
	Patterns []string
}

type DynamicServiceProvider struct {
	Name     string
	Category string
}

type HostedDKIMProvider struct {
	Name     string
	Patterns []string
}

var CNAMEProviderMap = map[string]ProviderInfo{
	"shopify.com":              {Name: "Shopify", Category: catEcommerce},
	"myshopify.com":            {Name: "Shopify", Category: catEcommerce},
	"bigcommerce.com":          {Name: "BigCommerce", Category: catEcommerce},
	"squarespace.com":          {Name: "Squarespace", Category: catWebsite},
	"wixdns.net":               {Name: "Wix", Category: catWebsite},
	"wix.com":                  {Name: "Wix", Category: catWebsite},
	"wordpress.com":            {Name: "WordPress.com", Category: catWebsite},
	"wpengine.com":             {Name: "WP Engine", Category: catWebsite},
	"pantheonsite.io":          {Name: "Pantheon", Category: catWebsite},
	"netlify.app":              {Name: "Netlify", Category: catWebsite},
	"netlify.com":              {Name: "Netlify", Category: catWebsite},
	"vercel.app":               {Name: "Vercel", Category: catWebsite},
	"vercel-dns.com":           {Name: "Vercel", Category: catWebsite},
	"webflow.io":               {Name: "Webflow", Category: catWebsite},
	"ghost.io":                 {Name: "Ghost", Category: catWebsite},
	"cargo.site":               {Name: "Cargo", Category: catWebsite},
	"strikingly.com":           {Name: "Strikingly", Category: catWebsite},
	"hubspot.net":              {Name: nameHubSpot, Category: catMarketing},
	"hubspot.com":              {Name: nameHubSpot, Category: catMarketing},
	"hs-sites.com":             {Name: nameHubSpot, Category: catMarketing},
	"marketo.com":              {Name: "Marketo (Adobe)", Category: catMarketing},
	"mktoweb.com":              {Name: "Marketo (Adobe)", Category: catMarketing},
	"pardot.com":               {Name: "Pardot (Salesforce)", Category: catMarketing},
	"mailchimp.com":            {Name: "Mailchimp", Category: catMarketing},
	"mailgun.org":              {Name: "Mailgun", Category: catEmail},
	"sendgrid.net":             {Name: "SendGrid (Twilio)", Category: catEmail},
	"postmarkapp.com":          {Name: "Postmark", Category: catEmail},
	"mandrillapp.com":          {Name: "Mandrill (Mailchimp)", Category: catEmail},
	"zendesk.com":              {Name: "Zendesk", Category: catSupport},
	"zendeskhost.com":          {Name: "Zendesk", Category: catSupport},
	"freshdesk.com":            {Name: "Freshdesk", Category: catSupport},
	"freshservice.com":         {Name: "Freshservice", Category: catSupport},
	"intercom.io":              {Name: "Intercom", Category: catSupport},
	"helpscout.com":            {Name: "Help Scout", Category: catSupport},
	"helpscout.net":            {Name: "Help Scout", Category: catSupport},
	"salesforce.com":           {Name: nameSalesforce, Category: catCRM},
	"force.com":                {Name: nameSalesforce, Category: catCRM},
	"salesforceliveagent.com":  {Name: nameSalesforce, Category: catCRM},
	"zoho.com":                 {Name: "Zoho", Category: catCRM},
	"zoho.eu":                  {Name: "Zoho", Category: catCRM},
	"pipedrive.com":            {Name: "Pipedrive", Category: catCRM},
	"cloudfront.net":           {Name: "AWS CloudFront", Category: catCDN},
	"amazonaws.com":            {Name: "AWS", Category: catCloud},
	"awsglobalaccelerator.com": {Name: "AWS Global Accelerator", Category: catCloud},
	"elasticbeanstalk.com":     {Name: "AWS Elastic Beanstalk", Category: catCloud},
	"s3.amazonaws.com":         {Name: "AWS S3", Category: catCloud},
	"azurewebsites.net":        {Name: "Azure App Service", Category: catCloud},
	"azure-api.net":            {Name: "Azure API Management", Category: catCloud},
	"azurefd.net":              {Name: "Azure Front Door", Category: catCDN},
	"azureedge.net":            {Name: "Azure CDN", Category: catCDN},
	"trafficmanager.net":       {Name: "Azure Traffic Manager", Category: catCloud},
	"cloudapp.azure.com":       {Name: "Azure", Category: catCloud},
	"blob.core.windows.net":    {Name: "Azure Blob Storage", Category: catCloud},
	"windows.net":              {Name: "Azure", Category: catCloud},
	"googleapis.com":           {Name: "Google Cloud", Category: catCloud},
	"appspot.com":              {Name: "Google App Engine", Category: catCloud},
	"googleplex.com":           {Name: "Google", Category: catCloud},
	"run.app":                  {Name: "Google Cloud Run", Category: catCloud},
	"web.app":                  {Name: "Firebase Hosting", Category: catCloud},
	"firebaseapp.com":          {Name: "Firebase", Category: catCloud},
	"cdn.cloudflare.net":       {Name: "Cloudflare", Category: catCDN},
	"cloudflare.net":           {Name: "Cloudflare", Category: catCDN},
	"cdn77.org":                {Name: "CDN77", Category: catCDN},
	"fastly.net":               {Name: "Fastly", Category: catCDN},
	"edgekey.net":              {Name: nameAkamai, Category: catCDN},
	"akamaiedge.net":           {Name: nameAkamai, Category: catCDN},
	"akadns.net":               {Name: nameAkamai, Category: catCDN},
	"akamaized.net":            {Name: nameAkamai, Category: catCDN},
	"edgesuite.net":            {Name: nameAkamai, Category: catCDN},
	"stackpathdns.com":         {Name: "StackPath", Category: catCDN},
	"stackpathcdn.com":         {Name: "StackPath", Category: catCDN},
	"sucuri.net":               {Name: "Sucuri", Category: catSecurity},
	"incapdns.net":             {Name: "Imperva (Incapsula)", Category: catSecurity},
	"impervadns.net":           {Name: "Imperva", Category: catSecurity},
	"heroku.com":               {Name: "Heroku", Category: catPaaS},
	"herokuapp.com":            {Name: "Heroku", Category: catPaaS},
	"fly.dev":                  {Name: "Fly.io", Category: catPaaS},
	"render.com":               {Name: "Render", Category: catPaaS},
	"onrender.com":             {Name: "Render", Category: catPaaS},
	"railway.app":              {Name: "Railway", Category: catPaaS},
	"deno.dev":                 {Name: "Deno Deploy", Category: catPaaS},
	"pages.dev":                {Name: "Cloudflare Pages", Category: catPaaS},
	"workers.dev":              {Name: "Cloudflare Workers", Category: catPaaS},
	"digitaloceanspaces.com":   {Name: "DigitalOcean Spaces", Category: catCloud},
	"ondigitalocean.app":       {Name: "DigitalOcean App Platform", Category: catPaaS},
	"linode.com":               {Name: "Linode (Akamai)", Category: catCloud},
	"linodeobjects.com":        {Name: "Linode Object Storage", Category: catCloud},
	"hetzner.cloud":            {Name: "Hetzner", Category: catCloud},
	"ovh.net":                  {Name: "OVH", Category: catCloud},
	"rackcdn.com":              {Name: "Rackspace CDN", Category: catCDN},
	"unbouncepages.com":        {Name: "Unbounce", Category: catLandingPages},
	"leadpages.net":            {Name: "Leadpages", Category: catLandingPages},
	"instapage.com":            {Name: "Instapage", Category: catLandingPages},
	"tawk.to":                  {Name: "Tawk.to", Category: catLiveChat},
	"crisp.chat":               {Name: "Crisp", Category: catLiveChat},
	"drift.com":                {Name: "Drift", Category: catLiveChat},
	"livechat.com":             {Name: "LiveChat", Category: catLiveChat},
	"statuspage.io":            {Name: "Atlassian Statuspage", Category: catMonitoring},
	"betteruptime.com":         {Name: "Better Uptime", Category: catMonitoring},
}

var DANEMXCapability = map[string]DANECapability{
	"microsoft365": {
		Name: "Microsoft 365", DANEInbound: false, DANEOutbound: false,
		Reason:      "Microsoft 365 does not support DANE for inbound mail. Microsoft uses its own certificate pinning mechanism.",
		Alternative: altMTASTS,
		Patterns:    []string{"outlook.com", "microsoft.com", "protection.outlook.com"},
	},
	"google_workspace": {
		Name: "Google Workspace", DANEInbound: false, DANEOutbound: true,
		Reason:      "Google Workspace supports DANE for outbound mail verification but does not publish TLSA records for its MX hosts.",
		Alternative: altMTASTS,
		Patterns:    []string{"google.com", "googlemail.com", "gmail-smtp-in.l.google.com"},
	},
	"postfix_default": {
		Name: "Self-Hosted (Postfix)", DANEInbound: true, DANEOutbound: true,
		Reason:   "Postfix supports DANE natively since version 2.11. Self-hosted servers can publish TLSA records.",
		Patterns: []string{},
	},
	"zoho": {
		Name: "Zoho Mail", DANEInbound: false, DANEOutbound: false,
		Reason:      "Zoho Mail does not publish DANE/TLSA records for its MX hosts.",
		Alternative: altMTASTS,
		Patterns:    []string{"zoho.com", "zoho.eu", "zoho.in"},
	},
	"fastmail": {
		Name: "Fastmail", DANEInbound: true, DANEOutbound: true,
		Reason:   "Fastmail publishes DANE/TLSA records for its MX hosts and supports DNSSEC.",
		Patterns: []string{"fastmail.com", "messagingengine.com"},
	},
	"mimecast": {
		Name: "Mimecast", DANEInbound: false, DANEOutbound: false,
		Reason:      "Mimecast is a security gateway with shared MX infrastructure. It does not publish per-customer TLSA records.",
		Alternative: altMTASTS,
		Patterns:    []string{"mimecast.com"},
	},
	"proofpoint": {
		Name: "Proofpoint", DANEInbound: false, DANEOutbound: false,
		Reason:      "Proofpoint is a security gateway with shared MX infrastructure. It does not publish per-customer TLSA records.",
		Alternative: altMTASTS,
		Patterns:    []string{"pphosted.com", "ppe-hosted.com"},
	},
	"barracuda": {
		Name: "Barracuda", DANEInbound: false, DANEOutbound: false,
		Reason:      "Barracuda is a security gateway with shared MX infrastructure. It does not publish per-customer TLSA records.",
		Alternative: altMTASTS,
		Patterns:    []string{"barracudanetworks.com"},
	},
	"icloud": {
		Name: "iCloud Mail", DANEInbound: false, DANEOutbound: false,
		Reason:      "Apple iCloud Mail does not publish TLSA records for its MX hosts.",
		Alternative: altMTASTS,
		Patterns:    []string{"icloud.com"},
	},
	"yahoo": {
		Name: "Yahoo Mail", DANEInbound: false, DANEOutbound: false,
		Reason:      "Yahoo Mail does not publish TLSA records for its MX hosts.",
		Alternative: altMTASTS,
		Patterns:    []string{"yahoodns.net"},
	},
}

var DMARCMonitoringProviders = map[string]MonitoringProvider{
	"agari.com":        {Name: "Agari", Capabilities: []string{capDMARCReporting, capDMARCEnforcement}},
	domainDmarcian:     {Name: "dmarcian", Capabilities: []string{capDMARCReporting, capDMARCAnalytics}},
	domainOndmarc:      {Name: nameRedSiftOnDMARC, Capabilities: []string{capDMARCReporting, capDMARCEnforcement}},
	domainRedsift:      {Name: nameRedSiftOnDMARC, Capabilities: []string{capDMARCReporting, capDMARCEnforcement}},
	domainValimail:     {Name: "Valimail", Capabilities: []string{capDMARCReporting, capDMARCEnforcement, capSPFManagement}},
	"postmarkapp.com":  {Name: "Postmark", Capabilities: []string{capDMARCReporting}},
	"250ok.com":        {Name: "250ok (Validity)", Capabilities: []string{capDMARCReporting}},
	"proofpoint.com":   {Name: "Proofpoint", Capabilities: []string{capDMARCReporting, capDMARCEnforcement}},
	"fraudmarc.com":    {Name: "Fraudmarc", Capabilities: []string{capDMARCReporting}},
	"mxtoolbox.com":    {Name: "MXToolbox", Capabilities: []string{capDMARCReporting}},
	"uriports.com":     {Name: "URIports", Capabilities: []string{capDMARCReporting, capTLSRPTReporting}},
	"easydmarc.com":    {Name: "EasyDMARC", Capabilities: []string{capDMARCReporting, capDMARCAnalytics}},
	"sendmarc.com":     {Name: "Sendmarc", Capabilities: []string{capDMARCReporting, capDMARCEnforcement}},
	"report-uri.com":   {Name: "Report URI", Capabilities: []string{capDMARCReporting}},
	"dmarc.report":     {Name: "DMARC Report", Capabilities: []string{capDMARCReporting}},
	"dmarcadvisor.com": {Name: "DMARC Advisor", Capabilities: []string{capDMARCReporting, capDMARCAnalytics}},
}

var SPFFlatteningProviders = []SPFFlatteningProvider{
	{Name: "AutoSPF", Patterns: []string{"_spf.autospf.com", "autospf.com"}},
	{Name: "dmarcian SPF Surveyor", Patterns: []string{domainDmarcian}},
	{Name: "EasyDMARC EasySPF", Patterns: []string{"easyspf.com", domainEasydmarc}},
	{Name: "Mailhardener SPF Optimizer", Patterns: []string{"mailhardener.com"}},
	{Name: nameRedSiftOnDMARC, Patterns: []string{domainRedsift, domainOndmarc}},
	{Name: "Valimail SPF", Patterns: []string{domainValimail, "_spf.valimail.com"}},
}

var DynamicServicesProviders = map[string]DynamicServiceProvider{
	"dyn.com":      {Name: "Dyn (Oracle)", Category: catDynamicDNS},
	"dynect.net":   {Name: "Dyn (Oracle)", Category: catDynamicDNS},
	"no-ip.com":    {Name: nameNoIP, Category: catDynamicDNS},
	"no-ip.org":    {Name: nameNoIP, Category: catDynamicDNS},
	"no-ip.biz":    {Name: nameNoIP, Category: catDynamicDNS},
	"changeip.com": {Name: "ChangeIP", Category: catDynamicDNS},
	"afraid.org":   {Name: "FreeDNS", Category: catDynamicDNS},
	"duckdns.org":  {Name: "DuckDNS", Category: catDynamicDNS},
	"dynu.com":     {Name: "Dynu", Category: catDynamicDNS},
	domainNsupdate: {Name: "nsupdate.info", Category: catDynamicDNS},
}

var DynamicServicesZones = []string{
	"dyndns.org", "dyndns.com", "homeip.net", "dyn.com",
	"no-ip.com", "no-ip.org", "no-ip.biz", "noip.com",
	"ddns.net", "hopto.org", "zapto.org", "sytes.net",
	"ddns.me", "freedns.afraid.org",
	"duckdns.org", "dynu.com", domainNsupdate,
	"changeip.com",
}

var HostedDKIMProviders = []HostedDKIMProvider{
	{Name: "dmarcian", Patterns: []string{domainDmarcian}},
	{Name: "Valimail", Patterns: []string{domainValimail}},
	{Name: nameRedSiftOnDMARC, Patterns: []string{domainRedsift, domainOndmarc}},
	{Name: "Agari", Patterns: []string{"agari.com"}},
	{Name: "EasyDMARC", Patterns: []string{domainEasydmarc}},
	{Name: "Sendmarc", Patterns: []string{"sendmarc.com"}},
}
