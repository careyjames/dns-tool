// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "encoding/base64"
        "fmt"
        "regexp"
        "sort"
        "strings"
        "sync"
)

const (
        domainkeySuffix              = "._domainkey"
        ancillaryServicesLikelyFmt   = "The %s SPF include likely supports ancillary services "
        ancillaryServicesDescription = "(e.g., calendar invitations, shared documents) rather than primary mailbox hosting."
)

const (
        providerMicrosoft365    = "Microsoft 365"
        providerGoogleWS        = "Google Workspace"
        providerMailChimp       = "MailChimp"
        providerSendGrid        = "SendGrid"
        providerMailjet         = "Mailjet"
        providerAmazonSES       = "Amazon SES"
        providerPostmark        = "Postmark"
        providerSparkPost       = "SparkPost"
        providerMailgun         = "Mailgun"
        providerBrevo           = "Brevo (Sendinblue)"
        providerMimecast        = "Mimecast"
        providerProofpoint      = "Proofpoint"
        providerZohoMail        = "Zoho Mail"
        providerFastmail        = "Fastmail"
        providerProtonMail      = "ProtonMail"
        providerCloudflareEmail = "Cloudflare Email"
        providerBarracuda       = "Barracuda"
        providerHornetsecurity  = "Hornetsecurity"
        providerSpamExperts     = "SpamExperts"
        providerZendesk         = "Zendesk"
        providerUnknown         = "Unknown"
        providerDrip            = "Drip"

        selDefault     = "default._domainkey"
        selDKIM        = "dkim._domainkey"
        selMail        = "mail._domainkey"
        selEmail       = "email._domainkey"
        selK1          = "k1._domainkey"
        selK2          = "k2._domainkey"
        selS1          = "s1._domainkey"
        selS2          = "s2._domainkey"
        selSig1        = "sig1._domainkey"
        selSelector1   = "selector1._domainkey"
        selSelector2   = "selector2._domainkey"
        selGoogle      = "google._domainkey"
        selGoogle2048  = "google2048._domainkey"
        selMailjet     = "mailjet._domainkey"
        selMandrill    = "mandrill._domainkey"
        selAmazonSES   = "amazonses._domainkey"
        selSendgrid    = "sendgrid._domainkey"
        selMailchimp   = "mailchimp._domainkey"
        selPostmark    = "postmark._domainkey"
        selSparkpost   = "sparkpost._domainkey"
        selMailgun     = "mailgun._domainkey"
        selSendinblue  = "sendinblue._domainkey"
        selMimecast    = "mimecast._domainkey"
        selProofpoint  = "proofpoint._domainkey"
        selEverlytic   = "everlytickey1._domainkey"
        selZendesk1    = "zendesk1._domainkey"
        selZendesk2    = "zendesk2._domainkey"
        selCM          = "cm._domainkey"
        selMX          = "mx._domainkey"
        selSMTP        = "smtp._domainkey"
        selMailer      = "mailer._domainkey"
        selProtonmail  = "protonmail._domainkey"
        selProtonmail2 = "protonmail2._domainkey"
        selProtonmail3 = "protonmail3._domainkey"
        selFM1         = "fm1._domainkey"
        selFM2         = "fm2._domainkey"
        selFM3         = "fm3._domainkey"

        selZoho     = "zoho._domainkey"
        selZohoMail = "zohomail._domainkey"
        selZmail    = "zmail._domainkey"
        selSquare   = "square._domainkey"
        selSquareup = "squareup._domainkey"
        selSQ       = "sq._domainkey"

        selDKIM1          = "dkim1._domainkey"
        selDKIM2          = "dkim2._domainkey"
        selDKIM3          = "dkim3._domainkey"
        selKey1           = "key1._domainkey"
        selKey2           = "key2._domainkey"
        selSig2           = "sig2._domainkey"
        selS3             = "s3._domainkey"
        selK3             = "k3._domainkey"
        selSelector3      = "selector3._domainkey"
        selBrevo          = "brevo._domainkey"
        selMTA            = "mta._domainkey"
        selMTA1           = "mta1._domainkey"
        selMTA2           = "mta2._domainkey"
        selSendgrid2      = "sendgrid2._domainkey"
        selSmtpapi        = "smtpapi._domainkey"
        selEM             = "em._domainkey"
        selBarracuda      = "barracuda._domainkey"
        selHornet         = "hornet._domainkey"
        selCiscoDKIM      = "cisco._domainkey"
        selTurbo          = "turbo-smtp._domainkey"
        selFreshdesk      = "freshdesk._domainkey"
        selHubspot        = "hubspot._domainkey"
        selHS1            = "hs1._domainkey"
        selHS2            = "hs2._domainkey"
        selSalesforce     = "salesforce._domainkey"
        selSF1            = "sf1._domainkey"
        selSF2            = "sf2._domainkey"
        selMandrill2      = "mandrill2._domainkey"
        selKlaviyo        = "klaviyo._domainkey"
        selIntercom       = "intercom._domainkey"
        selCustomerio     = "customerio._domainkey"
        selConstContact   = "ctct1._domainkey"
        selConstContact2  = "ctct2._domainkey"
        selActiveCampaign = "dk._domainkey"
        selMailchimp2     = "mc._domainkey"
        selMailerLite     = "ml._domainkey"
        selDrip           = "drip._domainkey"
        selEverlyticKey2  = "everlytickey2._domainkey"

        providerSquareOnline    = "Square Online"
        providerCustomerIO      = "Customer.io"
        providerConstantContact = "Constant Contact"

        mapKeyKeyBits     = "key_bits"
        mapKeyProvider    = "provider"
        mapKeyRevoked     = "revoked"
        strActivecampaign = "ActiveCampaign"
        strEverlytic      = "Everlytic"
        strFreshdesk      = "Freshdesk"
        strHubspot        = "HubSpot"
        strIntercom       = "Intercom"
        strKlaviyo        = "Klaviyo"
        strMailerlite     = "MailerLite"
        strSalesforce     = "Salesforce"
)

var (
        dkimKeyTypeRe  = regexp.MustCompile(`(?i)\bk=(\w+)`)
        dkimPKeyRe     = regexp.MustCompile(`(?i)\bp=([^;\s]*)`)
        dkimTestFlagRe = regexp.MustCompile(`(?i)\bt=y\b`)
)

var defaultDKIMSelectors = []string{
        selDefault, selDKIM, selMail,
        selEmail, selK1, selK2, selK3,
        selS1, selS2, selS3, selSig1, selSig2,
        selSelector1, selSelector2, selSelector3,
        selGoogle, selGoogle2048,
        selMailjet, selMandrill, selMandrill2, selAmazonSES,
        selSendgrid, selSendgrid2, selSmtpapi, selEM,
        selMailchimp, selMailchimp2, selPostmark,
        selSparkpost, selMailgun, selSendinblue, selBrevo,
        selMimecast, selProofpoint, selEverlytic, selEverlyticKey2,
        selZendesk1, selZendesk2, selCM,
        selMX, selSMTP, selMailer, selMTA, selMTA1, selMTA2,
        selProtonmail, selProtonmail2, selProtonmail3,
        selFM1, selFM2, selFM3,
        selZoho, selZohoMail, selZmail,
        selSquare, selSquareup, selSQ,
        selDKIM1, selDKIM2, selDKIM3,
        selKey1, selKey2,
        selBarracuda, selHornet, selCiscoDKIM, selTurbo,
        selFreshdesk, selHubspot, selHS1, selHS2,
        selSalesforce, selSF1, selSF2,
        selKlaviyo, selIntercom, selCustomerio,
        selConstContact, selConstContact2,
        selActiveCampaign, selMailerLite, selDrip,
}

var selectorProviderMap = map[string]string{
        selSelector1:      providerMicrosoft365,
        selSelector2:      providerMicrosoft365,
        selGoogle:         providerGoogleWS,
        selGoogle2048:     providerGoogleWS,
        selK1:             providerMailChimp,
        selK2:             providerMailChimp,
        "k3._domainkey":   providerMailChimp,
        selMailchimp:      providerMailChimp,
        selMandrill:       "MailChimp (Mandrill)",
        selS1:             providerSendGrid,
        selS2:             providerSendGrid,
        selSendgrid:       providerSendGrid,
        selMailjet:        providerMailjet,
        selAmazonSES:      providerAmazonSES,
        selPostmark:       providerPostmark,
        selSparkpost:      providerSparkPost,
        selMailgun:        providerMailgun,
        selSendinblue:     providerBrevo,
        selMimecast:       providerMimecast,
        selProofpoint:     providerProofpoint,
        selEverlytic:      strEverlytic,
        selEverlyticKey2:  strEverlytic,
        selZendesk1:       providerZendesk,
        selZendesk2:       providerZendesk,
        selCM:             "Campaign Monitor",
        selZoho:           providerZohoMail,
        selZohoMail:       providerZohoMail,
        selZmail:          providerZohoMail,
        selSquare:         providerSquareOnline,
        selSquareup:       providerSquareOnline,
        selSQ:             providerSquareOnline,
        selBrevo:          providerBrevo,
        selSendgrid2:      providerSendGrid,
        selSmtpapi:        providerSendGrid,
        selEM:             providerSendGrid,
        selMandrill2:      "MailChimp (Mandrill)",
        selMailchimp2:     providerMailChimp,
        selBarracuda:      providerBarracuda,
        selHornet:         providerHornetsecurity,
        selFreshdesk:      strFreshdesk,
        selHubspot:        strHubspot,
        selHS1:            strHubspot,
        selHS2:            strHubspot,
        selSalesforce:     strSalesforce,
        selSF1:            strSalesforce,
        selSF2:            strSalesforce,
        selKlaviyo:        strKlaviyo,
        selIntercom:       strIntercom,
        selCustomerio:     providerCustomerIO,
        selConstContact:   providerConstantContact,
        selConstContact2:  providerConstantContact,
        selActiveCampaign: strActivecampaign,
        selMailerLite:     strMailerlite,
        selDrip:           providerDrip,
}

var mxToDKIMProvider = map[string]string{
        "google":             providerGoogleWS,
        "googlemail":         providerGoogleWS,
        "gmail":              providerGoogleWS,
        "outlook":            providerMicrosoft365,
        "microsoft":          providerMicrosoft365,
        "protection.outlook": providerMicrosoft365,
        "o365":               providerMicrosoft365,
        "exchange":           providerMicrosoft365,
        "intermedia":         providerMicrosoft365,
        "pphosted":           providerProofpoint,
        "gpphosted":          providerProofpoint,
        "iphmx":              providerProofpoint,
        "mimecast":           providerMimecast,
        "barracudanetworks":  providerBarracuda,
        "barracuda":          providerBarracuda,
        "perception-point":   "Perception Point",
        "sophos":             "Sophos",
        "fireeyecloud":       "FireEye",
        "trendmicro":         "Trend Micro",
        "forcepoint":         "Forcepoint",
        "messagelabs":        "Symantec",
        "hornetsecurity":     providerHornetsecurity,
        "antispamcloud":      providerSpamExperts,
        "spamexperts":        providerSpamExperts,
        "zoho":               providerZohoMail,
        "mailgun":            providerMailgun,
        "sendgrid":           providerSendGrid,
        "amazonses":          providerAmazonSES,
        "fastmail":           providerFastmail,
        "protonmail":         providerProtonMail,
        "mx.cloudflare":      providerCloudflareEmail,
}

var securityGateways = map[string]bool{
        providerProofpoint: true, providerMimecast: true, providerBarracuda: true,
        "Perception Point": true, "Sophos": true, "FireEye": true,
        "Trend Micro": true, "Forcepoint": true, "Symantec": true,
        providerHornetsecurity: true, providerSpamExperts: true,
}

var mailboxProviders = map[string]bool{
        providerMicrosoft365:    true,
        providerGoogleWS:        true,
        providerZohoMail:        true,
        providerFastmail:        true,
        providerProtonMail:      true,
        providerCloudflareEmail: true,
}

var primaryProviderSelectors = map[string][]string{
        providerMicrosoft365:    {selSelector1, selSelector2, selSelector3},
        providerGoogleWS:        {selGoogle, selGoogle2048},
        providerProofpoint:      {selProofpoint},
        providerMimecast:        {selMimecast},
        providerMailgun:         {selMailgun},
        providerSendGrid:        {selS1, selS2, selS3, selSendgrid, selSendgrid2, selSmtpapi, selEM},
        providerAmazonSES:       {selAmazonSES},
        providerZohoMail:        {selZoho, selZohoMail, selZmail, selDefault},
        providerFastmail:        {selFM1, selFM2, selFM3},
        providerProtonMail:      {selProtonmail, selProtonmail2, selProtonmail3},
        providerCloudflareEmail: {selDefault},
        providerBarracuda:       {selBarracuda},
        providerHornetsecurity:  {selHornet},
        providerBrevo:           {selBrevo, selSendinblue},
        providerMailChimp:       {selMailchimp, selMailchimp2, selK1, selK2, selK3, selMandrill, selMandrill2},
        providerMailjet:         {selMailjet},
        providerPostmark:        {selPostmark},
        providerSparkPost:       {selSparkpost},
        providerZendesk:         {selZendesk1, selZendesk2},
        strHubspot:              {selHubspot, selHS1, selHS2},
        strSalesforce:           {selSalesforce, selSF1, selSF2},
        strKlaviyo:              {selKlaviyo},
        strIntercom:             {selIntercom},
        providerCustomerIO:      {selCustomerio},
        providerConstantContact: {selConstContact, selConstContact2},
        strActivecampaign:       {selActiveCampaign},
        strMailerlite:           {selMailerLite},
        providerDrip:            {selDrip},
        strFreshdesk:            {selFreshdesk},
        strEverlytic:            {selEverlytic, selEverlyticKey2},
}

var spfMailboxProviders = map[string]string{
        "spf.protection.outlook": providerMicrosoft365,
        "_spf.google":            providerGoogleWS,
        "spf.intermedia":         providerMicrosoft365,
        "emg.intermedia":         providerMicrosoft365,
        "zoho.com":               providerZohoMail,
        "messagingengine.com":    providerFastmail,
        "protonmail.ch":          providerProtonMail,
        "mimecast":               providerMimecast,
        "pphosted":               providerProofpoint,
}

var spfAncillarySenders = map[string]string{
        "servers.mcsv.net":    providerMailChimp,
        "spf.mandrillapp":     providerMailChimp,
        "sendgrid.net":        providerSendGrid,
        "amazonses.com":       providerAmazonSES,
        "mailgun.org":         providerMailgun,
        "spf.sparkpostmail":   providerSparkPost,
        "mail.zendesk.com":    providerZendesk,
        "spf.brevo.com":       providerBrevo,
        "spf.sendinblue":      providerBrevo,
        "spf.mailjet":         providerMailjet,
        "spf.postmarkapp":     providerPostmark,
        "spf.mtasv.net":       providerPostmark,
        "spf.freshdesk":       strFreshdesk,
        "hostedrt.com":        "Best Practical RT",
        "hubspot.net":         strHubspot,
        "spf.salesforce.com":  strSalesforce,
        "spf1.klaviyo.com":    strKlaviyo,
        "intercom.io":         strIntercom,
        "spf.customerio":      providerCustomerIO,
        "spf.constantcontact": providerConstantContact,
        "emsd1.com":           strActivecampaign,
        "spf.mailerlite":      strMailerlite,
        "getdrip.com":         providerDrip,
}

var ambiguousSelectors = map[string]bool{
        selSelector1: true,
        selSelector2: true,
        selS1:        true,
        selS2:        true,
        selDefault:   true,
        selK1:        true,
        selK2:        true,
}

type ProviderResolution struct {
        Primary           string
        Gateway           string
        SPFAncillaryNote  string
        DKIMInferenceNote string
        MXLegacyNote      string
}

func (pr *ProviderResolution) GatewayOrNil() interface{} {
        if pr.Gateway == "" {
                return nil
        }
        return pr.Gateway
}

func matchProviderFromRecords(records string, providerMap map[string]string) string {
        lower := strings.ToLower(records)
        for key, provider := range providerMap {
                if strings.Contains(lower, key) {
                        return provider
                }
        }
        return ""
}

func detectMXProvider(mxRecords []string) string {
        if len(mxRecords) == 0 {
                return ""
        }
        return matchProviderFromRecords(strings.Join(mxRecords, " "), mxToDKIMProvider)
}

func detectSPFMailboxProvider(spfRecord string) string {
        if spfRecord == "" {
                return ""
        }
        return matchProviderFromRecords(spfRecord, spfMailboxProviders)
}

func detectSPFAncillaryProvider(spfRecord string) string {
        if spfRecord == "" {
                return ""
        }
        return matchProviderFromRecords(spfRecord, spfAncillarySenders)
}

func resolveProviderWithGateway(mxProvider, spfMailbox string) (primary, gateway string) {
        if mxProvider != "" && securityGateways[mxProvider] && spfMailbox != "" && spfMailbox != mxProvider {
                return spfMailbox, mxProvider
        }
        if mxProvider != "" {
                return mxProvider, ""
        }
        if spfMailbox != "" {
                return spfMailbox, ""
        }
        return providerUnknown, ""
}

func detectAllSPFMailboxProviders(spfRecord string) []string {
        if spfRecord == "" {
                return nil
        }
        lower := strings.ToLower(spfRecord)
        var found []string
        seen := map[string]bool{}
        for key, provider := range spfMailboxProviders {
                if strings.Contains(lower, key) && !seen[provider] {
                        found = append(found, provider)
                        seen[provider] = true
                }
        }
        return found
}

func detectPrimaryMailProvider(mxRecords []string, spfRecord string) ProviderResolution {
        if len(mxRecords) == 0 && spfRecord == "" {
                return ProviderResolution{Primary: providerUnknown}
        }

        mxProvider := detectMXProvider(mxRecords)
        spfProviders := detectAllSPFMailboxProviders(spfRecord)

        spfMailbox, ancillaryNote := reconcileSPFWithMX(mxProvider, spfProviders)

        spfMailbox, mxProvider, ancillaryNote = handleSelfHostedMX(spfMailbox, mxProvider, mxRecords, spfRecord, ancillaryNote)

        if spfMailbox == "" && mxProvider == "" {
                ancillary := detectSPFAncillaryProvider(spfRecord)
                if ancillary != "" {
                        return ProviderResolution{Primary: providerUnknown, SPFAncillaryNote: ancillaryNote}
                }
        }

        primary, gateway := resolveProviderWithGateway(mxProvider, spfMailbox)
        mxLegacyNote := detectGoogleLegacyMX(mxRecords, mxProvider)

        return ProviderResolution{Primary: primary, Gateway: gateway, SPFAncillaryNote: ancillaryNote, MXLegacyNote: mxLegacyNote}
}

func reconcileSPFWithMX(mxProvider string, spfProviders []string) (string, string) {
        if mxProvider == "" || len(spfProviders) == 0 {
                if len(spfProviders) > 0 {
                        return spfProviders[0], ""
                }
                return "", ""
        }

        var ancillaryProviders []string
        mxMatchedInSPF := false
        for _, sp := range spfProviders {
                if sp == mxProvider {
                        mxMatchedInSPF = true
                } else {
                        ancillaryProviders = append(ancillaryProviders, sp)
                }
        }

        if mxMatchedInSPF {
                note := ""
                if len(ancillaryProviders) > 0 {
                        note = fmt.Sprintf(
                                "SPF authorizes %s alongside primary mail provider %s. "+
                                        ancillaryServicesLikelyFmt+
                                        ancillaryServicesDescription,
                                strings.Join(ancillaryProviders, ", "), mxProvider, strings.Join(ancillaryProviders, ", "))
                }
                return mxProvider, note
        }

        if securityGateways[mxProvider] {
                return spfProviders[0], ""
        }

        note := fmt.Sprintf(
                "SPF authorizes %s servers, but MX records point to %s. "+
                        ancillaryServicesLikelyFmt+
                        ancillaryServicesDescription,
                spfProviders[0], mxProvider, spfProviders[0])
        return "", note
}

func handleSelfHostedMX(spfMailbox, mxProvider string, mxRecords []string, spfRecord, ancillaryNote string) (string, string, string) {
        if spfMailbox == "" || mxProvider != "" || len(mxRecords) == 0 {
                return spfMailbox, mxProvider, ancillaryNote
        }
        ancillaryNote = fmt.Sprintf(
                "SPF authorizes %s servers, but MX records point to self-hosted infrastructure. "+
                        ancillaryServicesLikelyFmt+
                        ancillaryServicesDescription,
                spfMailbox, spfMailbox)
        if detectSPFAncillaryProvider(spfRecord) == "" {
                mxProvider = "Self-hosted"
        }
        return "", mxProvider, ancillaryNote
}

func detectGoogleLegacyMX(mxRecords []string, mxProvider string) string {
        if mxProvider != providerGoogleWS || len(mxRecords) < 4 {
                return ""
        }
        googleCount := 0
        for _, mx := range mxRecords {
                if strings.Contains(strings.ToLower(mx), "aspmx.l.google.com") ||
                        strings.Contains(strings.ToLower(mx), "googlemail.com") {
                        googleCount++
                }
        }
        if googleCount >= 4 {
                return fmt.Sprintf(
                        "Google Workspace now requires only a single MX record (aspmx.l.google.com). "+
                                "This domain has %d legacy Google MX records that can be consolidated.",
                        googleCount)
        }
        return ""
}

func classifySelectorProvider(selectorName, primaryProvider string) string {
        provider, ok := selectorProviderMap[selectorName]
        if !ok {
                return providerUnknown
        }

        if primaryProvider == providerUnknown && ambiguousSelectors[selectorName] {
                return providerUnknown
        }
        return provider
}

func checkDKIMSelector(ctx context.Context, dns interface {
        QueryDNS(ctx context.Context, recordType, domain string) []string
}, selector, domain string) (string, []string) {
        fqdn := fmt.Sprintf("%s.%s", selector, domain)
        records := dns.QueryDNS(ctx, "TXT", fqdn)
        if len(records) == 0 {
                return "", nil
        }

        var dkimRecords []string
        for _, r := range records {
                lower := strings.ToLower(r)
                if strings.Contains(lower, "v=dkim1") || strings.Contains(lower, "k=") || strings.Contains(lower, "p=") {
                        dkimRecords = append(dkimRecords, r)
                }
        }
        if len(dkimRecords) > 0 {
                return selector, dkimRecords
        }
        return "", nil
}

func estimateKeyBits(keyBytes int) int {
        switch {
        case keyBytes <= 140:
                return 1024
        case keyBytes <= 300:
                return 2048
        case keyBytes <= 600:
                return 4096
        default:
                return keyBytes * 8 / 10
        }
}

func analyzePublicKey(record string) (keyBits interface{}, revoked bool, issues []string) {
        m := dkimPKeyRe.FindStringSubmatch(record)
        if m == nil {
                return nil, false, nil
        }
        publicKey := strings.TrimSpace(m[1])
        if publicKey == "" {
                return nil, true, []string{"Key revoked (p= empty)"}
        }
        for len(publicKey)%4 != 0 {
                publicKey += "="
        }
        decoded, err := base64.StdEncoding.DecodeString(publicKey)
        if err != nil {
                decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(publicKey, "="))
                if err != nil {
                        return nil, false, nil
                }
        }
        bits := estimateKeyBits(len(decoded))
        if bits == 1024 {
                return bits, false, []string{"1024-bit key (weak, upgrade to 2048)"}
        }
        return bits, false, nil
}

func analyzeDKIMKey(record string) map[string]any {
        keyInfo := map[string]any{
                "key_type":    "rsa",
                mapKeyKeyBits: nil,
                mapKeyRevoked: false,
                "test_mode":   false,
                mapKeyIssues:  []string{},
        }

        keyType := "rsa"
        if m := dkimKeyTypeRe.FindStringSubmatch(strings.ToLower(record)); m != nil {
                keyType = m[1]
                keyInfo["key_type"] = keyType
        }

        lower := strings.ToLower(record)
        testMode := dkimTestFlagRe.MatchString(lower)
        keyInfo["test_mode"] = testMode

        keyBits, revoked, pkIssues := analyzePublicKey(record)
        keyInfo[mapKeyKeyBits] = keyBits
        keyInfo[mapKeyRevoked] = revoked

        if keyBits != nil {
                if bits, ok := keyBits.(int); ok {
                        c := ClassifyDKIMKey(keyType, bits)
                        keyInfo["key_strength"] = c.Strength
                        keyInfo["key_strength_label"] = c.Label
                        keyInfo["key_strength_rfc"] = c.RFC
                        keyInfo["key_strength_observation"] = c.Observation
                }
        }

        var issues []string
        issues = append(issues, pkIssues...)

        if testMode {
                issues = append(issues, "DKIM key in test mode (t=y per RFC 6376 §3.6.1) — verifiers should treat failures as unsigned, remove t=y for production")
        }

        if issues == nil {
                issues = []string{}
        }
        keyInfo[mapKeyIssues] = issues
        return keyInfo
}

func AllSelectorsKnown(customSelectors []string) bool {
        if len(customSelectors) == 0 {
                return true
        }
        known := make(map[string]bool, len(defaultDKIMSelectors))
        for _, s := range defaultDKIMSelectors {
                known[s] = true
        }
        for _, cs := range customSelectors {
                cs = strings.TrimSpace(strings.ToLower(cs))
                cs = strings.TrimRight(cs, ".")
                if cs == "" {
                        continue
                }
                if !strings.HasSuffix(cs, domainkeySuffix) {
                        cs = cs + domainkeySuffix
                }
                if !known[cs] {
                        return false
                }
        }
        return true
}

func buildSelectorList(customSelectors []string) []string {
        selectors := make([]string, 0, len(defaultDKIMSelectors)+len(customSelectors))
        if len(customSelectors) > 0 {
                for _, cs := range customSelectors {
                        if !strings.HasSuffix(cs, domainkeySuffix) {
                                cs = cs + domainkeySuffix
                        }
                        selectors = append(selectors, cs)
                }
        }
        for _, s := range defaultDKIMSelectors {
                found := false
                for _, existing := range selectors {
                        if existing == s {
                                found = true
                                break
                        }
                }
                if !found {
                        selectors = append(selectors, s)
                }
        }
        return selectors
}

func findSPFRecord(records []string) string {
        for _, r := range records {
                if strings.HasPrefix(strings.ToLower(r), "v=spf1") {
                        return r
                }
        }
        return ""
}

func collectUnattributed(foundSelectors map[string]map[string]any) []string {
        var unattributed []string
        for selName, selData := range foundSelectors {
                if selData[mapKeyProvider].(string) == providerUnknown {
                        unattributed = append(unattributed, selName)
                }
        }
        return unattributed
}

func checkPrimaryHasDKIM(foundSelectors map[string]map[string]any, primaryProvider string, foundProviders map[string]bool) bool {
        expected := primaryProviderSelectors[primaryProvider]
        if len(expected) > 0 {
                for _, s := range expected {
                        if _, ok := foundSelectors[s]; ok {
                                return true
                        }
                }
                return false
        }
        return foundProviders[primaryProvider]
}

func inferUnattributedSelectors(foundSelectors map[string]map[string]any, unattributed []string, primaryProvider string, foundProviders map[string]bool) string {
        for _, selName := range unattributed {
                foundSelectors[selName][mapKeyProvider] = primaryProvider
                foundSelectors[selName]["inferred"] = true
                foundProviders[primaryProvider] = true
        }
        var names []string
        for _, s := range unattributed {
                names = append(names, strings.TrimSuffix(s, domainkeySuffix))
        }
        return fmt.Sprintf(
                "DKIM selector(s) %s inferred as %s (custom selector names — not the standard %s selector).",
                strings.Join(names, ", "), primaryProvider, primaryProvider,
        )
}

func buildThirdPartyNote(foundProviders map[string]bool, primaryProvider string) string {
        var providerNames []string
        for p := range foundProviders {
                providerNames = append(providerNames, p)
        }
        sort.Strings(providerNames)
        thirdPartyNames := "third-party services"
        if len(providerNames) > 0 {
                thirdPartyNames = strings.Join(providerNames, ", ")
        }
        return fmt.Sprintf(
                "DKIM verified for %s only — no DKIM found for primary mail platform (%s). "+
                        "The primary provider may use custom selectors not discoverable through standard checks. "+
                        "Try re-scanning with a custom DKIM selector if you know yours.",
                thirdPartyNames, primaryProvider,
        )
}

func attributeSelectors(foundSelectors map[string]map[string]any, primaryProvider string, foundProviders map[string]bool) (bool, string, bool) {
        if primaryProvider == providerUnknown {
                return false, "", false
        }

        unattributed := collectUnattributed(foundSelectors)
        primaryHasDKIM := checkPrimaryHasDKIM(foundSelectors, primaryProvider, foundProviders)

        if !primaryHasDKIM && len(unattributed) > 0 {
                note := inferUnattributedSelectors(foundSelectors, unattributed, primaryProvider, foundProviders)
                return true, note, false
        }

        if len(foundSelectors) > 0 && !primaryHasDKIM {
                return false, buildThirdPartyNote(foundProviders, primaryProvider), true
        }

        return primaryHasDKIM, "", false
}

func buildDKIMVerdict(foundSelectors map[string]map[string]any, keyIssues, keyStrengths []string, primaryProvider string, primaryHasDKIM, thirdPartyOnly bool) (string, string) {
        if len(foundSelectors) == 0 {
                return "info", "DKIM not discoverable via common selectors (large providers use rotating selectors)"
        }

        hasWeakKey := false
        hasRevoked := false
        for _, issue := range keyIssues {
                if strings.Contains(issue, "1024-bit") {
                        hasWeakKey = true
                }
                if strings.Contains(issue, mapKeyRevoked) {
                        hasRevoked = true
                }
        }

        uniqueStrengths := uniqueStrings(keyStrengths)

        if hasRevoked {
                return "warning", fmt.Sprintf("Found %d DKIM selector(s) but some keys are revoked", len(foundSelectors))
        }
        if hasWeakKey {
                return "warning", fmt.Sprintf("Found %d DKIM selector(s) with weak key(s) (1024-bit)", len(foundSelectors))
        }
        if thirdPartyOnly {
                if len(uniqueStrengths) > 0 {
                        return "partial", fmt.Sprintf("Found DKIM for %d selector(s) (%s) but none for primary mail platform (%s)",
                                len(foundSelectors), strings.Join(uniqueStrengths, ", "), primaryProvider)
                }
                return "partial", fmt.Sprintf("Found DKIM for %d selector(s) but none for primary mail platform (%s)",
                        len(foundSelectors), primaryProvider)
        }

        if len(uniqueStrengths) > 0 {
                return "success", fmt.Sprintf("Found DKIM for %d selector(s) with strong keys (%s)",
                        len(foundSelectors), strings.Join(uniqueStrengths, ", "))
        }
        return "success", fmt.Sprintf("Found DKIM records for %d selector(s)", len(foundSelectors))
}

func isCustomSelector(selectorName string, customSelectors []string) bool {
        for _, cs := range customSelectors {
                csNorm := cs
                if !strings.HasSuffix(csNorm, domainkeySuffix) {
                        csNorm = csNorm + domainkeySuffix
                }
                if csNorm == selectorName {
                        return true
                }
        }
        return false
}

func analyzeRecordKeys(records []string) ([]map[string]any, []string, []string) {
        var keyInfoList []map[string]any
        var issues []string
        var strengths []string
        for _, rec := range records {
                ka := analyzeDKIMKey(rec)
                keyInfoList = append(keyInfoList, ka)
                issues = append(issues, ka[mapKeyIssues].([]string)...)
                if bits, ok := ka[mapKeyKeyBits]; ok && bits != nil {
                        if b, ok := bits.(int); ok && b >= 2048 {
                                strengths = append(strengths, fmt.Sprintf("%d-bit", b))
                        }
                }
        }
        return keyInfoList, issues, strengths
}

type dkimScanResult struct {
        selectorName string
        selectorInfo map[string]any
        keyIssues    []string
        keyStrengths []string
}

func processDKIMSelector(ctx context.Context, dns interface {
        QueryDNS(ctx context.Context, recordType, domain string) []string
}, sel, domain, primaryProvider string, customSelectors []string) *dkimScanResult {
        selectorName, records := checkDKIMSelector(ctx, dns, sel, domain)
        if selectorName == "" {
                return nil
        }

        provider := classifySelectorProvider(selectorName, primaryProvider)
        keyInfoList, localIssues, localStrengths := analyzeRecordKeys(records)

        selectorInfo := map[string]any{
                "records":      records,
                "key_info":     keyInfoList,
                mapKeyProvider: provider,
                "user_hint":    isCustomSelector(selectorName, customSelectors),
        }

        return &dkimScanResult{
                selectorName: selectorName,
                selectorInfo: selectorInfo,
                keyIssues:    localIssues,
                keyStrengths: localStrengths,
        }
}

func collectFoundProviders(foundSelectors map[string]map[string]any) map[string]bool {
        providers := make(map[string]bool)
        for _, selData := range foundSelectors {
                p := selData[mapKeyProvider].(string)
                if p != providerUnknown {
                        providers[p] = true
                }
        }
        return providers
}

func inferMailboxBehindGateway(res *ProviderResolution, foundProviders map[string]bool) {
        if !securityGateways[res.Primary] {
                return
        }

        var mailboxCandidates []string
        for p := range foundProviders {
                if mailboxProviders[p] {
                        mailboxCandidates = append(mailboxCandidates, p)
                }
        }

        if len(mailboxCandidates) == 1 {
                inferred := mailboxCandidates[0]
                res.DKIMInferenceNote = fmt.Sprintf(
                        "Primary mailbox provider inferred as %s from DKIM selectors (mail routed through %s security gateway).",
                        inferred, res.Primary,
                )
                res.Gateway = res.Primary
                res.Primary = inferred
                return
        }

        if len(mailboxCandidates) > 1 {
                sort.Strings(mailboxCandidates)
                res.DKIMInferenceNote = fmt.Sprintf(
                        "Multiple mailbox providers detected behind %s gateway (%s) — cannot determine single primary from DKIM alone.",
                        res.Primary, strings.Join(mailboxCandidates, ", "),
                )
        }
}

func reclassifyAmbiguousSelectors(foundSelectors map[string]map[string]any, finalPrimary string) {
        for selName, selData := range foundSelectors {
                if selData[mapKeyProvider].(string) != providerUnknown {
                        continue
                }
                if !ambiguousSelectors[selName] {
                        continue
                }
                if mapped, ok := selectorProviderMap[selName]; ok && finalPrimary != providerUnknown {
                        selData[mapKeyProvider] = mapped
                        selData["reclassified"] = true
                }
        }
}

var dkimNSProviders = map[string]string{
        "ondmarc.com":    "Red Sift OnDMARC",
        "easydmarc.com":  "EasyDMARC",
        "valimail.com":   "Valimail",
        "dmarcian.com":   "dmarcian",
        "powerdmarc.com": "PowerDMARC",
        "agari.com":      "Agari (Fortra)",
        "socketlabs.com": "SocketLabs",
        "proofpoint.com": "Proofpoint",
        "mimecast.com":   "Mimecast",
}

type DKIMDelegation struct {
        Detected    bool
        Nameservers []string
        Provider    string
}

func matchDKIMNSProvider(nameservers []string) string {
        for _, ns := range nameservers {
                for suffix, name := range dkimNSProviders {
                        if strings.HasSuffix(ns, suffix) {
                                return name
                        }
                }
        }
        return ""
}

func normalizeDKIMNS(nsRecords []string) []string {
        var nameservers []string
        for _, ns := range nsRecords {
                normalized := strings.ToLower(strings.TrimRight(ns, "."))
                if normalized != "" {
                        nameservers = append(nameservers, normalized)
                }
        }
        return nameservers
}

func (a *Analyzer) detectDKIMDelegation(ctx context.Context, domain string) DKIMDelegation {
        dkZone := "_domainkey." + domain
        nsRecords := a.DNS.QueryDNS(ctx, "NS", dkZone)
        if len(nsRecords) == 0 {
                return DKIMDelegation{}
        }

        nameservers := normalizeDKIMNS(nsRecords)
        if len(nameservers) == 0 {
                return DKIMDelegation{}
        }

        return DKIMDelegation{
                Detected:    true,
                Nameservers: nameservers,
                Provider:    matchDKIMNSProvider(nameservers),
        }
}

func (a *Analyzer) AnalyzeDKIM(ctx context.Context, domain string, mxRecords, customSelectors []string) map[string]any {
        selectors := buildSelectorList(customSelectors)

        if len(mxRecords) == 0 {
                mxRecords = a.DNS.QueryDNS(ctx, "MX", domain)
        }

        dkimDelegation := a.detectDKIMDelegation(ctx, domain)

        spfRecord := findSPFRecord(a.DNS.QueryDNS(ctx, "TXT", domain))

        res := detectPrimaryMailProvider(mxRecords, spfRecord)

        foundSelectors := make(map[string]map[string]any)
        var keyIssues []string
        var keyStrengths []string
        var mu sync.Mutex
        var wg sync.WaitGroup

        for _, sel := range selectors {
                wg.Add(1)
                go func(s string) {
                        defer wg.Done()
                        result := processDKIMSelector(ctx, a.DNS, s, domain, res.Primary, customSelectors)
                        if result == nil {
                                return
                        }
                        mu.Lock()
                        foundSelectors[result.selectorName] = result.selectorInfo
                        keyIssues = append(keyIssues, result.keyIssues...)
                        keyStrengths = append(keyStrengths, result.keyStrengths...)
                        mu.Unlock()
                }(sel)
        }
        wg.Wait()

        foundProviders := collectFoundProviders(foundSelectors)

        prePrimary := res.Primary
        inferMailboxBehindGateway(&res, foundProviders)

        if res.Primary != prePrimary {
                reclassifyAmbiguousSelectors(foundSelectors, res.Primary)
                foundProviders = collectFoundProviders(foundSelectors)
        }

        primaryHasDKIM, primaryDKIMNote, thirdPartyOnly := attributeSelectors(foundSelectors, res.Primary, foundProviders)
        if res.DKIMInferenceNote != "" && primaryDKIMNote == "" {
                primaryDKIMNote = res.DKIMInferenceNote
        } else if res.DKIMInferenceNote != "" {
                primaryDKIMNote = res.DKIMInferenceNote + " " + primaryDKIMNote
        }

        status, message := buildDKIMVerdict(foundSelectors, keyIssues, keyStrengths, res.Primary, primaryHasDKIM, thirdPartyOnly)

        var sortedProviders []string
        for p := range foundProviders {
                sortedProviders = append(sortedProviders, p)
        }
        sort.Strings(sortedProviders)

        selectorMap := make(map[string]any, len(foundSelectors))
        for k, v := range foundSelectors {
                selectorMap[k] = v
        }

        var delegationMap map[string]any
        if dkimDelegation.Detected {
                delegationMap = map[string]any{
                        "detected":     true,
                        "nameservers":  dkimDelegation.Nameservers,
                        mapKeyProvider: dkimDelegation.Provider,
                }
        }

        return map[string]any{
                "status":               status,
                "message":              message,
                "selectors":            selectorMap,
                "key_issues":           keyIssues,
                "key_strengths":        uniqueStrings(keyStrengths),
                "primary_provider":     res.Primary,
                "security_gateway":     res.GatewayOrNil(),
                "primary_has_dkim":     primaryHasDKIM,
                "third_party_only":     thirdPartyOnly,
                "primary_dkim_note":    primaryDKIMNote,
                "found_providers":      sortedProviders,
                "spf_ancillary_note":   res.SPFAncillaryNote,
                "mx_legacy_note":       res.MXLegacyNote,
                "domainkey_delegation": delegationMap,
        }
}
