// dns-tool:scrutiny science
package icae

import (
        "dnstool/go-server/internal/citation"
        "fmt"
)

const (
        fmtE2ePair   = "%s + %s (end-to-end)"
        fmtE2eSingle = "%s (end-to-end)"
)

var (
        rfcSPFSection5    string
        rfcSPFSection464  string
        rfcSPF            string
        rfcDMARC          string
        rfcDNSSECSection2 string
        rfcDNSSEC         string
        rfcDNSSection22   string
        rfcDNS            string

        rfcDKIM8301       string
        rfcDKIM8463       string
        rfcDKIM6376       string
        rfcMTASTSSection5 string
        rfcBIMISection3   string
        rfcDMARCSection63 string
        rfcDANE7672       string
        rfcCAA8659        string

        rfcNullMX7505    string
        rfcSMTP5321S5    string
        rfcMTASTS8461S31 string
        rfcCAASection4   string

        citRFC4033     string
        citRFC1035     string
        citRFC5321S5   string
        citRFC6376S361 string
        citRFC6698S21  string
        citRFC7208S3   string
        citRFC7208S32  string
        citRFC7208S5   string
        citRFC7208     string
        citRFC7489S61  string
        citRFC7489S63  string
        citRFC7489     string
        citRFC7505     string
        citRFC7672S13  string
        citRFC7672S31  string
        citRFC7672     string
        citRFC8460S3   string
        citRFC8461S31  string
        citRFC8461S32  string
        citRFC8624S33  string
        citRFC8659S4   string
        citRFC8659S43  string
        citRFC8659S44  string
        citRFC9495     string

        citFixtureE2eDmarcSPF   string
        citFixtureE2eBimiCAA    string
        citFixtureE2eDNSSEC     string
        citFixtureE2eMTASTS     string
        citFixtureE2eDANE       string
        citFixtureE2eNullMXSPF  string
        citFixtureE2eSPF        string
        citFixtureE2eBimiCAASec string
        citFixtureE2eDmarcS63   string
        citFixtureE2eSPFS5      string
        citFixtureE2eCAASection string
        citFixtureE2eDANEMulti  string
)

func init() {
        reg := citation.Global()

        rfcSPFSection5, _ = reg.ResolveRFC("rfc:7208§5")
        rfcSPFSection464, _ = reg.ResolveRFC("rfc:7208§4.6.4")
        rfcSPF, _ = reg.ResolveRFC("rfc:7208")
        rfcDMARC, _ = reg.ResolveRFC("rfc:7489")
        rfcDNSSECSection2, _ = reg.ResolveRFC("rfc:4033§2")
        rfcDNSSEC, _ = reg.ResolveRFC("rfc:4033")
        rfcDNSSection22, _ = reg.ResolveRFC("rfc:1035§2.2")
        rfcDNS, _ = reg.ResolveRFC("rfc:1035")

        rfcDKIM8301, _ = reg.ResolveRFC("rfc:8301")
        rfcDKIM8463, _ = reg.ResolveRFC("rfc:8463")
        rfcDKIM6376, _ = reg.ResolveRFC("rfc:6376")
        rfcMTASTSSection5, _ = reg.ResolveRFC("rfc:8461§5")
        rfcBIMISection3, _ = reg.ResolveRFC("rfc:9495§3")
        rfcDMARCSection63, _ = reg.ResolveRFC("rfc:7489§6.3")
        rfcDANE7672, _ = reg.ResolveRFC("rfc:7672")
        rfcCAA8659, _ = reg.ResolveRFC("rfc:8659")

        rfcNullMX7505, _ = reg.ResolveRFC("rfc:7505")
        rfcSMTP5321S5, _ = reg.ResolveRFC("rfc:5321§5")
        rfcMTASTS8461S31, _ = reg.ResolveRFC("rfc:8461§3.1")
        rfcCAASection4, _ = reg.ResolveRFC("rfc:8659§4")

        citRFC4033, _ = reg.ResolveRFC("rfc:4033")
        citRFC1035, _ = reg.ResolveRFC("rfc:1035")
        citRFC5321S5, _ = reg.ResolveRFC("rfc:5321§5")
        citRFC6376S361, _ = reg.ResolveRFC("rfc:6376§3.6.1")
        citRFC6698S21, _ = reg.ResolveRFC("rfc:6698§2.1")
        citRFC7208S3, _ = reg.ResolveRFC("rfc:7208§3")
        citRFC7208S32, _ = reg.ResolveRFC("rfc:7208§3.2")
        citRFC7208S5, _ = reg.ResolveRFC("rfc:7208§5")
        citRFC7208, _ = reg.ResolveRFC("rfc:7208")
        citRFC7489S61, _ = reg.ResolveRFC("rfc:7489§6.1")
        citRFC7489S63, _ = reg.ResolveRFC("rfc:7489§6.3")
        citRFC7489, _ = reg.ResolveRFC("rfc:7489")
        citRFC7505, _ = reg.ResolveRFC("rfc:7505")
        citRFC7672S13, _ = reg.ResolveRFC("rfc:7672§1.3")
        citRFC7672S31, _ = reg.ResolveRFC("rfc:7672§3.1")
        citRFC7672, _ = reg.ResolveRFC("rfc:7672")
        citRFC8460S3, _ = reg.ResolveRFC("rfc:8460§3")
        citRFC8461S31, _ = reg.ResolveRFC("rfc:8461§3.1")
        citRFC8461S32, _ = reg.ResolveRFC("rfc:8461§3.2")
        citRFC8624S33, _ = reg.ResolveRFC("rfc:8624§3.3")
        citRFC8659S4, _ = reg.ResolveRFC("rfc:8659§4")
        citRFC8659S43, _ = reg.ResolveRFC("rfc:8659§4.3")
        citRFC8659S44, _ = reg.ResolveRFC("rfc:8659§4.4")
        citRFC9495, _ = reg.ResolveRFC("rfc:9495")

        citFixtureE2eDmarcSPF = fmt.Sprintf(fmtE2ePair, citRFC7489S63, citRFC7208)
        citFixtureE2eBimiCAA = fmt.Sprintf("%s + BIMI Spec + %s (end-to-end)", citRFC7489, citRFC8659S4)
        citFixtureE2eDNSSEC = fmt.Sprintf(fmtE2ePair, citRFC4033, citRFC1035)
        citFixtureE2eMTASTS = fmt.Sprintf("%s-3.2 (end-to-end)", citRFC8461S31)
        citFixtureE2eDANE = fmt.Sprintf(fmtE2ePair, citRFC6698S21, citRFC7672)
        citFixtureE2eNullMXSPF = fmt.Sprintf(fmtE2ePair, citRFC7505, citRFC7208)
        citFixtureE2eSPF = fmt.Sprintf(fmtE2eSingle, citRFC7208)
        citFixtureE2eBimiCAASec = fmt.Sprintf("%s + BIMI + %s (end-to-end)", citRFC7489, citRFC8659S4)
        citFixtureE2eDmarcS63 = fmt.Sprintf(fmtE2eSingle, citRFC7489S63)
        citFixtureE2eSPFS5 = fmt.Sprintf(fmtE2eSingle, citRFC7208S5)
        citFixtureE2eCAASection = fmt.Sprintf(fmtE2eSingle, citRFC8659S4)
        citFixtureE2eDANEMulti = fmt.Sprintf(fmtE2ePair, citRFC6698S21, citRFC7672)
}
