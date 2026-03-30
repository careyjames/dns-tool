package icae

import (
	"strings"
	"testing"
)

func TestCitationLabelConstants(t *testing.T) {
	if fmtE2ePair != "%s + %s (end-to-end)" {
		t.Errorf("fmtE2ePair = %q", fmtE2ePair)
	}
	if fmtE2eSingle != "%s (end-to-end)" {
		t.Errorf("fmtE2eSingle = %q", fmtE2eSingle)
	}
}

func TestCitationLabels_InitPopulatesVars(t *testing.T) {
	vars := []struct {
		name string
		val  string
	}{
		{"rfcSPFSection5", rfcSPFSection5},
		{"rfcSPFSection464", rfcSPFSection464},
		{"rfcSPF", rfcSPF},
		{"rfcDMARC", rfcDMARC},
		{"rfcDNSSECSection2", rfcDNSSECSection2},
		{"rfcDNSSEC", rfcDNSSEC},
		{"rfcDNSSection22", rfcDNSSection22},
		{"rfcDNS", rfcDNS},
		{"rfcDKIM8301", rfcDKIM8301},
		{"rfcDKIM8463", rfcDKIM8463},
		{"rfcDKIM6376", rfcDKIM6376},
		{"rfcMTASTSSection5", rfcMTASTSSection5},
		{"rfcBIMISection3", rfcBIMISection3},
		{"rfcDMARCSection63", rfcDMARCSection63},
		{"rfcDANE7672", rfcDANE7672},
		{"rfcCAA8659", rfcCAA8659},
		{"rfcNullMX7505", rfcNullMX7505},
		{"rfcSMTP5321S5", rfcSMTP5321S5},
		{"rfcMTASTS8461S31", rfcMTASTS8461S31},
		{"rfcCAASection4", rfcCAASection4},
	}
	for _, v := range vars {
		if v.val == "" {
			t.Errorf("citation label %s is empty after init()", v.name)
		}
		if !strings.Contains(v.val, "RFC") {
			t.Errorf("citation label %s = %q, expected to contain 'RFC'", v.name, v.val)
		}
	}
}

func TestCitationLabels_CitVarsPopulated(t *testing.T) {
	citVars := []struct {
		name string
		val  string
	}{
		{"citRFC4033", citRFC4033},
		{"citRFC1035", citRFC1035},
		{"citRFC5321S5", citRFC5321S5},
		{"citRFC6376S361", citRFC6376S361},
		{"citRFC6698S21", citRFC6698S21},
		{"citRFC7208S3", citRFC7208S3},
		{"citRFC7208S32", citRFC7208S32},
		{"citRFC7208S5", citRFC7208S5},
		{"citRFC7208", citRFC7208},
		{"citRFC7489S61", citRFC7489S61},
		{"citRFC7489S63", citRFC7489S63},
		{"citRFC7489", citRFC7489},
		{"citRFC7505", citRFC7505},
		{"citRFC7672S13", citRFC7672S13},
		{"citRFC7672S31", citRFC7672S31},
		{"citRFC7672", citRFC7672},
		{"citRFC8460S3", citRFC8460S3},
		{"citRFC8461S31", citRFC8461S31},
		{"citRFC8461S32", citRFC8461S32},
		{"citRFC8624S33", citRFC8624S33},
		{"citRFC8659S4", citRFC8659S4},
		{"citRFC8659S43", citRFC8659S43},
		{"citRFC8659S44", citRFC8659S44},
		{"citRFC9495", citRFC9495},
	}
	for _, v := range citVars {
		if v.val == "" {
			t.Errorf("citation var %s is empty after init()", v.name)
		}
	}
}

func TestCitationLabels_FixtureVarsPopulated(t *testing.T) {
	fixtureVars := []struct {
		name string
		val  string
	}{
		{"citFixtureE2eDmarcSPF", citFixtureE2eDmarcSPF},
		{"citFixtureE2eBimiCAA", citFixtureE2eBimiCAA},
		{"citFixtureE2eDNSSEC", citFixtureE2eDNSSEC},
		{"citFixtureE2eMTASTS", citFixtureE2eMTASTS},
		{"citFixtureE2eDANE", citFixtureE2eDANE},
		{"citFixtureE2eNullMXSPF", citFixtureE2eNullMXSPF},
		{"citFixtureE2eSPF", citFixtureE2eSPF},
		{"citFixtureE2eBimiCAASec", citFixtureE2eBimiCAASec},
		{"citFixtureE2eDmarcS63", citFixtureE2eDmarcS63},
		{"citFixtureE2eSPFS5", citFixtureE2eSPFS5},
		{"citFixtureE2eCAASection", citFixtureE2eCAASection},
		{"citFixtureE2eDANEMulti", citFixtureE2eDANEMulti},
	}
	for _, v := range fixtureVars {
		if v.val == "" {
			t.Errorf("fixture var %s is empty after init()", v.name)
		}
		if !strings.Contains(v.val, "end-to-end") {
			t.Errorf("fixture var %s = %q, expected to contain 'end-to-end'", v.name, v.val)
		}
	}
}
