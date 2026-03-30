//go:build intel

package analyzer

import (
	"testing"
)

func TestIsHostedEmailProvider_Intel_AlwaysTrue(t *testing.T) {
	inputs := []string{"google.com", "outlook.com", "", "unknown"}
	for _, input := range inputs {
		if !isHostedEmailProvider(input) {
			t.Errorf("isHostedEmailProvider(%q) = false, intel should return true", input)
		}
	}
}

func TestIsBIMICapableProvider_Intel_AlwaysFalse(t *testing.T) {
	inputs := []string{"google.com", "yahoo.com", "", "unknown"}
	for _, input := range inputs {
		if isBIMICapableProvider(input) {
			t.Errorf("isBIMICapableProvider(%q) = true, intel should return false", input)
		}
	}
}

func TestIsKnownDKIMProvider_Intel_AlwaysFalse(t *testing.T) {
	inputs := []interface{}{"selector1._domainkey.example.com", nil, 42, ""}
	for _, input := range inputs {
		if isKnownDKIMProvider(input) {
			t.Errorf("isKnownDKIMProvider(%v) = true, intel should return false", input)
		}
	}
}

func TestDmarcMonitoringProviders_Intel_Initialized(t *testing.T) {
	if dmarcMonitoringProviders == nil {
		t.Error("dmarcMonitoringProviders should not be nil in intel build")
	}
}

func TestSpfFlatteningProviders_Intel_Initialized(t *testing.T) {
	if spfFlatteningProviders == nil {
		t.Error("spfFlatteningProviders should not be nil in intel build")
	}
}

func TestHostedDKIMProviders_Intel_Initialized(t *testing.T) {
	if hostedDKIMProviders == nil {
		t.Error("hostedDKIMProviders should not be nil in intel build")
	}
}

func TestDynamicServicesProviders_Intel_Initialized(t *testing.T) {
	if dynamicServicesProviders == nil {
		t.Error("dynamicServicesProviders should not be nil in intel build")
	}
}

func TestDynamicServicesZones_Intel_Initialized(t *testing.T) {
	if dynamicServicesZones == nil {
		t.Error("dynamicServicesZones should not be nil in intel build")
	}
}

func TestCnameProviderMap_Intel_Initialized(t *testing.T) {
	if cnameProviderMap == nil {
		t.Error("cnameProviderMap should not be nil in intel build")
	}
}

func TestProviderConstants_Intel_NonEmpty(t *testing.T) {
	constants := map[string]string{
		"nameOnDMARC":       nameOnDMARC,
		"nameDMARCReport":   nameDMARCReport,
		"nameDMARCLY":       nameDMARCLY,
		"nameDmarcian":      nameDmarcian,
		"nameSendmarc":      nameSendmarc,
		"nameProofpoint":    nameProofpoint,
		"nameValimailEnf":   nameValimailEnf,
		"nameProofpointEFD": nameProofpointEFD,
		"namePowerDMARC":    namePowerDMARC,
		"nameMailhardener":  nameMailhardener,
		"nameFraudmarc":     nameFraudmarc,
		"nameEasyDMARC":     nameEasyDMARC,
		"nameDMARCAdvisor":  nameDMARCAdvisor,
		"nameRedSift":       nameRedSift,
	}
	for name, val := range constants {
		if val == "" {
			t.Errorf("constant %s is empty", name)
		}
	}
}

func TestVendorConstants_Intel_NonEmpty(t *testing.T) {
	vendors := map[string]string{
		"vendorRedSift":    vendorRedSift,
		"vendorValimail":   vendorValimail,
		"vendorDmarcian":   vendorDmarcian,
		"vendorSendmarc":   vendorSendmarc,
		"vendorProofpoint": vendorProofpoint,
		"vendorDMARCLY":    vendorDMARCLY,
		"vendorPowerDMARC": vendorPowerDMARC,
		"vendorFraudmarc":  vendorFraudmarc,
		"vendorEasyDMARC":  vendorEasyDMARC,
	}
	for name, val := range vendors {
		if val == "" {
			t.Errorf("vendor constant %s is empty", name)
		}
	}
}

func TestDomainConstants_Intel_NonEmpty(t *testing.T) {
	domains := []string{domainOndmarc, domainRedsift, domainDmarcian, domainSendmarc}
	for _, d := range domains {
		if d == "" {
			t.Error("domain constant is empty")
		}
	}
}
