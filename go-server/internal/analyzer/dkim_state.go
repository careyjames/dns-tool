// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import "fmt"

type DKIMState int

const (
	DKIMAbsent DKIMState = iota
	DKIMSuccess
	DKIMProviderInferred
	DKIMThirdPartyOnly
	DKIMInconclusive
	DKIMWeakKeysOnly
	DKIMNoMailDomain
)

func (s DKIMState) String() string {
	switch s {
	case DKIMAbsent:
		return "absent"
	case DKIMSuccess:
		return "success"
	case DKIMProviderInferred:
		return "provider_inferred"
	case DKIMThirdPartyOnly:
		return "third_party_only"
	case DKIMInconclusive:
		return "inconclusive"
	case DKIMWeakKeysOnly:
		return "weak_keys_only"
	case DKIMNoMailDomain:
		return "no_mail_domain"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

func (s DKIMState) IsPresent() bool {
	switch s {
	case DKIMSuccess, DKIMProviderInferred, DKIMThirdPartyOnly, DKIMWeakKeysOnly:
		return true
	}
	return false
}

func (s DKIMState) IsConfigured() bool {
	switch s {
	case DKIMSuccess, DKIMProviderInferred, DKIMThirdPartyOnly:
		return true
	}
	return false
}

func (s DKIMState) NeedsAction() bool {
	return s == DKIMAbsent
}

func (s DKIMState) NeedsMonitoring() bool {
	return s == DKIMInconclusive
}

func classifyDKIMState(ps protocolState) DKIMState {
	if ps.isNoMailDomain {
		return DKIMNoMailDomain
	}
	if ps.dkimOK {
		return DKIMSuccess
	}
	if ps.dkimProvider {
		return DKIMProviderInferred
	}
	if ps.dkimPartial || ps.dkimThirdPartyOnly {
		return DKIMThirdPartyOnly
	}
	if ps.dkimWeakKeys {
		return DKIMWeakKeysOnly
	}
	return DKIMAbsent
}
