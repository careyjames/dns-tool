// Copyright (c) 2024-2026 IT Help San Diego Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL — See LICENSE for terms.
// This file is part of the DNS Tool Intelligence Module.
package analyzer

import "fmt"

type DKIMState int

const (
	DKIMAbsent          DKIMState = iota // Zero selectors found, domain sends mail
	DKIMSuccess                          // Primary provider DKIM found with valid keys
	DKIMProviderInferred                 // Primary provider known to use DKIM (e.g., Google Workspace via MX)
	DKIMThirdPartyOnly                   // Selectors found but only for third-party senders (e.g., MailChimp, SendGrid)
	DKIMInconclusive                     // No selectors found, provider unknown — may use custom/rotating selectors
	DKIMWeakKeysOnly                     // DKIM found but all keys are 1024-bit (weak)
	DKIMNoMailDomain                     // Domain does not send mail — DKIM not applicable
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
	switch s {
	case DKIMAbsent:
		return true
	}
	return false
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

	if ps.dkimThirdPartyOnly {
		return DKIMThirdPartyOnly
	}

	if ps.dkimPartial {
		return DKIMInconclusive
	}

	return DKIMAbsent
}
