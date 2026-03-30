// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import "fmt"

const (
	rfcDNSSEC = "RFC 8624 / RFC 9157"
	rfcDKIM   = "RFC 8301"

	mapKeyAdequate   = "adequate"
	mapKeyDeprecated = "deprecated"
	mapKeyLegacy     = "legacy"
	mapKeyModern     = "modern"
	mapKeyStrong     = "strong"
	strAdequate      = "Adequate"
	strDeprecated    = "Deprecated"
	strLegacy        = "Legacy"
	strModern        = "Modern"
	strStrong        = "Strong"
)

const pqcNote = "All current DNSSEC algorithms use classical cryptography. Post-quantum DNSSEC standards are in active IETF development (draft-sheth-pqc-dnssec-strategy) but no PQC algorithms have been standardized for DNSSEC yet."

type AlgorithmClassification struct {
	Strength    string
	Label       string
	RFC         string
	Observation string
	QuantumNote string
}

type KeyClassification struct {
	Strength    string
	Label       string
	RFC         string
	Observation string
}

type DigestClassification struct {
	Strength    string
	Label       string
	Observation string
}

var dnssecAlgorithms = map[int]AlgorithmClassification{
	1: {
		Strength:    mapKeyDeprecated,
		Label:       strDeprecated,
		RFC:         rfcDNSSEC,
		Observation: "RSAMD5 — MUST NOT use for signing or validation (RFC 8624 §3.1)",
		QuantumNote: pqcNote,
	},
	3: {
		Strength:    mapKeyDeprecated,
		Label:       strDeprecated,
		RFC:         rfcDNSSEC,
		Observation: "DSA — MUST NOT use for signing (RFC 8624 §3.1)",
		QuantumNote: pqcNote,
	},
	5: {
		Strength:    mapKeyLegacy,
		Label:       strLegacy,
		RFC:         rfcDNSSEC,
		Observation: "RSA/SHA-1 — NOT RECOMMENDED for signing (RFC 8624 §3.1). SHA-1 has known collision weaknesses.",
		QuantumNote: pqcNote,
	},
	6: {
		Strength:    mapKeyDeprecated,
		Label:       strDeprecated,
		RFC:         rfcDNSSEC,
		Observation: "DSA-NSEC3-SHA1 — MUST NOT use for signing (RFC 8624 §3.1)",
		QuantumNote: pqcNote,
	},
	7: {
		Strength:    mapKeyLegacy,
		Label:       strLegacy,
		RFC:         rfcDNSSEC,
		Observation: "RSASHA1-NSEC3-SHA1 — NOT RECOMMENDED for signing (RFC 8624 §3.1)",
		QuantumNote: pqcNote,
	},
	8: {
		Strength:    mapKeyAdequate,
		Label:       strAdequate,
		RFC:         rfcDNSSEC,
		Observation: "RSA/SHA-256 — MUST implement, widely deployed (RFC 8624 §3.1)",
		QuantumNote: pqcNote,
	},
	10: {
		Strength:    mapKeyLegacy,
		Label:       strLegacy,
		RFC:         rfcDNSSEC,
		Observation: "RSA/SHA-512 — NOT RECOMMENDED, offers no security advantage over RSA/SHA-256 (RFC 8624 §3.1)",
		QuantumNote: pqcNote,
	},
	12: {
		Strength:    mapKeyDeprecated,
		Label:       strDeprecated,
		RFC:         rfcDNSSEC,
		Observation: "ECC-GOST — MUST NOT use (RFC 8624 §3.1)",
		QuantumNote: pqcNote,
	},
	13: {
		Strength:    mapKeyModern,
		Label:       strModern,
		RFC:         rfcDNSSEC,
		Observation: "ECDSA P-256/SHA-256 — MUST implement, recommended default (RFC 8624 §3.1)",
		QuantumNote: pqcNote,
	},
	14: {
		Strength:    mapKeyModern,
		Label:       strModern,
		RFC:         rfcDNSSEC,
		Observation: "ECDSA P-384/SHA-384 — MAY use, strong security (RFC 8624 §3.1)",
		QuantumNote: pqcNote,
	},
	15: {
		Strength:    mapKeyModern,
		Label:       strModern,
		RFC:         rfcDNSSEC,
		Observation: "Ed25519 — RECOMMENDED, efficient modern algorithm (RFC 8624 §3.1)",
		QuantumNote: pqcNote,
	},
	16: {
		Strength:    mapKeyModern,
		Label:       strModern,
		RFC:         rfcDNSSEC,
		Observation: "Ed448 — MAY use, highest security EdDSA option (RFC 8624 §3.1)",
		QuantumNote: pqcNote,
	},
}

var dsDigests = map[int]DigestClassification{
	1: {Strength: mapKeyDeprecated, Label: strDeprecated, Observation: "SHA-1 DS digest — MUST NOT use (RFC 8624 §3.3)"},
	2: {Strength: mapKeyAdequate, Label: strAdequate, Observation: "SHA-256 DS digest — MUST implement, recommended default (RFC 8624 §3.3)"},
	3: {Strength: mapKeyDeprecated, Label: strDeprecated, Observation: "GOST R 34.11-94 — MUST NOT use (RFC 8624 §3.3)"},
	4: {Strength: mapKeyStrong, Label: strStrong, Observation: "SHA-384 DS digest — MAY use for high-security needs (RFC 8624 §3.3)"},
}

func ClassifyDNSSECAlgorithm(algorithmNum int) AlgorithmClassification {
	if c, ok := dnssecAlgorithms[algorithmNum]; ok {
		return c
	}
	return AlgorithmClassification{
		Strength:    mapKeyAdequate,
		Label:       strAdequate,
		RFC:         rfcDNSSEC,
		Observation: fmt.Sprintf("Algorithm %d — not classified in RFC 8624", algorithmNum),
		QuantumNote: pqcNote,
	}
}

func ClassifyDKIMKey(keyType string, keyBits int) KeyClassification {
	switch keyType {
	case "rsa":
		switch {
		case keyBits < 1024:
			return KeyClassification{
				Strength:    mapKeyDeprecated,
				Label:       strDeprecated,
				RFC:         rfcDKIM,
				Observation: "RSA key under 1024 bits — MUST NOT consider valid (RFC 8301 §3.2)",
			}
		case keyBits == 1024:
			return KeyClassification{
				Strength:    "weak",
				Label:       "Weak",
				RFC:         rfcDKIM,
				Observation: "1024-bit RSA — minimum per RFC 8301, upgrade to 2048-bit recommended",
			}
		case keyBits == 2048:
			return KeyClassification{
				Strength:    mapKeyAdequate,
				Label:       strAdequate,
				RFC:         rfcDKIM,
				Observation: "2048-bit RSA — recommended standard (RFC 8301, NIST guidance)",
			}
		case keyBits == 4096:
			return KeyClassification{
				Strength:    mapKeyStrong,
				Label:       strStrong,
				RFC:         rfcDKIM,
				Observation: "4096-bit RSA — exceeds recommendations, may cause DNS record size issues",
			}
		case keyBits >= 2048:
			return KeyClassification{
				Strength:    mapKeyAdequate,
				Label:       strAdequate,
				RFC:         rfcDKIM,
				Observation: fmt.Sprintf("%d-bit RSA — meets minimum recommended strength", keyBits),
			}
		default:
			return KeyClassification{
				Strength:    "weak",
				Label:       "Weak",
				RFC:         rfcDKIM,
				Observation: fmt.Sprintf("%d-bit RSA — below recommended 2048-bit minimum", keyBits),
			}
		}
	case "ed25519":
		return KeyClassification{
			Strength:    mapKeyStrong,
			Label:       strStrong,
			RFC:         rfcDKIM,
			Observation: "Ed25519 — modern elliptic curve algorithm, efficient and secure",
		}
	default:
		return KeyClassification{
			Strength:    mapKeyAdequate,
			Label:       strAdequate,
			RFC:         rfcDKIM,
			Observation: fmt.Sprintf("Key type '%s' — classification not available", keyType),
		}
	}
}

func ClassifyDSDigest(digestType int) DigestClassification {
	if c, ok := dsDigests[digestType]; ok {
		return c
	}
	return DigestClassification{
		Strength:    mapKeyAdequate,
		Label:       strAdequate,
		Observation: fmt.Sprintf("DS digest type %d — not classified in RFC 8624", digestType),
	}
}
