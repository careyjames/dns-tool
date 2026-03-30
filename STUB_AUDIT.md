# Stub-to-Private-Repo Audit

Generated: 2026-02-14
Purpose: Maps every public repo stub file to the real implementation needed in dnstool-intel.

## Status Key
- NEEDS UPDATE: Today's changes require a new/updated private repo file
- VERIFY: Already exists in private repo — confirm it's complete
- OK: No action needed (stub is self-contained)

---

## 1. providers.go → providers/
**Status: NEEDS UPDATE**

Today we added `isKnownDKIMProvider` as a new stub. The real implementation with the 17-provider map must be pushed to the private repo.

### Stubbed items requiring real implementations:
| Item | Type | Current Stub Behavior |
|------|------|----------------------|
| `dmarcMonitoringProviders` | map | Empty map `{}` |
| `spfFlatteningProviders` | map | Empty map `{}` |
| `hostedDKIMProviders` | map | Empty map `{}` |
| `dynamicServicesProviders` | map | Empty map `{}` |
| `dynamicServicesZones` | map | Empty map `{}` |
| `cnameProviderMap` | map | Empty map `{}` |
| `isHostedEmailProvider()` | func | Returns `false` |
| `isBIMICapableProvider()` | func | Returns `true` |
| `isKnownDKIMProvider()` | func | Returns `false` ← **NEW TODAY** |

### New file created:
`providers/dkim_providers.go` — Contains real `isKnownDKIMProvider` + `knownDKIMProviders` map.

---

## 2. infrastructure.go → providers/ or scoring/
**Status: VERIFY**

### Stubbed items:
| Item | Type | Current Stub Behavior |
|------|------|----------------------|
| `selfHostedEnterprise` | map | Empty map |
| `governmentDomains` | map | Empty map |
| `managedProviders` | map | Empty map |
| `hostingProviders` | map | Empty map |
| `hostingPTRProviders` | map | Empty map |
| `dnsHostingProviders` | map | Empty map |
| `emailHostingProviders` | map | Empty map |
| `hostedMXProviders` | map | Empty map |
| `DetectEmailSecurityManagement()` | func | Returns empty providers |
| `matchSelfHostedProvider()` | func | Returns nil |
| `matchManagedProvider()` | func | Returns nil |
| `matchGovernmentDomain()` | func | Returns nil, false |
| `collectAltSecurityItems()` | func | Returns nil |
| `matchAllProviders()` | func | Returns nil |
| `buildInfraResult()` | func | Returns empty map |
| `detectDMARCReportProviders()` | func | No-op |
| `detectTLSRPTReportProviders()` | func | No-op |
| `detectSPFFlatteningProvider()` | func | Returns nil |
| `detectMTASTSManagement()` | func | No-op |
| `detectHostedDKIMProviders()` | func | No-op |
| `detectDynamicServices()` | func | No-op |
| `scanDynamicServiceZones()` | func | Returns empty map |

**Note:** `matchEnterpriseProvider()`, `identifyEmailProvider()`, `identifyDNSProvider()`, `identifyWebHosting()` have REAL implementations in the public stub (with provider pattern maps). These are functional but could be enriched in the private repo.

---

## 3. commands.go → commands/
**Status: VERIFY**

### Stubbed items:
| Item | Type | Current Stub Behavior |
|------|------|----------------------|
| `GenerateVerificationCommands()` | func | Returns empty slice |
| `generateSecurityTxtCommands()` | func | Returns nil |
| `generateDNSRecordCommands()` | func | Returns nil |
| `generateSPFCommands()` | func | Returns nil |
| `generateDMARCCommands()` | func | Returns nil |
| `generateDKIMCommands()` | func | Returns nil |
| `generateDNSSECCommands()` | func | Returns nil |
| `generateDANECommands()` | func | Returns nil |
| `generateMTASTSCommands()` | func | Returns nil |
| `generateTLSRPTCommands()` | func | Returns nil |
| `generateBIMICommands()` | func | Returns nil |
| `generateCAACommands()` | func | Returns nil |
| `generateRegistrarCommands()` | func | Returns nil |
| `generateSMTPCommands()` | func | Returns nil |
| `generateCTCommands()` | func | Returns nil |
| `generateDMARCReportAuthCommands()` | func | Returns nil |
| `generateHTTPSSVCBCommands()` | func | Returns nil |
| `generateASNCommands()` | func | Returns nil |
| `generateCDSCommands()` | func | Returns nil |
| `generateAISurfaceCommands()` | func | Returns nil |
| `extractMXHostsFromResults()` | func | Returns nil |
| `parseMXHostEntries()` | func | Returns nil |
| `appendMXHost()` | func | Returns input unchanged |

---

## 4. confidence.go
**Status: OK — self-contained**

This stub is fully functional. Constants and helper functions work as-is. No private repo override needed unless you want to add additional confidence methods.

---

## 5. dkim_state.go
**Status: OK — self-contained**

DKIMState enum, String(), IsPresent(), IsConfigured(), NeedsAction(), NeedsMonitoring(), and classifyDKIMState() are all fully implemented in the public stub. No private repo override needed.

---

## 6. edge_cdn.go → providers/
**Status: VERIFY**

### Stubbed items:
| Item | Type | Current Stub Behavior |
|------|------|----------------------|
| `cdnASNs` | map | Empty map |
| `cloudASNs` | map | Empty map |
| `cloudCDNPTRPatterns` | map | Empty map |
| `cdnCNAMEPatterns` | map | Empty map |
| `DetectEdgeCDN()` | func | Returns "not behind CDN" |
| `checkASNForCDN()` | func | Returns empty |
| `matchASNEntries()` | func | Returns empty |
| `checkCNAMEForCDN()` | func | Returns empty |
| `classifyCloudIP()` | func | Returns empty, false |

---

## 7. ip_investigation.go
**Status: VERIFY**

### Stubbed items:
| Item | Type | Current Stub Behavior |
|------|------|----------------------|
| `InvestigateIP()` | func | Returns skeleton with empty results |
| `fetchNeighborhoodDomains()` | func | Returns nil, 0 |
| `buildNeighborhoodContext()` | func | Returns empty |
| `buildExecutiveVerdict()` | func | Returns empty |
| `findFirstHostname()` | func | Returns empty |
| `verdictSeverity()` | func | Returns "info" |
| `checkPTRRecords()` | func | Returns input unchanged |
| `checkDomainARecords()` | func | Returns input unchanged |
| `checkMXRecords()` | func | Returns input unchanged |
| `checkNSRecords()` | func | Returns input unchanged |
| `checkSPFAuthorization()` | func | Returns input unchanged |
| `findSPFTXTRecord()` | func | Returns empty |
| `checkSPFIncludes()` | func | Returns input unchanged |
| `checkIPInSPFRecord()` | func | Returns false |
| `checkCTSubdomains()` | func | Returns input unchanged |
| `lookupInvestigationASN()` | func | Returns empty map |
| `checkASNForCDNDirect()` | func | Returns empty, false |
| `extractMXHost()` | func | Returns empty |
| `classifyOverall()` | func | Returns "Unrelated", "" |

**Note:** `ValidateIPAddress()`, `IsPrivateIP()`, `IsIPv6()`, `buildArpaName()`, `mapGetStr()` have real implementations in the public stub.

---

## 8. manifest.go → commands/
**Status: VERIFY**

### Stubbed items:
| Item | Type | Current Stub Behavior |
|------|------|----------------------|
| `FeatureParityManifest` | slice | Empty slice |
| `RequiredSchemaKeys` | slice | Nil |
| `init()` | func | No-op (populated by dnstool-intel at build time) |

**Note:** `GetManifestByCategory()` is functional — it just operates on the empty manifest.

---

## 9. saas_txt.go → providers/
**Status: VERIFY**

### Stubbed items:
| Item | Type | Current Stub Behavior |
|------|------|----------------------|
| `saasPatterns` | slice | Empty slice |
| `ExtractSaaSTXTFootprint()` | func | Returns "no SaaS detected" |
| `matchSaaSPatterns()` | func | No-op |

---

## 10. ai_surface/http.go → ai_surface/
**Status: VERIFY**

### Stubbed items:
| Item | Type | Current Stub Behavior |
|------|------|----------------------|
| `fetchTextFile()` | method | Returns error "stub: not implemented" |

---

## 11. ai_surface/llms_txt.go → ai_surface/
**Status: VERIFY**

### Stubbed items:
| Item | Type | Current Stub Behavior |
|------|------|----------------------|
| `CheckLLMSTxt()` | method | Returns "not found" |
| `looksLikeLLMSTxt()` | func | Returns false |
| `parseLLMSTxt()` | func | Returns empty map |
| `parseLLMSTxtFieldLine()` | func | No-op |

---

## 12. ai_surface/poisoning.go → ai_surface/
**Status: VERIFY**

### Stubbed items:
| Item | Type | Current Stub Behavior |
|------|------|----------------------|
| `prefilledPromptRe` | regex | Placeholder (never matches) |
| `promptInjectionRe` | regex | Placeholder (never matches) |
| `hiddenTextSelectors` | slice | Empty |
| `DetectPoisoningIOCs()` | method | Returns "no indicators found" |
| `DetectHiddenPrompts()` | method | Returns "no artifacts found" |
| `detectHiddenTextArtifacts()` | func | Returns input unchanged |
| `buildHiddenBlockRegex()` | func | Returns nil |
| `extractTextContent()` | func | Returns empty |
| `looksLikePromptInstruction()` | func | Returns false |

---

## 13. ai_surface/robots_txt.go → ai_surface/
**Status: VERIFY**

### Stubbed items:
| Item | Type | Current Stub Behavior |
|------|------|----------------------|
| `knownAICrawlers` | slice | Empty |
| `CheckRobotsTxtAI()` | method | Returns "not found" |
| `parseRobotsForAI()` | func | Returns nil, nil, nil |
| `processRobotsLine()` | func | No-op |
| `matchAICrawler()` | func | Returns empty |

---

## Summary

| # | Stub File | Private Repo Folder | Status |
|---|-----------|-------------------|--------|
| 1 | providers.go | providers/ | **NEEDS UPDATE** (isKnownDKIMProvider) |
| 2 | infrastructure.go | providers/ or scoring/ | VERIFY |
| 3 | commands.go | commands/ | VERIFY |
| 4 | confidence.go | — | OK (self-contained) |
| 5 | dkim_state.go | — | OK (self-contained) |
| 6 | edge_cdn.go | providers/ | VERIFY |
| 7 | ip_investigation.go | (own folder?) | VERIFY |
| 8 | manifest.go | commands/ | VERIFY |
| 9 | saas_txt.go | providers/ | VERIFY |
| 10 | ai_surface/http.go | ai_surface/ | VERIFY |
| 11 | ai_surface/llms_txt.go | ai_surface/ | VERIFY |
| 12 | ai_surface/poisoning.go | ai_surface/ | VERIFY |
| 13 | ai_surface/robots_txt.go | ai_surface/ | VERIFY |

**Action required today:** Push `providers/dkim_providers.go` to dnstool-intel.
**Verify:** All other private repo files match their corresponding stubs.
