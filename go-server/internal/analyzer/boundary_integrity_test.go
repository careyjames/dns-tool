package analyzer

import (
        "os"
        "path/filepath"
        "strings"
        "testing"
)

type boundarySpec struct {
        Name          string
        FrameworkFile string
        StubFile      string
        IntelFile     string
        Package       string
        StubFunctions []string
        StubVars      []string
}

var analyzerBoundaries = []boundarySpec{
        {
                Name:          "edge_cdn",
                FrameworkFile: "edge_cdn.go",
                StubFile:      "edge_cdn_oss.go",
                IntelFile:     "edge_cdn_intel.go",
                Package:       "analyzer",
                StubFunctions: []string{
                        "func DetectEdgeCDN(",
                        "func checkASNForCDN(",
                        "func checkCNAMEForCDN(",
                        "func checkPTRForCDN(",
                        "func classifyCloudIP(",
                        "func isOriginVisible(",
                        "func matchASNEntries(",
                },
                StubVars: []string{
                        "cdnASNs",
                        "cloudASNs",
                        "cloudCDNPTRPatterns",
                        "cdnCNAMEPatterns",
                },
        },
        {
                Name:          "saas_txt",
                FrameworkFile: "saas_txt.go",
                StubFile:      "saas_txt_oss.go",
                IntelFile:     "saas_txt_intel.go",
                Package:       "analyzer",
                StubFunctions: []string{
                        "func ExtractSaaSTXTFootprint(",
                        "func matchSaaSPatterns(",
                },
                StubVars: []string{
                        "saasPatterns",
                },
        },
        {
                Name:          "infrastructure",
                FrameworkFile: "infrastructure.go",
                StubFile:      "infrastructure_oss.go",
                IntelFile:     "infrastructure_intel.go",
                Package:       "analyzer",
                StubFunctions: []string{
                        "func (a *Analyzer) AnalyzeDNSInfrastructure(",
                        "func (a *Analyzer) GetHostingInfo(",
                        "func (a *Analyzer) DetectEmailSecurityManagement(",
                        "func enrichHostingFromEdgeCDN(",
                        "func matchEnterpriseProvider(",
                        "func matchSelfHostedProvider(",
                        "func matchManagedProvider(",
                        "func matchGovernmentDomain(",
                },
                StubVars: []string{
                        "enterpriseProviders",
                        "legacyProviderBlocklist",
                        "selfHostedEnterprise",
                        "governmentDomains",
                        "managedProviders",
                        "hostingProviders",
                        "hostingPTRProviders",
                        "dnsHostingProviders",
                        "emailHostingProviders",
                        "hostedMXProviders",
                        "mxProviderPatterns",
                        "nsProviderPatterns",
                        "webHostingPatterns",
                        "ptrHostingPatterns",
                },
        },
        {
                Name:          "providers",
                FrameworkFile: "providers.go",
                StubFile:      "providers_oss.go",
                IntelFile:     "providers_intel.go",
                Package:       "analyzer",
                StubFunctions: []string{
                        "func isHostedEmailProvider(",
                        "func isBIMICapableProvider(",
                        "func isKnownDKIMProvider(",
                },
                StubVars: []string{
                        "dmarcMonitoringProviders",
                        "spfFlatteningProviders",
                        "hostedDKIMProviders",
                        "dynamicServicesProviders",
                        "dynamicServicesZones",
                        "cnameProviderMap",
                },
        },
        {
                Name:          "ip_investigation",
                FrameworkFile: "ip_investigation.go",
                StubFile:      "ip_investigation_oss.go",
                IntelFile:     "ip_investigation_intel.go",
                Package:       "analyzer",
                StubFunctions: []string{
                        "func (a *Analyzer) InvestigateIP(",
                        "func fetchNeighborhoodDomains(",
                        "func buildExecutiveVerdict(",
                        "func verdictSeverity(",
                        "func classifyOverall(",
                },
                StubVars: []string{},
        },
        {
                Name:          "manifest",
                FrameworkFile: "manifest.go",
                StubFile:      "manifest_oss.go",
                IntelFile:     "manifest_intel.go",
                Package:       "analyzer",
                StubFunctions: []string{},
                StubVars: []string{
                        "FeatureParityManifest",
                        "RequiredSchemaKeys",
                },
        },
        {
                Name:          "posture_diff",
                FrameworkFile: "posture_diff.go",
                StubFile:      "posture_diff_oss.go",
                IntelFile:     "posture_diff_intel.go",
                Package:       "analyzer",
                StubFunctions: []string{
                        "func classifyDriftSeverity(",
                        "func classifyPolicyChange(",
                        "func classifyStatusChange(",
                },
                StubVars: []string{},
        },
}

func TestBoundaryIntegrity_FilePresence(t *testing.T) {
        for _, b := range analyzerBoundaries {
                t.Run(b.Name+"_framework_exists", func(t *testing.T) {
                        if _, err := os.Stat(b.FrameworkFile); os.IsNotExist(err) {
                                t.Errorf("MISSING framework file %s for boundary %s", b.FrameworkFile, b.Name)
                        }
                })
                t.Run(b.Name+"_oss_stub_exists", func(t *testing.T) {
                        if _, err := os.Stat(b.StubFile); os.IsNotExist(err) {
                                t.Errorf("MISSING OSS stub file %s for boundary %s", b.StubFile, b.Name)
                        }
                })
        }
}

func isIntelRepo() bool {
        if role := os.Getenv("DNS_TOOL_REPO_ROLE"); role != "" {
                return role == "intel"
        }
        matches, _ := filepath.Glob("*_intel.go")
        return len(matches) > 0
}

func TestBoundaryIntegrity_IntelFilesBuildTagGated(t *testing.T) {
        for _, b := range analyzerBoundaries {
                t.Run(b.Name+"_intel_build_tag", func(t *testing.T) {
                        if _, err := os.Stat(b.IntelFile); err != nil {
                                t.Skipf("Intel file %s not present — skipping build tag check", b.IntelFile)
                                return
                        }
                        content, err := os.ReadFile(b.IntelFile)
                        if err != nil {
                                t.Fatalf("failed to read %s: %v", b.IntelFile, err)
                        }
                        if !strings.Contains(string(content), "//go:build intel") {
                                t.Errorf("INTEL FILE %s MISSING BUILD TAG — must have //go:build intel", b.IntelFile)
                        }
                })
        }

        err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
                if err != nil || info.IsDir() {
                        return nil
                }
                if strings.HasSuffix(path, "_intel.go") {
                        content, readErr := os.ReadFile(path)
                        if readErr != nil {
                                t.Errorf("failed to read %s: %v", path, readErr)
                                return nil
                        }
                        if !strings.Contains(string(content), "//go:build intel") {
                                t.Errorf("INTEL FILE %s MISSING BUILD TAG — all _intel.go files must have //go:build intel", path)
                        }
                }
                return nil
        })
        if err != nil {
                t.Fatalf("failed to walk directory: %v", err)
        }
}

func TestBoundaryIntegrity_IntelFilesPresent(t *testing.T) {
        if !isIntelRepo() {
                t.Skip("Skipping intel-only check — running in public repo context")
        }
        for _, b := range analyzerBoundaries {
                t.Run(b.Name+"_intel_file_exists", func(t *testing.T) {
                        if _, err := os.Stat(b.IntelFile); os.IsNotExist(err) {
                                t.Errorf("MISSING intel file %s for boundary %s — intel repo must have all intel implementations", b.IntelFile, b.Name)
                        }
                })
                t.Run(b.Name+"_intel_build_tag", func(t *testing.T) {
                        data, err := os.ReadFile(b.IntelFile)
                        if err != nil {
                                t.Skipf("cannot read %s: %v", b.IntelFile, err)
                        }
                        content := string(data)
                        if !strings.HasPrefix(content, "//go:build intel") {
                                t.Errorf("Intel file %s MISSING build tag '//go:build intel' — must be first line", b.IntelFile)
                        }
                })
                t.Run(b.Name+"_both_exist", func(t *testing.T) {
                        if _, err := os.Stat(b.StubFile); os.IsNotExist(err) {
                                t.Errorf("MISSING OSS stub %s for boundary %s — intel repo must keep stubs for public mirror builds", b.StubFile, b.Name)
                        }
                        if _, err := os.Stat(b.IntelFile); os.IsNotExist(err) {
                                t.Errorf("MISSING intel file %s — boundary %s incomplete", b.IntelFile, b.Name)
                        }
                })
        }
}

func TestBoundaryIntegrity_BuildTags(t *testing.T) {
        for _, b := range analyzerBoundaries {
                t.Run(b.Name+"_oss_build_tag", func(t *testing.T) {
                        data, err := os.ReadFile(b.StubFile)
                        if err != nil {
                                t.Skipf("cannot read %s: %v", b.StubFile, err)
                        }
                        content := string(data)
                        if !strings.HasPrefix(content, "//go:build !intel") {
                                t.Errorf("OSS stub %s MISSING build tag '//go:build !intel' — must be first line", b.StubFile)
                        }
                })

                t.Run(b.Name+"_framework_no_build_tag", func(t *testing.T) {
                        data, err := os.ReadFile(b.FrameworkFile)
                        if err != nil {
                                t.Skipf("cannot read %s: %v", b.FrameworkFile, err)
                        }
                        content := string(data)
                        if strings.Contains(content, "//go:build intel") || strings.Contains(content, "//go:build !intel") {
                                t.Errorf("Framework file %s has build tag — framework files must compile unconditionally", b.FrameworkFile)
                        }
                })
        }
}

func TestBoundaryIntegrity_StubFunctionsDefined(t *testing.T) {
        for _, b := range analyzerBoundaries {
                if len(b.StubFunctions) == 0 {
                        continue
                }
                t.Run(b.Name+"_stub_functions", func(t *testing.T) {
                        data, err := os.ReadFile(b.StubFile)
                        if err != nil {
                                t.Skipf("cannot read %s: %v", b.StubFile, err)
                        }
                        content := string(data)
                        for _, fn := range b.StubFunctions {
                                if !strings.Contains(content, fn) {
                                        t.Errorf("OSS stub %s missing function %s", b.StubFile, fn)
                                }
                        }
                })
        }
}

func TestBoundaryIntegrity_StubVarsDefined(t *testing.T) {
        for _, b := range analyzerBoundaries {
                if len(b.StubVars) == 0 {
                        continue
                }
                t.Run(b.Name+"_stub_vars", func(t *testing.T) {
                        data, err := os.ReadFile(b.StubFile)
                        if err != nil {
                                t.Skipf("cannot read %s: %v", b.StubFile, err)
                        }
                        content := string(data)
                        for _, v := range b.StubVars {
                                if !strings.Contains(content, v) {
                                        t.Errorf("OSS stub %s missing var %s — stub must initialize all boundary variables", b.StubFile, v)
                                }
                        }
                })
        }
}

func TestBoundaryIntegrity_CorrectPackage(t *testing.T) {
        for _, b := range analyzerBoundaries {
                for _, file := range []struct {
                        name string
                        path string
                }{
                        {"framework", b.FrameworkFile},
                        {"oss_stub", b.StubFile},
                } {
                        t.Run(b.Name+"_"+file.name+"_package", func(t *testing.T) {
                                data, err := os.ReadFile(file.path)
                                if err != nil {
                                        t.Skipf("cannot read %s: %v", file.path, err)
                                }
                                content := string(data)
                                expected := "package " + b.Package
                                if !strings.Contains(content, expected) {
                                        t.Errorf("File %s has wrong package — expected %q", file.path, expected)
                                }
                        })
                }
        }
}

func TestBoundaryIntegrity_NoDuplicateFunctions(t *testing.T) {
        for _, b := range analyzerBoundaries {
                t.Run(b.Name+"_no_duplicates", func(t *testing.T) {
                        frameworkData, err := os.ReadFile(b.FrameworkFile)
                        if err != nil {
                                t.Skipf("cannot read %s: %v", b.FrameworkFile, err)
                        }
                        stubData, err := os.ReadFile(b.StubFile)
                        if err != nil {
                                t.Skipf("cannot read %s: %v", b.StubFile, err)
                        }

                        frameworkFuncs := extractFuncSignatures(string(frameworkData))
                        stubFuncs := extractFuncSignatures(string(stubData))

                        for fn := range stubFuncs {
                                if frameworkFuncs[fn] {
                                        t.Errorf("DUPLICATE function %q defined in both %s and %s — each function must be in exactly one file", fn, b.FrameworkFile, b.StubFile)
                                }
                        }
                })
        }
}

func extractFuncSignatures(content string) map[string]bool {
        result := make(map[string]bool)
        for _, line := range strings.Split(content, "\n") {
                trimmed := strings.TrimSpace(line)
                if strings.HasPrefix(trimmed, "func ") && strings.Contains(trimmed, "(") {
                        parenIdx := strings.Index(trimmed, "(")
                        if parenIdx > 5 {
                                name := trimmed[5:parenIdx]
                                if strings.HasPrefix(name, "(") {
                                        closeParen := strings.Index(name, ")")
                                        if closeParen > 0 && closeParen+1 < len(name) {
                                                name = strings.TrimSpace(name[closeParen+1:])
                                                secondParen := strings.Index(trimmed[5+closeParen+1:], "(")
                                                if secondParen >= 0 {
                                                        name = strings.TrimSpace(trimmed[5+closeParen+1 : 5+closeParen+1+secondParen])
                                                }
                                        }
                                }
                                if name != "" {
                                        result[name] = true
                                }
                        }
                }
        }
        return result
}

func TestBoundaryIntegrity_NoIntelLeakage(t *testing.T) {
        intelTokens := []string{
                "GPTBot",
                "ClaudeBot",
                "PerplexityBot",
                "Bytespider",
                "Amazonbot",
                "Omgilibot",
                "Google-Extended",
                "Applebot-Extended",
                "ChatGPT-User",
                "anthropic-ai",
                "YouBot",
        }

        intelProviderTokens := []string{
                "_dmarc.protection.outlook.com",
                "spf.protection.outlook.com",
                "amazonses.com",
                "sendgrid.net",
        }

        for _, b := range analyzerBoundaries {
                for _, file := range []string{b.FrameworkFile, b.StubFile} {
                        t.Run(b.Name+"_no_intel_in_"+filepath.Base(file), func(t *testing.T) {
                                data, err := os.ReadFile(file)
                                if err != nil {
                                        t.Skipf("cannot read %s: %v", file, err)
                                }
                                content := string(data)

                                tokens := intelTokens
                                if b.Name == "providers" || b.Name == "infrastructure" {
                                        tokens = append(tokens, intelProviderTokens...)
                                }

                                for _, token := range tokens {
                                        lines := strings.Split(content, "\n")
                                        for i, line := range lines {
                                                trimmed := strings.TrimSpace(line)
                                                if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
                                                        continue
                                                }
                                                if strings.Contains(line, token) {
                                                        t.Errorf("INTEL LEAKAGE: token %q found in public file %s line %d — intelligence data must only be in _intel.go files in private repo", token, file, i+1)
                                                }
                                        }
                                }
                        })
                }
        }
}

func TestBoundaryIntegrity_StubsReturnSafeDefaults(t *testing.T) {
        t.Run("edge_cdn_safe_return", func(t *testing.T) {
                result := DetectEdgeCDN(map[string]any{})
                if result == nil {
                        t.Error("DetectEdgeCDN returned nil — stubs must return non-nil maps")
                }
                if result["status"] != "success" {
                        t.Errorf("DetectEdgeCDN status = %v, want 'success'", result["status"])
                }
                if result["cdn_indicators"] == nil {
                        t.Error("DetectEdgeCDN cdn_indicators is nil — must return empty slice")
                }
        })

        t.Run("saas_txt_safe_return", func(t *testing.T) {
                result := ExtractSaaSTXTFootprint(map[string]any{})
                if result == nil {
                        t.Error("ExtractSaaSTXTFootprint returned nil — stubs must return non-nil maps")
                }
                if result["status"] != "success" {
                        t.Errorf("ExtractSaaSTXTFootprint status = %v, want 'success'", result["status"])
                }
                if result["services"] == nil {
                        t.Error("ExtractSaaSTXTFootprint services is nil — must return empty slice")
                }
        })

        t.Run("providers_safe_returns", func(t *testing.T) {
                if dmarcMonitoringProviders == nil {
                        t.Error("dmarcMonitoringProviders is nil — must be initialized empty map")
                }
                if spfFlatteningProviders == nil {
                        t.Error("spfFlatteningProviders is nil — must be initialized empty map")
                }
                if hostedDKIMProviders == nil {
                        t.Error("hostedDKIMProviders is nil — must be initialized empty map")
                }
                if dynamicServicesProviders == nil {
                        t.Error("dynamicServicesProviders is nil — must be initialized empty map")
                }
                if cnameProviderMap == nil {
                        t.Error("cnameProviderMap is nil — must be initialized empty map")
                }
        })

        t.Run("edge_cdn_safe_maps", func(t *testing.T) {
                if cdnASNs == nil {
                        t.Error("cdnASNs is nil — must be initialized empty map")
                }
                if cloudASNs == nil {
                        t.Error("cloudASNs is nil — must be initialized empty map")
                }
                if cloudCDNPTRPatterns == nil {
                        t.Error("cloudCDNPTRPatterns is nil — must be initialized empty map")
                }
                if cdnCNAMEPatterns == nil {
                        t.Error("cdnCNAMEPatterns is nil — must be initialized empty map")
                }
        })

        t.Run("infrastructure_safe_maps", func(t *testing.T) {
                if enterpriseProviders == nil {
                        t.Error("enterpriseProviders is nil — must be initialized empty map")
                }
                if hostingProviders == nil {
                        t.Error("hostingProviders is nil — must be initialized empty map")
                }
                if dnsHostingProviders == nil {
                        t.Error("dnsHostingProviders is nil — must be initialized empty map")
                }
                if emailHostingProviders == nil {
                        t.Error("emailHostingProviders is nil — must be initialized empty map")
                }
        })

        t.Run("manifest_safe_vars", func(t *testing.T) {
                if FeatureParityManifest == nil {
                        t.Error("FeatureParityManifest is nil — must be initialized empty slice")
                }
        })
}

func TestBoundaryIntegrity_NoIntelStagingDirectory(t *testing.T) {
        paths := []string{
                "../../docs/intel-staging",
                "../../../docs/intel-staging",
                "../../../dns-tool-intel-staging",
                "../../../../dns-tool-intel-staging",
        }
        for _, p := range paths {
                if info, err := os.Stat(p); err == nil && info.IsDir() {
                        t.Errorf("intel-staging directory still exists at %s — must be deleted after transfer to private repo", p)
                }
        }
}

func TestBoundaryIntegrity_CompleteBoundaryInventory(t *testing.T) {
        expectedCount := 7
        if len(analyzerBoundaries) != expectedCount {
                t.Errorf("analyzerBoundaries has %d entries, expected %d — update boundary inventory when adding new boundaries", len(analyzerBoundaries), expectedCount)
        }

        aiSurfaceBoundaryCount := 5
        t.Logf("Total boundary files: %d (analyzer) + %d (ai_surface) = %d",
                len(analyzerBoundaries), aiSurfaceBoundaryCount,
                len(analyzerBoundaries)+aiSurfaceBoundaryCount)
}

func TestBoundaryIntegrity_FullRepoScan(t *testing.T) {
        intel := isIntelRepo()

        var intelFiles []string
        err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
                if err != nil || info.IsDir() {
                        return nil
                }
                if strings.HasSuffix(path, "_intel.go") {
                        intelFiles = append(intelFiles, path)
                }
                return nil
        })
        if err != nil {
                t.Fatalf("failed to walk directory: %v", err)
        }

        if intel {
                if len(intelFiles) == 0 {
                        t.Errorf("CRITICAL: No _intel.go files found in intel repo — expected intel implementations")
                }
                for _, f := range intelFiles {
                        data, readErr := os.ReadFile(f)
                        if readErr != nil {
                                t.Errorf("cannot read intel file %s: %v", f, readErr)
                                continue
                        }
                        content := string(data)
                        if !strings.HasPrefix(content, "//go:build intel") {
                                t.Errorf("Intel file %s missing '//go:build intel' build tag", f)
                        }
                }
                t.Logf("Verified %d intel files have correct build tags", len(intelFiles))
        } else {
                if len(intelFiles) > 0 {
                        t.Errorf("CRITICAL: Found %d _intel.go files in public repo: %v", len(intelFiles), intelFiles)
                }
        }

        var ossFiles []string
        err = filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
                if err != nil || info.IsDir() || strings.HasSuffix(path, "_test.go") {
                        return nil
                }
                if strings.HasSuffix(path, "_oss.go") {
                        ossFiles = append(ossFiles, path)
                }
                return nil
        })
        if err != nil {
                t.Fatalf("failed to walk directory: %v", err)
        }

        for _, f := range ossFiles {
                data, err := os.ReadFile(f)
                if err != nil {
                        t.Errorf("cannot read OSS file %s: %v", f, err)
                        continue
                }
                content := string(data)
                if !strings.HasPrefix(content, "//go:build !intel") {
                        t.Errorf("OSS file %s missing '//go:build !intel' build tag", f)
                }
        }
        t.Logf("Verified %d OSS stub files have correct build tags", len(ossFiles))
}
