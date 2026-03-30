package ai_surface

import (
        "context"
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
        StubFunctions []string
        StubVars      []string
}

var aiSurfaceBoundaries = []boundarySpec{
        {
                Name:          "http",
                FrameworkFile: "http.go",
                StubFile:      "http_oss.go",
                IntelFile:     "http_intel.go",
                StubFunctions: []string{
                        "func (s *Scanner) fetchTextFile(",
                },
                StubVars: []string{},
        },
        {
                Name:          "llms_txt",
                FrameworkFile: "llms_txt.go",
                StubFile:      "llms_txt_oss.go",
                IntelFile:     "llms_txt_intel.go",
                StubFunctions: []string{
                        "func (s *Scanner) CheckLLMSTxt(",
                        "func looksLikeLLMSTxt(",
                        "func parseLLMSTxt(",
                },
                StubVars: []string{},
        },
        {
                Name:          "robots_txt",
                FrameworkFile: "robots_txt.go",
                StubFile:      "robots_txt_oss.go",
                IntelFile:     "robots_txt_intel.go",
                StubFunctions: []string{
                        "func (s *Scanner) CheckRobotsTxtAI(",
                        "func parseRobotsForAI(",
                        "func matchAICrawler(",
                },
                StubVars: []string{
                        "knownAICrawlers",
                },
        },
        {
                Name:          "poisoning",
                FrameworkFile: "poisoning.go",
                StubFile:      "poisoning_oss.go",
                IntelFile:     "poisoning_intel.go",
                StubFunctions: []string{
                        "func (s *Scanner) DetectPoisoningIOCs(",
                        "func (s *Scanner) DetectHiddenPrompts(",
                        "func detectHiddenTextArtifacts(",
                        "func looksLikePromptInstruction(",
                },
                StubVars: []string{
                        "prefilledPromptRe",
                        "promptInjectionRe",
                        "hiddenTextSelectors",
                },
        },
        {
                Name:          "scanner",
                FrameworkFile: "scanner.go",
                StubFile:      "scanner_oss.go",
                IntelFile:     "scanner_intel.go",
                StubFunctions: []string{
                        "func GetAICrawlers(",
                },
                StubVars: []string{},
        },
}

func TestAISurfaceBoundary_FilePresence(t *testing.T) {
        for _, b := range aiSurfaceBoundaries {
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

func TestAISurfaceBoundary_IntelFilesBuildTagGated(t *testing.T) {
        for _, b := range aiSurfaceBoundaries {
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
}

func TestAISurfaceBoundary_BuildTags(t *testing.T) {
        for _, b := range aiSurfaceBoundaries {
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

func TestAISurfaceBoundary_StubFunctionsDefined(t *testing.T) {
        for _, b := range aiSurfaceBoundaries {
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

func TestAISurfaceBoundary_StubVarsDefined(t *testing.T) {
        for _, b := range aiSurfaceBoundaries {
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

func TestAISurfaceBoundary_CorrectPackage(t *testing.T) {
        for _, b := range aiSurfaceBoundaries {
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
                                if !strings.Contains(string(data), "package ai_surface") {
                                        t.Errorf("File %s has wrong package — expected 'package ai_surface'", file.path)
                                }
                        })
                }
        }
}

func TestAISurfaceBoundary_NoIntelLeakage(t *testing.T) {
        crawlerIntelTokens := []string{
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
                "Diffbot",
                "ImagesiftBot",
                "Timpibot",
        }

        for _, b := range aiSurfaceBoundaries {
                for _, file := range []string{b.FrameworkFile, b.StubFile} {
                        t.Run(b.Name+"_no_intel_in_"+filepath.Base(file), func(t *testing.T) {
                                data, err := os.ReadFile(file)
                                if err != nil {
                                        t.Skipf("cannot read %s: %v", file, err)
                                }
                                content := string(data)

                                for _, token := range crawlerIntelTokens {
                                        lines := strings.Split(content, "\n")
                                        for i, line := range lines {
                                                trimmed := strings.TrimSpace(line)
                                                if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
                                                        continue
                                                }
                                                if strings.Contains(line, token) {
                                                        t.Errorf("INTEL LEAKAGE: crawler name %q found in public file %s line %d — crawler lists must only be in _intel.go", token, file, i+1)
                                                }
                                        }
                                }
                        })
                }
        }
}

func TestAISurfaceBoundary_StubsReturnSafeDefaults(t *testing.T) {
        scanner := &Scanner{}
        ctx := context.Background()

        t.Run("llms_txt_safe_return", func(t *testing.T) {
                result := scanner.CheckLLMSTxt(ctx, "test.example.com")
                if result == nil {
                        t.Error("CheckLLMSTxt returned nil — stubs must return non-nil maps")
                }
                if result["found"] != false {
                        t.Errorf("CheckLLMSTxt found = %v, want false", result["found"])
                }
                if result["evidence"] == nil {
                        t.Error("CheckLLMSTxt evidence is nil — must return empty slice")
                }
        })

        t.Run("robots_txt_safe_return", func(t *testing.T) {
                result := scanner.CheckRobotsTxtAI(ctx, "test.example.com")
                if result == nil {
                        t.Error("CheckRobotsTxtAI returned nil — stubs must return non-nil maps")
                }
                if result["blocks_ai_crawlers"] != false {
                        t.Errorf("CheckRobotsTxtAI blocks_ai_crawlers = %v, want false", result["blocks_ai_crawlers"])
                }
        })

        t.Run("poisoning_safe_return", func(t *testing.T) {
                result := scanner.DetectPoisoningIOCs(ctx, "test.example.com")
                if result == nil {
                        t.Error("DetectPoisoningIOCs returned nil — stubs must return non-nil maps")
                }
                if result["status"] != "success" {
                        t.Errorf("DetectPoisoningIOCs status = %v, want 'success'", result["status"])
                }
                if result["iocs"] == nil {
                        t.Error("DetectPoisoningIOCs iocs is nil — must return empty slice")
                }
        })

        t.Run("hidden_prompts_safe_return", func(t *testing.T) {
                result := scanner.DetectHiddenPrompts(ctx, "test.example.com")
                if result == nil {
                        t.Error("DetectHiddenPrompts returned nil — stubs must return non-nil maps")
                }
                if result["status"] != "success" {
                        t.Errorf("DetectHiddenPrompts status = %v, want 'success'", result["status"])
                }
        })

        t.Run("get_ai_crawlers_safe_return", func(t *testing.T) {
                crawlers := GetAICrawlers()
                if crawlers == nil {
                        t.Error("GetAICrawlers returned nil — must return empty slice in OSS mode")
                }
        })

        t.Run("robots_txt_knownAICrawlers_safe", func(t *testing.T) {
                if knownAICrawlers == nil {
                        t.Error("knownAICrawlers is nil — must be initialized empty slice")
                }
        })

        t.Run("poisoning_regexes_safe", func(t *testing.T) {
                if prefilledPromptRe == nil {
                        t.Error("prefilledPromptRe is nil — must be initialized with placeholder regex")
                }
                if promptInjectionRe == nil {
                        t.Error("promptInjectionRe is nil — must be initialized with placeholder regex")
                }
        })
}

func TestAISurfaceBoundary_CompleteBoundaryInventory(t *testing.T) {
        expectedCount := 5
        if len(aiSurfaceBoundaries) != expectedCount {
                t.Errorf("aiSurfaceBoundaries has %d entries, expected %d — update boundary inventory when adding new boundaries", len(aiSurfaceBoundaries), expectedCount)
        }
}

func TestAISurfaceBoundary_NoDuplicateFunctions(t *testing.T) {
        for _, b := range aiSurfaceBoundaries {
                t.Run(b.Name+"_no_duplicates", func(t *testing.T) {
                        frameworkData, err := os.ReadFile(b.FrameworkFile)
                        if err != nil {
                                t.Skipf("cannot read %s: %v", b.FrameworkFile, err)
                        }
                        stubData, err := os.ReadFile(b.StubFile)
                        if err != nil {
                                t.Skipf("cannot read %s: %v", b.StubFile, err)
                        }

                        frameworkFuncs := extractFuncSigs(string(frameworkData))
                        stubFuncs := extractFuncSigs(string(stubData))

                        for fn := range stubFuncs {
                                if frameworkFuncs[fn] {
                                        t.Errorf("DUPLICATE function %q defined in both %s and %s", fn, b.FrameworkFile, b.StubFile)
                                }
                        }
                })
        }
}

func extractFuncSigs(content string) map[string]bool {
        result := make(map[string]bool)
        for _, line := range strings.Split(content, "\n") {
                trimmed := strings.TrimSpace(line)
                if strings.HasPrefix(trimmed, "func ") && strings.Contains(trimmed, "(") {
                        sig := strings.SplitN(trimmed, "{", 2)[0]
                        result[strings.TrimSpace(sig)] = true
                }
        }
        return result
}
