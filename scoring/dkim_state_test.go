// Copyright (c) 2024-2026 IT Help San Diego Inc. All rights reserved.
// PROPRIETARY AND CONFIDENTIAL — See LICENSE for terms.
// This file is part of the DNS Tool Intelligence Module.
package analyzer

import (
        "testing"
)

func TestDKIMStateClassification(t *testing.T) {
        tests := []struct {
                name     string
                ps       protocolState
                expected DKIMState
        }{
                {
                        name:     "success status → DKIMSuccess",
                        ps:       protocolState{dkimOK: true},
                        expected: DKIMSuccess,
                },
                {
                        name:     "provider inferred via known provider",
                        ps:       protocolState{dkimProvider: true},
                        expected: DKIMProviderInferred,
                },
                {
                        name:     "third-party only selectors found",
                        ps:       protocolState{dkimThirdPartyOnly: true},
                        expected: DKIMThirdPartyOnly,
                },
                {
                        name:     "inconclusive — no selectors, unknown provider",
                        ps:       protocolState{dkimPartial: true},
                        expected: DKIMInconclusive,
                },
                {
                        name:     "absent — nothing found, domain sends mail",
                        ps:       protocolState{},
                        expected: DKIMAbsent,
                },
                {
                        name:     "no-mail domain overrides absent",
                        ps:       protocolState{isNoMailDomain: true},
                        expected: DKIMNoMailDomain,
                },
                {
                        name:     "no-mail domain overrides even if dkimOK",
                        ps:       protocolState{dkimOK: true, isNoMailDomain: true},
                        expected: DKIMNoMailDomain,
                },
                {
                        name:     "dkimOK takes precedence over dkimThirdPartyOnly",
                        ps:       protocolState{dkimOK: true, dkimThirdPartyOnly: true},
                        expected: DKIMSuccess,
                },
                {
                        name:     "dkimProvider takes precedence over dkimPartial",
                        ps:       protocolState{dkimProvider: true, dkimPartial: true},
                        expected: DKIMProviderInferred,
                },
                {
                        name:     "dkimThirdPartyOnly takes precedence over dkimPartial",
                        ps:       protocolState{dkimThirdPartyOnly: true, dkimPartial: true},
                        expected: DKIMThirdPartyOnly,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := classifyDKIMState(tt.ps)
                        if got != tt.expected {
                                t.Errorf("classifyDKIMState() = %s, want %s", got, tt.expected)
                        }
                })
        }
}

func TestDKIMStatePredicates(t *testing.T) {
        tests := []struct {
                state        DKIMState
                isPresent    bool
                isConfigured bool
                needsAction  bool
                needsMonitor bool
        }{
                {DKIMSuccess, true, true, false, false},
                {DKIMProviderInferred, true, true, false, false},
                {DKIMThirdPartyOnly, true, true, false, false},
                {DKIMInconclusive, false, false, false, true},
                {DKIMAbsent, false, false, true, false},
                {DKIMNoMailDomain, false, false, false, false},
                {DKIMWeakKeysOnly, true, false, false, false},
        }

        for _, tt := range tests {
                t.Run(tt.state.String(), func(t *testing.T) {
                        if got := tt.state.IsPresent(); got != tt.isPresent {
                                t.Errorf("%s.IsPresent() = %v, want %v", tt.state, got, tt.isPresent)
                        }
                        if got := tt.state.IsConfigured(); got != tt.isConfigured {
                                t.Errorf("%s.IsConfigured() = %v, want %v", tt.state, got, tt.isConfigured)
                        }
                        if got := tt.state.NeedsAction(); got != tt.needsAction {
                                t.Errorf("%s.NeedsAction() = %v, want %v", tt.state, got, tt.needsAction)
                        }
                        if got := tt.state.NeedsMonitoring(); got != tt.needsMonitor {
                                t.Errorf("%s.NeedsMonitoring() = %v, want %v", tt.state, got, tt.needsMonitor)
                        }
                })
        }
}

func TestPostureMatrixDKIMxSPFxDMARC(t *testing.T) {
        a := testAnalyzer()

        type matrixCase struct {
                name string

                spfStatus string
                spfAll    string
                spfPerm   string

                dmarcStatus string
                dmarcPolicy string

                dkimStatus   string
                dkimProvider string
                dkimTPO      bool

                caaStatus string

                expectGradeNot   []string
                expectGradeIn    []string
                expectConfigured []string
                expectAbsent     []string
                expectMonitoring []string
                expectEmailAns   []string
                expectNoAbsent   []string

                expectFixTitle    string
                expectFixSeverity string
                expectNoFix       string
        }

        cases := []matrixCase{
                {
                        name: "Full_stack_SPF_hard_DMARC_reject_DKIM_success_CAA",
                        spfStatus: "success", spfAll: "-all",
                        dmarcStatus: "success", dmarcPolicy: "reject",
                        dkimStatus: "success", caaStatus: "success",
                        expectGradeIn:    []string{riskLow, "Secure"},
                        expectConfigured: []string{"SPF (-all)", "DMARC (reject)", "DKIM", "CAA"},
                        expectEmailAns:   []string{"No"},
                },
                {
                        name: "SPF_soft_DMARC_reject_DKIM_success",
                        spfStatus: "success", spfAll: "~all",
                        dmarcStatus: "success", dmarcPolicy: "reject",
                        dkimStatus: "success", caaStatus: "warning",
                        expectGradeIn:    []string{riskLow},
                        expectConfigured: []string{"SPF (~all)", "DMARC (reject)", "DKIM"},
                        expectEmailAns:   []string{"No"},
                },
                {
                        name: "Cloudflare_scenario_SPF_hard_DMARC_reject_DKIM_thirdparty_CAA",
                        spfStatus: "success", spfAll: "-all",
                        dmarcStatus: "success", dmarcPolicy: "reject",
                        dkimStatus: "partial", dkimProvider: "Google Workspace", dkimTPO: true,
                        caaStatus:        "success",
                        expectGradeIn:    []string{riskLow},
                        expectGradeNot:   []string{riskMedium, riskHigh, riskCritical},
                        expectConfigured: []string{"DKIM (third-party)"},
                        expectNoAbsent:   []string{"DKIM"},
                        expectEmailAns:   []string{"No"},
                        expectFixTitle:    "Enable DKIM for Google Workspace",
                        expectFixSeverity: severityMedium,
                },
                {
                        name: "SPF_soft_DMARC_reject_DKIM_absent",
                        spfStatus: "success", spfAll: "~all",
                        dmarcStatus: "success", dmarcPolicy: "reject",
                        dkimStatus: "warning", caaStatus: "warning",
                        expectGradeIn:  []string{riskMedium},
                        expectAbsent:   []string{"DKIM"},
                        expectEmailAns: []string{"Partially"},
                        expectFixTitle: "Configure DKIM signing",
                        expectFixSeverity: severityHigh,
                },
                {
                        name: "SPF_soft_DMARC_reject_DKIM_inconclusive",
                        spfStatus: "success", spfAll: "~all",
                        dmarcStatus: "success", dmarcPolicy: "reject",
                        dkimStatus: "info", dkimProvider: "Unknown", caaStatus: "warning",
                        expectGradeIn:    []string{riskLow + " Monitoring"},
                        expectMonitoring: []string{"DKIM (inconclusive)"},
                        expectFixTitle:   "Verify DKIM configuration",
                        expectFixSeverity: severityLow,
                },
                {
                        name: "SPF_soft_DMARC_reject_DKIM_provider_inferred",
                        spfStatus: "success", spfAll: "~all",
                        dmarcStatus: "success", dmarcPolicy: "reject",
                        dkimStatus: "info", dkimProvider: "Google Workspace", caaStatus: "warning",
                        expectGradeIn:    []string{riskLow},
                        expectConfigured: []string{"DKIM (provider-verified)"},
                        expectEmailAns:   []string{"No"},
                },
                {
                        name: "SPF_dangerous_DMARC_reject_DKIM_success",
                        spfStatus: "success", spfAll: "+all", spfPerm: "DANGEROUS",
                        dmarcStatus: "success", dmarcPolicy: "reject",
                        dkimStatus: "success", caaStatus: "warning",
                        expectConfigured: []string{"SPF (+all)"},
                },
                {
                        name: "No_SPF_No_DMARC_No_DKIM",
                        spfStatus: "warning", spfAll: "",
                        dmarcStatus: "warning", dmarcPolicy: "",
                        dkimStatus: "warning", caaStatus: "warning",
                        expectGradeIn: []string{riskCritical},
                        expectAbsent:  []string{"SPF", "DMARC", "DKIM"},
                        expectEmailAns: []string{"Yes"},
                },
                {
                        name: "SPF_only_no_DMARC",
                        spfStatus: "success", spfAll: "~all",
                        dmarcStatus: "warning", dmarcPolicy: "",
                        dkimStatus: "warning", caaStatus: "warning",
                        expectGradeIn:  []string{riskHigh},
                        expectAbsent:   []string{"DMARC", "DKIM"},
                        expectEmailAns: []string{"Yes"},
                },
                {
                        name: "SPF_DMARC_none_DKIM_success",
                        spfStatus: "success", spfAll: "~all",
                        dmarcStatus: "success", dmarcPolicy: "none",
                        dkimStatus: "success", caaStatus: "warning",
                        expectGradeIn:  []string{riskMedium},
                        expectEmailAns: []string{"Partially"},
                },
                {
                        name: "ThirdParty_DKIM_SPF_soft_DMARC_quarantine",
                        spfStatus: "success", spfAll: "~all",
                        dmarcStatus: "success", dmarcPolicy: "quarantine",
                        dkimStatus: "partial", dkimProvider: "Microsoft 365", dkimTPO: true,
                        caaStatus:        "warning",
                        expectGradeIn:    []string{riskLow},
                        expectGradeNot:   []string{riskMedium, riskHigh},
                        expectConfigured: []string{"DKIM (third-party)"},
                        expectNoAbsent:   []string{"DKIM"},
                        expectEmailAns:   []string{"Mostly No"},
                },
        }

        for _, tc := range cases {
                t.Run(tc.name, func(t *testing.T) {
                        r := baseResults()
                        withSPF(r, tc.spfStatus, tc.spfAll, tc.spfPerm)
                        withDMARC(r, tc.dmarcStatus, tc.dmarcPolicy)
                        withDKIM(r, tc.dkimStatus, tc.dkimProvider)
                        if tc.dkimTPO {
                                withDKIMThirdPartyOnly(r)
                        }
                        withCAA(r, tc.caaStatus)

                        pos := a.CalculatePosture(r)
                        rem := a.GenerateRemediation(r)

                        grade, _ := pos["grade"].(string)
                        for _, want := range tc.expectGradeIn {
                                if grade == want {
                                        goto gradeOk
                                }
                        }
                        if len(tc.expectGradeIn) > 0 {
                                t.Errorf("grade = %q, want one of %v", grade, tc.expectGradeIn)
                        }
                gradeOk:

                        for _, notWant := range tc.expectGradeNot {
                                if grade == notWant {
                                        t.Errorf("grade = %q, must NOT be %q", grade, notWant)
                                }
                        }

                        for _, want := range tc.expectConfigured {
                                postureHas(t, pos, "configured", want)
                        }
                        for _, want := range tc.expectAbsent {
                                postureHas(t, pos, "absent", want)
                        }
                        for _, want := range tc.expectMonitoring {
                                postureHas(t, pos, "monitoring", want)
                        }
                        for _, notWant := range tc.expectNoAbsent {
                                postureNotHas(t, pos, "absent", notWant)
                        }

                        if len(tc.expectEmailAns) > 0 {
                                verdicts, _ := pos["verdicts"].(map[string]any)
                                emailAns, _ := verdicts["email_answer"].(string)
                                found := false
                                for _, want := range tc.expectEmailAns {
                                        if emailAns == want {
                                                found = true
                                                break
                                        }
                                }
                                if !found {
                                        t.Errorf("email_answer = %q, want one of %v", emailAns, tc.expectEmailAns)
                                }
                        }

                        if tc.expectFixTitle != "" {
                                requireFixContaining(t, rem, tc.expectFixTitle)
                                if tc.expectFixSeverity != "" {
                                        requireSeverityContaining(t, rem, tc.expectFixTitle, tc.expectFixSeverity)
                                }
                        }
                        if tc.expectNoFix != "" {
                                forbidFixContaining(t, rem, tc.expectNoFix)
                        }
                })
        }
}

func TestDKIMStateConsistency(t *testing.T) {
        a := testAnalyzer()

        t.Run("posture_and_remediation_agree_on_third_party", func(t *testing.T) {
                r := baseResults()
                withSPF(r, "success", "-all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "partial", "Google Workspace")
                withDKIMThirdPartyOnly(r)

                pos := a.CalculatePosture(r)
                rem := a.GenerateRemediation(r)

                postureHas(t, pos, "configured", "DKIM (third-party)")
                postureNotHas(t, pos, "absent", "DKIM")

                requireFixContaining(t, rem, "Enable DKIM for Google Workspace")
                requireSeverityContaining(t, rem, "Enable DKIM for Google Workspace", severityMedium)

                forbidFixContaining(t, rem, "Configure DKIM signing")
                forbidFixContaining(t, rem, "Verify DKIM configuration")
        })

        t.Run("posture_and_remediation_agree_on_absent", func(t *testing.T) {
                r := baseResults()
                withSPF(r, "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "warning", "")

                pos := a.CalculatePosture(r)
                rem := a.GenerateRemediation(r)

                postureHas(t, pos, "absent", "DKIM")
                requireFixContaining(t, rem, "Configure DKIM signing")
                requireSeverityContaining(t, rem, "Configure DKIM signing", severityHigh)
        })

        t.Run("posture_and_remediation_agree_on_inconclusive", func(t *testing.T) {
                r := baseResults()
                withSPF(r, "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "info", "Unknown")

                pos := a.CalculatePosture(r)
                rem := a.GenerateRemediation(r)

                postureHas(t, pos, "monitoring", "DKIM (inconclusive)")
                requireFixContaining(t, rem, "Verify DKIM configuration")
                requireSeverityContaining(t, rem, "Verify DKIM configuration", severityLow)
        })

        t.Run("posture_and_remediation_agree_on_nomail", func(t *testing.T) {
                r := baseResults()
                withSPF(r, "success", "-all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "warning", "")
                withNoMail(r)

                rem := a.GenerateRemediation(r)
                forbidFixContaining(t, rem, "DKIM")
        })

        t.Run("spf_upgrade_not_recommended_with_third_party_dkim", func(t *testing.T) {
                r := baseResults()
                withSPF(r, "success", "~all", "")
                withDMARC(r, "success", "reject")
                withDKIM(r, "partial", "Google Workspace")
                withDKIMThirdPartyOnly(r)

                rem := a.GenerateRemediation(r)
                forbidFixContaining(t, rem, "Upgrade SPF to hard fail")
        })
}
