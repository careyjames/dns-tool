// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// Package-level documentation for the Science/Design classification system.
//
// dns-tool:scrutiny science
//
// Every .go file in this project carries a scrutiny classification comment
// on the line immediately following the copyright/license/build-tag block:
//
//     // dns-tool:scrutiny science   — RFC truth, mathematical formulas, confidence logic.
//     //                                Changes require: RFC citation verification,
//     //                                mathematical correctness, protocol test suite pass,
//     //                                Confidence Bridge pass, golden fixture cross-ref.
//
//     // dns-tool:scrutiny design    — UX, styling, copy, routing glue.
//     //                                Normal quality gates apply.
//
//     // dns-tool:scrutiny plumbing  — Build system, config, infrastructure glue.
//     //                                Changes need functional testing but not RFC audit.
//
// The classification test (scrutiny_classification_test.go) enforces that:
//   1. Every .go file has exactly one dns-tool:scrutiny tag.
//   2. The tag value is one of: science, design, plumbing.
//   3. Files in SCIENCE directories must be tagged "science".
//   4. Files in DESIGN directories must be tagged "design".
//
// Future-proofing: 40 years from now, engineers migrating this codebase
// can grep for "dns-tool:scrutiny science" to find every line of code
// that implements RFC truth, mathematical formulas, or confidence logic —
// the parts that must be migrated with extreme care and verification.
// Everything else is presentation or infrastructure — restyle it freely.
package analyzer
