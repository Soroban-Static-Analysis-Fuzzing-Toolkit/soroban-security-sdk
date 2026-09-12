//! Integration tests for the compiled-module detectors (`SSDK020`–`SSDK022`).
//!
//! Each case builds a real Wasm module from Wat text, parses it with the SDK and
//! runs the catalogue against it.
#![cfg(feature = "detectors")]

use std::collections::BTreeSet;

use soroban_security_sdk::prelude::*;
use soroban_security_sdk::wasm::WasmModule;

fn analyze_wasm(source: &str, config: &AnalysisConfig) -> AnalysisReport {
    let bytes = wat::parse_str(source).expect("valid wat");
    let module = WasmModule::parse("contract.wasm", &bytes).expect("valid wasm");
    let project = ProjectBuilder::new().wasm(module).build();
    analyze(&project, config)
}

fn fired(report: &AnalysisReport) -> BTreeSet<String> {
    report
        .findings
        .iter()
        .map(|finding| finding.rule.to_string())
        .collect()
}

const STORAGE_WRITE: &str = r#"
(module
  (import "env" "storage_set" (func $storage_set (param i32 i32 i32)))
  (memory 1)
  (func (export "set_total")
    (call $storage_set (i32.const 0) (i32.const 0) (i32.const 0))))
"#;

const STORAGE_WRITE_WITH_AUTH: &str = r#"
(module
  (import "env" "storage_set" (func $storage_set (param i32 i32 i32)))
  (import "env" "require_auth" (func $require_auth (param i32)))
  (memory 1)
  (func (export "set_total")
    (call $require_auth (i32.const 0))
    (call $storage_set (i32.const 0) (i32.const 0) (i32.const 0))))
"#;

#[test]
fn storage_write_without_auth_is_flagged() {
    let report = analyze_wasm(STORAGE_WRITE, &AnalysisConfig::default());
    assert!(
        fired(&report).contains("SSDK020"),
        "expected SSDK020, got {:#?}",
        report.findings
    );
}

#[test]
fn storage_write_with_require_auth_is_clean() {
    let report = analyze_wasm(STORAGE_WRITE_WITH_AUTH, &AnalysisConfig::default());
    assert!(
        fired(&report).is_empty(),
        "unexpected findings: {:#?}",
        report.findings
    );
}

#[test]
fn oversized_module_is_flagged_against_the_entry_limit() {
    let mut config = AnalysisConfig::default();
    config.limits.max_entry_size_bytes = 16;
    let report = analyze_wasm(STORAGE_WRITE, &config);
    assert!(
        fired(&report).contains("SSDK021"),
        "expected SSDK021, got {:#?}",
        report.findings
    );
}

#[test]
fn start_function_is_flagged() {
    let source = r#"
(module
  (func $init)
  (start $init)
  (func (export "f")))
"#;
    let report = analyze_wasm(source, &AnalysisConfig::default());
    assert!(
        fired(&report).contains("SSDK022"),
        "expected SSDK022, got {:#?}",
        report.findings
    );
}

#[test]
fn a_clean_module_produces_no_findings() {
    let source = r#"
(module
  (memory 1)
  (func (export "f") (result i32) (i32.const 1)))
"#;
    let report = analyze_wasm(source, &AnalysisConfig::default());
    assert!(
        fired(&report).is_empty(),
        "unexpected findings: {:#?}",
        report.findings
    );
}

#[test]
fn wasm_rules_are_reported_as_needing_a_module_without_one() {
    // Analysing source alone should surface the wasm rules as skipped, not silent.
    let project = ProjectBuilder::new()
        .source("src/lib.rs", "pub fn f() {}")
        .unwrap()
        .build();
    let report = analyze(&project, &AnalysisConfig::default());
    assert!(report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == DiagnosticKind::MissingWasm));
}
