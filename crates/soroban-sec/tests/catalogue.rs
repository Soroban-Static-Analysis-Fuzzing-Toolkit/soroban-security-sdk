//! Rule-catalogue output contract.
//!
//! The Markdown catalogue is committed as `docs/rules.md`, and the JSON catalogue
//! is consumed by tooling. Both are generated from detector metadata, so these
//! tests fail when a rule is added, removed or re-described without regenerating —
//! the same "cannot drift silently" discipline the corpus test applies to findings.

use std::process::Command;

use serde_json::Value;

/// The committed reference, regenerated with
/// `cargo run -p soroban-sec -- --list-rules --format markdown > docs/rules.md`.
const COMMITTED_RULES: &str = include_str!("../../../docs/rules.md");

/// Fields every rule object in the JSON catalogue must expose. Adding or renaming
/// one is a deliberate interface change, so it must update this list.
const DOCUMENTED_KEYS: &[&str] = &[
    "category",
    "confidence",
    "default_enabled",
    "description",
    "id",
    "name",
    "references",
    "requires_wasm",
    "severity",
    "summary",
    "tags",
];

fn run(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-sec"))
        .args(args)
        .output()
        .expect("run soroban-sec");
    assert!(
        output.status.success(),
        "`soroban-sec {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("stdout is UTF-8")
}

#[test]
fn committed_rule_reference_is_up_to_date() {
    let generated = run(&["--list-rules", "--format", "markdown"]);
    assert_eq!(
        generated, COMMITTED_RULES,
        "docs/rules.md is stale; regenerate it with\n  \
         cargo run -p soroban-sec -- --list-rules --format markdown > docs/rules.md"
    );
}

#[test]
fn catalogue_json_lists_every_rule_with_documented_keys() {
    let text = run(&["--list-rules", "--format", "json"]);
    let rules: Vec<Value> = serde_json::from_str(&text).expect("catalogue JSON parses");
    assert!(!rules.is_empty(), "the catalogue should not be empty");

    for rule in &rules {
        let object = rule.as_object().expect("each rule is an object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut documented = DOCUMENTED_KEYS.to_vec();
        documented.sort_unstable();
        assert_eq!(keys, documented, "unexpected keys in {rule}");
    }

    let ids: Vec<&str> = rules
        .iter()
        .map(|rule| rule["id"].as_str().expect("id is a string"))
        .collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "rules should be ordered by id");
}

#[test]
fn rule_catalogue_rejects_report_only_formats() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-sec"))
        .args(["--list-rules", "--format", "sarif"])
        .output()
        .expect("run soroban-sec");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cannot render the rule catalogue"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
