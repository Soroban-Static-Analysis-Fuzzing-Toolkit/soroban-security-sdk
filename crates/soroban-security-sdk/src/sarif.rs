//! SARIF 2.1.0 output.
//!
//! [SARIF](https://sarifweb.azurewebsites.net/) is the interchange format GitHub
//! code scanning and most CI security dashboards consume. Rendering a report into
//! it is what lets a `soroban-sec` run surface as inline annotations in a pull
//! request rather than as log noise.
//!
//! ```no_run
//! use soroban_security_sdk::prelude::*;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let project = Project::from_dir(".")?;
//! let report = analyze(&project, &AnalysisConfig::default());
//! let sarif = soroban_security_sdk::sarif::to_sarif_string(&report);
//! std::fs::write("soroban-sec.sarif", sarif)?;
//! # Ok(())
//! # }
//! ```
//!
//! Every rule carries a `security-severity` property (`0.0`–`10.0`) and every
//! result carries a stable `partialFingerprints` entry, so GitHub can track a
//! finding across commits instead of re-opening it on every push.

use serde_json::{json, Map, Value};

use crate::analysis::{AnalysisReport, Diagnostic};
use crate::finding::{Finding, Location};
use crate::rule::DetectorMeta;
use crate::severity::Severity;

/// URL of the SARIF 2.1.0 JSON schema.
pub const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

/// SARIF specification version this module emits.
pub const VERSION: &str = "2.1.0";

/// Name of the tool written into the SARIF driver object.
pub const TOOL_NAME: &str = "soroban-sec";

/// Render an analysis report as a SARIF log.
pub fn to_sarif(report: &AnalysisReport) -> Value {
    let rules: Vec<Value> = report.rules.iter().map(rule_json).collect();
    let results: Vec<Value> = report.findings.iter().map(result_json).collect();

    let mut driver = Map::new();
    driver.insert("name".to_string(), json!(TOOL_NAME));
    driver.insert("version".to_string(), json!(env!("CARGO_PKG_VERSION")));
    driver.insert(
        "informationUri".to_string(),
        json!("https://github.com/Soroban-Static-Analysis-Fuzzing-Toolkit/soroban-security-sdk"),
    );
    driver.insert("rules".to_string(), Value::Array(rules));

    let mut run = Map::new();
    run.insert(
        "tool".to_string(),
        json!({ "driver": Value::Object(driver) }),
    );
    run.insert("results".to_string(), Value::Array(results));
    if !report.diagnostics.is_empty() {
        run.insert(
            "invocations".to_string(),
            json!([{
                "executionSuccessful": true,
                "toolExecutionNotifications": report.diagnostics.iter().map(diagnostic_json).collect::<Vec<_>>(),
            }]),
        );
    }

    json!({
        "$schema": SCHEMA,
        "version": VERSION,
        "runs": [Value::Object(run)],
    })
}

/// Render an analysis report as pretty-printed SARIF JSON.
pub fn to_sarif_string(report: &AnalysisReport) -> String {
    serde_json::to_string_pretty(&to_sarif(report)).expect("SARIF values always serialise to JSON")
}

/// The `security-severity` score GitHub associates with a severity level.
pub fn security_severity(severity: Severity) -> f64 {
    match severity {
        Severity::Info => 0.0,
        Severity::Low => 3.1,
        Severity::Medium => 5.5,
        Severity::High => 7.8,
        Severity::Critical => 9.5,
    }
}

fn rule_json(meta: &DetectorMeta) -> Value {
    let description = if meta.description.is_empty() {
        meta.summary
    } else {
        meta.description
    };
    let help_uri = meta
        .references
        .first()
        .map(|reference| reference.url)
        .unwrap_or(
            "https://github.com/Soroban-Static-Analysis-Fuzzing-Toolkit/soroban-security-sdk",
        );

    let mut properties = Map::new();
    properties.insert("category".to_string(), json!(meta.category.as_str()));
    properties.insert(
        "security-severity".to_string(),
        json!(format!("{:.1}", security_severity(meta.severity))),
    );
    properties.insert("tags".to_string(), json!(meta.tags));

    json!({
        "id": meta.id.as_str(),
        "name": meta.name,
        "shortDescription": { "text": meta.summary },
        "fullDescription": { "text": description },
        "helpUri": help_uri,
        "help": { "text": description },
        "defaultConfiguration": { "level": meta.severity.sarif_level() },
        "properties": Value::Object(properties),
    })
}

fn result_json(finding: &Finding) -> Value {
    let locations: Vec<Value> = finding.locations.iter().map(location_json).collect();
    let mut properties = Map::new();
    properties.insert("confidence".to_string(), json!(finding.confidence.as_str()));
    properties.insert("category".to_string(), json!(finding.category.as_str()));
    if !finding.notes.is_empty() {
        properties.insert("notes".to_string(), json!(finding.notes));
    }
    if let Some(help) = &finding.help {
        properties.insert("help".to_string(), json!(help));
    }

    let mut result = Map::new();
    result.insert("ruleId".to_string(), json!(finding.rule.as_str()));
    result.insert("level".to_string(), json!(finding.severity.sarif_level()));
    result.insert("message".to_string(), json!({ "text": finding.message }));
    result.insert("locations".to_string(), Value::Array(locations));
    result.insert(
        "partialFingerprints".to_string(),
        json!({ "sorobanSec/v1": finding.fingerprint() }),
    );
    result.insert("properties".to_string(), Value::Object(properties));
    Value::Object(result)
}

fn location_json(location: &Location) -> Value {
    let mut physical = Map::new();
    physical.insert(
        "artifactLocation".to_string(),
        json!({ "uri": location.file }),
    );

    if let Some(span) = location.span.filter(|span| span.is_known()) {
        let mut region = Map::new();
        region.insert("startLine".to_string(), json!(span.start_line));
        region.insert("startColumn".to_string(), json!(span.start_column));
        region.insert("endLine".to_string(), json!(span.end_line));
        region.insert("endColumn".to_string(), json!(span.end_column));
        if let Some(label) = &location.label {
            region.insert("message".to_string(), json!({ "text": label }));
        }
        physical.insert("region".to_string(), Value::Object(region));
    }

    let mut entry = Map::new();
    entry.insert("physicalLocation".to_string(), Value::Object(physical));
    if let Some(function) = &location.function {
        entry.insert(
            "logicalLocations".to_string(),
            json!([{ "name": function, "kind": "function" }]),
        );
    }
    if let Some(offset) = location.wasm_offset {
        entry.insert("properties".to_string(), json!({ "wasmOffset": offset }));
    }
    Value::Object(entry)
}

fn diagnostic_json(diagnostic: &Diagnostic) -> Value {
    let message = match &diagnostic.location {
        Some(location) => format!("{location}: {}", diagnostic.message),
        None => diagnostic.message.clone(),
    };
    json!({
        "level": "warning",
        "descriptor": { "id": diagnostic.kind.as_str() },
        "message": { "text": message },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{analyze_with, ProjectBuilder};
    use crate::category::Category;
    use crate::config::AnalysisConfig;
    use crate::context::AnalysisContext;
    use crate::detector::Detector;
    use crate::finding::FindingSink;
    use crate::registry::DetectorRegistry;
    use crate::rule::{DetectorMeta, RuleId};
    use crate::severity::Confidence;
    use crate::span::SourceSpan;

    #[derive(Default)]
    struct Flag;

    impl Detector for Flag {
        const META: DetectorMeta = DetectorMeta::new(RuleId::new("SSDK980"), "flag", "flags")
            .severity(Severity::High)
            .confidence(Confidence::High)
            .category(Category::Auth)
            .tags(&["auth"]);

        fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
            for entrypoint in ctx.entrypoints() {
                sink.report("flagged")
                    .primary(entrypoint.file, entrypoint.span)
                    .in_function(entrypoint.name.clone())
                    .note("a note")
                    .emit();
            }
        }
    }

    fn report() -> AnalysisReport {
        let project = ProjectBuilder::new()
            .source(
                "src/lib.rs",
                "#[contractimpl]\nimpl T {\n    pub fn a(env: Env) {}\n}\n",
            )
            .unwrap()
            .build();
        let mut registry = DetectorRegistry::empty();
        registry.register::<Flag>();
        analyze_with(&project, &AnalysisConfig::default(), &registry)
    }

    #[test]
    fn produces_a_valid_sarif_envelope() {
        let sarif = to_sarif(&report());
        assert_eq!(sarif["version"], VERSION);
        assert_eq!(sarif["$schema"], SCHEMA);
        assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], TOOL_NAME);
        assert_eq!(
            sarif["runs"][0]["tool"]["driver"]["rules"][0]["id"],
            "SSDK980"
        );
        assert_eq!(sarif["runs"][0]["results"][0]["ruleId"], "SSDK980");
        assert_eq!(sarif["runs"][0]["results"][0]["level"], "error");
    }

    #[test]
    fn results_carry_locations_and_fingerprints() {
        let sarif = to_sarif(&report());
        let result = &sarif["runs"][0]["results"][0];
        let location = &result["locations"][0];
        assert_eq!(
            location["physicalLocation"]["artifactLocation"]["uri"],
            "src/lib.rs"
        );
        assert_eq!(location["physicalLocation"]["region"]["startLine"], 3);
        assert_eq!(location["logicalLocations"][0]["name"], "a");
        assert!(result["partialFingerprints"]["sorobanSec/v1"].is_string());
    }

    #[test]
    fn rules_carry_security_severity() {
        let sarif = to_sarif(&report());
        let rule = &sarif["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(rule["defaultConfiguration"]["level"], "error");
        assert_eq!(rule["properties"]["security-severity"], "7.8");
        assert_eq!(rule["properties"]["category"], "auth");
    }

    #[test]
    fn output_is_parseable_json() {
        let text = to_sarif_string(&report());
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["runs"][0]["results"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn severity_scores_are_ordered() {
        let scores: Vec<f64> = Severity::ALL
            .iter()
            .copied()
            .map(security_severity)
            .collect();
        for pair in scores.windows(2) {
            assert!(pair[1] > pair[0], "severities should increase: {scores:?}");
        }
    }

    #[test]
    fn diagnostics_become_invocation_notifications() {
        let project = ProjectBuilder::new()
            .source("src/lib.rs", "pub fn f() {}")
            .unwrap()
            .build();
        let config = AnalysisConfig::with_rules([RuleId::new("SSDK981")]);
        let mut registry = DetectorRegistry::empty();
        registry.register::<Flag>();
        let report = analyze_with(&project, &config, &registry);
        let sarif = to_sarif(&report);
        let notifications = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
            .as_array()
            .unwrap();
        assert!(!notifications.is_empty());
        let _ = SourceSpan::point(1, 1);
    }
}
