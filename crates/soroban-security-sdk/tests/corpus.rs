//! Fixture-corpus regression tests.
//!
//! Every fixture declares the **exact** set of rules it must produce. The
//! assertions are set equality rather than "the rule fired", so a change that
//! makes a detector noisier fails the suite: adding a false positive to any fixture
//! is a test failure, not a silent regression. That is how precision is kept
//! honest as the catalogue grows.
#![cfg(feature = "detectors")]

use std::collections::BTreeSet;

use soroban_security_sdk::prelude::*;

struct Fixture {
    name: &'static str,
    source: &'static str,
    expected: &'static [&'static str],
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        name: "clean/token.rs",
        source: include_str!("fixtures/clean/token.rs"),
        expected: &[],
    },
    Fixture {
        name: "clean/custom_account.rs",
        source: include_str!("fixtures/clean/custom_account.rs"),
        expected: &[],
    },
    Fixture {
        name: "clean/upgradeable.rs",
        source: include_str!("fixtures/clean/upgradeable.rs"),
        expected: &[],
    },
    Fixture {
        name: "clean/bounded_storage.rs",
        source: include_str!("fixtures/clean/bounded_storage.rs"),
        expected: &[],
    },
    // Near-miss fixtures: code that superficially resembles a vulnerability but is
    // correct. They exist to keep false positives out as detectors grow.
    Fixture {
        name: "clean/near_miss_transitive_auth.rs",
        source: include_str!("fixtures/clean/near_miss_transitive_auth.rs"),
        expected: &[],
    },
    Fixture {
        name: "clean/near_miss_checked_arithmetic.rs",
        source: include_str!("fixtures/clean/near_miss_checked_arithmetic.rs"),
        expected: &[],
    },
    Fixture {
        name: "clean/near_miss_bounded_loop.rs",
        source: include_str!("fixtures/clean/near_miss_bounded_loop.rs"),
        expected: &[],
    },
    Fixture {
        name: "vulnerable/missing_auth.rs",
        source: include_str!("fixtures/vulnerable/missing_auth.rs"),
        expected: &["SSDK001"],
    },
    Fixture {
        name: "vulnerable/tier_confusion.rs",
        source: include_str!("fixtures/vulnerable/tier_confusion.rs"),
        expected: &["SSDK002"],
    },
    Fixture {
        name: "vulnerable/unchecked_arithmetic.rs",
        source: include_str!("fixtures/vulnerable/unchecked_arithmetic.rs"),
        expected: &["SSDK003"],
    },
    Fixture {
        name: "vulnerable/lossy_cast.rs",
        source: include_str!("fixtures/vulnerable/lossy_cast.rs"),
        expected: &["SSDK004"],
    },
    Fixture {
        name: "vulnerable/wrapping.rs",
        source: include_str!("fixtures/vulnerable/wrapping.rs"),
        expected: &["SSDK005"],
    },
    Fixture {
        name: "vulnerable/unbounded_loop.rs",
        source: include_str!("fixtures/vulnerable/unbounded_loop.rs"),
        expected: &["SSDK006"],
    },
    Fixture {
        name: "vulnerable/read_budget.rs",
        source: include_str!("fixtures/vulnerable/read_budget.rs"),
        expected: &["SSDK007"],
    },
    Fixture {
        name: "vulnerable/temporary_storage.rs",
        source: include_str!("fixtures/vulnerable/temporary_storage.rs"),
        expected: &["SSDK008"],
    },
    Fixture {
        name: "vulnerable/missing_ttl.rs",
        source: include_str!("fixtures/vulnerable/missing_ttl.rs"),
        expected: &["SSDK009"],
    },
    Fixture {
        name: "vulnerable/auth_hook.rs",
        source: include_str!("fixtures/vulnerable/auth_hook.rs"),
        expected: &["SSDK010"],
    },
    Fixture {
        name: "vulnerable/randomness.rs",
        source: include_str!("fixtures/vulnerable/randomness.rs"),
        expected: &["SSDK011"],
    },
    Fixture {
        name: "vulnerable/upgrade.rs",
        source: include_str!("fixtures/vulnerable/upgrade.rs"),
        expected: &["SSDK012"],
    },
    Fixture {
        name: "vulnerable/panic.rs",
        source: include_str!("fixtures/vulnerable/panic.rs"),
        expected: &["SSDK013"],
    },
    Fixture {
        name: "vulnerable/unbounded_growth.rs",
        source: include_str!("fixtures/vulnerable/unbounded_growth.rs"),
        expected: &["SSDK023"],
    },
    Fixture {
        name: "vulnerable/unauthorized_deploy.rs",
        source: include_str!("fixtures/vulnerable/unauthorized_deploy.rs"),
        expected: &["SSDK024"],
    },
    // A single contract with several independent problems, to exercise rule
    // interaction rather than one isolated pattern at a time.
    Fixture {
        name: "vulnerable/insecure_vault.rs",
        source: include_str!("fixtures/vulnerable/insecure_vault.rs"),
        expected: &["SSDK001", "SSDK003", "SSDK008", "SSDK009", "SSDK011"],
    },
];

fn analyze_source(source: &str) -> AnalysisReport {
    let project = ProjectBuilder::new()
        .source("src/lib.rs", source)
        .unwrap()
        .build();
    analyze(&project, &AnalysisConfig::default())
}

fn fired_rules(report: &AnalysisReport) -> BTreeSet<String> {
    report
        .findings
        .iter()
        .map(|finding| finding.rule.to_string())
        .collect()
}

fn expected_rules(fixture: &Fixture) -> BTreeSet<String> {
    fixture
        .expected
        .iter()
        .map(|rule| (*rule).to_string())
        .collect()
}

#[test]
fn corpus_matches_expectations_exactly() {
    for fixture in FIXTURES {
        let report = analyze_source(fixture.source);
        let fired = fired_rules(&report);
        let expected = expected_rules(fixture);
        assert_eq!(
            fired, expected,
            "fixture `{}` rule set mismatch.\n  expected: {expected:?}\n  fired:    {fired:?}\n\nfindings:\n{:#?}",
            fixture.name, report.findings
        );
    }
}

#[test]
fn clean_fixtures_produce_no_findings() {
    for fixture in FIXTURES
        .iter()
        .filter(|fixture| fixture.expected.is_empty())
    {
        let report = analyze_source(fixture.source);
        assert!(
            report.is_empty(),
            "clean fixture `{}` is not clean:\n{:#?}",
            fixture.name,
            report.findings
        );
    }
}

#[test]
fn findings_have_clean_messages() {
    // Guards against escaped line-continuation artefacts leaking into user-facing
    // text: messages must be single-line prose, not raw source fragments.
    for fixture in FIXTURES {
        let report = analyze_source(fixture.source);
        for finding in &report.findings {
            let texts = std::iter::once(&finding.message)
                .chain(finding.notes.iter())
                .chain(finding.help.iter());
            for text in texts {
                assert!(
                    !text.contains('\\') && !text.contains('\n'),
                    "fixture `{}` has a malformed message: {text:?}",
                    fixture.name
                );
            }
        }
    }
}

#[test]
fn every_catalogued_rule_has_a_fixture() {
    // Rules whose coverage lives in a dedicated test file rather than this corpus:
    // SSDK014 needs a Cargo.toml and SSDK020-022 need a compiled module.
    const COVERED_ELSEWHERE: [&str; 4] = ["SSDK014", "SSDK020", "SSDK021", "SSDK022"];
    let covered: BTreeSet<&str> = FIXTURES
        .iter()
        .flat_map(|fixture| fixture.expected.iter().copied())
        .chain(COVERED_ELSEWHERE)
        .collect();
    let registry = DetectorRegistry::from_inventory();
    for meta in registry.metas() {
        assert!(
            covered.contains(meta.id.as_str()),
            "rule {} has no corpus fixture; add one so its precision is measured",
            meta.id
        );
    }
}

#[test]
fn overflow_checks_disabled_fixture() {
    let project = ProjectBuilder::new()
        .source(
            "src/lib.rs",
            include_str!("fixtures/vulnerable/overflow_checks/lib.rs"),
        )
        .unwrap()
        .manifest(include_str!(
            "fixtures/vulnerable/overflow_checks/Cargo.toml"
        ))
        .unwrap()
        .build();
    let report = analyze(&project, &AnalysisConfig::default());
    assert_eq!(
        fired_rules(&report),
        BTreeSet::from(["SSDK014".to_string()]),
        "findings: {:#?}",
        report.findings
    );
}

#[test]
fn precision_and_recall_benchmark() {
    // Aggregate the corpus into precision and recall figures so a regression is
    // visible as a number rather than only as a failing assertion. Precision is
    // measured against each fixture's declared rule set; recall against the
    // catalogue, since every rule must be exercised by at least one fixture so a
    // rule cannot silently stop detecting. Run with `--nocapture` to see the
    // numbers, for example in CI summaries.
    //
    // Rules whose coverage lives in a dedicated test file rather than this corpus:
    // SSDK014 needs a Cargo.toml and SSDK020-022 need a compiled module.
    const COVERED_ELSEWHERE: [&str; 4] = ["SSDK014", "SSDK020", "SSDK021", "SSDK022"];

    let mut true_positives = 0usize;
    let mut false_positives = 0usize;
    for fixture in FIXTURES {
        let report = analyze_source(fixture.source);
        let expected = expected_rules(fixture);
        for rule in fired_rules(&report) {
            if expected.contains(&rule) {
                true_positives += 1;
            } else {
                false_positives += 1;
            }
        }
    }
    let precision = true_positives as f64 / (true_positives + false_positives) as f64;

    let registry = DetectorRegistry::from_inventory();
    let exercised: BTreeSet<&str> = FIXTURES
        .iter()
        .flat_map(|fixture| fixture.expected.iter().copied())
        .chain(COVERED_ELSEWHERE)
        .collect();
    let catalogued: Vec<&str> = registry
        .metas()
        .iter()
        .map(|meta| meta.id.as_str())
        .collect();
    let covered = catalogued
        .iter()
        .filter(|id| exercised.contains(*id))
        .count();
    let recall = covered as f64 / catalogued.len() as f64;

    println!(
        "corpus benchmark: precision {:.3} ({true_positives} tp, {false_positives} fp); \
         recall {:.3} ({covered}/{} rules exercised)",
        precision,
        recall,
        catalogued.len()
    );

    assert!(
        (precision - 1.0).abs() < f64::EPSILON,
        "corpus precision is {precision:.3} ({true_positives} true positives, {false_positives} false positives)"
    );
    assert!(
        (recall - 1.0).abs() < f64::EPSILON,
        "corpus recall is {recall:.3}; unexercised rules: {:?}",
        catalogued
            .iter()
            .filter(|id| !exercised.contains(*id))
            .collect::<Vec<_>>()
    );
}
