//! Integration tests for the built-in detector catalogue.
//!
//! Each test drives the public API exactly as a user would: build a [`Project`],
//! call [`analyze`], then ask the report whether a given rule fired. Positive and
//! negative cases live together so the contract of each rule is explicit.
#![cfg(feature = "detectors")]

use soroban_security_sdk::prelude::*;

fn project(source: &str) -> Project {
    ProjectBuilder::new()
        .source("src/lib.rs", source)
        .unwrap()
        .build()
}

fn analyze_source(source: &str) -> AnalysisReport {
    analyze(&project(source), &AnalysisConfig::default())
}

fn fired(report: &AnalysisReport, rule: &str) -> bool {
    let id = RuleId::parse(rule).unwrap();
    report.findings_for(&id).next().is_some()
}

#[test]
fn catalogue_registers_every_builtin_rule() {
    let registry = DetectorRegistry::from_inventory();
    for id in [
        "SSDK001", "SSDK002", "SSDK003", "SSDK004", "SSDK005", "SSDK006", "SSDK007", "SSDK008",
        "SSDK009", "SSDK010", "SSDK011", "SSDK012", "SSDK013", "SSDK014",
    ] {
        let rule = RuleId::parse(id).unwrap();
        assert!(
            registry.meta(&rule).is_some(),
            "rule {id} should be registered"
        );
    }
    assert!(registry.duplicates().is_empty(), "no rule ids should collide");
}

#[test]
fn sdk001_missing_require_auth() {
    let report = analyze_source(
        r#"
#[contractimpl]
impl Token {
    pub fn set_fee(env: Env, fee: i128) {
        env.storage().instance().set(&DataKey::Fee, &fee);
    }
}
"#,
    );
    assert!(fired(&report, "SSDK001"));
}

#[test]
fn sdk001_does_not_fire_when_authorized_or_read_only() {
    let report = analyze_source(
        r#"
#[contractimpl]
impl Token {
    pub fn set_fee(env: Env, admin: Address, fee: i128) {
        admin.require_auth();
        env.storage().instance().set(&DataKey::Fee, &fee);
    }

    pub fn fee(env: Env) -> i128 {
        env.storage().instance().get(&DataKey::Fee).unwrap_or(0)
    }
}
"#,
    );
    assert!(!fired(&report, "SSDK001"));
}

#[test]
fn sdk002_storage_tier_confusion() {
    let report = analyze_source(
        r#"
#[contractimpl]
impl Token {
    pub fn f(env: Env) {
        env.storage().persistent().set(&K, &1);
        let _ = env.storage().instance().get(&K);
    }
}
"#,
    );
    assert!(fired(&report, "SSDK002"));
}

#[test]
fn sdk003_unchecked_token_arithmetic() {
    let report = analyze_source(
        r#"
#[contractimpl]
impl Token {
    pub fn add(env: Env, amount: i128) {
        let total: i128 = env.storage().instance().get(&Total).unwrap_or(0);
        let next = total + amount;
        env.storage().instance().set(&Total, &next);
    }
}
"#,
    );
    assert!(fired(&report, "SSDK003"));
}

#[test]
fn sdk003_is_quiet_when_overflow_checks_are_on() {
    let project = ProjectBuilder::new()
        .source(
            "src/lib.rs",
            r#"
#[contractimpl]
impl Token {
    pub fn add(env: Env, amount: i128) {
        let total: i128 = env.storage().instance().get(&Total).unwrap_or(0);
        let next = total + amount;
        env.storage().instance().set(&Total, &next);
    }
}
"#,
        )
        .unwrap()
        .manifest(
            "[package]\nname = \"token\"\n\n[dependencies]\nsoroban-sdk = \"27\"\n\n[profile.release]\noverflow-checks = true\n",
        )
        .unwrap()
        .build();
    let report = analyze(&project, &AnalysisConfig::default());
    assert!(!fired(&report, "SSDK003"));
    assert!(!fired(&report, "SSDK014"));
}

#[test]
fn sdk004_lossy_cast() {
    let report = analyze_source(
        r#"
#[contractimpl]
impl Token {
    pub fn narrow(env: Env, amount: i128) -> u32 {
        amount as u32
    }
}
"#,
    );
    assert!(fired(&report, "SSDK004"));
}

#[test]
fn sdk005_wrapping_arithmetic() {
    let report = analyze_source(
        r#"
#[contractimpl]
impl Token {
    pub fn wrap(env: Env, amount: i128) -> i128 {
        amount.wrapping_mul(3)
    }
}
"#,
    );
    assert!(fired(&report, "SSDK005"));
}

#[test]
fn sdk006_unbounded_loop_over_storage() {
    let report = analyze_source(
        r#"
#[contractimpl]
impl Token {
    pub fn sweep(env: Env, holders: Vec<Address>) {
        for holder in holders.iter() {
            env.storage().persistent().set(holder, &1);
        }
    }
}
"#,
    );
    assert!(fired(&report, "SSDK006"));
}

#[test]
fn sdk007_read_budget_ceiling() {
    let report = analyze_source(
        r#"
#[contractimpl]
impl Token {
    pub fn spam(env: Env) {
        for i in 0..500 {
            env.storage().persistent().get(&i);
        }
    }
}
"#,
    );
    assert!(fired(&report, "SSDK007"));
}

#[test]
fn sdk008_temporary_storage_write() {
    let report = analyze_source(
        r#"
#[contractimpl]
impl Token {
    pub fn cache(env: Env, admin: Address) {
        env.storage().temporary().set(&DataKey::Admin, &admin);
    }
}
"#,
    );
    assert!(fired(&report, "SSDK008"));
}

#[test]
fn sdk009_missing_ttl_extension() {
    let report = analyze_source(
        r#"
#[contractimpl]
impl Token {
    pub fn store(env: Env) {
        env.storage().persistent().set(&K, &1);
    }
}
"#,
    );
    assert!(fired(&report, "SSDK009"));
}

#[test]
fn sdk010_check_auth_without_verification() {
    let report = analyze_source(
        r#"
#[contractimpl]
impl Account {
    pub fn __check_auth(env: Env, signature: BytesN<64>) {}
}
"#,
    );
    assert!(fired(&report, "SSDK010"));
}

#[test]
fn sdk011_predictable_randomness() {
    let report = analyze_source(
        r#"
#[contractimpl]
impl Lottery {
    pub fn draw(env: Env) -> u64 {
        env.ledger().timestamp() % 10
    }
}
"#,
    );
    assert!(fired(&report, "SSDK011"));
}

#[test]
fn sdk012_unauthorized_upgrade() {
    let report = analyze_source(
        r#"
#[contractimpl]
impl Vault {
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}
"#,
    );
    assert!(fired(&report, "SSDK012"));
}

#[test]
fn sdk013_panic_on_caller_input() {
    let report = analyze_source(
        r#"
#[contractimpl]
impl Token {
    pub fn get(env: Env) -> i128 {
        env.storage().persistent().get(&K).unwrap()
    }
}
"#,
    );
    assert!(fired(&report, "SSDK013"));
}

#[test]
fn sdk014_overflow_checks_disabled() {
    let project = ProjectBuilder::new()
        .source(
            "src/lib.rs",
            "#[contractimpl]\nimpl Token { pub fn f(env: Env) {} }\n",
        )
        .unwrap()
        .manifest("[package]\nname = \"token\"\n\n[dependencies]\nsoroban-sdk = \"27\"\n")
        .unwrap()
        .build();
    let report = analyze(&project, &AnalysisConfig::default());
    assert!(fired(&report, "SSDK014"));
}

#[test]
fn a_careful_contract_produces_no_findings() {
    let report = analyze_source(
        r#"
#[contractimpl]
impl Token {
    pub fn transfer(env: Env, from: Address, amount: i128) {
        from.require_auth();
        let balance: i128 = env.storage().persistent().get(&DataKey::Balance).unwrap_or(0);
        let next = balance.checked_sub(amount).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Balance, &next);
        env.storage().persistent().extend_ttl(&DataKey::Balance, 100, 1000);
    }
}
"#,
    );
    assert!(report.is_empty(), "unexpected findings: {:#?}", report.findings);
    assert_eq!(report.summary(), "no findings");
}

#[test]
fn from_dir_discovers_sources_and_manifest() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"demo\"\n\n[dependencies]\nsoroban-sdk = \"27\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("src/lib.rs"),
        "#[contractimpl]\nimpl Token {\n    pub fn exposed(env: Env) {\n        env.storage().instance().set(&K, &1);\n    }\n}\n",
    )
    .unwrap();

    let project = Project::from_dir(dir.path()).unwrap();
    assert_eq!(project.sources().len(), 1);
    assert_eq!(project.sources().display_paths(), vec!["src/lib.rs"]);
    assert!(project.package().is_some());
    assert!(project.has_contracts());

    let report = analyze(&project, &AnalysisConfig::default());
    assert!(fired(&report, "SSDK001"));
}
