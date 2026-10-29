//! Repositories with several independent contracts are analysed package by
//! package, so facts about one contract never leak into another.

use std::fs;
use std::path::{Path, PathBuf};

use soroban_security_sdk::prelude::*;

/// A scratch directory removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "soroban-sec-workspace-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn write(&self, path: &str, text: &str) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const CONTRACT_MANIFEST: &str = "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\n\n[lib]\ncrate-type = [\"cdylib\"]\n\n[dependencies]\nsoroban-sdk = \"23\"\n";

fn contract_manifest(name: &str) -> String {
    CONTRACT_MANIFEST.replace("{name}", name)
}

fn workspace() -> Scratch {
    let scratch =
        Scratch::new(&format!("{:?}", std::thread::current().id()).replace(['(', ')'], ""));
    scratch.write(
        "Cargo.toml",
        "[workspace]\nmembers = [\"vault\", \"counter\", \"cli\"]\n\n[profile.release]\noverflow-checks = true\n",
    );
    // Two unrelated contracts that both call their key `DataKey::Balance`, one in
    // persistent storage and one in instance storage.
    scratch.write("vault/Cargo.toml", &contract_manifest("vault"));
    scratch.write(
        "vault/src/lib.rs",
        r#"
#[contractimpl]
impl Vault {
    pub fn deposit(env: Env, from: Address, amount: i128) {
        from.require_auth();
        env.storage().persistent().set(&DataKey::Balance, &amount);
        env.storage().persistent().extend_ttl(&DataKey::Balance, 100, 1000);
    }
}
"#,
    );
    scratch.write("counter/Cargo.toml", &contract_manifest("counter"));
    scratch.write(
        "counter/src/lib.rs",
        r#"
#[contractimpl]
impl Counter {
    pub fn bump(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().instance().set(&DataKey::Balance, &1u32);
    }
}
"#,
    );
    // A command-line helper with no Soroban dependency.
    scratch.write(
        "cli/Cargo.toml",
        "[package]\nname = \"cli\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde_json = \"1\"\n",
    );
    scratch.write(
        "cli/src/main.rs",
        "fn main() { let v: Vec<u8> = Vec::new(); let _ = v[0]; }\n",
    );
    // A `cargo fuzz` harness: never deployed, and it has no release profile.
    scratch.write(
        "vault/fuzz/Cargo.toml",
        "[package]\nname = \"vault-fuzz\"\nversion = \"0.0.0\"\n\n[workspace]\n\n[dependencies]\nsoroban-sdk = \"23\"\n",
    );
    scratch.write(
        "vault/fuzz/fuzz_targets/deposit.rs",
        "#[contractimpl]\nimpl Harness { pub fn run(env: Env) { env.storage().instance().set(&K, &1); } }\n",
    );
    scratch
}

#[test]
#[cfg(feature = "detectors")]
fn packages_are_analysed_separately() {
    let scratch = workspace();
    let workspace = Project::from_workspace(scratch.path()).unwrap();
    assert_eq!(
        workspace.projects.len(),
        2,
        "the CLI crate and the fuzz harness are skipped"
    );
    let notes: Vec<&str> = workspace
        .diagnostics
        .iter()
        .map(|d| d.message.as_str())
        .collect();
    assert!(notes.iter().any(|note| note.contains("cli")), "{notes:?}");
    assert!(
        notes.iter().any(|note| note.contains("vault/fuzz")),
        "{notes:?}"
    );

    let report = analyze_workspace(scratch.path(), &AnalysisConfig::default()).unwrap();
    let rules: Vec<&str> = report.findings.iter().map(|f| f.rule.as_str()).collect();
    // Merged into one model, the shared key name would read as tier confusion.
    assert!(
        !rules.contains(&"SSDK002"),
        "unexpected findings: {rules:?}"
    );
    assert_eq!(report.budget.entrypoints.len(), 2);

    let merged = analyze(
        &Project::from_dir(scratch.path()).unwrap(),
        &AnalysisConfig::default(),
    );
    assert!(
        merged.findings.iter().any(|f| f.rule.as_str() == "SSDK002"),
        "the single-model mode still merges everything, which is what this test guards against"
    );
}

#[test]
#[cfg(feature = "detectors")]
fn members_use_the_workspace_release_profile() {
    let scratch = workspace();
    let workspace = Project::from_workspace(scratch.path()).unwrap();
    for project in &workspace.projects {
        let package = project.package().unwrap();
        assert!(
            package.release_overflow_checks,
            "{} should inherit overflow-checks from the workspace root",
            package.display_name()
        );
    }
    let report = analyze_workspace(scratch.path(), &AnalysisConfig::default()).unwrap();
    assert!(!report.findings.iter().any(|f| f.rule.as_str() == "SSDK014"));
}

#[test]
fn report_paths_stay_relative_to_the_scanned_root() {
    let scratch = workspace();
    let workspace = Project::from_workspace(scratch.path()).unwrap();
    let mut paths: Vec<&str> = workspace
        .projects
        .iter()
        .flat_map(|project| project.sources().iter().map(|file| file.display_path()))
        .collect();
    paths.sort();
    assert_eq!(paths, ["counter/src/lib.rs", "vault/src/lib.rs"]);
}

#[test]
fn a_tree_without_manifests_falls_back_to_a_single_project() {
    let scratch = Scratch::new("loose");
    scratch.write(
        "lib.rs",
        "#[contractimpl]\nimpl A { pub fn f(env: Env) {} }\n",
    );
    let workspace = Project::from_workspace(scratch.path()).unwrap();
    assert_eq!(workspace.projects.len(), 1);
}
