//! Cargo manifest facts.
//!
//! The manifest matters for security review because build settings decide whether
//! some vulnerabilities are exploitable at all. The important one is
//! `[profile.release] overflow-checks = true`: the official Soroban template sets
//! it, and a contract that drops it silently wraps integer arithmetic instead of
//! panicking.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{Error, Result};

/// Facts extracted from a `Cargo.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageInfo {
    /// Package name.
    pub name: Option<String>,
    /// Package version.
    pub version: Option<String>,
    /// Rust edition.
    pub edition: Option<String>,
    /// Path to the manifest.
    pub manifest_path: PathBuf,
    /// Directory containing the manifest.
    pub root: PathBuf,
    /// Whether `soroban-sdk` appears in any dependency table.
    pub depends_on_soroban_sdk: bool,
    /// `[profile.release] overflow-checks`, defaulting to Rust's `false`.
    pub release_overflow_checks: bool,
    /// `[profile.release] panic`.
    pub release_panic: Option<String>,
    /// `[profile.release] opt-level`.
    pub release_opt_level: Option<String>,
    /// Whether a `[lib] crate-type` containing `cdylib` is declared, which is what
    /// makes a crate deployable.
    pub is_cdylib: bool,
}

impl PackageInfo {
    /// Parse a manifest from text.
    pub fn parse(text: &str, manifest_path: impl Into<PathBuf>) -> Result<Self> {
        let manifest_path = manifest_path.into();
        let root = manifest_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let value: toml::Value = toml::from_str(text).map_err(|err| Error::Manifest {
            path: manifest_path.clone(),
            message: err.to_string(),
        })?;

        let package = value.get("package");
        let name = package
            .and_then(|section| section.get("name"))
            .and_then(toml::Value::as_str)
            .map(str::to_string);
        let version = package
            .and_then(|section| section.get("version"))
            .and_then(toml::Value::as_str)
            .map(str::to_string);
        let edition = package
            .and_then(|section| section.get("edition"))
            .and_then(|edition| match edition {
                toml::Value::String(text) => Some(text.clone()),
                toml::Value::Integer(number) => Some(number.to_string()),
                _ => None,
            });

        let depends_on_soroban_sdk = [
            "dependencies",
            "dev-dependencies",
            "build-dependencies",
            "workspace.dependencies",
        ]
        .iter()
        .any(|table| {
            table
                .split('.')
                .try_fold(&value, |current, key| current.get(key))
                .and_then(|section| section.as_table())
                .is_some_and(|entries| {
                    entries.keys().any(|key| {
                        key == "soroban-sdk" || key == "soroban_sdk" || key.starts_with("soroban-sdk")
                    })
                })
        });

        let release = value
            .get("profile")
            .and_then(|profile| profile.get("release"));
        // Rust disables overflow checks in release builds unless told otherwise.
        let release_overflow_checks = release
            .and_then(|section| section.get("overflow-checks"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        let release_panic = release
            .and_then(|section| section.get("panic"))
            .and_then(toml::Value::as_str)
            .map(str::to_string);
        let release_opt_level = release
            .and_then(|section| section.get("opt-level"))
            .and_then(|level| match level {
                toml::Value::String(text) => Some(text.clone()),
                toml::Value::Integer(number) => Some(number.to_string()),
                _ => None,
            });

        let is_cdylib = value
            .get("lib")
            .and_then(|lib| lib.get("crate-type"))
            .and_then(toml::Value::as_array)
            .is_some_and(|types| {
                types
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .any(|kind| kind == "cdylib")
            });

        Ok(PackageInfo {
            name,
            version,
            edition,
            manifest_path,
            root,
            depends_on_soroban_sdk,
            release_overflow_checks,
            release_panic,
            release_opt_level,
            is_cdylib,
        })
    }

    /// Load and parse a manifest from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(Error::io(path))?;
        PackageInfo::parse(&text, path)
    }

    /// Whether the crate looks like a Soroban contract that is built for deploy.
    pub fn is_contract_crate(&self) -> bool {
        self.depends_on_soroban_sdk
    }

    /// Display name of the package.
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or("<unnamed>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_official_contract_template() {
        let info = PackageInfo::parse(
            r#"
[package]
name = "hello-world"
version = "0.0.1"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
soroban-sdk = "27.0.6"

[profile.release]
opt-level = "z"
overflow-checks = true
lto = true
panic = "abort"
codegen-units = 1
"#,
            "contracts/hello/Cargo.toml",
        )
        .unwrap();
        assert_eq!(info.name.as_deref(), Some("hello-world"));
        assert_eq!(info.edition.as_deref(), Some("2021"));
        assert!(info.is_contract_crate());
        assert!(info.release_overflow_checks);
        assert_eq!(info.release_panic.as_deref(), Some("abort"));
        assert_eq!(info.release_opt_level.as_deref(), Some("z"));
        assert!(info.is_cdylib);
        assert_eq!(info.root, PathBuf::from("contracts/hello"));
    }

    #[test]
    fn missing_overflow_checks_defaults_to_false() {
        let info = PackageInfo::parse(
            "[package]\nname = \"x\"\n\n[dependencies]\nsoroban-sdk = \"27\"\n",
            "Cargo.toml",
        )
        .unwrap();
        assert!(!info.release_overflow_checks);
        assert!(info.is_contract_crate());
        assert!(!info.is_cdylib);
        assert_eq!(info.release_panic, None);
    }

    #[test]
    fn detects_workspace_dependency_inheritance() {
        let info = PackageInfo::parse(
            "[package]\nname = \"x\"\n\n[dependencies]\nsoroban-sdk = { workspace = true }\n",
            "Cargo.toml",
        )
        .unwrap();
        assert!(info.is_contract_crate());
    }

    #[test]
    fn non_contract_crates_are_not_contract_crates() {
        let info = PackageInfo::parse(
            "[package]\nname = \"tool\"\n\n[dependencies]\nclap = \"4\"\n",
            "Cargo.toml",
        )
        .unwrap();
        assert!(!info.is_contract_crate());
        assert_eq!(info.display_name(), "tool");
    }

    #[test]
    fn reports_manifest_syntax_errors() {
        let error = PackageInfo::parse("this is not toml = = ", "Cargo.toml").unwrap_err();
        assert!(matches!(error, Error::Manifest { .. }));
    }

    #[test]
    fn edition_may_be_a_number() {
        let info = PackageInfo::parse("[package]\nname = \"x\"\nedition = 2024\n", "Cargo.toml").unwrap();
        assert_eq!(info.edition.as_deref(), Some("2024"));
    }
}
