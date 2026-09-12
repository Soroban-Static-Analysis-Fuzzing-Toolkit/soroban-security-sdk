//! Analysis configuration.
//!
//! Everything a user can tune lives in [`AnalysisConfig`], which is
//! deserializable from a `.soroban-sec.toml` file so CI and local runs agree.
//!
//! ```toml
//! include_tests = false
//!
//! [rules]
//! enabled = ["SSDK001", "SSDK003"]
//! disabled = ["SSDK010"]
//! categories = ["auth", "storage"]
//!
//! [rules.severity]
//! SSDK003 = "high"
//!
//! [limits]
//! max_read_entries = 200
//!
//! [estimator]
//! assumed_loop_iterations = 100
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::category::Category;
use crate::error::{Error, Result};
use crate::rule::{DetectorMeta, RuleId};
use crate::severity::Severity;

/// Baseline fingerprints of findings that are known and accepted.
pub type Baseline = Vec<String>;

/// Which rules run, and at what severity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuleConfig {
    /// When non-empty, only these rules run.
    pub enabled: Vec<RuleId>,
    /// Rules to skip, applied after `enabled`.
    pub disabled: Vec<RuleId>,
    /// When non-empty, only rules in these categories run.
    pub categories: Vec<Category>,
    /// Severity overrides applied at report time.
    pub severity: BTreeMap<RuleId, Severity>,
}

impl RuleConfig {
    /// Whether a rule should run under this configuration.
    pub fn is_enabled(&self, meta: &DetectorMeta) -> bool {
        if self.disabled.contains(&meta.id) {
            return false;
        }
        if !self.categories.is_empty() && !self.categories.contains(&meta.category) {
            return false;
        }
        if self.enabled.is_empty() {
            meta.default_enabled
        } else {
            self.enabled.contains(&meta.id)
        }
    }

    /// Whether a rule is enabled *and* forced on despite being opt-in.
    pub fn is_forced(&self, meta: &DetectorMeta) -> bool {
        self.enabled.contains(&meta.id)
    }

    /// Effective severity for a rule, honouring overrides.
    pub fn severity_for(&self, meta: &DetectorMeta) -> Severity {
        self.severity
            .get(&meta.id)
            .copied()
            .unwrap_or(meta.severity)
    }
}

/// Resource ceilings a contract call must fit inside.
///
/// The defaults match Stellar mainnet settings observed in the Protocol 27 era.
/// Validators can and do change these, so confirm with
/// `stellar network settings --network mainnet` before treating a budget finding
/// as a hard failure, or override the values here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkLimits {
    /// Maximum CPU instructions per transaction.
    pub max_instructions_per_tx: u64,
    /// Maximum contract memory per transaction, in bytes.
    pub max_memory_bytes: u64,
    /// Maximum ledger entries read per transaction.
    pub max_read_entries: u32,
    /// Maximum ledger entries written per transaction.
    pub max_write_entries: u32,
    /// Maximum bytes read from the ledger per transaction.
    pub max_read_bytes: u32,
    /// Maximum bytes written to the ledger per transaction.
    pub max_write_bytes: u32,
    /// Maximum size of a single ledger entry, in bytes.
    pub max_entry_size_bytes: u32,
    /// Maximum size of a serialized ledger key, in bytes.
    pub max_ledger_key_bytes: u32,
    /// Maximum size of the events a contract call may emit, in bytes.
    pub max_event_bytes: u32,
}

impl NetworkLimits {
    /// Mainnet-era defaults. See the type documentation for caveats.
    pub const fn mainnet() -> Self {
        NetworkLimits {
            max_instructions_per_tx: 100_000_000,
            max_memory_bytes: 40 * 1024 * 1024,
            max_read_entries: 200,
            max_write_entries: 200,
            max_read_bytes: 200_000,
            max_write_bytes: 132_000,
            max_entry_size_bytes: 65_536,
            max_ledger_key_bytes: 250,
            max_event_bytes: 8_192,
        }
    }

    /// Limits effectively disabled. Useful for unit tests that are about pattern
    /// matching rather than budgets.
    pub const fn permissive() -> Self {
        NetworkLimits {
            max_instructions_per_tx: u64::MAX,
            max_memory_bytes: u64::MAX,
            max_read_entries: u32::MAX,
            max_write_entries: u32::MAX,
            max_read_bytes: u32::MAX,
            max_write_bytes: u32::MAX,
            max_entry_size_bytes: u32::MAX,
            max_ledger_key_bytes: u32::MAX,
            max_event_bytes: u32::MAX,
        }
    }
}

impl Default for NetworkLimits {
    fn default() -> Self {
        NetworkLimits::mainnet()
    }
}

/// Tuning for the static cost estimator.
///
/// The estimator is deliberately explicit about its assumptions: wasm instruction
/// counting is exact for straight-line code and calls, but loop trip counts are not
/// statically known, so they are modelled with [`CostModel::assumed_loop_iterations`]
/// and reported at reduced confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CostModel {
    /// Instructions charged per wasm operator.
    pub cost_per_instruction: u64,
    /// Extra instructions charged per function call.
    pub cost_per_call: u64,
    /// Assumed trip count for loops whose bound is not visible in the source.
    pub assumed_loop_iterations: u64,
    /// Trip count assumed for a loop whose bound comes from a literal range.
    pub literal_loop_iterations_cap: u64,
}

impl CostModel {
    /// Conservative defaults.
    pub const fn conservative() -> Self {
        CostModel {
            cost_per_instruction: 1,
            cost_per_call: 1,
            assumed_loop_iterations: 100,
            literal_loop_iterations_cap: 10_000,
        }
    }
}

impl Default for CostModel {
    fn default() -> Self {
        CostModel::conservative()
    }
}

/// Complete analysis configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnalysisConfig {
    /// Rule selection and severity overrides.
    pub rules: RuleConfig,
    /// Network resource ceilings used by budget detectors.
    pub limits: NetworkLimits,
    /// Estimator tuning.
    pub estimator: CostModel,
    /// Analyse `#[cfg(test)]` items too. Off by default: test code is allowed to
    /// panic and to use unchecked arithmetic.
    pub include_tests: bool,
    /// Keep findings that were silenced by an inline suppression comment, marking
    /// them as suppressed instead of dropping them.
    pub report_suppressed: bool,
    /// Findings whose fingerprint appears here are dropped (accepted baseline).
    pub baseline: Baseline,
    /// Path to a compiled contract, used by wasm-level detectors. Relative paths
    /// are resolved against the project root.
    pub wasm_path: Option<PathBuf>,
}

impl AnalysisConfig {
    /// Mainnet limits with default rules.
    pub fn mainnet() -> Self {
        AnalysisConfig::default()
    }

    /// Config that only runs the given rules.
    pub fn with_rules(rules: impl IntoIterator<Item = RuleId>) -> Self {
        AnalysisConfig {
            rules: RuleConfig {
                enabled: rules.into_iter().collect(),
                ..RuleConfig::default()
            },
            ..AnalysisConfig::default()
        }
    }

    /// Analysis that never reports budget problems, for tests focused on patterns.
    pub fn without_limits() -> Self {
        AnalysisConfig {
            limits: NetworkLimits::permissive(),
            ..AnalysisConfig::default()
        }
    }

    /// Parse a config from TOML text.
    pub fn from_toml_str(text: &str) -> std::result::Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// Parse a config from a TOML string, attributing errors to `path`.
    pub fn parse(text: &str, path: impl AsRef<Path>) -> Result<Self> {
        AnalysisConfig::from_toml_str(text).map_err(|err| Error::Config {
            path: path.as_ref().to_path_buf(),
            message: err.to_string(),
        })
    }

    /// Load a config file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(Error::io(path))?;
        AnalysisConfig::parse(&text, path)
    }

    /// Apply environment-provided overrides on top of this config.
    ///
    /// Recognised variables: `SOROBAN_SEC_RULES` (comma-separated allow list) and
    /// `SOROBAN_SEC_DISABLE` (comma-separated deny list).
    pub fn with_env_overrides(mut self) -> Self {
        if let Ok(value) = std::env::var("SOROBAN_SEC_RULES") {
            let ids: Vec<RuleId> = value
                .split(',')
                .filter_map(|part| RuleId::parse(part.trim()).ok())
                .collect();
            if !ids.is_empty() {
                self.rules.enabled = ids;
            }
        }
        if let Ok(value) = std::env::var("SOROBAN_SEC_DISABLE") {
            self.rules.disabled.extend(
                value
                    .split(',')
                    .filter_map(|part| RuleId::parse(part.trim()).ok()),
            );
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::severity::Confidence;

    fn meta(id: &'static str) -> DetectorMeta {
        DetectorMeta::new(RuleId::new(id), "name", "summary")
            .severity(Severity::Medium)
            .confidence(Confidence::Medium)
    }

    #[test]
    fn defaults_match_mainnet_limits() {
        let limits = NetworkLimits::default();
        assert_eq!(limits.max_read_entries, 200);
        assert_eq!(limits.max_write_entries, 200);
        assert_eq!(limits.max_instructions_per_tx, 100_000_000);
    }

    #[test]
    fn parses_full_config() {
        let config = AnalysisConfig::from_toml_str(
            r#"
include_tests = true
baseline = ["abc123"]

[rules]
enabled = ["SSDK001"]
disabled = ["SSDK010"]
categories = ["auth"]

[rules.severity]
SSDK003 = "high"

[limits]
max_read_entries = 42
"#,
        )
        .unwrap();
        assert!(config.include_tests);
        assert_eq!(config.baseline, vec!["abc123".to_string()]);
        assert_eq!(config.rules.enabled[0].as_str(), "SSDK001");
        assert_eq!(config.rules.categories, vec![Category::Auth]);
        assert_eq!(
            config.rules.severity.get(&RuleId::new("SSDK003")),
            Some(&Severity::High)
        );
        assert_eq!(config.limits.max_read_entries, 42);
        assert_eq!(config.limits.max_write_entries, 200, "untouched fields keep defaults");
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(AnalysisConfig::from_toml_str("nonsense = 1").is_err());
    }

    #[test]
    fn rejects_invalid_rule_ids_in_config() {
        assert!(AnalysisConfig::from_toml_str("[rules]\nenabled = [\"1bad\"]").is_err());
    }

    #[test]
    fn rule_selection_prefers_the_allow_list() {
        let config = AnalysisConfig::with_rules([RuleId::new("SSDK001")]);
        assert!(config.rules.is_enabled(&meta("SSDK001")));
        assert!(!config.rules.is_enabled(&meta("SSDK002")));
    }

    #[test]
    fn disabled_beats_enabled() {
        let config = AnalysisConfig {
            rules: RuleConfig {
                enabled: vec![RuleId::new("SSDK001")],
                disabled: vec![RuleId::new("SSDK001")],
                ..RuleConfig::default()
            },
            ..AnalysisConfig::default()
        };
        assert!(!config.rules.is_enabled(&meta("SSDK001")));
    }

    #[test]
    fn category_filter_applies() {
        let config = AnalysisConfig {
            rules: RuleConfig {
                categories: vec![Category::Storage],
                ..RuleConfig::default()
            },
            ..AnalysisConfig::default()
        };
        let auth_rule = DetectorMeta::new(RuleId::new("SSDK001"), "n", "s").category(Category::Auth);
        assert!(!config.rules.is_enabled(&auth_rule));
        let storage_rule =
            DetectorMeta::new(RuleId::new("SSDK002"), "n", "s").category(Category::Storage);
        assert!(config.rules.is_enabled(&storage_rule));
    }

    #[test]
    fn severity_override_is_used() {
        let mut config = AnalysisConfig::default();
        config
            .rules
            .severity
            .insert(RuleId::new("SSDK001"), Severity::Critical);
        assert_eq!(config.rules.severity_for(&meta("SSDK001")), Severity::Critical);
        assert_eq!(config.rules.severity_for(&meta("SSDK002")), Severity::Medium);
    }

    #[test]
    fn permissive_limits_disable_budget_rules() {
        let limits = NetworkLimits::permissive();
        assert_eq!(limits.max_instructions_per_tx, u64::MAX);
        assert_eq!(limits.max_read_entries, u32::MAX);
    }
}
