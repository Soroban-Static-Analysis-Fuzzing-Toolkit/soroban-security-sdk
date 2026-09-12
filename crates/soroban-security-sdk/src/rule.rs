//! Rule identity and detector metadata.
//!
//! Every detector declares a `const META: DetectorMeta` describing the rule. That
//! metadata drives reporting, `--explain`, the generated rule catalogue and user
//! severity overrides, so it is worth keeping accurate.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize};

use crate::category::Category;
use crate::severity::{Confidence, Severity};

/// Identifier of a detection rule, for example `SSDK001`.
///
/// Rule ids are stable: they appear in reports, baselines and CI thresholds, so a
/// rule keeps its id even if its implementation changes. Ids are validated on
/// construction, which means an invalid literal is a compile error inside a `const`
/// and an [`crate::Error::InvalidRuleId`] at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct RuleId(Cow<'static, str>);

impl RuleId {
    /// Build a rule id, panicking if `raw` is not a valid id.
    ///
    /// This is a `const fn`, so a typo in a detector's metadata fails the build.
    ///
    /// ```
    /// use soroban_security_sdk::RuleId;
    ///
    /// const ID: RuleId = RuleId::new("SSDK001");
    /// assert_eq!(ID.as_str(), "SSDK001");
    /// ```
    pub const fn new(raw: &'static str) -> Self {
        assert!(is_valid_rule_id(raw), "invalid rule id");
        RuleId(Cow::Borrowed(raw))
    }

    /// Validate a rule id from a runtime string.
    pub fn parse(raw: impl Into<String>) -> Result<Self, crate::Error> {
        let raw = raw.into();
        if !is_valid_rule_id(&raw) {
            return Err(crate::Error::InvalidRuleId(raw));
        }
        Ok(RuleId(Cow::Owned(raw)))
    }

    /// The id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The leading alphabetic prefix, e.g. `SSDK`.
    pub fn prefix(&self) -> &str {
        let end = self
            .0
            .find(|c: char| !c.is_ascii_alphabetic())
            .unwrap_or(self.0.len());
        &self.0[..end]
    }

    /// The trailing numeric portion, if the id ends in digits.
    pub fn number(&self) -> Option<u32> {
        let digits: String = self
            .0
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_digit())
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        digits.parse().ok()
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for RuleId {
    type Err = crate::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        RuleId::parse(value)
    }
}

impl<'de> Deserialize<'de> for RuleId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        RuleId::parse(raw).map_err(serde::de::Error::custom)
    }
}

/// Validate rule id syntax without allocating.
///
/// Accepted shape: an ASCII letter followed by ASCII alphanumerics, `-` or `_`,
/// with a maximum length of 32 characters.
const fn is_valid_rule_id(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return false;
    }
    let first = bytes[0];
    if !((first >= b'a' && first <= b'z') || (first >= b'A' && first <= b'Z')) {
        return false;
    }
    let mut i = 1;
    while i < bytes.len() {
        let b = bytes[i];
        let ok = (b >= b'a' && b <= b'z')
            || (b >= b'A' && b <= b'Z')
            || (b >= b'0' && b <= b'9')
            || b == b'-'
            || b == b'_';
        if !ok {
            return false;
        }
        i += 1;
    }
    true
}

/// A published reference backing a detector, such as a documentation page or a
/// real-world incident report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct Reference {
    /// Short human label, e.g. `Stellar docs: storage strategies`.
    pub label: &'static str,
    /// Absolute URL.
    pub url: &'static str,
}

impl Reference {
    /// Build a reference.
    pub const fn new(label: &'static str, url: &'static str) -> Self {
        Reference { label, url }
    }
}

/// Everything the SDK knows about a rule that does not depend on the analysed code.
///
/// `DetectorMeta` is built with a `const` builder so it can live in an associated
/// constant on the detector:
///
/// ```
/// use soroban_security_sdk::{Category, Confidence, DetectorMeta, Reference, RuleId, Severity};
///
/// pub const META: DetectorMeta = DetectorMeta::new(
///     RuleId::new("SSDK900"),
///     "example-rule",
///     "One sentence describing what is wrong.",
/// )
/// .severity(Severity::High)
/// .confidence(Confidence::Medium)
/// .category(Category::Auth)
/// .description("Longer markdown description.")
/// .references(&[Reference::new("Stellar docs", "https://developers.stellar.org/")])
/// .tags(&["auth"]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DetectorMeta {
    /// Stable rule id.
    pub id: RuleId,
    /// Kebab-case rule name, used in SARIF rule ids and docs anchors.
    pub name: &'static str,
    /// One-line summary of the problem.
    pub summary: &'static str,
    /// Impact if the pattern is a true positive.
    pub severity: Severity,
    /// How likely a hit is a true positive.
    pub confidence: Confidence,
    /// Vulnerability class.
    pub category: Category,
    /// Longer explanation, where a "why it matters" paragraph belongs.
    pub description: &'static str,
    /// Supporting references.
    pub references: &'static [Reference],
    /// Free-form tags for filtering and grouping.
    pub tags: &'static [&'static str],
    /// Whether the rule runs unless explicitly enabled.
    pub default_enabled: bool,
    /// Whether the detector needs a compiled `.wasm` module to do useful work.
    pub requires_wasm: bool,
}

impl DetectorMeta {
    /// Start building metadata. Severity, confidence and category default to
    /// `Info`, `Low` and `BestPractice` so a half-finished rule is never loud.
    pub const fn new(id: RuleId, name: &'static str, summary: &'static str) -> Self {
        DetectorMeta {
            id,
            name,
            summary,
            severity: Severity::Info,
            confidence: Confidence::Low,
            category: Category::BestPractice,
            description: "",
            references: &[],
            tags: &[],
            default_enabled: true,
            requires_wasm: false,
        }
    }

    /// Set the severity.
    pub const fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Set the confidence.
    pub const fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Set the category.
    pub const fn category(mut self, category: Category) -> Self {
        self.category = category;
        self
    }

    /// Set the long description.
    pub const fn description(mut self, description: &'static str) -> Self {
        self.description = description;
        self
    }

    /// Set the supporting references.
    pub const fn references(mut self, references: &'static [Reference]) -> Self {
        self.references = references;
        self
    }

    /// Set the tags.
    pub const fn tags(mut self, tags: &'static [&'static str]) -> Self {
        self.tags = tags;
        self
    }

    /// Mark the detector as opt-in.
    pub const fn disabled_by_default(mut self) -> Self {
        self.default_enabled = false;
        self
    }

    /// Mark the detector as requiring a compiled wasm module.
    pub const fn requires_wasm(mut self) -> Self {
        self.requires_wasm = true;
        self
    }

    /// True when the rule belongs to `category`.
    pub fn is_category(&self, category: Category) -> bool {
        self.category == category
    }

    /// True when any tag matches, case-insensitively.
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t.eq_ignore_ascii_case(tag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_id_accepts_canonical_ids() {
        for raw in ["SSDK001", "SSDK-001", "X", "custom_rule_2", "S1"] {
            assert!(RuleId::parse(raw).is_ok(), "{raw} should be valid");
        }
    }

    #[test]
    fn rule_id_rejects_invalid_ids() {
        for raw in ["", "1SSDK", "SSDK 001", "SSDK/e1", &"a".repeat(33)] {
            assert!(RuleId::parse(raw).is_err(), "{raw:?} should be invalid");
        }
    }

    #[test]
    fn rule_id_parts() {
        let id = RuleId::new("SSDK042");
        assert_eq!(id.prefix(), "SSDK");
        assert_eq!(id.number(), Some(42));
        assert_eq!(id.to_string(), "SSDK042");
    }

    #[test]
    fn meta_builder_defaults_are_quiet() {
        let meta = DetectorMeta::new(RuleId::new("SSDK999"), "n", "s");
        assert_eq!(meta.severity, Severity::Info);
        assert_eq!(meta.confidence, Confidence::Low);
        assert!(meta.default_enabled);
        assert!(!meta.requires_wasm);
    }

    #[test]
    fn meta_serializes_rule_id_as_plain_string() {
        let meta = DetectorMeta::new(RuleId::new("SSDK999"), "n", "s")
            .severity(Severity::High)
            .category(Category::Auth)
            .tags(&["auth"]);
        let json = serde_json::to_value(&meta).unwrap();
        assert_eq!(json["id"], "SSDK999");
        assert_eq!(json["severity"], "high");
        assert_eq!(json["category"], "auth");
    }
}
