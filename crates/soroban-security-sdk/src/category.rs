//! Finding categories.
//!
//! Categories group detectors for reporting, filtering (`--category auth`) and for
//! keeping the detector catalogue navigable as it grows.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The vulnerability class a detector belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Category {
    /// Missing or misplaced `require_auth` checks.
    Auth,
    /// Authorization logic in custom accounts (`__check_auth`) and admin gating.
    AccessControl,
    /// Storage-tier selection, ledger key layout and entry growth.
    Storage,
    /// Integer arithmetic and casts.
    Arithmetic,
    /// Instruction, memory, read-entry and write-entry budgets.
    ResourceBudget,
    /// Code paths that panic the host and can brick a call.
    PanicSafety,
    /// Predictable values used as randomness.
    Randomness,
    /// Contract upgrade and deployment flows.
    Upgradeability,
    /// Token balances, allowances and value movement.
    TokenFlow,
    /// Hardening and convention advice.
    BestPractice,
}

impl Category {
    /// Every category, in catalogue order.
    pub const ALL: [Category; 10] = [
        Category::Auth,
        Category::AccessControl,
        Category::Storage,
        Category::Arithmetic,
        Category::ResourceBudget,
        Category::PanicSafety,
        Category::Randomness,
        Category::Upgradeability,
        Category::TokenFlow,
        Category::BestPractice,
    ];

    /// Stable kebab-case identifier used in configuration files and reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Category::Auth => "auth",
            Category::AccessControl => "access-control",
            Category::Storage => "storage",
            Category::Arithmetic => "arithmetic",
            Category::ResourceBudget => "resource-budget",
            Category::PanicSafety => "panic-safety",
            Category::Randomness => "randomness",
            Category::Upgradeability => "upgradeability",
            Category::TokenFlow => "token-flow",
            Category::BestPractice => "best-practice",
        }
    }

    /// One-line human description.
    pub const fn description(self) -> &'static str {
        match self {
            Category::Auth => "Missing, misplaced or unbound authorization checks",
            Category::AccessControl => "Custom-account authorization and admin gating",
            Category::Storage => "Ledger entry layout, storage tiers and entry growth",
            Category::Arithmetic => "Integer overflow, truncation and division safety",
            Category::ResourceBudget => "Instruction, memory and ledger-access budgets",
            Category::PanicSafety => "Panicking paths that abort a contract call",
            Category::Randomness => "Predictable ledger values used as entropy",
            Category::Upgradeability => "Contract code upgrades and deployments",
            Category::TokenFlow => "Moving value: balances, allowances and transfers",
            Category::BestPractice => "Hardening and convention advice",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Category {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
        match normalized.as_str() {
            "auth" | "authorization" => Ok(Category::Auth),
            "access-control" | "access" | "accounts" => Ok(Category::AccessControl),
            "storage" | "ledger" | "state" => Ok(Category::Storage),
            "arithmetic" | "math" => Ok(Category::Arithmetic),
            "resource-budget" | "resources" | "budget" | "limits" => Ok(Category::ResourceBudget),
            "panic-safety" | "panic" | "dos" | "availability" => Ok(Category::PanicSafety),
            "randomness" | "entropy" => Ok(Category::Randomness),
            "upgradeability" | "upgrade" | "deployment" => Ok(Category::Upgradeability),
            "token-flow" | "token" | "tokens" | "defi" => Ok(Category::TokenFlow),
            "best-practice" | "best-practices" | "hardening" | "convention" => {
                Ok(Category::BestPractice)
            }
            other => Err(format!("unknown category `{other}`")),
        }
    }
}

impl Serialize for Category {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Category {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_round_trip() {
        for category in Category::ALL {
            assert_eq!(category.as_str().parse::<Category>().unwrap(), category);
        }
    }

    #[test]
    fn category_aliases() {
        assert_eq!("AUTH".parse::<Category>().unwrap(), Category::Auth);
        assert_eq!(
            "resource_budget".parse::<Category>().unwrap(),
            Category::ResourceBudget
        );
        assert!("banana".parse::<Category>().is_err());
    }
}
