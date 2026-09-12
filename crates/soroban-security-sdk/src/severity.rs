//! Severity and confidence levels.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// How damaging a finding is if a real attacker exploits it.
///
/// The ordering is meaningful (`Info < Low < Medium < High < Critical`), which lets
/// callers use `>=` for thresholds such as "fail the build on High or above".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Style, documentation or hardening advice. Not exploitable on its own.
    Info,
    /// Defensive-programming gap that is only reachable under unusual conditions.
    Low,
    /// Real weakness that usually requires specific conditions or a cooperating caller.
    Medium,
    /// Exploitable weakness with material impact (funds, authorization, availability).
    High,
    /// Direct loss of funds or total authorization bypass; never ship.
    Critical,
}

impl Severity {
    /// All variants from least to most severe.
    pub const ALL: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    /// Stable lowercase identifier used in configuration files and reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// The SARIF 2.1.0 `reportingConfiguration.level` closest to this severity.
    pub const fn sarif_level(self) -> &'static str {
        match self {
            Severity::Info | Severity::Low => "note",
            Severity::Medium => "warning",
            Severity::High | Severity::Critical => "error",
        }
    }

    /// Short uppercase label for terminal output.
    pub const fn badge(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MED",
            Severity::High => "HIGH",
            Severity::Critical => "CRIT",
        }
    }

    /// ANSI colour escape for terminal output (no-op friendly: callers check `color`).
    pub const fn ansi_color(self) -> &'static str {
        match self {
            Severity::Info => "\u{1b}[36m",
            Severity::Low => "\u{1b}[32m",
            Severity::Medium => "\u{1b}[33m",
            Severity::High => "\u{1b}[31m",
            Severity::Critical => "\u{1b}[1;31m",
        }
    }

    /// How many report entries this severity maps to. Used for summary tables.
    pub const fn sarif_rank(self) -> i64 {
        (self as i64) * 10
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "info" | "informational" | "note" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" | "moderate" | "warning" => Ok(Severity::Medium),
            "high" | "error" => Ok(Severity::High),
            "critical" | "crit" => Ok(Severity::Critical),
            other => Err(format!("unknown severity `{other}`")),
        }
    }
}

impl Serialize for Severity {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Severity {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

/// How sure the detector is that the reported pattern is a real problem.
///
/// A detector should lower its confidence rather than its severity when it relies
/// on a heuristic: severity answers "how bad if true", confidence answers
/// "how likely is this true".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// Heuristic match; likely to include false positives.
    Low,
    /// Pattern match with partial type or data-flow evidence.
    Medium,
    /// Pattern is unambiguous given the source, though runtime behaviour may differ.
    High,
    /// Provable from the source alone (e.g. a token that is literally absent).
    Certain,
}

impl Confidence {
    /// All variants from least to most certain.
    pub const ALL: [Confidence; 4] = [
        Confidence::Low,
        Confidence::Medium,
        Confidence::High,
        Confidence::Certain,
    ];

    /// Stable lowercase identifier used in reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
            Confidence::Certain => "certain",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Confidence {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "low" => Ok(Confidence::Low),
            "medium" | "moderate" => Ok(Confidence::Medium),
            "high" => Ok(Confidence::High),
            "certain" | "definite" => Ok(Confidence::Certain),
            other => Err(format!("unknown confidence `{other}`")),
        }
    }
}

impl Serialize for Confidence {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Confidence {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_from_info_to_critical() {
        let mut values = Severity::ALL;
        values.reverse();
        for pair in values.windows(2) {
            assert!(pair[0] > pair[1], "{:?} should outrank {:?}", pair[0], pair[1]);
        }
    }

    #[test]
    fn severity_round_trips_through_string() {
        for severity in Severity::ALL {
            assert_eq!(severity.as_str().parse::<Severity>().unwrap(), severity);
        }
        for confidence in Confidence::ALL {
            assert_eq!(confidence.as_str().parse::<Confidence>().unwrap(), confidence);
        }
    }

    #[test]
    fn severity_accepts_common_aliases() {
        assert_eq!("CRIT".parse::<Severity>().unwrap(), Severity::Critical);
        assert_eq!("warning".parse::<Severity>().unwrap(), Severity::Medium);
        assert!("nope".parse::<Severity>().is_err());
    }

    #[test]
    fn sarif_levels_follow_spec() {
        assert_eq!(Severity::Critical.sarif_level(), "error");
        assert_eq!(Severity::Medium.sarif_level(), "warning");
        assert_eq!(Severity::Low.sarif_level(), "note");
    }
}
