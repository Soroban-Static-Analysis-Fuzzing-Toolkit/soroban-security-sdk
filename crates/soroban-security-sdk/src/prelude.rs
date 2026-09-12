//! Everything a detector author needs, in one import.
//!
//! ```
//! use soroban_security_sdk::prelude::*;
//! ```
//!
//! Detector modules typically need only this prelude plus [`crate::declare_detector!`].

pub use crate::analysis::{
    analyze, analyze_with, AnalysisReport, Diagnostic, DiagnosticKind, Project, ProjectBuilder,
};
pub use crate::budget::{BudgetAxis, BudgetReport, BudgetViolation, EntrypointBudget};
pub use crate::category::Category;
pub use crate::config::{AnalysisConfig, CostModel, NetworkLimits, RuleConfig};
pub use crate::context::AnalysisContext;
pub use crate::declare_detector;
pub use crate::detector::{Detector, DynDetector};
pub use crate::finding::{Edit, Finding, FindingBuilder, FindingSink, Fix, Location};
pub use crate::model::{AuthKind, Entrypoint, LoopBound, StorageAccess, StorageOp, StorageTier};
pub use crate::registry::DetectorRegistry;
pub use crate::rule::{DetectorMeta, Reference, RuleId};
pub use crate::sarif::{to_sarif, to_sarif_string};
pub use crate::severity::{Confidence, Severity};
pub use crate::source::{FileId, ParseFailure, SourceFile, SourceMap};
pub use crate::span::{SourceSpan, Spanned};
