//! # soroban-security-sdk
//!
//! Developer-facing SDK for static analysis of Soroban smart contracts.
//!
//! The SDK provides three things:
//!
//! 1. **A detector framework.** [`Detector`] is a two-method trait, [`declare_detector!`]
//!    registers an implementation with the global [`DetectorRegistry`], and
//!    [`FindingSink`] handles the mechanics of reporting so a new rule is a single
//!    file and a one-line registration.
//! 2. **A typed model of a Soroban contract.** Source is parsed with `syn` into a
//!    [`Project`], from which the SDK derives entrypoints, storage operations,
//!    authorization checks, arithmetic sites, loops and cross-contract calls. A
//!    compiled `.wasm` module can be loaded alongside it for instruction and memory
//!    accounting.
//! 3. **A resource-budget estimator.** Per entrypoint, the SDK estimates instruction
//!    count, memory, and ledger read/write entries, and compares them with
//!    configurable network limits, so a team knows before deploy whether a call fits.
//!
//! ## Quick start
//!
//! ```no_run
//! use soroban_security_sdk::prelude::*;
//!
//! let project = Project::from_dir(".")?;
//! let report = analyze(&project, &AnalysisConfig::default());
//! for finding in &report.findings {
//!     println!("{} {}", finding.severity, finding.message);
//! }
//! # Ok::<(), soroban_security_sdk::Error>(())
//! ```
//!
//! ## Writing a detector
//!
//! ```ignore
//! use soroban_security_sdk::prelude::*;
//! use soroban_security_sdk::declare_detector;
//!
//! pub struct MissingRequireAuth;
//!
//! impl Detector for MissingRequireAuth {
//!     const META: DetectorMeta = DetectorMeta::new(
//!         RuleId::new("SSDK901"),
//!         "missing-require-auth",
//!         "State-changing entrypoint performs no authorization check.",
//!     )
//!     .severity(Severity::High)
//!     .confidence(Confidence::Medium)
//!     .category(Category::Auth);
//!
//!     fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
//!         for entrypoint in ctx.entrypoints().iter().filter(|e| e.writes_state()) {
//!             if !ctx.model().has_transitive_auth(&entrypoint.name) {
//!                 sink.report(format!("`{}` writes state without authorizing the caller", entrypoint.name))
//!                     .primary(entrypoint.file, entrypoint.span)
//!                     .in_function(&entrypoint.name)
//!                     .note("Add `caller.require_auth()` before the first state change.")
//!                     .emit();
//!             }
//!         }
//!     }
//! }
//!
//! declare_detector!(MissingRequireAuth);
//! ```
//!
//! See `docs/writing-a-detector.md` for the full walkthrough, including how to test
//! a rule against the fixture corpus.

#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![forbid(unsafe_code)]

pub mod analysis;
pub mod budget;
pub mod category;
pub mod config;
pub mod context;
pub mod detector;
#[cfg(feature = "detectors")]
pub mod detectors;
pub mod error;
pub mod finding;
pub mod fix;
pub mod macros;
pub mod manifest;
pub mod model;
pub mod prelude;
pub mod registry;
pub mod rule;
pub mod severity;
pub mod source;
pub mod span;
pub mod suppression;
pub mod syntax;
pub mod wasm;

pub use crate::analysis::{
    analyze, analyze_with, AnalysisReport, Diagnostic, DiagnosticKind, Project, ProjectBuilder,
};
pub use crate::budget::{
    BudgetAxis, BudgetEstimate, BudgetReport, BudgetViolation, EntrypointBudget,
};
pub use crate::category::Category;
pub use crate::context::AnalysisContext;
pub use crate::detector::{Detector, DynDetector};
pub use crate::manifest::PackageInfo;
pub use crate::registry::{DetectorRegistration, DetectorRegistry};
pub use crate::config::{AnalysisConfig, CostModel, NetworkLimits, RuleConfig};
pub use crate::error::{Error, Result};
pub use crate::finding::{Edit, Finding, FindingBuilder, FindingSink, Fix, Location};
pub use crate::fix::{apply_edits, FixPlan, FilePatch};
pub use crate::rule::{DetectorMeta, Reference, RuleId};
pub use crate::severity::{Confidence, Severity};
pub use crate::source::{FileId, ParseFailure, SourceFile, SourceMap};
pub use crate::model::{
    AuthCheck, AuthKind, Contract, ContractModel, ContractType, Entrypoint, LoopBound, LoopKind,
    LoopSite, PanicKind, PanicSite, Site, StorageAccess, StorageOp, StorageTier,
};
pub use crate::span::{SourceSpan, Spanned};
pub use crate::suppression::Suppression;
pub use crate::syntax::{FunctionView, Param, ParamKind};

/// Implementation details referenced by the public macros. Not a stable API.
#[doc(hidden)]
pub mod __private {
    pub use inventory;
}
