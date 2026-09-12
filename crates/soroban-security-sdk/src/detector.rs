//! The detector trait.
//!
//! A detector is a type that declares its rule metadata as an associated constant
//! and implements one method. Registration is handled by
//! [`crate::declare_detector!`], so adding a rule is one file plus one line.
//!
//! ```ignore
//! use soroban_security_sdk::prelude::*;
//! use soroban_security_sdk::declare_detector;
//!
//! pub struct UnboundedLoop;
//!
//! impl Detector for UnboundedLoop {
//!     const META: DetectorMeta = DetectorMeta::new(
//!         RuleId::new("SSDK901"),
//!         "unbounded-loop-over-storage",
//!         "Loop with an unknown bound performs storage work on every iteration.",
//!     )
//!     .severity(Severity::High)
//!     .confidence(Confidence::Medium)
//!     .category(Category::ResourceBudget);
//!
//!     fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
//!         for loop_site in ctx.model().loops.iter().filter(|item| item.is_risky()) {
//!             sink.report("loop bound is not statically known")
//!                 .primary(loop_site.site.file, loop_site.site.span)
//!                 .in_function(loop_site.site.function.clone())
//!                 .emit();
//!         }
//!     }
//! }
//!
//! declare_detector!(UnboundedLoop);
//! ```
//!
//! ## Rules for detector authors
//!
//! 1. **Never report without evidence.** If the pattern needs a type you could not
//!    resolve, skip it or lower [`Confidence`](crate::severity::Confidence); do not guess.
//! 2. **Point at something actionable.** Use the span of the expression that must
//!    change, not the whole function.
//! 3. **Use `ctx.model()` before re-walking the syntax tree.** Storage operations,
//!    auth checks, loops and calls are already classified.
//! 4. **Stay out of test code.** The model already excludes `#[cfg(test)]` items
//!    unless the user asks otherwise.
//! 5. **Ship tests.** Unit tests using [`AnalysisContext`] plus a fixture under
//!    `tests/fixtures` are the review checklist for a new rule.

use crate::context::AnalysisContext;
use crate::finding::FindingSink;
use crate::rule::DetectorMeta;

/// A static analysis rule.
///
/// Implementations must be cheap to construct: the registry constructs one instance
/// per analysis run.
pub trait Detector: Send + Sync + 'static {
    /// Metadata describing the rule. Rule ids are validated at compile time.
    const META: DetectorMeta;

    /// Inspect the project and report findings.
    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>);
}

/// Object-safe projection of [`Detector`].
///
/// [`Detector`] declares its metadata as `const META`, which is what lets a rule's
/// severity and description be a compile-time constant, but an associated constant
/// also makes the trait unusable as a trait object. The registry therefore stores
/// detectors behind this companion trait, which is implemented automatically for
/// every `Detector`:
///
/// ```
/// use soroban_security_sdk::{AnalysisContext, Detector, DynDetector, FindingSink};
///
/// fn as_object<D: Detector>(detector: D) -> Box<dyn DynDetector> {
///     Box::new(detector)
/// }
/// # fn _unused(_: &AnalysisContext<'_>, _: &mut FindingSink<'_>) {}
/// ```
///
/// Detector authors never implement this trait directly and do not need to import
/// it: `declare_detector!` and the registry handle the erasure.
pub trait DynDetector: Send + Sync + 'static {
    /// Metadata of the detector, copied out of its `Detector::META`.
    fn meta(&self) -> DetectorMeta;

    /// Inspect the project and report findings.
    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>);
}

impl<D: Detector> DynDetector for D {
    fn meta(&self) -> DetectorMeta {
        D::META.clone()
    }

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        Detector::detect(self, ctx, sink);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::BudgetReport;
    use crate::category::Category;
    use crate::config::AnalysisConfig;
    use crate::model::ContractModel;
    use crate::rule::RuleId;
    use crate::severity::{Confidence, Severity};
    use crate::source::SourceMap;

    struct Noop;

    impl Detector for Noop {
        const META: DetectorMeta =
            DetectorMeta::new(RuleId::new("SSDK950"), "noop", "does nothing")
                .severity(Severity::Info)
                .confidence(Confidence::Certain)
                .category(Category::BestPractice);

        fn detect<'a>(&self, _ctx: &AnalysisContext<'a>, _sink: &mut FindingSink<'a>) {}
    }

    #[test]
    fn meta_is_available_without_construction() {
        assert_eq!(Noop::META.id.as_str(), "SSDK950");
        assert_eq!(Noop::META.name, "noop");
        // The object-safe projection reads the same metadata.
        assert_eq!(DynDetector::meta(&Noop).name, "noop");
    }

    #[test]
    fn detectors_can_run_against_an_empty_project() {
        let sources = SourceMap::default();
        let model = ContractModel::default();
        let budget = BudgetReport::estimate(
            &model,
            None,
            crate::config::NetworkLimits::mainnet(),
            crate::config::CostModel::conservative(),
        );
        let config = AnalysisConfig::default();
        let ctx = AnalysisContext::new(&sources, &model, None, &budget, &config, None);
        let mut sink = FindingSink::new(Noop::META, &sources);
        Detector::detect(&Noop, &ctx, &mut sink);
        assert!(sink.is_empty());
    }
}
