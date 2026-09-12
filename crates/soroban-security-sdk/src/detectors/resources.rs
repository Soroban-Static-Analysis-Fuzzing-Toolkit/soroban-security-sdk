//! Resource-budget detectors (`SSDK006`, `SSDK007`).

use crate::category::Category;
use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::finding::FindingSink;
use crate::rule::{DetectorMeta, Reference, RuleId};
use crate::severity::{Confidence, Severity};

/// `SSDK006`: a loop with an unknown bound that does per-iteration storage or
/// cross-contract work inside a contract entrypoint.
#[derive(Debug, Default)]
pub struct UnboundedLoopOverStorage;

impl Detector for UnboundedLoopOverStorage {
    const META: DetectorMeta = DetectorMeta::new(
        RuleId::new("SSDK006"),
        "unbounded-loop-over-storage",
        "A loop of unknown length performs ledger or cross-contract work each iteration.",
    )
    .severity(Severity::High)
    .confidence(Confidence::High)
    .category(Category::ResourceBudget)
    .description(
        "Soroban caps a transaction at 200 ledger reads and 200 writes. A loop whose \
         trip count is not statically known can exhaust that budget, aborting the \
         call after the caller has already paid for it.",
    )
    .tags(&["loop", "storage", "budget", "dos"])
    .references(&[Reference::new(
        "Stellar docs: Resource limits",
        "https://developers.stellar.org/docs/learn/encyclopedia/network-configuration/transaction-fees",
    )]);

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        for loop_site in ctx.model().loops.iter().filter(|site| site.is_risky()) {
            sink.report(format!(
                "`{}` loop ({}) performs {} storage operation(s) and {} cross-contract call(s) per iteration",
                loop_site.kind.as_str(),
                loop_site.bound.describe(),
                loop_site.storage_ops,
                loop_site.contract_calls
            ))
            .primary(loop_site.site.file, loop_site.site.span)
            .in_function(loop_site.site.function.clone())
            .note(
                "The trip count is not statically bounded, so the read and write \
                 budgets can be exhausted at runtime.",
            )
            .help("Bound the iteration count, cap the collection, or move the work off-chain.")
            .emit();
        }
    }
}

crate::declare_detector!(UnboundedLoopOverStorage);

/// `SSDK007`: an entrypoint is estimated to cross one of the network resource
/// ceilings.
#[derive(Debug, Default)]
pub struct ResourceBudgetExceeded;

impl Detector for ResourceBudgetExceeded {
    const META: DetectorMeta = DetectorMeta::new(
        RuleId::new("SSDK007"),
        "resource-budget-exceeded",
        "An entrypoint is estimated to exceed a network resource limit.",
    )
    .severity(Severity::High)
    .confidence(Confidence::Medium)
    .category(Category::ResourceBudget)
    .description(
        "Every Soroban call is metered for CPU instructions, contract memory and \
         ledger entry reads and writes. The static estimator bounds each axis from \
         the source and, when a `.wasm` module is supplied, the compiled code; a \
         call that exceeds any ceiling fails at runtime.",
    )
    .tags(&["budget", "instructions", "memory", "ledger"])
    .references(&[Reference::new(
        "Stellar docs: Resource limits",
        "https://developers.stellar.org/docs/learn/encyclopedia/network-configuration/transaction-fees",
    )]);

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        for (name, violation) in ctx.budget().violations() {
            let Some(entrypoint) = ctx.entrypoint(name) else {
                continue;
            };
            let certain = violation.certain;
            sink.report(format!(
                "`{name}` is estimated to use {} {} against a limit of {}",
                violation.estimate.describe(),
                violation.axis,
                violation.limit
            ))
            .severity(if certain {
                Severity::High
            } else {
                Severity::Medium
            })
            .confidence(if certain {
                Confidence::High
            } else {
                Confidence::Low
            })
            .primary(entrypoint.file, entrypoint.span)
            .in_function(name.to_string())
            .note(if certain {
                "The lower bound alone exceeds the limit, so the call cannot succeed."
            } else {
                "The best-effort estimate exceeds the limit; the real figure depends on \
                 loop trip counts and runtime state."
            })
            .help("Reduce the work per call, cache values, or split the operation across calls.")
            .emit();
        }
    }
}

crate::declare_detector!(ResourceBudgetExceeded);
