//! Randomness, upgrade and panic-safety detectors (`SSDK011`, `SSDK012`, `SSDK013`).

use crate::category::Category;
use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::finding::FindingSink;
use crate::model::PanicKind;
use crate::rule::{DetectorMeta, Reference, RuleId};
use crate::severity::{Confidence, Severity};

/// `SSDK011`: a ledger value used as entropy.
#[derive(Debug, Default)]
pub struct PredictableRandomness;

impl Detector for PredictableRandomness {
    const META: DetectorMeta = DetectorMeta::new(
        RuleId::new("SSDK011"),
        "predictable-randomness",
        "A predictable ledger value is used as a source of randomness.",
    )
    .severity(Severity::High)
    .confidence(Confidence::High)
    .category(Category::Randomness)
    .description(
        "Ledger timestamps and sequence numbers are known to whoever submits a \
         transaction and can be ground until the outcome is favourable, so they are \
         not usable as entropy for lotteries, mints or shuffles.",
    )
    .tags(&["randomness", "entropy", "lottery"])
    .references(&[Reference::new(
        "Stellar docs: Randomness",
        "https://developers.stellar.org/docs/learn/encyclopedia/security/",
    )]);

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        for site in &ctx.model().randomness {
            sink.report(format!(
                "`{}` is used as entropy, but it is fully predictable to a transaction submitter",
                site.source.as_str()
            ))
            .primary(site.site.file, site.span)
            .in_function(site.site.function.clone())
            .note(
                "A submitter can predict the value before signing and retry until the \
                 outcome is favourable.",
            )
            .help("Use a commit–reveal scheme or an external randomness beacon instead.")
            .emit();
        }
    }
}

crate::declare_detector!(PredictableRandomness);

/// `SSDK012`: an entrypoint that replaces the contract's own code.
#[derive(Debug, Default)]
pub struct UnauthorizedUpgrade;

impl Detector for UnauthorizedUpgrade {
    const META: DetectorMeta = DetectorMeta::new(
        RuleId::new("SSDK012"),
        "unauthorized-upgrade",
        "An upgrade path is missing authorization or trusts a caller-supplied hash.",
    )
    .severity(Severity::Critical)
    .confidence(Confidence::High)
    .category(Category::Upgradeability)
    .description(
        "`update_current_contract_wasm` replaces all of the contract's code, including \
         its authorization logic. An upgrade path that is not gated on an admin \
         `require_auth`, or that accepts the new wasm hash from a caller, hands the \
         contract to the attacker.",
    )
    .tags(&["upgrade", "admin", "auth"])
    .references(&[Reference::new(
        "Stellar docs: Contract upgrades",
        "https://developers.stellar.org/docs/learn/encyclopedia/security/",
    )]);

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        let model = ctx.model();
        for upgrade in &model.upgrades {
            if !upgrade.replaces_current_contract() {
                continue;
            }
            let authorized = model.has_transitive_auth(&upgrade.site.function);
            if authorized && !upgrade.argument_is_parameter {
                continue;
            }
            let reason = if !authorized {
                "no authorization check reaches this entrypoint".to_string()
            } else {
                format!(
                    "the new wasm hash `{}` is supplied by the caller",
                    upgrade.argument.as_deref().unwrap_or("?")
                )
            };
            sink.report(format!(
                "`{}` replaces the contract code and {}",
                upgrade.method, reason
            ))
            .severity(if authorized {
                Severity::High
            } else {
                Severity::Critical
            })
            .primary(upgrade.site.file, upgrade.span)
            .in_function(upgrade.site.function.clone())
            .note(
                "Upgrading changes the contract's code and therefore every rule it \
                 enforces.",
            )
            .help(
                "Gate the upgrade behind an admin `require_auth` and store the approved \
                 wasm hash on-chain rather than accepting it as an argument.",
            )
            .emit();
        }
    }
}

crate::declare_detector!(UnauthorizedUpgrade);

/// `SSDK013`: a panicking expression that aborts the whole transaction.
#[derive(Debug, Default)]
pub struct PanicOnCallerInput;

impl Detector for PanicOnCallerInput {
    const META: DetectorMeta = DetectorMeta::new(
        RuleId::new("SSDK013"),
        "panic-on-caller-input",
        "A panicking expression can abort a contract call.",
    )
    .severity(Severity::Medium)
    .confidence(Confidence::Medium)
    .category(Category::PanicSafety)
    .description(
        "A panic aborts the entire transaction. When the panic is reachable from \
         caller-controlled data it becomes a denial-of-service primitive: the caller \
         pays the fee and the call cannot be recovered.",
    )
    .tags(&["panic", "dos", "availability"])
    .references(&[Reference::new(
        "Stellar docs: Error handling",
        "https://developers.stellar.org/docs/learn/encyclopedia/errors-and-debugging/",
    )]);

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        for panic in &ctx.model().panics {
            if !panic.kind.is_always_defect() {
                continue;
            }
            let fatal = matches!(
                panic.kind,
                PanicKind::Panic | PanicKind::Todo | PanicKind::Unimplemented
            );
            sink.report(format!("`{}` aborts the call", panic.describe()))
                .severity(if fatal {
                    Severity::High
                } else {
                    Severity::Medium
                })
                .confidence(if panic.on_storage_read() {
                    Confidence::High
                } else {
                    Confidence::Medium
                })
                .primary(panic.site.file, panic.span)
                .in_function(panic.site.function.clone())
                .note(
                    "An attacker who can trigger the panic can deny service, and the \
                     caller still pays the transaction fee.",
                )
                .help("Return a typed error (`Result`) instead of panicking on caller input.")
                .emit();
        }
    }
}

crate::declare_detector!(PanicOnCallerInput);
