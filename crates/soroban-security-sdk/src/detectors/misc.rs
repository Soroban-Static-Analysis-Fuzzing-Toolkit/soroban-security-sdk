//! Randomness, upgrade, deployment and panic-safety detectors
//! (`SSDK011`, `SSDK012`, `SSDK013`, `SSDK024`).

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
         not usable as entropy for lotteries, mints or shuffles. Reported when the \
         value is reduced or mixed (`%`, `^`, `&`); deadline comparisons and \
         elapsed-time arithmetic are ordinary uses and are not reported.",
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
        "A contract upgrade is reachable without authorization.",
    )
    .severity(Severity::Critical)
    .confidence(Confidence::High)
    .category(Category::Upgradeability)
    .description(
        "`update_current_contract_wasm` replaces all of the contract's code, including \
         its authorization logic. An upgrade path that is not gated on an admin \
         `require_auth` hands the contract to whoever calls it.",
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
            // An admin-authorized upgrade that takes the new hash as an argument is
            // the ordinary pattern, so only the missing check is reported.
            if model.has_transitive_auth(&upgrade.site.function) {
                continue;
            }
            let mut builder = sink
                .report(format!(
                    "`{}` replaces the contract code without authorizing the caller",
                    upgrade.method
                ))
                .severity(Severity::Critical)
                .primary(upgrade.site.file, upgrade.span)
                .in_function(upgrade.site.function.clone());
            if upgrade.argument_is_parameter {
                builder = builder.note(format!(
                    "The new wasm hash `{}` also comes straight from the caller.",
                    upgrade.argument.as_deref().unwrap_or("?")
                ));
            }
            builder
                .note(
                    "Upgrading changes the contract's code and therefore every rule it \
                     enforces.",
                )
                .help("Gate the upgrade behind an admin `require_auth`.")
                .emit();
        }
    }
}

crate::declare_detector!(UnauthorizedUpgrade);

/// `SSDK024`: a contract deployment that is not authorized.
///
/// `SSDK012` covers upgrades of the running contract. Deploying a *new* contract is
/// equally privileged — in the factory/deployer pattern the deployer can become the
/// admin of the derived contract — so an unauthenticated deploy lets anyone install
/// code and consume the protocol's resources.
#[derive(Debug, Default)]
pub struct UnauthorizedDeploy;

impl Detector for UnauthorizedDeploy {
    const META: DetectorMeta = DetectorMeta::new(
        RuleId::new("SSDK024"),
        "unauthorized-deploy",
        "A contract deployment is reachable without authorization.",
    )
    .severity(Severity::High)
    .confidence(Confidence::High)
    .category(Category::Upgradeability)
    .description(
        "Deploying a contract installs new code and, in the factory pattern, makes \
         the caller the admin of the deployed instance. A deploy path with no \
         `require_auth` hands that privilege to anyone, letting them spawn contracts \
         at the protocol's expense.",
    )
    .tags(&["deploy", "factory", "auth"])
    .references(&[Reference::new(
        "Stellar docs: Deploying contracts",
        "https://developers.stellar.org/docs/learn/encyclopedia/contract-development/",
    )]);

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        let model = ctx.model();
        for site in &model.upgrades {
            if !site.deploys() {
                continue;
            }
            // The ordinary factory gates the deploy on an admin, exactly like an
            // upgrade; only the missing check is reported.
            if model.has_transitive_auth(&site.site.function) {
                continue;
            }
            let mut builder = sink
                .report(format!(
                    "`{}` deploys a contract without authorizing the caller",
                    site.method
                ))
                .severity(Severity::High)
                .primary(site.site.file, site.span)
                .in_function(site.site.function.clone());
            if site.argument_is_parameter {
                builder = builder.note(
                    "The deployment argument also comes straight from the caller, so an \
                     attacker chooses what is deployed.",
                );
            }
            builder
                .note(
                    "In the factory pattern the deployer typically becomes the admin of \
                     the new contract.",
                )
                .help("Gate the deploy behind an admin `require_auth`, or restrict callers to a known set.")
                .emit();
        }
    }
}

crate::declare_detector!(UnauthorizedDeploy);

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
        "A panic aborts the entire transaction. Reported when an `unwrap`, `expect` or \
         index depends on a parameter of the enclosing function — most often a storage \
         read keyed by a caller-supplied address that has no entry yet — and for \
         `todo!`/`unimplemented!` left in contract code. Panics on contract state \
         alone and explicit `panic!` rejections are treated as deliberate.",
    )
    .tags(&["panic", "dos", "availability"])
    .references(&[Reference::new(
        "Stellar docs: Error handling",
        "https://developers.stellar.org/docs/learn/encyclopedia/errors-and-debugging/",
    )]);

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        for panic in &ctx.model().panics {
            match panic.kind {
                // Unfinished code that reached a deployed contract.
                PanicKind::Todo | PanicKind::Unimplemented => {
                    sink.report(format!(
                        "`{}` aborts every call that reaches it",
                        panic.describe()
                    ))
                    .severity(Severity::High)
                    .confidence(Confidence::High)
                    .primary(panic.site.file, panic.span)
                    .in_function(panic.site.function.clone())
                    .help("Implement the branch or return a typed error before deploying.")
                    .emit();
                }
                // An `unwrap`, `expect` or index whose outcome the caller decides.
                // A panic on contract state alone (`get(&Admin).unwrap()` after the
                // constructor set it) is an invariant, and an explicit `panic!` is a
                // deliberate rejection; neither is caller-triggerable by accident.
                //
                // Only panics written directly in an entrypoint are reported: its
                // parameters are exactly what the caller sends, whereas a helper's
                // parameters may be validated or constructed internally. A
                // `checked_*(..).expect(..)` is the recommended overflow guard.
                PanicKind::Unwrap | PanicKind::Expect | PanicKind::Index
                    if !panic.inputs.is_empty()
                        && ctx.is_entrypoint(&panic.site.function)
                        && !guards_checked_arithmetic(panic.on.as_deref()) =>
                {
                    let inputs = panic
                        .inputs
                        .iter()
                        .map(|input| format!("`{input}`"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let mut finding = sink
                        .report(format!(
                            "`{}` aborts the call for caller-chosen {inputs}",
                            panic.describe()
                        ))
                        .confidence(if panic.on_storage_read() {
                            Confidence::High
                        } else {
                            Confidence::Medium
                        })
                        .primary(panic.site.file, panic.span)
                        .in_function(panic.site.function.clone())
                        .note(
                            "Any caller can pick a value that triggers the panic, so the \
                             call fails with an opaque host error instead of a typed one.",
                        );
                    if panic.on_storage_read() {
                        finding = finding.help(
                            "A missing entry is an expected case for caller-supplied keys: \
                             use `unwrap_or` with a default or return a `#[contracterror]`.",
                        );
                    } else {
                        finding = finding.help(
                            "Validate the input and return a `#[contracterror]` instead of \
                             panicking.",
                        );
                    }
                    finding.emit();
                }
                _ => {}
            }
        }
    }
}

crate::declare_detector!(PanicOnCallerInput);

/// Whether an `unwrap`/`expect` receiver is a `checked_*` arithmetic call, e.g.
/// `balance.checked_add(amount)`.
fn guards_checked_arithmetic(receiver: Option<&str>) -> bool {
    receiver.is_some_and(|text| {
        text.rsplit_once(".checked_")
            .is_some_and(|(_, call)| !call.contains('.'))
    })
}
