//! Arithmetic detectors (`SSDK003`, `SSDK004`, `SSDK005`, `SSDK014`).

use crate::category::Category;
use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::finding::{FindingSink, Location};
use crate::rule::{DetectorMeta, Reference, RuleId};
use crate::severity::{Confidence, Severity};
use crate::syntax::IntegerTy;

use super::{moves_value, stores_integer};

/// `SSDK003`: overflow-capable arithmetic on an amount-like integer in a release
/// build that does not enable overflow checks.
#[derive(Debug, Default)]
pub struct UncheckedTokenArithmetic;

impl Detector for UncheckedTokenArithmetic {
    const META: DetectorMeta = DetectorMeta::new(
        RuleId::new("SSDK003"),
        "unchecked-token-arithmetic",
        "Amount arithmetic can wrap because release overflow checks are disabled.",
    )
    .severity(Severity::High)
    .confidence(Confidence::Medium)
    .category(Category::Arithmetic)
    .description(
        "Rust disables integer overflow checks in release builds unless the crate \
         opts in with `[profile.release] overflow-checks = true`. On an amount-like \
         type such as `i128`, an overflow it not caught and the balance silently \
         wraps, which is the classic token-mint bug.",
    )
    .tags(&["arithmetic", "overflow", "token"])
    .references(&[Reference::new(
        "Stellar docs: Security best practices",
        "https://developers.stellar.org/docs/learn/encyclopedia/security/",
    )]);

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        let model = ctx.model();
        let package = ctx.package();
        let overflow_checked = package.is_some_and(|info| info.release_overflow_checks);
        for site in &model.arithmetic {
            if !site.op.can_overflow() || site.guarded || !site.is_typed() {
                continue;
            }
            let Some(ty) = site.integer_type() else {
                continue;
            };
            if !is_amount_type(ty) {
                continue;
            }
            if !(moves_value(model, &site.site.function)
                || stores_integer(model, &site.site.function))
            {
                continue;
            }
            // With overflow checks on, the operation panics rather than wrapping;
            // that is a denial-of-service concern, not a silent balance corruption.
            if overflow_checked {
                continue;
            }
            let mut builder = sink
                .report(format!(
                    "`{}` on {} can wrap an amount",
                    site.op.as_str(),
                    ty.name()
                ))
                .primary(site.site.file, site.span)
                .in_function(site.site.function.clone());
            builder = match package {
                Some(_) => builder.note(
                    "`[profile.release] overflow-checks` is not enabled, so this \
                     operation wraps instead of panicking.",
                ),
                None => builder.note(
                    "No `Cargo.toml` was analysed, so the overflow-check setting is \
                     unknown; the official Soroban template enables it.",
                ),
            };
            builder
                .help(
                    "Use `checked_add`/`checked_sub`/`checked_mul` and handle the `None` \
                     case explicitly.",
                )
                .emit();
        }
    }
}

crate::declare_detector!(UncheckedTokenArithmetic);

/// `SSDK004`: numeric `as` casts that can silently change a value.
#[derive(Debug, Default)]
pub struct LossyCast;

impl Detector for LossyCast {
    const META: DetectorMeta = DetectorMeta::new(
        RuleId::new("SSDK004"),
        "lossy-cast",
        "An `as` cast can silently truncate or reinterpret an integer.",
    )
    .severity(Severity::Medium)
    .confidence(Confidence::High)
    .category(Category::Arithmetic)
    .description(
        "Rust's `as` operator truncates on narrowing and reinterprets signedness \
         without any check. On token amounts a silent truncation is a value loss.",
    )
    .tags(&["arithmetic", "cast", "truncation"])
    .references(&[Reference::new(
        "Rust reference: Type cast expressions",
        "https://doc.rust-lang.org/reference/expressions/operator-expr.html#type-cast-expressions",
    )]);

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        for cast in &ctx.model().casts {
            if !cast.lossy {
                continue;
            }
            sink.report(format!(
                "`{}` truncates or reinterprets the value",
                cast.describe()
            ))
            .primary(cast.site.file, cast.span)
            .in_function(cast.site.function.clone())
            .note(
                "`as` never checks range or sign, so the result can silently differ \
                     from the operand.",
            )
            .help("Use `try_into()` and handle the error, or widen the target type.")
            .emit();
        }
    }
}

crate::declare_detector!(LossyCast);

/// `SSDK005`: explicit `wrapping_*` arithmetic, which opts out of overflow checks.
#[derive(Debug, Default)]
pub struct WrappingArithmetic;

impl Detector for WrappingArithmetic {
    const META: DetectorMeta = DetectorMeta::new(
        RuleId::new("SSDK005"),
        "wrapping-arithmetic",
        "`wrapping_*` arithmetic silently wraps instead of failing.",
    )
    .severity(Severity::High)
    .confidence(Confidence::High)
    .category(Category::Arithmetic)
    .description(
        "The `wrapping_add`/`wrapping_sub`/`wrapping_mul`/`wrapping_div` family is an \
         explicit request to ignore overflow. In contract code this is almost always \
         a bug: a balance that overflows becomes a much smaller number.",
    )
    .tags(&["arithmetic", "wrapping", "overflow"])
    .references(&[Reference::new(
        "Rust docs: Wrapping arithmetic",
        "https://doc.rust-lang.org/std/primitive.i128.html#method.wrapping_add",
    )]);

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        for site in &ctx.model().arithmetic {
            if !site.op.is_wrapping() {
                continue;
            }
            sink.report(format!("`{}` never checks for overflow", site.op.as_str()))
                .primary(site.site.file, site.span)
                .in_function(site.site.function.clone())
                .note("A wrapped result passes every downstream balance check.")
                .help("Use the `checked_*` family and propagate a typed error instead.")
                .emit();
        }
    }
}

crate::declare_detector!(WrappingArithmetic);

/// `SSDK014`: `[profile.release] overflow-checks` is not enabled.
#[derive(Debug, Default)]
pub struct OverflowChecksDisabled;

impl Detector for OverflowChecksDisabled {
    const META: DetectorMeta = DetectorMeta::new(
        RuleId::new("SSDK014"),
        "overflow-checks-disabled",
        "The release profile does not enable `overflow-checks`.",
    )
    .severity(Severity::High)
    .confidence(Confidence::High)
    .category(Category::Arithmetic)
    .description(
        "Rust's release profile disables integer overflow checks by default. The \
         official Soroban contract template turns them back on with \
         `overflow-checks = true`; a contract that drops the setting silently wraps \
         its arithmetic when deployed.",
    )
    .tags(&["arithmetic", "manifest", "release-profile"])
    .references(&[Reference::new(
        "Stellar docs: Optimization settings",
        "https://developers.stellar.org/docs/build/guides/conventions/release-profile",
    )]);

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        let Some(package) = ctx.package() else {
            return;
        };
        if !package.is_contract_crate() || package.release_overflow_checks {
            return;
        }
        let location = Location {
            file: package.manifest_path.display().to_string(),
            file_id: None,
            span: None,
            function: None,
            label: Some("[profile.release]".to_string()),
            wasm_offset: None,
        };
        sink.report(
            "`[profile.release] overflow-checks` is not enabled, so arithmetic wraps \
             instead of panicking in release builds",
        )
        .location(location)
        .note("The official Soroban contract template sets `overflow-checks = true`.")
        .help("Add `overflow-checks = true` under `[profile.release]` in `Cargo.toml`.")
        .emit();
    }
}

crate::declare_detector!(OverflowChecksDisabled);

/// Whether an integer type is wide enough to be a token amount.
fn is_amount_type(ty: IntegerTy) -> bool {
    matches!(
        ty,
        IntegerTy::I128 | IntegerTy::U128 | IntegerTy::I256 | IntegerTy::U256
    )
}
