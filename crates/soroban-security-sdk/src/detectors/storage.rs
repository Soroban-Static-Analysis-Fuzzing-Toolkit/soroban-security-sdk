//! Storage detectors (`SSDK002`, `SSDK008`, `SSDK009`).

use crate::category::Category;
use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::finding::FindingSink;
use crate::model::StorageTier;
use crate::rule::{DetectorMeta, Reference, RuleId};
use crate::severity::{Confidence, Severity};

/// `SSDK002`: the same ledger key accessed through more than one storage tier.
///
/// `instance`, `persistent` and `temporary` are distinct key spaces with different
/// lifetimes. Writing a key under one tier and reading it under another silently
/// yields `None`.
#[derive(Debug, Default)]
pub struct StorageTierConfusion;

impl Detector for StorageTierConfusion {
    const META: DetectorMeta = DetectorMeta::new(
        RuleId::new("SSDK002"),
        "storage-tier-confusion",
        "The same ledger key is accessed through different storage tiers.",
    )
    .severity(Severity::High)
    .confidence(Confidence::High)
    .category(Category::Storage)
    .description(
        "Soroban's three storage tiers are separate key spaces. A value written to \
         `persistent` is not visible through `instance.get` for the same key, so \
         mixing tiers for one logical key produces missing reads or lost writes.",
    )
    .tags(&["storage", "tiers", "state"])
    .references(&[Reference::new(
        "Stellar docs: Storage",
        "https://developers.stellar.org/docs/learn/encyclopedia/storage/state-archival",
    )]);

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        for (key, ops) in ctx.model().storage_ops_by_key() {
            let mut tiers: Vec<StorageTier> = ops
                .iter()
                .map(|op| op.tier)
                .filter(|tier| *tier != StorageTier::Unknown)
                .collect();
            tiers.sort();
            tiers.dedup();
            if tiers.len() < 2 {
                continue;
            }
            let names: Vec<&str> = tiers.iter().map(|tier| tier.as_str()).collect();
            let primary = ops[0];
            let mut builder = sink
                .report(format!(
                    "ledger key `{key}` is accessed through inconsistent storage tiers ({})",
                    names.join(", ")
                ))
                .primary(primary.site.file, primary.site.span)
                .in_function(primary.site.function.clone());
            for other in ops.iter().skip(1) {
                builder = builder
                    .secondary(other.site.file, other.site.span)
                    .label(format!("{} {}", other.tier, other.access));
            }
            builder
                .note(
                    "Each tier is a different key space, so the value written under one \
                     tier is invisible to a read through another.",
                )
                .help("Pick a single tier for the key and use it everywhere.")
                .emit();
        }
    }
}

crate::declare_detector!(StorageTierConfusion);

/// `SSDK008`: a write to the `temporary` tier of a key that looks long-lived.
///
/// Temporary entries are deleted permanently when their TTL lapses; unlike
/// persistent entries they cannot be restored.
#[derive(Debug, Default)]
pub struct TemporaryStorageWrite;

impl Detector for TemporaryStorageWrite {
    const META: DetectorMeta = DetectorMeta::new(
        RuleId::new("SSDK008"),
        "temporary-storage-write",
        "A mutation writes long-lived-looking state to `temporary` storage.",
    )
    .severity(Severity::Medium)
    .confidence(Confidence::Low)
    .category(Category::Storage)
    .description(
        "`temporary` entries are deleted forever once their time to live expires; \
         they cannot be restored the way persistent entries can. Using the tier for \
         keys that look like balances, configuration or ownership risks permanent \
         state loss.",
    )
    .tags(&["storage", "temporary", "ttl"])
    .references(&[Reference::new(
        "Stellar docs: State archival",
        "https://developers.stellar.org/docs/learn/encyclopedia/storage/state-archival",
    )]);

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        for op in &ctx.model().storage_ops {
            if op.tier != StorageTier::Temporary || !op.access.is_mutation() {
                continue;
            }
            let variant = op.key_variant().unwrap_or_default();
            let critical = looks_long_lived(variant);
            let mut builder = sink
                .report(format!(
                    "`{}` writes the `temporary` tier, whose entries are deleted on expiry",
                    op.describe()
                ))
                .primary(op.site.file, op.site.span)
                .in_function(op.site.function.clone());
            builder = if critical {
                builder
                    .severity(Severity::High)
                    .confidence(Confidence::High)
                    .note(format!(
                        "The key variant `{variant}` looks like long-lived state, which \
                         temporary storage cannot preserve."
                    ))
            } else {
                builder.confidence(Confidence::Low).note(
                    "Temporary storage is only safe for data that can be regenerated or \
                     discarded.",
                )
            };
            builder
                .help("Use `persistent` storage and extend its TTL for anything that must survive.")
                .emit();
        }
    }
}

crate::declare_detector!(TemporaryStorageWrite);

/// `SSDK009`: persistent writes that never extend a TTL.
///
/// Persistent entries are archived once their TTL lapses. A contract that writes
/// state and never bumps it can find its own entries unavailable later.
#[derive(Debug, Default)]
pub struct MissingTtlExtension;

impl Detector for MissingTtlExtension {
    const META: DetectorMeta = DetectorMeta::new(
        RuleId::new("SSDK009"),
        "missing-ttl-extension",
        "Persistent entries are written without a matching TTL extension.",
    )
    .severity(Severity::Medium)
    .confidence(Confidence::Low)
    .category(Category::Storage)
    .description(
        "Every persistent entry has a time to live. A contract that writes persistent \
         state but never calls `extend_ttl`/`bump` risks the entry being archived, at \
         which point reads return `None` until the entry is restored.",
    )
    .tags(&["storage", "ttl", "archival"])
    .references(&[Reference::new(
        "Stellar docs: State archival",
        "https://developers.stellar.org/docs/learn/encyclopedia/storage/state-archival",
    )]);

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        let model = ctx.model();
        for entrypoint in ctx.entrypoints() {
            if entrypoint.is_constructor {
                continue;
            }
            let writes_persistent = model.has_transitive(&entrypoint.name, |name| {
                model.storage_ops_in(name).any(|op| {
                    op.access.is_mutation() && op.tier == StorageTier::Persistent
                })
            });
            if !writes_persistent || model.has_transitive_ttl_extension(&entrypoint.name) {
                continue;
            }
            sink.report(format!(
                "`{}` writes persistent entries without extending their TTL",
                entrypoint.name
            ))
            .primary(entrypoint.file, entrypoint.span)
            .in_function(entrypoint.name.clone())
            .note(
                "Persistent entries can be archived once their TTL lapses, making the \
                 contract's state unavailable until a restore is submitted.",
            )
            .help("Call `extend_ttl` or `bump` on the entries that must stay live.")
            .emit();
        }
    }
}

crate::declare_detector!(MissingTtlExtension);

/// Whether a key variant name suggests state that must outlive its TTL.
fn looks_long_lived(variant: &str) -> bool {
    const MARKERS: [&str; 10] = [
        "admin",
        "owner",
        "authority",
        "config",
        "root",
        "supply",
        "total",
        "balance",
        "allowance",
        "reserve",
    ];
    let lower = variant.to_ascii_lowercase();
    MARKERS.iter().any(|marker| lower.contains(marker))
}
