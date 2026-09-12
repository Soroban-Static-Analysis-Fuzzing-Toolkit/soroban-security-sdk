//! Compiled-module detectors (`SSDK020`–`SSDK022`).
//!
//! Source analysis is the right place to reason about authorization and storage
//! layout, but only the compiled module knows what a deployed contract actually
//! imports and how large it is. These detectors run against the `.wasm` module and
//! cross-check the source-level conclusions at the binary level.

use crate::category::Category;
use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::finding::FindingSink;
use crate::rule::{DetectorMeta, Reference, RuleId};
use crate::severity::{Confidence, Severity};

/// `SSDK020`: the module writes ledger state but never imports `require_auth`.
///
/// This is the binary-level confirmation of a missing `require_auth`: the host
/// function a contract must call to authorize an address is simply not linked in.
#[derive(Debug, Default)]
pub struct WasmStorageWithoutAuth;

impl Detector for WasmStorageWithoutAuth {
    const META: DetectorMeta = DetectorMeta::new(
        RuleId::new("SSDK020"),
        "wasm-storage-without-auth",
        "The compiled module writes ledger state but never imports `require_auth`.",
    )
    .severity(Severity::High)
    .confidence(Confidence::Medium)
    .category(Category::Auth)
    .description(
        "A contract can only authorize an address by calling the host's `require_auth` \
         function, so a module that imports ledger-writing host functions but never \
         imports `require_auth` cannot be checking authorization at all.",
    )
    .tags(&["wasm", "auth", "require-auth"])
    .references(&[Reference::new(
        "Stellar docs: Authorization",
        "https://developers.stellar.org/docs/learn/encyclopedia/security/authorization",
    )])
    .requires_wasm();

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        let Some(module) = ctx.wasm() else {
            return;
        };
        let writes = module
            .imports
            .iter()
            .filter(|import| import.is_function && is_storage_write(&import.name))
            .count();
        if writes == 0 {
            return;
        }
        let authorized = module
            .imports
            .iter()
            .any(|import| import.is_function && is_auth_import(&import.name));
        if authorized {
            return;
        }
        sink.report(format!(
            "the compiled module imports {writes} ledger-writing host function(s) but never imports `require_auth`"
        ))
        .primary_wasm(0, module.name.clone())
        .note("No authorization host function is linked into the deployed contract.")
        .help("Call `<address>.require_auth()` before the first state change.")
        .emit();
    }
}

crate::declare_detector!(WasmStorageWithoutAuth);

/// `SSDK021`: the module is larger than a single ledger entry may be.
#[derive(Debug, Default)]
pub struct ContractOversized;

impl Detector for ContractOversized {
    const META: DetectorMeta = DetectorMeta::new(
        RuleId::new("SSDK021"),
        "contract-oversized",
        "The compiled module exceeds the per-entry ledger size limit.",
    )
    .severity(Severity::High)
    .confidence(Confidence::High)
    .category(Category::ResourceBudget)
    .description(
        "A contract's Wasm is stored in a ledger entry, so it is subject to the same \
         size ceiling as any other entry. A module over the limit cannot be uploaded \
         or upgraded on-chain.",
    )
    .tags(&["wasm", "size", "deployment"])
    .references(&[Reference::new(
        "Stellar docs: Contract size",
        "https://developers.stellar.org/docs/learn/encyclopedia/contract-development/",
    )])
    .requires_wasm();

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        let Some(module) = ctx.wasm() else {
            return;
        };
        let limit = ctx.budget().limits.max_entry_size_bytes as u64;
        let size = module.size_bytes as u64;
        if limit == u64::from(u32::MAX) || size <= limit {
            return;
        }
        sink.report(format!(
            "the compiled module is {size} bytes, over the {limit}-byte ledger entry limit"
        ))
        .primary_wasm(0, module.name.clone())
        .note("Optimize the release profile (`opt-level = \"z\"`, LTO, `codegen-units = 1`).")
        .help("Reduce code size or split the contract before deploying.")
        .emit();
    }
}

crate::declare_detector!(ContractOversized);

/// `SSDK022`: the module declares a start function.
#[derive(Debug, Default)]
pub struct WasmStartFunction;

impl Detector for WasmStartFunction {
    const META: DetectorMeta = DetectorMeta::new(
        RuleId::new("SSDK022"),
        "wasm-start-function",
        "The compiled module declares a Wasm start function.",
    )
    .severity(Severity::Medium)
    .confidence(Confidence::High)
    .category(Category::BestPractice)
    .description(
        "A Wasm start function runs on instantiation, before any entrypoint and \
         outside the transaction's authorization context. Soroban contracts are not \
         expected to have one, and code that runs there cannot be authorized.",
    )
    .tags(&["wasm", "deployment"])
    .references(&[Reference::new(
        "WebAssembly spec: start function",
        "https://webassembly.github.io/spec/core/syntax/modules.html#start-function",
    )])
    .requires_wasm();

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        let Some(module) = ctx.wasm() else {
            return;
        };
        if !module.has_start {
            return;
        }
        sink.report("the compiled module declares a Wasm start function")
            .primary_wasm(0, module.name.clone())
            .note("Instantiation runs the start function before any entrypoint.")
            .help("Move initialization into `__constructor` or an explicit entrypoint.")
            .emit();
    }
}

crate::declare_detector!(WasmStartFunction);

/// Whether a host function import writes ledger state.
fn is_storage_write(name: &str) -> bool {
    const WRITE_SUFFIXES: [&str; 6] = ["_set", "_remove", "_put", "_del", "_extend_ttl", "_bump"];
    let storage_like = name.contains("storage") || name.contains("contract_data");
    storage_like && WRITE_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
}

/// Whether a host function import authorizes an address.
fn is_auth_import(name: &str) -> bool {
    name.contains("require_auth")
}
