//! A typed model of a Soroban contract.
//!
//! The model is derived once per project from the syntax trees and answers the
//! questions detectors actually ask: which functions are entrypoints, where the
//! contract reads and writes ledger entries, where it authorizes, and which code
//! runs before that authorization happens.
//!
//! Everything in the model is plain owned data plus spans, so detectors never
//! deal with lifetimes from the syntax tree.

pub mod arithmetic;
pub mod auth;
pub mod builder;
pub mod calls;
pub mod control;
pub mod storage;

pub use arithmetic::{ArithmeticSite, CastSite, IntegerOp};
pub use auth::{AuthCheck, AuthKind};
pub use calls::{ContractCall, RandomnessSite, RandomnessSource, RandomnessUse, UpgradeSite};
pub use control::{LoopBound, LoopKind, LoopSite, PanicKind, PanicSite};
pub use storage::{StorageAccess, StorageOp, StorageTier};

use std::collections::{BTreeMap, BTreeSet};

use crate::source::{FileId, SourceMap};
use crate::span::SourceSpan;
use crate::syntax::Param;

/// Common provenance of a detected site: which file, contract and function it is in.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Site {
    /// File the site was found in.
    pub file: FileId,
    /// Enclosing contract, when the site is inside a `#[contractimpl]`.
    pub contract: Option<String>,
    /// Enclosing function name.
    pub function: String,
    /// Span of the enclosing function's name.
    pub function_span: SourceSpan,
    /// Span of the site itself.
    pub span: SourceSpan,
    /// Whether the site is lexically inside a loop.
    pub in_loop: bool,
}

impl Site {
    /// Build a site with the minimum information.
    pub fn new(file: FileId, function: impl Into<String>, span: SourceSpan) -> Self {
        Site {
            file,
            contract: None,
            function: function.into(),
            function_span: SourceSpan::UNKNOWN,
            span,
            in_loop: false,
        }
    }

    /// `(file, span)` of the site, for reporting.
    pub fn location(&self) -> (FileId, SourceSpan) {
        (self.file, self.span)
    }

    /// `(file, span)` of the enclosing function, for reporting.
    pub fn function_location(&self) -> (FileId, SourceSpan) {
        (self.file, self.function_span)
    }
}

/// A contract declared with `#[contract]` and its exported entrypoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contract {
    /// Contract type name.
    pub name: String,
    /// File declaring the contract.
    pub file: FileId,
    /// Span of the declaration, or the first `#[contractimpl]` block when the
    /// `#[contract]` struct lives in another file.
    pub span: SourceSpan,
    /// Whether a `#[contract]` attribute was seen.
    pub declared: bool,
    /// Exported functions, in source order.
    pub entrypoints: Vec<Entrypoint>,
}

impl Contract {
    /// Whether the contract has an entrypoint with this name.
    pub fn has_entrypoint(&self, name: &str) -> bool {
        self.entrypoints.iter().any(|entry| entry.name == name)
    }
}

/// A function exported from a contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entrypoint {
    /// Function name.
    pub name: String,
    /// Contract the entrypoint belongs to.
    pub contract: String,
    /// File the entrypoint is defined in.
    pub file: FileId,
    /// Span of the function name.
    pub span: SourceSpan,
    /// Span of the whole function including attributes.
    pub full_span: SourceSpan,
    /// Parameters, with their classifications.
    pub params: Vec<Param>,
    /// Canonical return type.
    pub return_type: Option<String>,
    /// Whether this is the `__constructor`.
    pub is_constructor: bool,
    /// Whether this is a custom-account `__check_auth` hook.
    pub is_check_auth: bool,
}

impl Entrypoint {
    /// Parameters that are `Address`.
    pub fn addresses(&self) -> impl Iterator<Item = &Param> {
        self.params.iter().filter(|param| param.is_address())
    }

    /// Look up a parameter by name.
    pub fn param(&self, name: &str) -> Option<&Param> {
        self.params.iter().find(|param| param.name == name)
    }

    /// Parameter names, in order.
    pub fn param_names(&self) -> Vec<&str> {
        self.params
            .iter()
            .map(|param| param.name.as_str())
            .collect()
    }

    /// The first collection-typed parameter, if any.
    pub fn collection_param(&self) -> Option<&Param> {
        self.params.iter().find(|param| param.is_collection())
    }

    /// Whether a parameter carries data supplied by the caller (as opposed to `Env`).
    pub fn caller_params(&self) -> impl Iterator<Item = &Param> {
        self.params.iter().filter(|param| !param.is_env())
    }
}

/// Kind of a `#[contracttype]`-family declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractTypeKind {
    /// `#[contracttype] struct`
    Struct,
    /// `#[contracttype] enum`
    Enum,
    /// `#[contracterror]`
    Error,
    /// `#[contractevent]`
    Event,
}

/// A `#[contracttype]`, `#[contracterror]` or `#[contractevent]` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractType {
    /// Type name.
    pub name: String,
    /// Which attribute declared it.
    pub kind: ContractTypeKind,
    /// File of the declaration.
    pub file: FileId,
    /// Span of the declaration.
    pub span: SourceSpan,
    /// Variant names for enums: `(name, carries_data)`.
    pub variants: Vec<(String, bool)>,
    /// Field type names for structs.
    pub fields: Vec<String>,
}

impl ContractType {
    /// Whether the declaration is an enum.
    pub fn is_enum(&self) -> bool {
        self.kind == ContractTypeKind::Enum
    }
}

/// The derived model of every contract in a project.
#[derive(Debug, Clone, Default)]
pub struct ContractModel {
    /// Contracts and their entrypoints.
    pub contracts: Vec<Contract>,
    /// `#[contracttype]`-family declarations.
    pub types: Vec<ContractType>,
    /// Ledger storage operations.
    pub storage_ops: Vec<StorageOp>,
    /// Authorization checks and signature verifications.
    pub auth_checks: Vec<AuthCheck>,
    /// Integer arithmetic sites.
    pub arithmetic: Vec<ArithmeticSite>,
    /// `as` casts between numeric types.
    pub casts: Vec<CastSite>,
    /// Loops.
    pub loops: Vec<LoopSite>,
    /// Panicking expressions.
    pub panics: Vec<PanicSite>,
    /// Cross-contract calls through generated clients.
    pub calls: Vec<ContractCall>,
    /// Upgrade and deploy calls.
    pub upgrades: Vec<UpgradeSite>,
    /// Ledger-derived values used as entropy.
    pub randomness: Vec<RandomnessSite>,
    /// Source-level call graph between function names.
    pub call_graph: BTreeMap<String, Vec<String>>,
}

/// Build the model for every file in `sources`.
pub fn build(sources: &SourceMap, include_tests: bool) -> ContractModel {
    builder::build(sources, include_tests)
}

impl ContractModel {
    /// Every entrypoint across all contracts.
    pub fn entrypoints(&self) -> impl Iterator<Item = &Entrypoint> {
        self.contracts
            .iter()
            .flat_map(|contract| contract.entrypoints.iter())
    }

    /// Look up an entrypoint by name across all contracts.
    pub fn entrypoint(&self, name: &str) -> Option<&Entrypoint> {
        self.entrypoints().find(|entry| entry.name == name)
    }

    /// Names of every entrypoint.
    pub fn entrypoint_names(&self) -> Vec<&str> {
        self.entrypoints()
            .map(|entry| entry.name.as_str())
            .collect()
    }

    /// Whether a function name is an exported entrypoint.
    pub fn is_entrypoint(&self, name: &str) -> bool {
        self.entrypoint(name).is_some()
    }

    /// Storage operations inside a function.
    pub fn storage_ops_in<'a>(&'a self, function: &'a str) -> impl Iterator<Item = &'a StorageOp> {
        self.storage_ops
            .iter()
            .filter(move |op| op.site.function == function)
    }

    /// Authorization checks inside a function.
    pub fn auth_in<'a>(&'a self, function: &'a str) -> impl Iterator<Item = &'a AuthCheck> {
        self.auth_checks
            .iter()
            .filter(move |check| check.site.function == function)
    }

    /// Loops inside a function.
    pub fn loops_in<'a>(&'a self, function: &'a str) -> impl Iterator<Item = &'a LoopSite> {
        self.loops
            .iter()
            .filter(move |item| item.site.function == function)
    }

    /// Arithmetic sites inside a function.
    pub fn arithmetic_in<'a>(
        &'a self,
        function: &'a str,
    ) -> impl Iterator<Item = &'a ArithmeticSite> {
        self.arithmetic
            .iter()
            .filter(move |item| item.site.function == function)
    }

    /// Functions called directly by `function` (source-level call graph).
    pub fn callees(&self, function: &str) -> &[String] {
        self.call_graph
            .get(function)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Whether `predicate` holds for `function` or for any function it can reach.
    ///
    /// Authorization and TTL bumps are routinely factored into private helpers, so
    /// detectors must follow calls before concluding something is missing.
    pub fn has_transitive(&self, function: &str, predicate: impl Fn(&str) -> bool) -> bool {
        let mut visited: BTreeSet<&str> = BTreeSet::new();
        let mut stack = vec![function];
        while let Some(current) = stack.pop() {
            if !visited.insert(current) {
                continue;
            }
            if predicate(current) {
                return true;
            }
            for callee in self.callees(current) {
                stack.push(callee.as_str());
            }
        }
        false
    }

    /// Whether `function` performs an authorization check, directly or in a callee.
    pub fn has_transitive_auth(&self, function: &str) -> bool {
        self.has_transitive(function, |name| {
            self.auth_in(name)
                .any(|check| check.kind.establishes_authorization())
        })
    }

    /// Whether `function` extends a TTL, directly or in a callee.
    pub fn has_transitive_ttl_extension(&self, function: &str) -> bool {
        self.has_transitive(function, |name| {
            self.storage_ops_in(name)
                .any(|op| op.access == StorageAccess::ExtendTtl)
        })
    }

    /// Whether any function in the model extends a TTL at all.
    ///
    /// Contracts routinely keep long-lived entries alive from a dedicated
    /// `bump`/keeper entrypoint rather than from every writer, so a check scoped to
    /// one entrypoint reports a false positive on the recommended pattern. A
    /// whole-contract check distinguishes "the contract never maintains a TTL" from
    /// "this particular entrypoint does not".
    pub fn extends_any_ttl(&self) -> bool {
        self.storage_ops
            .iter()
            .any(|op| op.access == StorageAccess::ExtendTtl)
    }

    /// Authorization checks whose target text matches `expression`.
    ///
    /// The match is textual on canonical expressions, which is what a detector can
    /// check without a full data-flow analysis: `from.require_auth()` binds to the
    /// expression `from`.
    pub fn auth_targets<'a>(&'a self, function: &str, expression: &str) -> Vec<&'a AuthCheck> {
        let mut matches = Vec::new();
        for name in self.reachable_functions(function) {
            matches.extend(
                self.auth_checks
                    .iter()
                    .filter(|check| check.site.function == name && check.binds_to(expression)),
            );
        }
        matches
    }

    /// Every function reachable from `function`, including itself.
    pub fn reachable_functions(&self, function: &str) -> Vec<String> {
        let mut visited: BTreeSet<String> = BTreeSet::new();
        let mut stack = vec![function.to_string()];
        while let Some(current) = stack.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            for callee in self.callees(&current) {
                stack.push(callee.clone());
            }
        }
        visited.into_iter().collect()
    }

    /// Names of enums used as storage keys, derived from key expressions.
    pub fn storage_key_enums(&self) -> Vec<&str> {
        let mut names: BTreeSet<&str> = BTreeSet::new();
        for op in &self.storage_ops {
            if let Some(key) = &op.key {
                if let Some((prefix, _)) = key.split_once("::") {
                    if self
                        .types
                        .iter()
                        .any(|ty| ty.name == prefix && ty.is_enum())
                    {
                        names.insert(prefix);
                    }
                }
            }
        }
        names.into_iter().collect()
    }

    /// Storage keys grouped by their canonical text, for tier-confusion analysis.
    pub fn storage_ops_by_key(&self) -> BTreeMap<&str, Vec<&StorageOp>> {
        let mut grouped: BTreeMap<&str, Vec<&StorageOp>> = BTreeMap::new();
        for op in &self.storage_ops {
            if let Some(key) = &op.key {
                grouped.entry(key.as_str()).or_default().push(op);
            }
        }
        grouped
    }

    /// Panics inside a function.
    pub fn panics_in<'a>(&'a self, function: &'a str) -> impl Iterator<Item = &'a PanicSite> {
        self.panics
            .iter()
            .filter(move |item| item.site.function == function)
    }

    /// Cross-contract calls inside a function.
    pub fn calls_in<'a>(&'a self, function: &'a str) -> impl Iterator<Item = &'a ContractCall> {
        self.calls
            .iter()
            .filter(move |item| item.site.function == function)
    }

    /// Upgrades inside a function.
    pub fn upgrades_in<'a>(&'a self, function: &'a str) -> impl Iterator<Item = &'a UpgradeSite> {
        self.upgrades
            .iter()
            .filter(move |item| item.site.function == function)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::SourceFile;

    fn model_of(source: &str) -> ContractModel {
        let file = SourceFile::parse(FileId(0), "src/lib.rs", "src/lib.rs", source).unwrap();
        let sources = SourceMap::new(vec![file]);
        build(&sources, false)
    }

    #[test]
    fn builds_entrypoints_and_private_helpers() {
        let model = model_of(
            r#"
#[contract]
pub struct Token;

#[contractimpl]
impl Token {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        helper(&env);
    }

    fn helper(env: &Env) {}
}
"#,
        );
        assert_eq!(model.contracts.len(), 1);
        assert_eq!(model.contracts[0].name, "Token");
        assert!(model.contracts[0].declared);
        assert_eq!(model.entrypoint_names(), vec!["transfer"]);
        let entrypoint = model.entrypoint("transfer").unwrap();
        assert_eq!(entrypoint.addresses().count(), 2);
        assert_eq!(entrypoint.param("amount").unwrap().ty, "i128");
        assert!(entrypoint.param("amount").unwrap().is_integer());
        assert!(entrypoint.return_type.is_none());
    }

    #[test]
    fn transitive_queries_follow_calls() {
        let model = model_of(
            r#"
#[contractimpl]
impl Token {
    pub fn transfer(env: Env, from: Address) {
        check(&env, &from);
        bump(&env);
    }

    fn check(env: &Env, from: &Address) {
        from.require_auth();
    }

    fn bump(env: &Env) {
        env.storage().persistent().extend_ttl(&KEY, 100, 1000);
    }
}
"#,
        );
        assert!(model.has_transitive_auth("transfer"));
        assert!(model.has_transitive_ttl_extension("transfer"));
        assert!(!model.has_transitive_auth("bump"));
        assert!(model.has_transitive_auth("check"));
    }

    #[test]
    fn auth_targets_match_the_bound_expression() {
        let model = model_of(
            r#"
#[contractimpl]
impl Token {
    pub fn transfer(env: Env, from: Address, admin: Address) {
        admin.require_auth();
        from.require_auth();
    }
}
"#,
        );
        assert_eq!(model.auth_targets("transfer", "from").len(), 1);
        assert_eq!(model.auth_targets("transfer", "admin").len(), 1);
        assert!(model.auth_targets("transfer", "someone_else").is_empty());
    }

    #[test]
    fn groups_storage_ops_by_key() {
        let model = model_of(
            r#"
#[contracttype]
pub enum DataKey { Total, Admin }

#[contractimpl]
impl Token {
    pub fn a(env: Env) {
        env.storage().instance().set(&DataKey::Total, &1);
        env.storage().instance().get::<_, i128>(&DataKey::Total);
    }
}
"#,
        );
        let grouped = model.storage_ops_by_key();
        let total = grouped.get("DataKey::Total").unwrap();
        assert_eq!(total.len(), 2);
        assert_eq!(model.storage_key_enums(), vec!["DataKey"]);
    }

    #[test]
    fn reachable_functions_includes_self_and_callees() {
        let model = model_of(
            r#"
#[contractimpl]
impl Token {
    pub fn a(env: Env) { b(&env); }
    fn b(env: &Env) { c(&env); }
    fn c(env: &Env) {}
    fn d(env: &Env) {}
}
"#,
        );
        let mut reachable = model.reachable_functions("a");
        reachable.sort();
        assert_eq!(reachable, vec!["a", "b", "c"]);
    }

    #[test]
    fn ignores_test_functions_when_asked() {
        let source = r#"
#[contractimpl]
impl Token {
    pub fn real(env: Env) {
        env.storage().instance().set(&KEY, &1);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        env.storage().instance().set(&KEY, &1);
    }
}
"#;
        let with_tests = {
            let file = SourceFile::parse(FileId(0), "src/lib.rs", "src/lib.rs", source).unwrap();
            build(&SourceMap::new(vec![file]), true)
        };
        let without_tests = model_of(source);
        assert!(with_tests.storage_ops.len() > without_tests.storage_ops.len());
    }
}
