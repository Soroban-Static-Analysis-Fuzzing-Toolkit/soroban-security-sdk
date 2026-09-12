//! Static resource-budget estimation.
//!
//! Soroban meters every call along several independent axes: CPU instructions,
//! contract memory, and ledger entry reads/writes. A call that exceeds any of them
//! fails, and the failing transaction still pays. This module estimates each axis
//! per entrypoint so a team knows before deploy which calls are close to a limit.
//!
//! # How much to trust the numbers
//!
//! The estimator is deliberately explicit about uncertainty:
//!
//! * **Ledger reads and writes** come from the source, where every
//!   `storage().<tier>().get/set/...` is countable. Loops with literal bounds are
//!   multiplied out; loops with unknown bounds make the axis unbounded. Each
//!   reachable function is counted once, so repeated calls to the same helper are
//!   undercounted: the estimate is a lower bound on purpose.
//! * **Instructions** come from the compiled wasm, where every operator is counted
//!   and the call graph is walked. Loop bodies are counted once and then multiplied
//!   by [`CostModel::assumed_loop_iterations`], which is an *assumption*, not a
//!   bound. Indirect calls, `memory.grow` and bulk-memory operations make the figure
//!   unbounded.
//! * **Memory** is the module's declared initial memory, which is exact.
//!
//! Every estimate therefore carries a [`BudgetEstimate::lower_bound`], an optional
//! [`BudgetEstimate::bounded_upper_bound`] that is only present when no unbounded
//! construct is reachable, and a best-effort `estimate`. Findings distinguish
//! "certainly exceeds" from "is estimated to exceed".

use std::collections::BTreeSet;

use serde::Serialize;

use crate::config::{CostModel, NetworkLimits};
use crate::model::{ContractModel, LoopBound};
use crate::wasm::WasmModule;

/// One dimension of the resource budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BudgetAxis {
    /// CPU instructions.
    Instructions,
    /// Contract memory in bytes.
    Memory,
    /// Ledger entry reads.
    ReadEntries,
    /// Ledger entry writes.
    WriteEntries,
}

impl BudgetAxis {
    /// Name used in reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            BudgetAxis::Instructions => "instructions",
            BudgetAxis::Memory => "memory",
            BudgetAxis::ReadEntries => "read-entries",
            BudgetAxis::WriteEntries => "write-entries",
        }
    }

    /// The network limit for this axis.
    pub fn limit(self, limits: &NetworkLimits) -> u64 {
        match self {
            BudgetAxis::Instructions => limits.max_instructions_per_tx,
            BudgetAxis::Memory => limits.max_memory_bytes,
            BudgetAxis::ReadEntries => u64::from(limits.max_read_entries),
            BudgetAxis::WriteEntries => u64::from(limits.max_write_entries),
        }
    }
}

impl std::fmt::Display for BudgetAxis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An estimate for one axis of one entrypoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BudgetEstimate {
    /// Value that is definitely reached when the entrypoint runs to completion.
    pub lower_bound: u64,
    /// Exact upper bound, present only when no unbounded construct is reachable.
    pub bounded_upper_bound: Option<u64>,
    /// Best-effort figure, using assumed loop trip counts where the real count is
    /// unknown. Never smaller than `lower_bound`.
    pub estimate: u64,
    /// Whether some construct prevented a bound from being computed.
    pub unbounded: bool,
    /// Why no bound could be computed.
    pub reason: Option<String>,
}

impl BudgetEstimate {
    /// An exact estimate.
    pub const fn exact(value: u64) -> Self {
        BudgetEstimate {
            lower_bound: value,
            bounded_upper_bound: Some(value),
            estimate: value,
            unbounded: false,
            reason: None,
        }
    }

    /// An estimate that could not be computed at all.
    pub fn unknown(reason: impl Into<String>) -> Self {
        BudgetEstimate {
            lower_bound: 0,
            bounded_upper_bound: None,
            estimate: 0,
            unbounded: true,
            reason: Some(reason.into()),
        }
    }

    /// An estimate with an unbounded component.
    pub fn unbounded(lower_bound: u64, estimate: u64, reason: impl Into<String>) -> Self {
        BudgetEstimate {
            lower_bound,
            bounded_upper_bound: None,
            estimate: estimate.max(lower_bound),
            unbounded: true,
            reason: Some(reason.into()),
        }
    }

    /// Whether the axis certainly exceeds `limit`, whatever the runtime does.
    pub fn certainly_exceeds(&self, limit: u64) -> bool {
        self.lower_bound > limit || self.bounded_upper_bound.is_some_and(|upper| upper > limit)
    }

    /// Whether the best-effort figure exceeds `limit`.
    pub fn may_exceed(&self, limit: u64) -> bool {
        self.estimate > limit
    }

    /// Ratio of the estimate to `limit`, for ranking findings.
    pub fn ratio(&self, limit: u64) -> f64 {
        if limit == 0 {
            return f64::INFINITY;
        }
        self.estimate as f64 / limit as f64
    }

    /// Human-readable description used in reports, e.g. `~12,000 (unbounded: loop)`.
    pub fn describe(&self) -> String {
        let base = if self.unbounded {
            format!("~{}", self.estimate)
        } else {
            self.estimate.to_string()
        };
        match &self.reason {
            Some(reason) => format!("{base} ({reason})"),
            None => base,
        }
    }
}

/// A limit that a call is expected to break.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BudgetViolation {
    /// Which axis.
    pub axis: BudgetAxis,
    /// The configured limit.
    pub limit: u64,
    /// What the estimator found.
    pub estimate: BudgetEstimate,
    /// Whether the violation is certain rather than estimated.
    pub certain: bool,
}

impl BudgetViolation {
    /// How far above the limit the estimate is, as a ratio (1.0 means at the limit).
    pub fn ratio(&self) -> f64 {
        self.estimate.ratio(self.limit)
    }
}

/// The estimated budget of a single entrypoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntrypointBudget {
    /// Entrypoint name.
    pub name: String,
    /// Estimated CPU instructions.
    pub instructions: BudgetEstimate,
    /// Declared memory in bytes, when a wasm module was provided.
    pub memory_bytes: Option<u64>,
    /// Estimated ledger entry reads.
    pub reads: BudgetEstimate,
    /// Estimated ledger entry writes.
    pub writes: BudgetEstimate,
    /// Limits this entrypoint is expected to break.
    pub violations: Vec<BudgetViolation>,
    /// Extra context, e.g. which helper made the axis unbounded.
    pub notes: Vec<String>,
    /// Whether the instructions figure came from a compiled module.
    pub instructions_from_wasm: bool,
}

impl EntrypointBudget {
    /// Look up a violation by axis.
    pub fn violation(&self, axis: BudgetAxis) -> Option<&BudgetViolation> {
        self.violations.iter().find(|item| item.axis == axis)
    }

    /// Whether any limit is expected to be broken certainly.
    pub fn has_certain_violation(&self) -> bool {
        self.violations.iter().any(|item| item.certain)
    }

    /// Worst estimate-to-limit ratio across all axes.
    pub fn worst_ratio(&self) -> f64 {
        self.violations
            .iter()
            .map(BudgetViolation::ratio)
            .fold(0.0_f64, f64::max)
    }
}

/// Budget estimates for every entrypoint of a contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BudgetReport {
    /// Limits the estimates were compared against.
    pub limits: NetworkLimits,
    /// Estimator tuning.
    pub estimator: CostModel,
    /// Module-level facts, when wasm was analysed.
    pub module: Option<ModuleBudget>,
    /// Per-entrypoint estimates.
    pub entrypoints: Vec<EntrypointBudget>,
}

/// Module-level budget facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModuleBudget {
    /// Display name of the module.
    pub name: String,
    /// Size in bytes.
    pub size_bytes: usize,
    /// Declared initial memory in bytes.
    pub memory_bytes: u64,
    /// Total instructions in all defined functions.
    pub total_instructions: u64,
    /// Number of exported functions.
    pub exported_functions: usize,
    /// Whether the module was compiled with the contract spec section.
    pub has_contract_spec: bool,
}

impl BudgetReport {
    /// Estimate the budget for every entrypoint in `model`.
    pub fn estimate(
        model: &ContractModel,
        wasm: Option<&WasmModule>,
        limits: NetworkLimits,
        estimator: CostModel,
    ) -> Self {
        let module = wasm.map(|module| ModuleBudget {
            name: module.name.clone(),
            size_bytes: module.size_bytes,
            memory_bytes: module.memory_bytes(),
            total_instructions: module.total_instructions(),
            exported_functions: module.exported_function_names().len(),
            has_contract_spec: module.has_contract_spec(),
        });

        let mut entrypoints: Vec<EntrypointBudget> = model
            .entrypoints()
            .map(|entrypoint| {
                build_entrypoint(entrypoint.name.as_str(), model, wasm, &limits, &estimator)
            })
            .collect();
        entrypoints.sort_by(|a, b| a.name.cmp(&b.name));
        BudgetReport {
            limits,
            estimator,
            module,
            entrypoints,
        }
    }

    /// Look up an entrypoint's estimate.
    pub fn entrypoint(&self, name: &str) -> Option<&EntrypointBudget> {
        self.entrypoints.iter().find(|item| item.name == name)
    }

    /// Every violation in the report, with the entrypoint name.
    pub fn violations(&self) -> Vec<(&str, &BudgetViolation)> {
        self.entrypoints
            .iter()
            .flat_map(|entrypoint| {
                entrypoint
                    .violations
                    .iter()
                    .map(move |violation| (entrypoint.name.as_str(), violation))
            })
            .collect()
    }

    /// Whether the contract is estimated to fit every limit.
    pub fn fits(&self) -> bool {
        self.violations().is_empty()
    }
}

fn build_entrypoint(
    name: &str,
    model: &ContractModel,
    wasm: Option<&WasmModule>,
    limits: &NetworkLimits,
    estimator: &CostModel,
) -> EntrypointBudget {
    let mut notes = Vec::new();
    let (instructions, instructions_from_wasm) =
        match wasm {
            Some(module) => match module.exports.iter().find(|export| {
                export.kind == crate::wasm::ExportKind::Function && export.name == name
            }) {
                Some(export) => (instruction_estimate(module, export.index, estimator), true),
                None => (
                    BudgetEstimate::unknown("entrypoint is not exported from the wasm module"),
                    false,
                ),
            },
            None => (
                BudgetEstimate::unknown("no wasm module provided; build with --target wasm32"),
                false,
            ),
        };
    if instructions.unbounded {
        if let Some(reason) = &instructions.reason {
            notes.push(format!("instructions: {reason}"));
        }
    }

    let (reads, writes) = source_ledger_usage(name, model, estimator);
    let memory_bytes = wasm.map(WasmModule::memory_bytes);

    let mut violations = Vec::new();
    push_violation(
        &mut violations,
        BudgetAxis::Instructions,
        &instructions,
        limits,
    );
    if let Some(memory) = memory_bytes {
        push_violation(
            &mut violations,
            BudgetAxis::Memory,
            &BudgetEstimate::exact(memory),
            limits,
        );
    }
    push_violation(&mut violations, BudgetAxis::ReadEntries, &reads, limits);
    push_violation(&mut violations, BudgetAxis::WriteEntries, &writes, limits);
    violations.sort_by_key(|violation| violation.axis);

    EntrypointBudget {
        name: name.to_string(),
        instructions,
        memory_bytes,
        reads,
        writes,
        violations,
        notes,
        instructions_from_wasm,
    }
}

fn push_violation(
    violations: &mut Vec<BudgetViolation>,
    axis: BudgetAxis,
    estimate: &BudgetEstimate,
    limits: &NetworkLimits,
) {
    let limit = axis.limit(limits);
    if limit == u64::MAX {
        return;
    }
    let certain = estimate.certainly_exceeds(limit);
    if certain || estimate.may_exceed(limit) {
        violations.push(BudgetViolation {
            axis,
            limit,
            estimate: estimate.clone(),
            certain,
        });
    }
}

/// Estimated ledger reads and writes for an entrypoint, from the source.
fn source_ledger_usage(
    name: &str,
    model: &ContractModel,
    estimator: &CostModel,
) -> (BudgetEstimate, BudgetEstimate) {
    let reachable: BTreeSet<String> = model.reachable_functions(name).into_iter().collect();
    let mut reads = Usage::default();
    let mut writes = Usage::default();

    for op in &model.storage_ops {
        if !reachable.contains(&op.site.function) {
            continue;
        }
        let weight = loop_weight(model, op.site.function.as_str(), op.site.span);
        if op.access.is_read() {
            reads.add(weight);
        }
        if op.access.is_write() {
            writes.add(weight);
        }
    }
    (reads.finish(estimator), writes.finish(estimator))
}

/// Accumulator for a ledger axis.
#[derive(Default)]
struct Usage {
    base: u64,
    bounded_extra: u64,
    unbounded_ops: u64,
    reason: Option<String>,
}

impl Usage {
    fn add(&mut self, weight: Option<u64>) {
        self.base += 1;
        match weight {
            Some(multiplier) => self.bounded_extra += multiplier.saturating_sub(1),
            None => {
                self.unbounded_ops += 1;
                if self.reason.is_none() {
                    self.reason = Some("storage access inside a loop with an unknown bound".into());
                }
            }
        }
    }

    fn finish(self, estimator: &CostModel) -> BudgetEstimate {
        let lower_bound = self.base;
        if self.unbounded_ops == 0 {
            BudgetEstimate::exact(lower_bound + self.bounded_extra)
        } else {
            let estimate = lower_bound
                + self.bounded_extra
                + self.unbounded_ops * estimator.assumed_loop_iterations;
            BudgetEstimate::unbounded(
                lower_bound,
                estimate,
                self.reason.unwrap_or_else(|| "unbounded loop".to_string()),
            )
        }
    }
}

/// Multiplier contributed by the loops enclosing a storage operation.
///
/// `Some(multiplier)` when every enclosing loop has a literal bound, `None` when at
/// least one loop's trip count is unknown.
fn loop_weight(
    model: &ContractModel,
    function: &str,
    span: crate::span::SourceSpan,
) -> Option<u64> {
    let mut multiplier: u64 = 1;
    let mut bounded = true;
    for loop_site in model.loops.iter().filter(|loop_site| {
        loop_site.site.function == function && loop_site.body_span.contains_span(span)
    }) {
        match &loop_site.bound {
            LoopBound::Literal(count) => multiplier = multiplier.saturating_mul(*count),
            _ => bounded = false,
        }
    }
    bounded.then_some(multiplier)
}

/// Estimated instruction cost of calling an exported function.
fn instruction_estimate(
    module: &WasmModule,
    entry_index: u32,
    estimator: &CostModel,
) -> BudgetEstimate {
    let mut reachable: BTreeSet<u32> = BTreeSet::new();
    let mut stack = vec![entry_index];
    while let Some(index) = stack.pop() {
        if !reachable.insert(index) {
            continue;
        }
        if let Some(function) = module.function(index) {
            stack.extend(function.calls.iter().copied());
        }
    }

    if let Some(cycle) = find_cycle(module, entry_index) {
        return BudgetEstimate::unknown(format!(
            "recursion detected through function index {cycle}"
        ));
    }

    let mut lower = 0u64;
    let mut looped = 0u64;
    let mut hard_reasons: Vec<&str> = Vec::new();
    for index in &reachable {
        let Some(function) = module.function(*index) else {
            hard_reasons.push("call into an imported function");
            continue;
        };
        lower += function.straight_line_instructions() * estimator.cost_per_instruction;
        lower += function.calls.len() as u64 * estimator.cost_per_call;
        looped += function.loop_instructions * estimator.cost_per_instruction;
        if function.has_call_indirect {
            hard_reasons.push("indirect call");
        }
        if function.has_memory_grow {
            hard_reasons.push("memory.grow");
        }
        if function.has_bulk_memory {
            hard_reasons.push("bulk memory operation");
        }
    }

    if looped > 0 {
        hard_reasons.push("loop bodies");
    }
    if hard_reasons.is_empty() {
        return BudgetEstimate::exact(lower);
    }

    hard_reasons.sort_unstable();
    hard_reasons.dedup();
    let estimate = lower + looped * estimator.assumed_loop_iterations;
    let reason = format!(
        "{} (assumed {} iterations per loop)",
        hard_reasons.join(", "),
        estimator.assumed_loop_iterations
    );
    BudgetEstimate::unbounded(lower, estimate, reason)
}

/// Find a function reachable from `start` that calls back into a frame on the
/// current path, i.e. a cycle in the wasm call graph.
fn find_cycle(module: &WasmModule, start: u32) -> Option<u32> {
    #[derive(Clone, Copy, PartialEq)]
    enum Color {
        InProgress,
        Done,
    }
    fn walk(
        module: &WasmModule,
        index: u32,
        colors: &mut std::collections::BTreeMap<u32, Color>,
    ) -> Option<u32> {
        match colors.get(&index) {
            Some(Color::InProgress) => return Some(index),
            Some(Color::Done) => return None,
            None => {}
        }
        colors.insert(index, Color::InProgress);
        if let Some(function) = module.function(index) {
            for callee in &function.calls {
                if let Some(found) = walk(module, *callee, colors) {
                    return Some(found);
                }
            }
        }
        colors.insert(index, Color::Done);
        None
    }
    let mut colors = std::collections::BTreeMap::new();
    walk(module, start, &mut colors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model;
    use crate::source::{FileId, SourceFile, SourceMap};

    fn model_of(source: &str) -> ContractModel {
        let file = SourceFile::parse(FileId(0), "src/lib.rs", "src/lib.rs", source).unwrap();
        model::build(&SourceMap::new(vec![file]), false)
    }

    #[test]
    fn counts_ledger_accesses_from_source() {
        let model = model_of(
            r#"
#[contractimpl]
impl Token {
    pub fn transfer(env: Env, from: Address) {
        from.require_auth();
        let balance: i128 = env.storage().persistent().get(&DataKey::Balance).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Balance, &(balance - 1));
        env.storage().instance().set(&DataKey::Total, &1);
    }
}
"#,
        );
        let report = BudgetReport::estimate(
            &model,
            None,
            NetworkLimits::mainnet(),
            CostModel::conservative(),
        );
        let entrypoint = report.entrypoint("transfer").unwrap();
        assert_eq!(entrypoint.reads, BudgetEstimate::exact(1));
        assert_eq!(entrypoint.writes, BudgetEstimate::exact(2));
        assert!(!entrypoint.instructions_from_wasm);
        assert!(report.fits());
    }

    #[test]
    fn multiplies_literal_loops_and_flags_unknown_ones() {
        let model = model_of(
            r#"
#[contractimpl]
impl Token {
    pub fn bounded(env: Env) {
        for i in 0..8 {
            env.storage().persistent().get(&i);
        }
    }

    pub fn unbounded(env: Env, holders: Vec<Address>) {
        for holder in holders.iter() {
            env.storage().persistent().get(holder);
        }
    }
}
"#,
        );
        let report = BudgetReport::estimate(
            &model,
            None,
            NetworkLimits::mainnet(),
            CostModel::conservative(),
        );
        let bounded = report.entrypoint("bounded").unwrap();
        assert_eq!(bounded.reads.bounded_upper_bound, Some(8));
        assert!(!bounded.reads.unbounded);

        let unbounded = report.entrypoint("unbounded").unwrap();
        assert!(unbounded.reads.unbounded);
        assert_eq!(unbounded.reads.lower_bound, 1);
        assert_eq!(unbounded.reads.estimate, 1 + 100);
    }

    #[test]
    fn read_ceiling_violations_are_reported() {
        let model = model_of(
            r#"
#[contractimpl]
impl Token {
    pub fn spam(env: Env) {
        for i in 0..500 {
            env.storage().persistent().get(&i);
        }
    }
}
"#,
        );
        let report = BudgetReport::estimate(
            &model,
            None,
            NetworkLimits::mainnet(),
            CostModel::conservative(),
        );
        let entrypoint = report.entrypoint("spam").unwrap();
        let violation = entrypoint.violation(BudgetAxis::ReadEntries).unwrap();
        assert!(violation.certain);
        assert_eq!(violation.limit, 200);
        assert_eq!(violation.estimate.estimate, 500);
        assert!(!report.fits());
    }

    #[test]
    fn estimates_instructions_from_wasm() {
        let model = model_of(
            r#"
#[contractimpl]
impl Token {
    pub fn ping(env: Env) {
        env.storage().instance().get(&KEY);
    }
}
"#,
        );
        let bytes = wat::parse_str(
            r#"
(module
  (memory 1)
  (func $ping
    (i32.const 1)
    drop)
  (export "ping" (func $ping))
)
"#,
        )
        .unwrap();
        let module = WasmModule::parse("contract.wasm", &bytes).unwrap();
        let report = BudgetReport::estimate(
            &model,
            Some(&module),
            NetworkLimits::mainnet(),
            CostModel::conservative(),
        );
        let entrypoint = report.entrypoint("ping").unwrap();
        assert!(entrypoint.instructions_from_wasm);
        assert!(!entrypoint.instructions.unbounded);
        assert_eq!(
            entrypoint.instructions.bounded_upper_bound,
            Some(entrypoint.instructions.lower_bound)
        );
        assert_eq!(entrypoint.memory_bytes, Some(65_536));
        assert_eq!(report.module.as_ref().unwrap().exported_functions, 1);
    }

    #[test]
    fn loops_in_wasm_make_the_instruction_estimate_unbounded() {
        let model = model_of(
            r#"
#[contractimpl]
impl Token {
    pub fn iterate(env: Env) {}
}
"#,
        );
        let bytes = wat::parse_str(
            r#"
(module
  (func $iterate (param i32)
    (loop $l (br_if $l (i32.const 0))))
  (export "iterate" (func $iterate))
)
"#,
        )
        .unwrap();
        let module = WasmModule::parse("contract.wasm", &bytes).unwrap();
        let report = BudgetReport::estimate(
            &model,
            Some(&module),
            NetworkLimits::mainnet(),
            CostModel::conservative(),
        );
        let entrypoint = report.entrypoint("iterate").unwrap();
        assert!(entrypoint.instructions.unbounded);
        assert!(entrypoint
            .instructions
            .reason
            .as_deref()
            .unwrap()
            .contains("assumed 100 iterations"));
    }

    #[test]
    fn detects_wasm_recursion_and_marks_it_unbounded() {
        let model = model_of(
            r#"
#[contractimpl]
impl Token {
    pub fn recurse(env: Env) {}
}
"#,
        );
        let bytes = wat::parse_str(
            r#"
(module
  (func $recurse (call $recurse))
  (export "recurse" (func $recurse))
)
"#,
        )
        .unwrap();
        let module = WasmModule::parse("contract.wasm", &bytes).unwrap();
        let report = BudgetReport::estimate(
            &model,
            Some(&module),
            NetworkLimits::mainnet(),
            CostModel::conservative(),
        );
        let entrypoint = report.entrypoint("recurse").unwrap();
        assert!(entrypoint.instructions.unbounded);
        assert!(entrypoint
            .instructions
            .reason
            .as_deref()
            .unwrap()
            .contains("recursion"));
    }

    #[test]
    fn instruction_limit_violations_are_flagged() {
        let model = model_of(
            r#"
#[contractimpl]
impl Token {
    pub fn heavy(env: Env) {}
}
"#,
        );
        let mut limits = NetworkLimits::mainnet();
        limits.max_instructions_per_tx = 4;
        let bytes = wat::parse_str(
            r#"
(module
  (func $heavy
    (i32.const 1) (i32.const 2) (i32.const 3) (i32.const 4) (i32.const 5)
    (i32.const 6) (i32.const 7) (i32.const 8) (i32.const 9)
    drop drop drop drop drop drop drop drop drop)
  (export "heavy" (func $heavy))
)
"#,
        )
        .unwrap();
        let module = WasmModule::parse("contract.wasm", &bytes).unwrap();
        let report =
            BudgetReport::estimate(&model, Some(&module), limits, CostModel::conservative());
        let violation = report
            .entrypoint("heavy")
            .unwrap()
            .violation(BudgetAxis::Instructions)
            .unwrap();
        assert!(violation.certain);
        assert!(!report.fits());
        assert!(violation.ratio() > 1.0);
    }

    #[test]
    fn memory_limit_violations_are_flagged() {
        let model = model_of(
            r#"
#[contractimpl]
impl Token {
    pub fn big(env: Env) {}
}
"#,
        );
        let bytes =
            wat::parse_str("(module (memory 100) (func $big) (export \"big\" (func $big)))")
                .unwrap();
        let module = WasmModule::parse("contract.wasm", &bytes).unwrap();
        let mut limits = NetworkLimits::mainnet();
        limits.max_memory_bytes = 1024;
        let report =
            BudgetReport::estimate(&model, Some(&module), limits, CostModel::conservative());
        let violation = report
            .entrypoint("big")
            .unwrap()
            .violation(BudgetAxis::Memory)
            .unwrap();
        assert!(violation.certain);
        assert_eq!(violation.estimate.lower_bound, 100 * 65_536);
    }

    #[test]
    fn missing_wasm_leaves_instructions_unknown() {
        let model = model_of(
            r#"
#[contractimpl]
impl Token {
    pub fn f(env: Env) {}
}
"#,
        );
        let report = BudgetReport::estimate(
            &model,
            None,
            NetworkLimits::mainnet(),
            CostModel::conservative(),
        );
        let entrypoint = report.entrypoint("f").unwrap();
        assert!(entrypoint.instructions.unbounded);
        assert_eq!(entrypoint.instructions.lower_bound, 0);
        assert!(!entrypoint
            .violations
            .iter()
            .any(|v| v.axis == BudgetAxis::Instructions));
    }

    #[test]
    fn permissive_limits_never_violate() {
        let model = model_of(
            r#"
#[contractimpl]
impl Token {
    pub fn spam(env: Env) {
        for i in 0..5000 {
            env.storage().persistent().get(&i);
        }
    }
}
"#,
        );
        let report = BudgetReport::estimate(
            &model,
            None,
            NetworkLimits::permissive(),
            CostModel::conservative(),
        );
        assert!(report.fits());
        assert!(report.violations().is_empty());
    }
}
