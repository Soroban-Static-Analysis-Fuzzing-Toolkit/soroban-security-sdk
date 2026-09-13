# soroban-security-sdk

An open-source security toolkit for [Soroban](https://soroban.stellar.org/) smart
contracts: a detector engine for the vulnerability classes that are specific to
Soroban, a typed model of a contract derived from its Rust source, a
resource-budget estimator that bounds instruction, memory and ledger-entry usage
per entrypoint, and a property-based fuzzing harness for declaring and checking
invariants. Findings can be emitted as SARIF for GitHub code scanning.

Soroban is not EVM. It forbids reentrancy, has no implicit sender, caps a
transaction at 200 ledger reads and 200 writes, and meters CPU instructions and
contract memory on every call. The bugs that follow from those rules — a missing
`require_auth`, the same ledger key read and written through different storage
tiers, arithmetic that wraps because release overflow checks are off — are not
caught by a general-purpose Rust linter. This project encodes them as detectors.

## Layout

| crate | purpose |
|-------|---------|
| `crates/soroban-security-sdk` | The developer-facing library: detector trait, macros, contract model, budget estimator and the built-in rule catalogue. |
| `crates/soroban-sec` | The command-line front end (text / JSON / SARIF, rule catalogue, thresholds). |
| `crates/soroban-sec-fuzz` | Property-based invariant fuzzing: declare invariants, generate call sequences, shrink failures. |

## Quick start

```rust
use soroban_security_sdk::prelude::*;

let project = Project::from_dir(".")?;
let report = analyze(&project, &AnalysisConfig::default());

println!("{}", report.summary());
for finding in &report.findings {
    println!("{} {} {}", finding.severity, finding.headline_location(), finding.message);
}
# Ok::<(), soroban_security_sdk::Error>(())
```

An [`AnalysisReport`] carries the findings, the findings that inline
suppressions silenced, non-fatal diagnostics (unparseable files, unknown rule
ids, unused suppressions) and the per-entrypoint budget estimates.

## Command line

```bash
soroban-sec path/to/contract                       # human-readable report
soroban-sec path/to/contract --wasm contract.wasm  # include the compiled code
soroban-sec path/to/contract --format sarif -o out.sarif
soroban-sec path/to/contract --fail-on high        # non-zero exit for CI
soroban-sec --list-rules                       # human-readable catalogue
soroban-sec --list-rules --format json         # machine-readable catalogue
soroban-sec --list-rules --format markdown      # the docs/rules.md source
soroban-sec --explain SSDK001
```

Adopting the scanner on an existing contract? Record the findings you already
accept as a baseline, then fail CI only on new ones:

```bash
soroban-sec path/to/contract --write-baseline .soroban-sec.baseline
soroban-sec path/to/contract --baseline .soroban-sec.baseline --fail-on high
```

The baseline is a plain-text list of finding fingerprints (one per line, `#`
comments allowed), so it merges cleanly in review.

`--format sarif` emits SARIF 2.1.0, so a run can be uploaded straight to GitHub
code scanning and appear as annotations on the pull request:

```yaml
- run: soroban-sec . --format sarif -o soroban-sec.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: soroban-sec.sarif
```

## Rule catalogue

Each rule carries a severity, confidence and description; severity, confidence,
tags and references can be listed with `--explain RULE`, and the full generated
reference lives in [`docs/rules.md`](docs/rules.md).

| id | rule | category | default severity |
|----|------|----------|------------------|
| `SSDK001` | `missing-require-auth` | auth | high |
| `SSDK002` | `storage-tier-confusion` | storage | high |
| `SSDK003` | `unchecked-token-arithmetic` | arithmetic | high |
| `SSDK004` | `lossy-cast` | arithmetic | medium |
| `SSDK005` | `wrapping-arithmetic` | arithmetic | high |
| `SSDK006` | `unbounded-loop-over-storage` | resource-budget | high |
| `SSDK007` | `resource-budget-exceeded` | resource-budget | high |
| `SSDK008` | `temporary-storage-for-durable-data` | storage | high |
| `SSDK009` | `missing-ttl-extension` | storage | medium |
| `SSDK010` | `check-auth-without-verification` | access-control | critical |
| `SSDK011` | `predictable-randomness` | randomness | high |
| `SSDK012` | `unauthorized-upgrade` | upgradeability | critical |
| `SSDK013` | `panic-on-caller-input` | panic-safety | medium |
| `SSDK014` | `overflow-checks-disabled` | arithmetic | high |
| `SSDK020` | `wasm-storage-without-auth` | auth | high |
| `SSDK021` | `contract-oversized` | resource-budget | high |
| `SSDK022` | `wasm-start-function` | best-practice | medium |
| `SSDK023` | `unbounded-entry-growth` | storage | high |
| `SSDK024` | `unauthorized-deploy` | upgradeability | high |

Severity can be overridden per rule in `.soroban-sec.toml` without changing the
catalogue:

```toml
[rules.severity]
SSDK013 = "high"
```

## Suppressing a finding

Findings are sometimes deliberate. Rather than disabling a rule for the whole
project, acknowledge one in place:

```rust
// soroban-sec: ignore SSDK003 -- amount is bounded by MAX_SUPPLY above
let total = balance + amount;
```

A comment inside an item scopes to that item; `ignore-file` silences the whole
file. Suppressions that match nothing are reported as diagnostics so stale
ignores do not accumulate.

## Adding a detector

A rule is one file plus one line. The engine discovers detectors through the
[`inventory`](https://docs.rs/inventory) registry, so no central list needs to be
edited and a downstream crate can ship private rules without forking this one.

```rust
use soroban_security_sdk::prelude::*;

pub struct MyRule;

impl Detector for MyRule {
    const META: DetectorMeta = DetectorMeta::new(
        RuleId::new("SSDK100"),
        "my-rule",
        "One sentence describing what is wrong.",
    )
    .severity(Severity::Medium)
    .confidence(Confidence::High)
    .category(Category::BestPractice);

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        for entrypoint in ctx.entrypoints() {
            sink.report("what was observed and why it matters")
                .primary(entrypoint.file, entrypoint.span)
                .in_function(entrypoint.name.clone())
                .help("how to fix it")
                .emit();
        }
    }
}

declare_detector!(MyRule);
```

See [`docs/writing-a-detector.md`](docs/writing-a-detector.md) for the full
walkthrough, including how to test a rule against a fixture.

## Invariant fuzzing

The [`soroban-sec-fuzz`](crates/soroban-sec-fuzz) crate closes the other half of
the problem: it generates call sequences, checks invariants after every call, and
shrinks any failure to a minimal reproduction.

```rust
use soroban_sec_fuzz::{fuzz, invariant, sequence, FuzzConfig, SystemUnderTest};

// 1. Describe the contract and the calls it accepts.
// 2. Declare the properties that must always hold.
let conserved = invariant("total supply is conserved", |token: &TokenModel| {
    if token.total() == token.sum_of_balances() { Ok(()) } else { Err("supply changed".into()) }
});

fuzz(&FuzzConfig::default(), TokenModel::default, calls(), &[&conserved]).assert_ok();
```

See [`docs/fuzzing.md`](docs/fuzzing.md) for the full walkthrough, including how
to adapt a real contract over the Soroban test environment.

## GitHub Action

A composite action runs the analyser and uploads the SARIF report to code
scanning, so findings appear inline on the pull request:

```yaml
- uses: Soroban-Static-Analysis-Fuzzing-Toolkit/soroban-security-sdk@main
  with:
    path: contracts/token
    wasm: target/wasm32-unknown-unknown/release/token.wasm
    fail-on: high
```

## Testing and precision

The catalogue is measured against a fixture corpus in
[`crates/soroban-security-sdk/tests/fixtures/`](crates/soroban-security-sdk/tests/fixtures/).
Every fixture declares the **exact** set of rules it must produce and the clean
fixtures must produce none, so an extra finding is a test failure rather than a
silent regression. The corpus includes *near-miss* fixtures — code that
superficially resembles a vulnerability but is correct — and
`tests/corpus.rs` reports both precision and recall, currently 100% on each:
precision against the declared rule sets and recall against the catalogue, since
every rule must be exercised by at least one fixture.

The analyser also fuzzes itself: `tests/robustness.rs` feeds the parser and model
builder generated token soup and mutated real contracts, because a panic on code
that does not compile would deny service to the tool's own users.

CI runs `cargo fmt --check`, `clippy -D warnings`, the full test matrix,
`rustdoc -D warnings` and a build against the declared minimum Rust (1.85) on
every pull request — see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

MIT. See [`LICENSE`](LICENSE).
