# soroban-security-sdk

An open-source security toolkit for [Soroban](https://soroban.stellar.org/) smart
contracts: a detector engine for the vulnerability classes that are specific to
Soroban, a typed model of a contract derived from its Rust source, and a
resource-budget estimator that bounds instruction, memory and ledger-entry usage
per entrypoint.

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
| `crates/soroban-sec` | The command-line front end. |

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

## Rule catalogue

| id | rule | category | default severity |
|----|------|----------|------------------|
| `SSDK001` | `missing-require-auth` | auth | high |
| `SSDK002` | `storage-tier-confusion` | storage | high |
| `SSDK003` | `unchecked-token-arithmetic` | arithmetic | high |
| `SSDK004` | `lossy-cast` | arithmetic | medium |
| `SSDK005` | `wrapping-arithmetic` | arithmetic | high |
| `SSDK006` | `unbounded-loop-over-storage` | resource-budget | high |
| `SSDK007` | `resource-budget-exceeded` | resource-budget | high |
| `SSDK008` | `temporary-storage-write` | storage | medium |
| `SSDK009` | `missing-ttl-extension` | storage | medium |
| `SSDK010` | `check-auth-without-verification` | access-control | critical |
| `SSDK011` | `predictable-randomness` | randomness | high |
| `SSDK012` | `unauthorized-upgrade` | upgradeability | critical |
| `SSDK013` | `panic-on-caller-input` | panic-safety | medium |
| `SSDK014` | `overflow-checks-disabled` | arithmetic | high |

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

## License

MIT. See [`LICENSE`](LICENSE).
