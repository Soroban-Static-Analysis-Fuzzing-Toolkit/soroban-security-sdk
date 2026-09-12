# soroban-security-sdk

Developer-facing SDK for static analysis of [Soroban](https://soroban.stellar.org/)
smart contracts. It provides:

1. **A detector framework.** A two-method [`Detector`] trait, the
   `declare_detector!` registration macro, and a typed [`FindingSink`] so a new
   rule is one file plus one line.
2. **A typed contract model.** Source is parsed with `syn` into a `Project`, from
   which the SDK derives entrypoints, storage operations, authorization checks,
   arithmetic sites, loops, casts and cross-contract calls. A compiled `.wasm`
   module can be loaded alongside it for instruction and memory accounting.
3. **A resource-budget estimator.** Per entrypoint, the SDK estimates instruction
   count, memory, and ledger read/write entries, and compares them with
   configurable network limits.
4. **A built-in rule catalogue** of fourteen Soroban-specific detectors, from
   `missing-require-auth` to `overflow-checks-disabled`.

## Example

```rust
use soroban_security_sdk::prelude::*;

let project = Project::from_dir(".")?;
let report = analyze(&project, &AnalysisConfig::default());

for finding in &report.findings {
    println!("{} {} {}", finding.severity, finding.headline_location(), finding.message);
}
# Ok::<(), soroban_security_sdk::Error>(())
```

## Adding a detector

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
        let _ = (ctx, sink);
    }
}

declare_detector!(MyRule);
```

The engine discovers detectors through the `inventory` registry, so a downstream
crate can ship private rules without forking this one. See the repository's
`docs/writing-a-detector.md` for the full walkthrough.

## Feature flags

- `detectors` *(default)* — compiles the built-in rule catalogue. Disable it to
  embed the framework with only your own rules; the model, budget estimator and
  reporters stay available.

## License

MIT.
