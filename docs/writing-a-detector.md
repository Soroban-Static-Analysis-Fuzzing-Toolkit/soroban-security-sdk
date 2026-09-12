# Writing a detector

A detector is a rule: a piece of code that inspects a project and reports the
places where a Soroban-specific mistake appears. The engine is designed so that a
new rule is **one file plus one line**, which is what makes the catalogue
practical to grow one pull request at a time.

This walkthrough builds a real rule end to end.

## 1. Decide what the rule is

Every rule has a stable id, a kebab-case name and a one-line summary. Ids are
validated at compile time, so a typo fails the build. The built-in catalogue
uses `SSDK001`–`SSDK099`; pick the next free id (the catalogue is listed in
[`src/detectors/mod.rs`](../crates/soroban-security-sdk/src/detectors/mod.rs)).

| field | meaning |
|-------|---------|
| `severity` | how damaging a true positive is (`Info` .. `Critical`) |
| `confidence` | how likely a hit is a true positive (`Low` .. `Certain`) |
| `category` | the vulnerability class, used for filtering and reporting |

Prefer lowering **confidence** rather than severity when a rule is heuristic:
severity answers "how bad if true", confidence answers "how likely is this
true".

## 2. Look at the model before the syntax tree

`AnalysisContext` hands out a typed [`ContractModel`] that already classifies
entrypoints, storage operations, authorization checks, arithmetic sites, loops,
casts, panics, cross-contract calls and upgrades. Ask it a question instead of
re-walking `syn`:

```rust
use soroban_security_sdk::prelude::*;

fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
    let model = ctx.model();

    // Every function reachable from `function`, following the source call graph.
    model.reachable_functions("transfer");

    // Storage ops inside one function.
    model.storage_ops_in("transfer");

    // Whether a function authorizes, directly or in a helper.
    model.has_transitive_auth("transfer");

    // The tier a key is stored under, grouped by canonical key text.
    model.storage_ops_by_key();

    // Enumerate exported entrypoints.
    for entrypoint in ctx.entrypoints() { /* ... */ }
}
```

Transitive queries matter. Contracts routinely factor `require_auth` and TTL
bumps into private helpers, so a rule that only looks at the entrypoint's own
body will report false positives.

## 3. Write the detector

Create `src/detectors/my_rule.rs`:

```rust
//! `SSDK100`: a short description of the problem.

use crate::category::Category;
use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::finding::FindingSink;
use crate::rule::{DetectorMeta, Reference, RuleId};
use crate::severity::{Confidence, Severity};

/// A state-changing entrypoint with no authorization check.
#[derive(Debug, Default)]
pub struct MissingRequireAuth;

impl Detector for MissingRequireAuth {
    const META: DetectorMeta = DetectorMeta::new(
        RuleId::new("SSDK100"),
        "my-rule",
        "One sentence describing what is wrong.",
    )
    .severity(Severity::High)
    .confidence(Confidence::Medium)
    .category(Category::Auth)
    .description("A longer paragraph: why the pattern is dangerous and when it applies.")
    .tags(&["auth", "require-auth"])
    .references(&[Reference::new(
        "Stellar docs: Authorization",
        "https://developers.stellar.org/docs/learn/encyclopedia/security/authorization",
    )]);

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        for entrypoint in ctx.entrypoints() {
            if !entrypoint_writes_state(ctx, &entrypoint.name) {
                continue;
            }
            if ctx.model().has_transitive_auth(&entrypoint.name) {
                continue;
            }
            sink.report(format!(
                "`{}` changes state without authorizing any address",
                entrypoint.name
            ))
            .primary(entrypoint.file, entrypoint.span)
            .in_function(entrypoint.name.clone())
            .note("Why this instance is suspicious.")
            .help("Add `<address>.require_auth()` before the first write.")
            .emit();
        }
    }
}

crate::declare_detector!(MissingRequireAuth);
```

The `declare_detector!` invocation registers the detector with the global
registry at link time. Nothing else in the crate needs to change except the
`mod` line below.

### Point at something actionable

Use the span of the expression that must change, not the whole function. The
builder's `severity`, `confidence`, `secondary`, `label` and `fix` methods let a
finding explain itself and, where possible, offer a machine-applicable edit.

### Do not report without evidence

If a pattern needs a type you could not resolve, skip it or lower confidence.
Never guess: a rule that fires on healthy code will be turned off, and a rule
that is off catches nothing.

## 4. Register it

Add the module and re-export it in `src/detectors/mod.rs`:

```rust
mod my_rule;
pub use my_rule::MissingRequireAuth;
```

That is the one line the "one file plus one line" promise refers to.

## 5. Test it

Both positive and negative cases are required. The `ProjectBuilder` lets you
build a project from source text, with an optional `Cargo.toml`, all in memory.

```rust
use soroban_security_sdk::prelude::*;

fn analyze_source(source: &str) -> AnalysisReport {
    let project = ProjectBuilder::new()
        .source("src/lib.rs", source)
        .unwrap()
        .build();
    analyze(&project, &AnalysisConfig::default())
}

#[test]
fn fires_on_unauthorized_state_change() {
    let report = analyze_source(
        r#"
#[contractimpl]
impl Token {
    pub fn set_fee(env: Env, fee: i128) {
        env.storage().instance().set(&DataKey::Fee, &fee);
    }
}
"#,
    );
    assert!(report
        .findings_for(&RuleId::new("SSDK100"))
        .next()
        .is_some());
}

#[test]
fn is_quiet_when_authorized() {
    let report = analyze_source(
        r#"
#[contractimpl]
impl Token {
    pub fn set_fee(env: Env, admin: Address, fee: i128) {
        admin.require_auth();
        env.storage().instance().set(&DataKey::Fee, &fee);
    }
}
"#,
    );
    assert!(report.findings_for(&RuleId::new("SSDK100")).next().is_none());
}
```

Integration tests live in
[`crates/soroban-security-sdk/tests/detectors.rs`](../crates/soroban-security-sdk/tests/detectors.rs).

## 6. Tune the rule, not the code

Users can change a rule's severity, disable it, or restrict a run to a category
from `.soroban-sec.toml`:

```toml
[rules]
enabled = ["SSDK100"]
categories = ["auth"]

[rules.severity]
SSDK100 = "critical"
```

`default_enabled = false` (via `DetectorMeta::disabled_by_default`) makes a rule
opt-in; `requires_wasm` makes the engine skip it when no compiled module was
supplied and emit a diagnostic instead.

## Checklist for a new rule

- [ ] Stable `SSDK` id, unique across the catalogue.
- [ ] Severity and confidence reflect the evidence the rule actually has.
- [ ] Long description explains *why* the pattern is dangerous.
- [ ] At least one reference to authoritative documentation or an incident.
- [ ] Positive **and** negative test cases.
- [ ] Transitive queries used for authorization and TTL checks.
- [ ] Registered with `declare_detector!` and re-exported from `detectors/mod.rs`.
- [ ] `cargo test` and `cargo clippy` clean.
