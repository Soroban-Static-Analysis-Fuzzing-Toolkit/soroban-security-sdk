# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/). Rule ids are permanent across
versions; a rule's behaviour may change, and such changes are listed here.

## [Unreleased]

## [0.2.0] - 2026-10-29

Validated against audited production code for the first time. On
`stellar/soroban-examples`, `OpenZeppelin/stellar-contracts` and
`blend-capital/blend-contracts-v2`, findings dropped from 924 to 109 while the
number of analysed entrypoints rose from 247 to 512. Each remaining finding was
reviewed by hand. See
[`docs/real-world-evaluation.md`](docs/real-world-evaluation.md).

### Added

- Workspace-aware analysis: `Project::from_workspace` and `analyze_workspace`
  load each Cargo package separately and merge the reports. The CLI uses this
  for directories, unless `--wasm` is given. Packages that do not depend on
  `soroban-sdk`, and `fuzz`/`tests`/`benches` packages, are skipped with a
  diagnostic.
- Workspace members inherit `[profile.release]` from the workspace root, as
  Cargo does (`PackageInfo::load_in_workspace`).
- OpenZeppelin access-control macros (`#[only_owner]`, `#[only_admin]`,
  `#[only_role]`, `#[only_any_role]`) are modelled as `require_auth`.
- Storage keys bound with `let key = ...` resolve to the expression they hold.
- `PanicSite::inputs`: the function parameters a panicking expression depends on.
- `ContractModel::external_calls`: `module::function(..)` calls that resolve
  outside the analysed package.
- `scripts/real-world-eval.sh` and a weekly `real-world` workflow that fails if
  the corpus total exceeds its budget.
- Release workflow publishing prebuilt `soroban-sec` binaries for Linux, macOS
  and Windows; issue templates for false positives and missed vulnerabilities;
  `SECURITY.md`.

### Changed

- **SSDK013** now reports an `unwrap`/`expect`/index in an entrypoint that
  depends on a caller-supplied parameter, and `todo!`/`unimplemented!`. Before,
  it reported every panic, including invariants and explicit `panic!`
  rejections, which are how Soroban contracts reject calls.
- **SSDK011** reports ledger time/sequence only when reduced or mixed (`%`, `^`,
  `&`), not in deadline comparisons or elapsed-time arithmetic.
- **SSDK002** compares a key held in a local variable or parameter only within
  one function.
- **SSDK008** no longer treats `Allowance` keys as durable; SEP-41 allowances
  live in temporary storage by design.
- **SSDK023** requires a `get` of the key in the same function; a `has` guard is
  no longer taken as evidence of an append.
- **SSDK014** reports the manifest path relative to the scanned root.

### Fixed

- Methods of `#[contractimpl] impl Trait for Contract` are now entrypoints.
  Before, every rule ignored trait-based contracts, because trait items cannot
  be `pub`.
- **SSDK010** no longer reports `__check_auth` hooks that delegate the decision
  through `require_auth*`, `custom_account().delegate_auth` or a function in
  another crate.
- Test-only files (`src/test.rs` declared with `#[cfg(test)] mod test;`, and
  files under `tests/`, `benches/` and `fuzz/`) are no longer analysed as
  contract code.
- `#[cfg(not(test))]` items were treated as test code and skipped.
- `Cargo.toml` pointed `repository` and `homepage` at the wrong GitHub
  organisation.

## [0.1.0] - 2026-09-13

Initial release: detector framework, 19-rule catalogue, contract model,
resource-budget estimator, SARIF output, `soroban-sec` CLI with baselines,
GitHub Action, and the `soroban-sec-fuzz` invariant fuzzing harness.
