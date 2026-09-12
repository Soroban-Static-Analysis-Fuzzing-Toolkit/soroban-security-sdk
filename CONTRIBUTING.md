# Contributing

Thanks for helping make Soroban contracts safer.

The project is deliberately structured so that the most valuable contribution — a
new detector — is **one file plus one line**. Detectors are discovered through the
[`inventory`](https://docs.rs/inventory) registry, so there is no central list to
edit and no risk of merge conflicts between rule authors.

## Getting started

```bash
cargo build --workspace
cargo test  --workspace
cargo run   -p soroban-sec -- --list-rules      # print the catalogue
cargo run   -p soroban-sec -- path/to/contract  # analyse a crate
cargo test  -p soroban-sec-fuzz                 # the invariant fuzzing harness
```

The workspace has three crates: `soroban-security-sdk` (the analyser),
`soroban-sec` (the CLI), and `soroban-sec-fuzz` (property-based invariant
fuzzing, documented in [`docs/fuzzing.md`](docs/fuzzing.md)).

## Adding a detector

A step-by-step walkthrough lives in
[`docs/writing-a-detector.md`](docs/writing-a-detector.md). In short:

1. Pick the next free `SSDK0xx` id and a stable kebab-case name.
2. Create `crates/soroban-security-sdk/src/detectors/<name>.rs` with a `Detector`
   implementation and a `declare_detector!` invocation.
3. Re-export it from `src/detectors/mod.rs`.
4. Add a fixture under `crates/soroban-security-sdk/tests/fixtures/` and list it in
   `tests/corpus.rs` with the **exact** set of rules it must produce.
5. Run `cargo test --workspace`.

## Rule ids

Ids are permanent: they appear in reports, baselines and CI thresholds. A rule
keeps its id even if its implementation changes. `SSDK001`–`SSDK099` are reserved
for the built-in catalogue; downstream crates shipping private rules should use
their own prefix.

## Working on other parts

- **CLI** (`crates/soroban-sec`): keep the output stable — downstream CI parses
  the JSON and SARIF formats. Add a test under `#[cfg(test)]` in `main.rs` for new
  flags, and consider whether the change affects `--fail-on` exit codes.
- **Fuzzing harness** (`crates/soroban-sec-fuzz`): new behaviour needs a unit test
  with a deliberately buggy model, so shrinking is exercised, not just the happy
  path.
- **GitHub Action** (`action.yml`): a composite action; validate it against a
  throwaway repository before changing its inputs.

## What CI checks

Every pull request must be clean under:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test -p soroban-security-sdk --no-default-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

## Precision is a feature

A rule that fires on healthy code will be switched off, and a rule that is off
catches nothing. Before opening a pull request, make sure:

- The fixture corpus still reports **exactly** the expected rules. The assertions
  in `tests/corpus.rs` are set equality, so an extra finding is a test failure.
- Every clean fixture under `tests/fixtures/clean/` produces zero findings.
- Heuristic rules use a lower `confidence` rather than a lower `severity`.

If you find a false positive in a built-in rule, please open an issue with the
smallest contract that reproduces it; that snippet becomes a regression fixture.

## Reporting a security issue in the toolkit itself

Please open a private security advisory rather than a public issue if the problem
could be used against the tool's users.

## License

By contributing you agree that your contributions are licensed under the MIT
License, as described in [`LICENSE`](LICENSE).
