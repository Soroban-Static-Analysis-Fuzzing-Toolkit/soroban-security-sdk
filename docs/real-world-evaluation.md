# Real-world evaluation

The fixture corpus in `crates/soroban-security-sdk/tests/fixtures/` shows that each
rule fires on the pattern it targets and stays quiet on near misses. It can't show
how the scanner behaves on code nobody wrote for it. This page covers that: we run
`soroban-sec` on three widely used, audited Soroban codebases and triage what it
reports.

Reproduce it with:

```bash
scripts/real-world-eval.sh            # clones into target/real-world/
```

The script pins each repository to the commit below. The weekly
`real-world` workflow runs the same script, so a detector change that floods real
code with findings fails CI before it ships.

## Corpus

| repository | commit | what it is |
|------------|--------|------------|
| [stellar/soroban-examples](https://github.com/stellar/soroban-examples) | `03d42aa` | SDF's official example contracts (~40 independent crates) |
| [OpenZeppelin/stellar-contracts](https://github.com/OpenZeppelin/stellar-contracts) | `ddc327e` | OpenZeppelin's Stellar library: tokens, access control, governance, accounts, RWA |
| [blend-capital/blend-contracts-v2](https://github.com/blend-capital/blend-contracts-v2) | `0bf9b74` | Blend v2 lending protocol (pool, backstop, emitter, factory) |

## Results

Findings on the default configuration (no `.wasm`, no baseline):

| repository | v0.1.0 | now |
|------------|-------:|----:|
| soroban-examples | 379 | 52 |
| stellar-contracts | 374 | 47 |
| blend-contracts-v2 | 171 | 10 |
| **total** | **924** | **109** |

At the same time, the number of entrypoints the scanner analyses rose from 247
to 512 (see the trait-implementation fix below). So the drop in findings comes
from fixing false positives, not from looking at less code.

### What the first run got wrong

The first run produced 924 findings, and most were noise. It also missed half
of the code. Each cause was a systematic gap, not a one-off case, so each was
fixed in the engine with a regression test:

| cause | effect | fix |
|-------|--------|-----|
| Methods of `#[contractimpl] impl Trait for Contract` were not treated as entrypoints, because trait items cannot be `pub` | Every rule was blind to trait-based contracts, including Blend's entire lending API (`submit`, `flash_loan`, auctions, admin) | `#[contractimpl]` trait-impl methods are entrypoints, as in the Soroban SDK. |
| Test files (`src/test.rs` via `#[cfg(test)] mod test;`, `tests/`, `fuzz/`, `benches/`) were analysed as contract code | 488 findings in test code | Whole test-only files are now excluded (`model/test_files.rs`). `#[cfg(not(test))]` is no longer mistaken for test code. |
| A multi-crate repository was merged into one model | Unrelated contracts' `DataKey::Balance` looked like one key in two tiers. Helpers were matched by name across crates. Workspace `[profile.release]` was ignored. | Each Cargo package is analysed on its own (`Project::from_workspace`, `analyze_workspace`). Members inherit the workspace release profile. Non-Soroban crates and fuzz harnesses are skipped with a diagnostic. |
| SSDK013 flagged every `panic!`, `unwrap` and `expect` | 598 findings. In Soroban, panicking *is* how a call is rejected. | The rule now does what its name says: it reports an `unwrap`/`expect`/index in an entrypoint that depends on a caller-supplied parameter, plus `todo!`/`unimplemented!`. Invariants (`get(&Admin).unwrap()`) and `checked_*(..).expect(..)` guards are not reported. |
| SSDK011 treated any use of `ledger().timestamp()`/`sequence()` as entropy | 71 findings on deadline checks like `if now > expiry` | Only entropy-shaped uses (`%`, `^`, `&`) are reported. |
| SSDK001 didn't recognise OpenZeppelin's access-control macros | `#[only_owner]`, `#[only_admin]`, `#[only_role]`, `#[only_any_role]` entrypoints reported as unauthenticated | These macros expand to `require_auth` and are now modelled as such. `#[has_role]` is not, because it does not authenticate. |
| Storage keys bound to a local (`let key = ...`) were compared by variable name | Two `key`s in different functions or `match` arms looked like one ledger entry | Local bindings are resolved to the key expression they hold. Bare locals and parameters are only compared within one function. |
| SSDK008 treated `Allowance` keys as durable | SEP-41 allowances, which are *meant* to expire, flagged in temporary storage | `allowance` removed from the durable-name list. |
| SSDK023 counted a `has` guard as a read | "register once" writes reported as unbounded growth | Only a `get` in the same function counts as evidence of append. |
| SSDK010 accepted only cryptographic verification in `__check_auth` | Accounts that delegate to signers (`delegate_auth`), to an executor (`require_auth_for_args`) or to a shared library were reported as critical | Delegated `require_auth*`/`delegate_auth` count as verification. A hand-off to a function defined outside the package is not judged. |

### What remains

The 109 remaining findings were reviewed by hand. None is a parser or model
error. Each is an accurate statement of what the rule checks. Whether it matters
depends on intent, which a static analyser can't know.

| rule | count | assessment |
|------|------:|------------|
| SSDK004 lossy-cast | 33 | Accurate. Mostly `usize as u32` on lengths and `i128 as u128` after a sign check. Worth a glance and rarely exploitable, which is why the rule is `medium`. |
| SSDK001 missing-require-auth | 27 | Accurate by definition, and almost always deliberate: demo counters (`increment`), Merkle-proof claims and votes (authorised by proof, not address), test mocks, lazy-migration getters, and Blend's permissionless keeper entrypoints (running a queued reserve after its timelock, starting liquidation auctions, deleting stale auctions, distributing emissions). Mark these with an inline `// soroban-sec: ignore SSDK001 -- permissionless keeper` or a baseline. |
| SSDK023 unbounded-entry-growth | 15 | Worth reviewing. A `Vec` is read, appended to and written back to one persistent/instance entry, e.g. privacy-pool leaves in instance storage and RWA claim topics. Business logic may bound them; the scanner cannot see that. |
| SSDK006 unbounded-loop-over-storage | 13 | Accurate. Loops over signer lists and topic lists that touch storage per iteration. Usually bounded by admin-controlled sizes. |
| SSDK009 missing-ttl-extension | 10 | Accurate. Example contracts such as `liquidity_pool` write persistent state without ever extending its TTL. |
| SSDK013 panic-on-caller-input | 9 | Accurate. E.g. `get_score` in OZ's lazy-upgrade example unwraps a read keyed by a caller-supplied address, so an unknown user aborts the call. Some are intended rejections of malformed input (`from_xdr(..).expect(..)` in a WebAuthn verifier). |
| SSDK002 storage-tier-confusion | 2 | Accurate and deliberate: the `ttl` example writes one key to all three tiers to demonstrate them, and OZ's total-supply migration moves a key from instance to persistent. |

Blend v2, the one production DeFi protocol in the corpus, gets 10 findings, all
SSDK001: seven permissionless keeper entrypoints and three in its `mocks/` test
doubles.

## Limitations

- **Precision is measured, recall isn't.** These codebases have no known
  vulnerabilities to recover. Recall is covered by the fixture corpus, where
  every rule must fire on at least one vulnerable fixture.
- **Taint is one level deep.** SSDK013 sees `get(&Key(user)).unwrap()` in an
  entrypoint, but not a parameter passed through a helper or a `let` chain. A
  proper intra-procedural taint pass is tracked in the issue tracker.
- **Trait default methods are invisible.** OpenZeppelin's
  `#[contractimpl(contracttrait)] impl FungibleToken for Token {}` exports
  methods whose bodies live in the library's trait definition, in another
  crate, so they are not analysed as entrypoints of the example contract.
- **No `.wasm` was supplied**, so SSDK020–SSDK022 did not run. Building every
  crate in the corpus is out of scope for a quick, reproducible check.
