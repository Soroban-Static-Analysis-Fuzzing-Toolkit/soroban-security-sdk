# Rule catalogue

soroban-sec ships 19 rules. This file is generated from detector metadata.
Regenerate it with `cargo run -p soroban-sec -- --list-rules --format markdown > docs/rules.md`.

| id | rule | severity | confidence | category | default |
|----|------|----------|------------|----------|---------|
| `SSDK001` | `missing-require-auth` | high | medium | auth | on |
| `SSDK002` | `storage-tier-confusion` | high | high | storage | on |
| `SSDK003` | `unchecked-token-arithmetic` | high | medium | arithmetic | on |
| `SSDK004` | `lossy-cast` | medium | high | arithmetic | on |
| `SSDK005` | `wrapping-arithmetic` | high | high | arithmetic | on |
| `SSDK006` | `unbounded-loop-over-storage` | high | high | resource-budget | on |
| `SSDK007` | `resource-budget-exceeded` | high | medium | resource-budget | on |
| `SSDK008` | `temporary-storage-for-durable-data` | high | medium | storage | on |
| `SSDK009` | `missing-ttl-extension` | medium | low | storage | on |
| `SSDK010` | `check-auth-without-verification` | critical | medium | access-control | on |
| `SSDK011` | `predictable-randomness` | high | high | randomness | on |
| `SSDK012` | `unauthorized-upgrade` | critical | high | upgradeability | on |
| `SSDK013` | `panic-on-caller-input` | medium | medium | panic-safety | on |
| `SSDK014` | `overflow-checks-disabled` | high | high | arithmetic | on |
| `SSDK020` | `wasm-storage-without-auth` | high | medium | auth | on |
| `SSDK021` | `contract-oversized` | high | high | resource-budget | on |
| `SSDK022` | `wasm-start-function` | medium | high | best-practice | on |
| `SSDK023` | `unbounded-entry-growth` | high | medium | storage | on |
| `SSDK024` | `unauthorized-deploy` | high | high | upgradeability | on |

## SSDK001 - `missing-require-auth`

- **Severity:** high
- **Confidence:** medium
- **Category:** auth

A state-changing entrypoint never authorizes a caller.

Soroban does not expose a caller identity the way most chains do; a contract must ask the host to authorize an `Address` explicitly. An entrypoint that writes to storage but never calls `require_auth` (directly or through a helper) is therefore callable by anyone.

**Tags:** `auth`, `require-auth`, `authorization`

**References:**
- [Stellar docs: Authorization](https://developers.stellar.org/docs/learn/encyclopedia/security/authorization)

## SSDK002 - `storage-tier-confusion`

- **Severity:** high
- **Confidence:** high
- **Category:** storage

The same ledger key is accessed through different storage tiers.

Soroban's three storage tiers are separate key spaces. A value written to `persistent` is not visible through `instance.get` for the same key, so mixing tiers for one logical key produces missing reads or lost writes.

**Tags:** `storage`, `tiers`, `state`

**References:**
- [Stellar docs: Storage](https://developers.stellar.org/docs/learn/encyclopedia/storage/state-archival)

## SSDK003 - `unchecked-token-arithmetic`

- **Severity:** high
- **Confidence:** medium
- **Category:** arithmetic

Amount arithmetic can wrap because release overflow checks are disabled.

Rust disables integer overflow checks in release builds unless the crate opts in with `[profile.release] overflow-checks = true`. On an amount-like type such as `i128`, an overflow it not caught and the balance silently wraps, which is the classic token-mint bug.

**Tags:** `arithmetic`, `overflow`, `token`

**References:**
- [Stellar docs: Security best practices](https://developers.stellar.org/docs/learn/encyclopedia/security/)

## SSDK004 - `lossy-cast`

- **Severity:** medium
- **Confidence:** high
- **Category:** arithmetic

An `as` cast can silently truncate or reinterpret an integer.

Rust's `as` operator truncates on narrowing and reinterprets signedness without any check. On token amounts a silent truncation is a value loss.

**Tags:** `arithmetic`, `cast`, `truncation`

**References:**
- [Rust reference: Type cast expressions](https://doc.rust-lang.org/reference/expressions/operator-expr.html#type-cast-expressions)

## SSDK005 - `wrapping-arithmetic`

- **Severity:** high
- **Confidence:** high
- **Category:** arithmetic

`wrapping_*` arithmetic silently wraps instead of failing.

The `wrapping_add`/`wrapping_sub`/`wrapping_mul`/`wrapping_div` family is an explicit request to ignore overflow. In contract code this is almost always a bug: a balance that overflows becomes a much smaller number.

**Tags:** `arithmetic`, `wrapping`, `overflow`

**References:**
- [Rust docs: Wrapping arithmetic](https://doc.rust-lang.org/std/primitive.i128.html#method.wrapping_add)

## SSDK006 - `unbounded-loop-over-storage`

- **Severity:** high
- **Confidence:** high
- **Category:** resource-budget

A loop of unknown length performs ledger or cross-contract work each iteration.

Soroban caps a transaction at 200 ledger reads and 200 writes. A loop whose trip count is not statically known can exhaust that budget, aborting the call after the caller has already paid for it.

**Tags:** `loop`, `storage`, `budget`, `dos`

**References:**
- [Stellar docs: Resource limits](https://developers.stellar.org/docs/learn/encyclopedia/network-configuration/transaction-fees)

## SSDK007 - `resource-budget-exceeded`

- **Severity:** high
- **Confidence:** medium
- **Category:** resource-budget

An entrypoint is estimated to exceed a network resource limit.

Every Soroban call is metered for CPU instructions, contract memory and ledger entry reads and writes. The static estimator bounds each axis from the source and, when a `.wasm` module is supplied, the compiled code; a call that exceeds any ceiling fails at runtime.

**Tags:** `budget`, `instructions`, `memory`, `ledger`

**References:**
- [Stellar docs: Resource limits](https://developers.stellar.org/docs/learn/encyclopedia/network-configuration/transaction-fees)

## SSDK008 - `temporary-storage-for-durable-data`

- **Severity:** high
- **Confidence:** medium
- **Category:** storage

A long-lived-looking key is stored in the `temporary` tier.

`temporary` entries are deleted forever once their time to live expires; they cannot be restored the way persistent entries can. Using the tier for keys named like balances, configuration or ownership risks permanent state loss, whereas caches and locks are exactly what it is for.

**Tags:** `storage`, `temporary`, `ttl`

**References:**
- [Stellar docs: State archival](https://developers.stellar.org/docs/learn/encyclopedia/storage/state-archival)

## SSDK009 - `missing-ttl-extension`

- **Severity:** medium
- **Confidence:** low
- **Category:** storage

Persistent entries are written without a matching TTL extension.

Every persistent entry has a time to live. A contract that writes persistent state but never calls `extend_ttl`/`bump` risks the entry being archived, at which point reads return `None` until the entry is restored.

**Tags:** `storage`, `ttl`, `archival`

**References:**
- [Stellar docs: State archival](https://developers.stellar.org/docs/learn/encyclopedia/storage/state-archival)

## SSDK010 - `check-auth-without-verification`

- **Severity:** critical
- **Confidence:** medium
- **Category:** access-control

`__check_auth` does not verify a signature or credential.

A custom account implements `__check_auth` to validate the signatures the host forwards with an authorization entry. If the hook returns success without verifying anything, every operation on the account is authorized.

**Tags:** `auth`, `custom-account`, `check-auth`

**References:**
- [Stellar docs: Custom accounts](https://developers.stellar.org/docs/learn/encyclopedia/security/authorization)

## SSDK011 - `predictable-randomness`

- **Severity:** high
- **Confidence:** high
- **Category:** randomness

A predictable ledger value is used as a source of randomness.

Ledger timestamps and sequence numbers are known to whoever submits a transaction and can be ground until the outcome is favourable, so they are not usable as entropy for lotteries, mints or shuffles.

**Tags:** `randomness`, `entropy`, `lottery`

**References:**
- [Stellar docs: Randomness](https://developers.stellar.org/docs/learn/encyclopedia/security/)

## SSDK012 - `unauthorized-upgrade`

- **Severity:** critical
- **Confidence:** high
- **Category:** upgradeability

A contract upgrade is reachable without authorization.

`update_current_contract_wasm` replaces all of the contract's code, including its authorization logic. An upgrade path that is not gated on an admin `require_auth` hands the contract to whoever calls it.

**Tags:** `upgrade`, `admin`, `auth`

**References:**
- [Stellar docs: Contract upgrades](https://developers.stellar.org/docs/learn/encyclopedia/security/)

## SSDK013 - `panic-on-caller-input`

- **Severity:** medium
- **Confidence:** medium
- **Category:** panic-safety

A panicking expression can abort a contract call.

A panic aborts the entire transaction. When the panic is reachable from caller-controlled data it becomes a denial-of-service primitive: the caller pays the fee and the call cannot be recovered.

**Tags:** `panic`, `dos`, `availability`

**References:**
- [Stellar docs: Error handling](https://developers.stellar.org/docs/learn/encyclopedia/errors-and-debugging/)

## SSDK014 - `overflow-checks-disabled`

- **Severity:** high
- **Confidence:** high
- **Category:** arithmetic

The release profile does not enable `overflow-checks`.

Rust's release profile disables integer overflow checks by default. The official Soroban contract template turns them back on with `overflow-checks = true`; a contract that drops the setting silently wraps its arithmetic when deployed.

**Tags:** `arithmetic`, `manifest`, `release-profile`

**References:**
- [Stellar docs: Optimization settings](https://developers.stellar.org/docs/build/guides/conventions/release-profile)

## SSDK020 - `wasm-storage-without-auth`

- **Severity:** high
- **Confidence:** medium
- **Category:** auth
- **Requires:** a compiled `.wasm` module

The compiled module writes ledger state but never imports `require_auth`.

A contract can only authorize an address by calling the host's `require_auth` function, so a module that imports ledger-writing host functions but never imports `require_auth` cannot be checking authorization at all.

**Tags:** `wasm`, `auth`, `require-auth`

**References:**
- [Stellar docs: Authorization](https://developers.stellar.org/docs/learn/encyclopedia/security/authorization)

## SSDK021 - `contract-oversized`

- **Severity:** high
- **Confidence:** high
- **Category:** resource-budget
- **Requires:** a compiled `.wasm` module

The compiled module exceeds the per-entry ledger size limit.

A contract's Wasm is stored in a ledger entry, so it is subject to the same size ceiling as any other entry. A module over the limit cannot be uploaded or upgraded on-chain.

**Tags:** `wasm`, `size`, `deployment`

**References:**
- [Stellar docs: Contract size](https://developers.stellar.org/docs/learn/encyclopedia/contract-development/)

## SSDK022 - `wasm-start-function`

- **Severity:** medium
- **Confidence:** high
- **Category:** best-practice
- **Requires:** a compiled `.wasm` module

The compiled module declares a Wasm start function.

A Wasm start function runs on instantiation, before any entrypoint and outside the transaction's authorization context. Soroban contracts are not expected to have one, and code that runs there cannot be authorized.

**Tags:** `wasm`, `deployment`

**References:**
- [WebAssembly spec: start function](https://webassembly.github.io/spec/core/syntax/modules.html#start-function)

## SSDK023 - `unbounded-entry-growth`

- **Severity:** high
- **Confidence:** medium
- **Category:** storage

A ledger entry grows without bound and can exceed the per-entry size limit.

A single ledger entry may not exceed the per-entry size limit. An entry that is read, appended to and written back (or appended to inside a loop) grows on every call until the write is rejected, leaving the key unusable and any state it held unreachable.

**Tags:** `storage`, `unbounded`, `state-bloat`

**References:**
- [Stellar docs: State archival](https://developers.stellar.org/docs/learn/encyclopedia/storage/state-archival)

## SSDK024 - `unauthorized-deploy`

- **Severity:** high
- **Confidence:** high
- **Category:** upgradeability

A contract deployment is reachable without authorization.

Deploying a contract installs new code and, in the factory pattern, makes the caller the admin of the deployed instance. A deploy path with no `require_auth` hands that privilege to anyone, letting them spawn contracts at the protocol's expense.

**Tags:** `deploy`, `factory`, `auth`

**References:**
- [Stellar docs: Deploying contracts](https://developers.stellar.org/docs/learn/encyclopedia/contract-development/)
