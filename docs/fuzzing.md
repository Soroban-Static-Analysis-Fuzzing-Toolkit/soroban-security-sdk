# Invariant fuzzing

Static analysis answers *"does this pattern look wrong?"*. Fuzzing answers the
complement: *"can I actually reach a state that breaks a rule the contract
promises to keep?"*. The `soroban-sec-fuzz` crate generates call sequences against
a contract, checks declared invariants after every call, and uses
[`proptest`](https://docs.rs/proptest) shrinking to reduce any failure to the
shortest sequence that still reproduces it.

## The two things you declare

1. A **`SystemUnderTest`** — the contract in a test environment, plus the calls it
   accepts.
2. One or more **`Invariant`s** — properties that must hold after *every* call.

```rust
pub trait SystemUnderTest {
    type Call: Clone + Debug;

    /// Apply one call. `Err` means the contract *rejected* it (for example an
    /// authorization failure); that is a normal outcome, not a bug.
    fn execute(&mut self, call: &Self::Call) -> Result<(), String>;

    /// Return to a clean state before the next generated sequence.
    fn reset(&mut self);
}
```

The harness reports a failure only when an invariant is broken, so rejected calls
do not produce false alarms.

## A worked example

```rust
use proptest::prelude::*;
use soroban_sec_fuzz::{fuzz, invariant, sequence, FuzzConfig, SystemUnderTest};

#[derive(Debug, Clone)]
enum Call {
    Deposit { amount: u8 },
    Withdraw { amount: u8 },
}

#[derive(Default)]
struct Vault {
    balance: i64,
}

impl SystemUnderTest for Vault {
    type Call = Call;

    fn execute(&mut self, call: &Call) -> Result<(), String> {
        match *call {
            Call::Deposit { amount } => self.balance += i64::from(amount),
            Call::Withdraw { amount } if self.balance >= i64::from(amount) => {
                self.balance -= i64::from(amount);
            }
            Call::Withdraw { .. } => return Err("insufficient funds".to_string()),
        }
        Ok(())
    }

    fn reset(&mut self) {
        self.balance = 0;
    }
}

#[test]
fn balance_never_goes_negative() {
    let calls = sequence(
        prop_oneof![
            (1u8..=10).prop_map(|amount| Call::Deposit { amount }),
            (1u8..=10).prop_map(|amount| Call::Withdraw { amount }),
        ],
        8,
    );

    let never_negative = invariant("balance is never negative", |vault: &Vault| {
        if vault.balance < 0 {
            Err(format!("balance is {}", vault.balance))
        } else {
            Ok(())
        }
    });

    fuzz(&FuzzConfig::default(), Vault::default, calls, &[&never_negative]).assert_ok();
}
```

A failure prints the minimal reproduction:

```text
invariant `total supply is conserved` violated: sum(balances)=30 but total=20 (at step 1)
minimal sequence (1 call(s)):
  1. Transfer { from: 0, to: 0, amount: 10 }
```

## Adapting a real contract

Point `SystemUnderTest` at the Soroban test environment. `execute` maps each
`Call` variant to the generated contract client, and `reset` builds a fresh `Env`.
Because `execute` borrows `&mut self`, keep the environment and the clients on the
struct.

```rust
use soroban_sdk::{Address, Env};
use my_token::{TokenClient, Token};
use soroban_sec_fuzz::SystemUnderTest;

enum Call {
    Transfer { from: Address, to: Address, amount: i128 },
    Mint { admin: Address, amount: i128 },
}

struct TokenUnderTest {
    env: Env,
    client: TokenClient<'static>,
    admin: Address,
}

impl SystemUnderTest for TokenUnderTest {
    type Call = Call;

    fn execute(&mut self, call: &Call) -> Result<(), String> {
        match call {
            // `try_transfer` returns a Result instead of panicking, which is what
            // the fuzzer wants: a rejected transfer is not a failure.
            Call::Transfer { from, to, amount } => self
                .client
                .try_transfer(from, to, amount)
                .map(|_| ())
                .map_err(|_| "transfer rejected".to_string()),
            Call::Mint { admin, amount } => {
                let _ = admin;
                self.client.try_mint(&self.admin, amount).map(|_| ()).map_err(|e| format!("{e:?}"))
            }
        }
    }

    fn reset(&mut self) {
        // Rebuild the environment and re-deploy for a clean slate.
        let rebuilt = TokenUnderTest::deploy();
        *self = rebuilt;
    }
}
```

Generate calls with a `proptest` strategy. Addresses are easiest to draw from a
small fixed pool so that sequences actually interact:

```rust
fn calls() -> impl Strategy<Value = Vec<Call>> {
    let accounts = proptest::sample::select(vec![ALICE, BOB, CAROL]);
    let call = proptest::prop_oneof![
        (accounts.clone(), accounts.clone(), 0i128..1_000)
            .prop_map(|(from, to, amount)| Call::Transfer { from, to, amount }),
        (accounts.clone(), 0i128..1_000).prop_map(|(_admin, amount)| Call::Mint { admin: ADMIN, amount }),
    ];
    sequence(call, 12)
}
```

## Invariants worth declaring

- **Value conservation**: `sum(balances) == total_supply` after every call.
- **No unauthorized balance change**: a transfer by an address that did not
  authorize must leave both balances unchanged (encode the "did it authorize"
  fact in your model).
- **Monotonic nonce / sequence**: a counter only ever increases.
- **Reachability bounds**: no account can acquire more than `MAX_SUPPLY`.
- **No stuck state**: after any call, at least one entrypoint can still succeed.

Prefer invariants that are cheap and total. An invariant that panics on valid
states will be disabled, and a disabled invariant catches nothing.

## Tuning

`FuzzConfig` controls how many sequences to generate and how long they may be:

```rust
let config = FuzzConfig::new(1024, 24); // 1024 sequences, up to 24 calls each
```

Failures are **shrunk**: `proptest` reduces the generated sequence to a minimal
reproduction, which is what the `Violation` carries. The harness does not write
regression files, so a run leaves no trace on disk; copy a minimal reproduction
into a normal unit test to lock it in.
