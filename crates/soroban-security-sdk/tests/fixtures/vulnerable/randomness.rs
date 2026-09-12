//! The ledger timestamp is predictable to the transaction submitter, so this is
//! not a fair draw. Expected: SSDK011.

use soroban_sdk::{contractimpl, Env};

#[contractimpl]
impl Lottery {
    pub fn draw(env: Env) -> u64 {
        env.ledger().timestamp() % 10
    }
}
