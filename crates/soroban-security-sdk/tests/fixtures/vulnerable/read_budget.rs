//! A literal loop that performs 500 ledger reads, far past the 200-read ceiling.
//! Expected: SSDK007.

use soroban_sdk::{contractimpl, Env};

#[contractimpl]
impl Token {
    pub fn scan(env: Env) {
        for i in 0..500 {
            env.storage().persistent().get(&i);
        }
    }
}
