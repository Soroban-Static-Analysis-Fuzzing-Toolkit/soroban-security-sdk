//! `unwrap` on a storage read aborts the call when the entry is absent.
//! Expected: SSDK013.

use soroban_sdk::{contractimpl, Env};

#[contractimpl]
impl Token {
    pub fn balance(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance)
            .unwrap()
    }
}
