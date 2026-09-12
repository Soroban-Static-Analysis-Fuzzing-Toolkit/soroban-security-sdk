//! An amount narrowed through `as`, which truncates silently. Expected: SSDK004.

use soroban_sdk::{contractimpl, Env};

#[contractimpl]
impl Token {
    pub fn amount_as_u32(env: Env, amount: i128) -> u32 {
        amount as u32
    }
}
