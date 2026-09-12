//! Arithmetic that explicitly opts out of overflow checking. Expected: SSDK005.

use soroban_sdk::{contractimpl, Env};

#[contractimpl]
impl Counter {
    pub fn bump(env: Env, value: i128) -> i128 {
        value.wrapping_add(1)
    }
}
