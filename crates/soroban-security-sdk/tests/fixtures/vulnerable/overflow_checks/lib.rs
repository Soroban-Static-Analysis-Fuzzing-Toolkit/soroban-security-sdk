//! A harmless contract whose crate is missing the release overflow-checks
//! setting. Expected: SSDK014.

use soroban_sdk::{contractimpl, Env};

#[contractimpl]
impl Token {
    pub fn version(env: Env) -> u32 {
        1
    }
}
