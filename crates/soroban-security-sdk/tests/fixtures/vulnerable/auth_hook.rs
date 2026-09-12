//! A custom account whose authorization hook returns success without verifying
//! anything. Expected: SSDK010.

use soroban_sdk::{contractimpl, BytesN, Env};

#[contractimpl]
impl Account {
    pub fn __check_auth(env: Env, signature: BytesN<64>) {}
}
