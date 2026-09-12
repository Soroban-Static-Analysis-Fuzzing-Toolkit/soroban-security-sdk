//! A factory that deploys child contracts for anyone. Expected: SSDK024.

use soroban_sdk::{contractimpl, BytesN, Env};

#[contractimpl]
impl Factory {
    pub fn spawn(env: Env, salt: BytesN<32>, wasm_hash: BytesN<32>) {
        env.deployer()
            .with_current_contract(salt)
            .deploy(wasm_hash);
    }
}
