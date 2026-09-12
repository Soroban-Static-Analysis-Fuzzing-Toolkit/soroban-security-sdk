//! `update_current_contract_wasm` is reachable by anyone. Expected: SSDK012.

use soroban_sdk::{contractimpl, BytesN, Env};

#[contractimpl]
impl Vault {
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        env.deployer()
            .update_current_contract_wasm(new_wasm_hash);
    }
}
