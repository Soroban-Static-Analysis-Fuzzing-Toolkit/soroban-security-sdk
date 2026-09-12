//! An upgradeable contract that gates the upgrade on the admin.

use soroban_sdk::{contractimpl, Address, BytesN, Env};

#[contractimpl]
impl Vault {
    pub fn upgrade(env: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        admin.require_auth();
        env.storage().instance().set(&DataKey::WasmHash, &new_wasm_hash);
        env.deployer()
            .update_current_contract_wasm(new_wasm_hash);
    }
}
