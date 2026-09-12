//! A custom account that actually verifies the signature it is handed.

use soroban_sdk::{contractimpl, Address, BytesN, Env};

#[contractimpl]
impl Account {
    pub fn __check_auth(
        env: Env,
        signature_payload: BytesN<32>,
        signature: BytesN<64>,
        public_key: BytesN<32>,
    ) {
        env.crypto()
            .ed25519_verify(&public_key, &signature_payload.into(), &signature);
    }

    pub fn add_signer(env: Env, admin: Address, key: BytesN<32>) {
        admin.require_auth();
        env.storage().instance().set(&DataKey::Signer, &key);
    }
}
