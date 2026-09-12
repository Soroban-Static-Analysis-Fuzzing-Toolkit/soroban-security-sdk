//! A bounded snapshot that fully replaces the entry. Clean: no findings.

use soroban_sdk::{contractimpl, Address, Env, Vec};

#[contracttype]
pub enum DataKey {
    Log,
}

#[contractimpl]
impl Feed {
    pub fn reset(env: Env, admin: Address, latest: u32) {
        admin.require_auth();
        let log: Vec<u32> = vec![&env, latest];
        env.storage().persistent().set(&DataKey::Log, &log);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Log, 100, 10_000);
    }
}
