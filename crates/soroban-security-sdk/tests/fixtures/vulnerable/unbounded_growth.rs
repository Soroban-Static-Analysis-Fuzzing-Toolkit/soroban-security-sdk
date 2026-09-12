//! An append-only log entry that grows on every call. Expected: SSDK023.

use soroban_sdk::{contractimpl, Address, Env, Vec};

#[contracttype]
pub enum DataKey {
    Log,
}

#[contractimpl]
impl Feed {
    pub fn record(env: Env, admin: Address, entry: u32) {
        admin.require_auth();
        let mut log: Vec<u32> = env
            .storage()
            .persistent()
            .get(&DataKey::Log)
            .unwrap_or(Vec::new(&env));
        log.push_back(entry);
        env.storage().persistent().set(&DataKey::Log, &log);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Log, 100, 10_000);
    }
}
