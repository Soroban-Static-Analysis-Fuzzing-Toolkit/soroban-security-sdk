//! Panics that are deliberate, not caller-triggerable by accident: an invariant
//! set by the constructor, an explicit rejection of bad input, and a read that
//! defaults a missing entry. Expected: none.

use soroban_sdk::{contractimpl, Address, Env};

#[contractimpl]
impl Vault {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("admin is set by the constructor")
    }

    pub fn deposit(env: Env, from: Address, amount: i128) {
        from.require_auth();
        if amount <= 0 {
            panic!("amount must be positive");
        }
        let key = DataKey::Balance(from);
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&key, &balance.checked_add(amount).unwrap_or(balance));
        env.storage().persistent().extend_ttl(&key, 100, 1000);
    }
}
