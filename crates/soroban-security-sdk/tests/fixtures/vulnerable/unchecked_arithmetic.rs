//! A balance update that adds without checking. Expected: SSDK003.

use soroban_sdk::{contractimpl, Address, Env};

#[contractimpl]
impl Token {
    pub fn deposit(env: Env, caller: Address, amount: i128) {
        caller.require_auth();
        let total: i128 = env.storage().persistent().get(&DataKey::Total).unwrap_or(0);
        let next = total + amount;
        env.storage().persistent().set(&DataKey::Total, &next);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Total, 100, 1000);
    }
}
