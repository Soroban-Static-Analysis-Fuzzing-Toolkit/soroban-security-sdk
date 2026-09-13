//! Near-miss: token-amount arithmetic that looks like the classic overflow bug
//! but uses the checked API. Expected: no findings.

use soroban_sdk::{contractimpl, Address, Env};

#[contractimpl]
impl Token {
    pub fn add(env: Env, caller: Address, amount: i128) {
        caller.require_auth();
        let total: i128 = env.storage().persistent().get(&DataKey::Total).unwrap_or(0);
        let next = total.checked_add(amount).unwrap_or(total);
        env.storage().persistent().set(&DataKey::Total, &next);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Total, 100, 10_000);
    }
}
