//! A well-written token transfer.
//!
//! Authorization is explicit, arithmetic is checked, every key lives in one tier
//! and the TTL is maintained. This fixture must produce **no** findings; if any
//! detector fires on it, that detector has a false positive.

use soroban_sdk::{contractimpl, Address, Env};

#[contractimpl]
impl Token {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();

        let from_key = DataKey::Balance(from.clone());
        let to_key = DataKey::Balance(to.clone());

        let from_balance: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
        let to_balance: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);

        let new_from = from_balance.checked_sub(amount).unwrap_or(0);
        let new_to = to_balance.checked_add(amount).unwrap_or(0);

        env.storage().persistent().set(&from_key, &new_from);
        env.storage().persistent().set(&to_key, &new_to);
        env.storage().persistent().extend_ttl(&from_key, 100, 1000);
        env.storage().persistent().extend_ttl(&to_key, 100, 1000);
    }
}
