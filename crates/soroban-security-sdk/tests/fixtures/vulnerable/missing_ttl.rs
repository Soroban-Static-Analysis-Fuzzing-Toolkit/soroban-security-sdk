//! A persistent write that is never accompanied by a TTL bump, so the entry can
//! be archived. Expected: SSDK009.

use soroban_sdk::{contractimpl, Address, Env};

#[contractimpl]
impl Token {
    pub fn set_total(env: Env, caller: Address) {
        caller.require_auth();
        env.storage().persistent().set(&DataKey::Total, &1);
    }
}
