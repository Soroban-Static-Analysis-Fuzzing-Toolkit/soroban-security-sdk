//! The admin key is stored in `temporary`, so it is deleted forever on expiry.
//! Expected: SSDK008.

use soroban_sdk::{contractimpl, Address, Env};

#[contractimpl]
impl Token {
    pub fn remember_admin(env: Env, caller: Address, admin: Address) {
        caller.require_auth();
        env.storage().temporary().set(&DataKey::Admin, &admin);
    }
}
