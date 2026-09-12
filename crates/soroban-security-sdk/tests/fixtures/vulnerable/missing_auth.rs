//! A privileged setter with no authorization check. Expected: SSDK001.

use soroban_sdk::{contractimpl, Env};

#[contractimpl]
impl Token {
    pub fn set_fee(env: Env, fee: i128) {
        env.storage().instance().set(&DataKey::Fee, &fee);
    }
}
