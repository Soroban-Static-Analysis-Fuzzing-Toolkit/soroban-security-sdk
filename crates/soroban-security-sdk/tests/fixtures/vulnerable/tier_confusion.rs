//! The same logical key is written through `persistent` and read through
//! `instance`, so the read silently misses. Expected: SSDK002.

use soroban_sdk::{contractimpl, Address, Env};

#[contractimpl]
impl Token {
    pub fn read_config(env: Env, caller: Address) {
        caller.require_auth();
        env.storage().persistent().set(&DataKey::Config, &1);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Config, 100, 1000);
        let _cached = env.storage().instance().get(&DataKey::Config);
    }
}
