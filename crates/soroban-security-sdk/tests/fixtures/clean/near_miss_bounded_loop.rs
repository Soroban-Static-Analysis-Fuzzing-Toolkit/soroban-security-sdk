//! Near-miss: a loop that performs storage work every iteration, but whose trip
//! count is a literal, so it cannot exhaust the resource budget. Expected: no
//! findings.

use soroban_sdk::{contractimpl, Address, Env};

#[contractimpl]
impl Feed {
    pub fn seed(env: Env, admin: Address) {
        admin.require_auth();
        for i in 0..4u32 {
            env.storage().instance().set(&DataKey::Slot(i), &1);
        }
    }
}
