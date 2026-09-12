//! A contract with several independent problems, to check that detectors compose
//! on one file without masking or duplicating each other.
//!
//! Expected: SSDK001, SSDK003, SSDK008, SSDK009, SSDK011.

use soroban_sdk::{contractimpl, Address, Env};

#[contractimpl]
impl Vault {
    /// Writes state with no authorization (SSDK001), accumulates with an
    /// unchecked add (SSDK003) and never bumps the TTL (SSDK009).
    pub fn deposit(env: Env, amount: i128) {
        let total: i128 = env.storage().persistent().get(&DataKey::Total).unwrap_or(0);
        let next = total + amount;
        env.storage().persistent().set(&DataKey::Total, &next);
    }

    /// Stores durable state in the wrong tier (SSDK008). Authorized, so it is not
    /// also an SSDK001.
    pub fn remember_admin(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().temporary().set(&DataKey::Admin, &admin);
    }

    /// Uses a predictable ledger value as entropy (SSDK011).
    pub fn pick_winner(env: Env) -> u64 {
        env.ledger().timestamp() % 100
    }
}
