//! `unwrap` on a storage read keyed by a caller-supplied address: any address
//! that has never held a balance aborts the call instead of reading as zero.
//! Expected: SSDK013.

use soroban_sdk::{contractimpl, Address, Env};

#[contractimpl]
impl Token {
    pub fn balance(env: Env, id: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(id))
            .unwrap()
    }
}
