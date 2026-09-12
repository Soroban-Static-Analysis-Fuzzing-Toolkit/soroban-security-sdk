//! The loop length is a caller-supplied collection and each iteration reads the
//! ledger, so the read budget can be exhausted. Expected: SSDK006.

use soroban_sdk::{contractimpl, Address, Env, Vec};

#[contractimpl]
impl Registry {
    pub fn total_balance(env: Env, holders: Vec<Address>) -> i128 {
        let mut total = 0;
        for holder in holders.iter() {
            let balance: i128 = env.storage().persistent().get(holder).unwrap_or(0);
            total = total.checked_add(balance).unwrap_or(total);
        }
        total
    }
}
