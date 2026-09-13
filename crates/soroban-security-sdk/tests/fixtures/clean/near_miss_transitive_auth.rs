//! Near-miss: a state-changing entrypoint that never calls `require_auth`
//! directly. The check is factored into a helper, which the detector must follow
//! through the call graph. Expected: no findings.

use soroban_sdk::{contractimpl, Address, Env};

fn require_admin(admin: &Address) {
    admin.require_auth();
}

#[contractimpl]
impl Vault {
    pub fn set_fee(env: Env, admin: Address, fee: i128) {
        require_admin(&admin);
        env.storage().instance().set(&DataKey::Fee, &fee);
    }
}
