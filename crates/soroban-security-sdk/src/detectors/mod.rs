//! The built-in detector catalogue.
//!
//! Each rule lives in its own module and registers itself with the global
//! [`DetectorRegistry`](crate::registry::DetectorRegistry) through
//! [`declare_detector!`](crate::declare_detector), so a new rule is a single file
//! plus a `mod` line. Detectors ask [`AnalysisContext`](crate::context::AnalysisContext)
//! and the typed model questions, never the syntax tree directly.
//!
//! | id | rule | category |
//! |----|------|----------|
//! | `SSDK001` | `missing-require-auth` | auth |
//! | `SSDK002` | `storage-tier-confusion` | storage |
//! | `SSDK003` | `unchecked-token-arithmetic` | arithmetic |
//! | `SSDK004` | `lossy-cast` | arithmetic |
//! | `SSDK005` | `wrapping-arithmetic` | arithmetic |
//! | `SSDK006` | `unbounded-loop-over-storage` | resource-budget |
//! | `SSDK007` | `resource-budget-exceeded` | resource-budget |
//! | `SSDK008` | `temporary-storage-for-durable-data` | storage |
//! | `SSDK009` | `missing-ttl-extension` | storage |
//! | `SSDK010` | `check-auth-without-verification` | access-control |
//! | `SSDK011` | `predictable-randomness` | randomness |
//! | `SSDK012` | `unauthorized-upgrade` | upgradeability |
//! | `SSDK013` | `panic-on-caller-input` | panic-safety |
//! | `SSDK014` | `overflow-checks-disabled` | arithmetic |
//! | `SSDK020` | `wasm-storage-without-auth` | auth |
//! | `SSDK021` | `contract-oversized` | resource-budget |
//! | `SSDK022` | `wasm-start-function` | best-practice |

mod arithmetic;
mod auth;
mod misc;
mod resources;
mod storage;
mod wasm;

pub use arithmetic::{
    LossyCast, OverflowChecksDisabled, UncheckedTokenArithmetic, WrappingArithmetic,
};
pub use auth::{CheckAuthWithoutVerification, MissingRequireAuth};
pub use misc::{PanicOnCallerInput, PredictableRandomness, UnauthorizedUpgrade};
pub use resources::{ResourceBudgetExceeded, UnboundedLoopOverStorage};
pub use storage::{MissingTtlExtension, StorageTierConfusion, TemporaryStorageWrite};
pub use wasm::{ContractOversized, WasmStartFunction, WasmStorageWithoutAuth};

use crate::model::ContractModel;

/// Whether any function reachable from `function` mutates ledger state.
pub(crate) fn writes_state(model: &ContractModel, function: &str) -> bool {
    model.has_transitive(function, |name| {
        model.storage_ops_in(name).any(|op| op.access.is_mutation())
    })
}

/// Whether any function reachable from `function` performs a token value transfer.
pub(crate) fn moves_value(model: &ContractModel, function: &str) -> bool {
    model.has_transitive(function, |name| {
        model.calls_in(name).any(|call| {
            call.is_value_transfer()
                && call
                    .interface
                    .as_deref()
                    .is_some_and(|interface| interface.contains("token"))
        })
    })
}

/// Whether any function reachable from `function` writes an integer to storage.
pub(crate) fn stores_integer(model: &ContractModel, function: &str) -> bool {
    model.has_transitive(function, |name| {
        model
            .storage_ops_in(name)
            .any(|op| op.access.is_mutation() && op.integer_type.is_some())
    })
}
