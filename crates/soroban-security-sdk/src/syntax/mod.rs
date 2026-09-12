//! Thin, uniform helpers over `syn`'s syntax tree.
//!
//! Detectors should be able to ask questions like "is this method
//! `require_auth`?" or "what integer type is this?" without re-deriving them.
//! These helpers keep that knowledge in one place, which is also where the
//! Soroban-specific conventions (`#[contractimpl]`, `env.storage().persistent()`,
//! ...) are encoded.

pub mod attrs;
pub mod exprs;
pub mod functions;
pub mod paths;

/// Re-exported so detectors can match on syntax nodes without importing `syn`.
pub use syn::{Expr, ExprBinary, ExprCast, ExprMethodCall, Item, Stmt};

pub use attrs::{attr_name, find_attr, has_attr, has_any_attr, is_test_attr};
pub use exprs::{is_int_literal, literal_int, method_name, unwrap_refs};
pub use functions::{collect, collect_from_items, FunctionView, Param, ParamKind};
pub use paths::{
    canonical, collection_type_of, collection_type_of_name, integer_type_of,
    integer_type_of_name, last_segment, path_ends_with, CollectionTy, IntegerTy,
};
