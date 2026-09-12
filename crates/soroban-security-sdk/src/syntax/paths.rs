//! Paths, token canonicalisation and integer types.

use quote::ToTokens;
use syn::{Expr, Path, Type};

/// Canonical, whitespace-free rendering of a syntax node.
///
/// Used to compare expressions textually. `DataKey :: Balance (addr)` becomes
/// `DataKey::Balance(addr)`, which is stable across formatting but not across
/// renames; comparisons that need more than that should use spans or types.
///
/// Whitespace inside string literals is removed too, so only compare values that
/// are known not to contain strings (keys, method names, call chains).
pub fn canonical<T: ToTokens + ?Sized>(node: &T) -> String {
    let rendered = node.to_token_stream().to_string();
    let mut out = String::with_capacity(rendered.len());
    for character in rendered.chars() {
        if !character.is_whitespace() {
            out.push(character);
        }
    }
    out
}

/// The last segment of a path.
pub fn last_segment(path: &Path) -> Option<&syn::Ident> {
    path.segments.last().map(|segment| &segment.ident)
}

/// Whether `path`'s trailing segments match `expected` exactly.
///
/// `["token", "Client"]` matches both `token::Client` and `soroban_sdk::token::Client`.
pub fn path_ends_with(path: &Path, expected: &[&str]) -> bool {
    let segments: Vec<String> = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    if segments.len() < expected.len() {
        return false;
    }
    let tail = &segments[segments.len() - expected.len()..];
    tail.iter()
        .zip(expected)
        .all(|(actual, want)| actual == want)
}

/// Whether a path contains a segment with the given name.
pub fn path_has_segment(path: &Path, name: &str) -> bool {
    path.segments.iter().any(|segment| segment.ident == name)
}

/// The path of a plain path expression, or of a call's callee.
pub fn callee_path(expr: &Expr) -> Option<&Path> {
    match expr {
        Expr::Path(path) => Some(&path.path),
        Expr::Call(call) => match &*call.func {
            Expr::Path(path) => Some(&path.path),
            _ => None,
        },
        _ => None,
    }
}

/// Whether an expression is a call to a function whose path ends with `expected`.
pub fn is_call_to(expr: &Expr, expected: &[&str]) -> bool {
    match expr {
        Expr::Call(call) => match &*call.func {
            Expr::Path(path) => path_ends_with(&path.path, expected),
            _ => false,
        },
        _ => false,
    }
}

/// The method name of a method call expression.
pub fn method_call_name(expr: &Expr) -> Option<&syn::Ident> {
    match expr {
        Expr::MethodCall(call) => Some(&call.method),
        _ => None,
    }
}

/// Integer types that matter for Soroban contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntegerTy {
    /// `i8`
    I8,
    /// `i16`
    I16,
    /// `i32`
    I32,
    /// `i64`
    I64,
    /// `i128`, the default Soroban amount type.
    I128,
    /// `i256` / `soroban_sdk::I256`
    I256,
    /// `u8`
    U8,
    /// `u16`
    U16,
    /// `u32`
    U32,
    /// `u64`
    U64,
    /// `u128`
    U128,
    /// `u256` / `soroban_sdk::U256`
    U256,
    /// `isize`
    ISize,
    /// `usize`
    USize,
}

impl IntegerTy {
    /// All supported integer types.
    pub const ALL: [IntegerTy; 14] = [
        IntegerTy::I8,
        IntegerTy::I16,
        IntegerTy::I32,
        IntegerTy::I64,
        IntegerTy::I128,
        IntegerTy::I256,
        IntegerTy::U8,
        IntegerTy::U16,
        IntegerTy::U32,
        IntegerTy::U64,
        IntegerTy::U128,
        IntegerTy::U256,
        IntegerTy::ISize,
        IntegerTy::USize,
    ];

    /// Whether the type is signed.
    pub const fn is_signed(self) -> bool {
        matches!(
            self,
            IntegerTy::I8
                | IntegerTy::I16
                | IntegerTy::I32
                | IntegerTy::I64
                | IntegerTy::I128
                | IntegerTy::I256
                | IntegerTy::ISize
        )
    }

    /// Type width in bits.
    pub const fn bits(self) -> u16 {
        match self {
            IntegerTy::I8 | IntegerTy::U8 => 8,
            IntegerTy::I16 | IntegerTy::U16 => 16,
            IntegerTy::I32 | IntegerTy::U32 => 32,
            IntegerTy::I64 | IntegerTy::U64 => 64,
            IntegerTy::I128 | IntegerTy::U128 => 128,
            IntegerTy::I256 | IntegerTy::U256 => 256,
            IntegerTy::ISize | IntegerTy::USize => 64,
        }
    }

    /// Lowercase type name.
    pub const fn name(self) -> &'static str {
        match self {
            IntegerTy::I8 => "i8",
            IntegerTy::I16 => "i16",
            IntegerTy::I32 => "i32",
            IntegerTy::I64 => "i64",
            IntegerTy::I128 => "i128",
            IntegerTy::I256 => "I256",
            IntegerTy::U8 => "u8",
            IntegerTy::U16 => "u16",
            IntegerTy::U32 => "u32",
            IntegerTy::U64 => "u64",
            IntegerTy::U128 => "u128",
            IntegerTy::U256 => "U256",
            IntegerTy::ISize => "isize",
            IntegerTy::USize => "usize",
        }
    }

    /// Whether casting to `target` can silently change the value.
    ///
    /// - same signedness: lossy when narrowing;
    /// - unsigned to signed: lossy unless the target is strictly wider;
    /// - signed to unsigned: always lossy, negative values have no representation.
    pub fn cast_is_lossy(self, target: IntegerTy) -> bool {
        match (self.is_signed(), target.is_signed()) {
            (false, true) => target.bits() <= self.bits(),
            (true, false) => true,
            _ => target.bits() < self.bits(),
        }
    }
}

impl std::fmt::Display for IntegerTy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Parse an integer type name.
///
/// Matches Rust primitives and the Soroban `I256`/`U256` types, case-insensitively
/// so both `i128` and `I128` (as written in some contracts) are recognised.
pub fn integer_type_of_name(name: &str) -> Option<IntegerTy> {
    match name.to_ascii_lowercase().as_str() {
        "i8" => Some(IntegerTy::I8),
        "i16" => Some(IntegerTy::I16),
        "i32" => Some(IntegerTy::I32),
        "i64" => Some(IntegerTy::I64),
        "i128" => Some(IntegerTy::I128),
        "i256" => Some(IntegerTy::I256),
        "u8" => Some(IntegerTy::U8),
        "u16" => Some(IntegerTy::U16),
        "u32" => Some(IntegerTy::U32),
        "u64" => Some(IntegerTy::U64),
        "u128" => Some(IntegerTy::U128),
        "u256" => Some(IntegerTy::U256),
        "isize" => Some(IntegerTy::ISize),
        "usize" => Some(IntegerTy::USize),
        _ => None,
    }
}

/// Integer type of a syntax type, if it is an integer.
pub fn integer_type_of(ty: &Type) -> Option<IntegerTy> {
    match ty {
        Type::Path(path) => {
            last_segment(&path.path).and_then(|ident| integer_type_of_name(&ident.to_string()))
        }
        Type::Paren(paren) => integer_type_of(&paren.elem),
        Type::Group(group) => integer_type_of(&group.elem),
        _ => None,
    }
}

/// Collection types whose size is not statically bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CollectionTy {
    /// `Vec<_>` / `soroban_sdk::Vec<_>`
    Vec,
    /// `Map<_, _>` / `soroban_sdk::Map<_, _>`
    Map,
    /// `Bytes` / `BytesN<_>`
    Bytes,
    /// `String` / `soroban_sdk::String`
    String,
    /// `BTreeMap` / `BTreeSet` / `HashMap` / `HashSet`
    Ordered,
}

impl CollectionTy {
    /// Name for messages.
    pub const fn name(self) -> &'static str {
        match self {
            CollectionTy::Vec => "Vec",
            CollectionTy::Map => "Map",
            CollectionTy::Bytes => "Bytes",
            CollectionTy::String => "String",
            CollectionTy::Ordered => "BTreeMap/HashMap",
        }
    }
}

/// Collection type of a syntax type, if it is an unbounded collection.
pub fn collection_type_of(ty: &Type) -> Option<CollectionTy> {
    let ident = match ty {
        Type::Path(path) => last_segment(&path.path)?.to_string(),
        Type::Paren(paren) => return collection_type_of(&paren.elem),
        Type::Group(group) => return collection_type_of(&group.elem),
        _ => return None,
    };
    collection_type_of_name(&ident)
}

/// Collection type from a bare type name.
pub fn collection_type_of_name(name: &str) -> Option<CollectionTy> {
    match name {
        "Vec" | "VecDeque" => Some(CollectionTy::Vec),
        "Map" => Some(CollectionTy::Map),
        "Bytes" | "BytesN" => Some(CollectionTy::Bytes),
        "String" | "Symbol" => Some(CollectionTy::String),
        "BTreeMap" | "BTreeSet" | "HashMap" | "HashSet" => Some(CollectionTy::Ordered),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_strips_all_whitespace() {
        let expr: Expr = syn::parse_str("DataKey :: Balance ( addr )").unwrap();
        assert_eq!(canonical(&expr), "DataKey::Balance(addr)");
    }

    #[test]
    fn path_suffix_matching_ignores_module_prefixes() {
        let path: Path = syn::parse_str("soroban_sdk::token::Client").unwrap();
        assert!(path_ends_with(&path, &["token", "Client"]));
        assert!(path_ends_with(&path, &["Client"]));
        assert!(!path_ends_with(&path, &["soroban_sdk", "Client"]));
        assert_eq!(last_segment(&path).unwrap().to_string(), "Client");
    }

    #[test]
    fn detects_calls_by_path_suffix() {
        let expr: Expr = syn::parse_str("soroban_sdk::token::Client::new(&env, &id)").unwrap();
        assert!(is_call_to(&expr, &["Client", "new"]));
        assert!(!is_call_to(&expr, &["Client", "old"]));
    }

    #[test]
    fn integer_types_report_width_and_signedness() {
        assert_eq!(integer_type_of_name("i128"), Some(IntegerTy::I128));
        assert_eq!(integer_type_of_name("u64"), Some(IntegerTy::U64));
        assert_eq!(integer_type_of_name("f64"), None);
        assert!(IntegerTy::I128.is_signed());
        assert!(!IntegerTy::U128.is_signed());
        assert_eq!(IntegerTy::U128.bits(), 128);
        assert_eq!(IntegerTy::I256.name(), "I256");
    }

    #[test]
    fn lossy_casts_are_detected() {
        // Narrowing, signed to unsigned, and same-width sign flips lose information.
        assert!(IntegerTy::I128.cast_is_lossy(IntegerTy::U32));
        assert!(IntegerTy::I128.cast_is_lossy(IntegerTy::U128));
        assert!(IntegerTy::U64.cast_is_lossy(IntegerTy::I64));
        assert!(IntegerTy::I128.cast_is_lossy(IntegerTy::I64));
        // Widening is safe, including unsigned into a strictly wider signed type.
        assert!(!IntegerTy::U32.cast_is_lossy(IntegerTy::U64));
        assert!(!IntegerTy::U32.cast_is_lossy(IntegerTy::I64));
        assert!(!IntegerTy::I32.cast_is_lossy(IntegerTy::I64));
    }

    #[test]
    fn integer_type_names_are_case_insensitive() {
        assert_eq!(integer_type_of_name("I128"), Some(IntegerTy::I128));
        assert_eq!(integer_type_of_name("U256"), Some(IntegerTy::U256));
    }

    #[test]
    fn integer_type_of_reads_type_nodes() {
        let ty: Type = syn::parse_str("soroban_sdk::I128").unwrap();
        assert_eq!(integer_type_of(&ty), Some(IntegerTy::I128));
        let ty: Type = syn::parse_str("Vec<i128>").unwrap();
        assert_eq!(integer_type_of(&ty), None);
    }

    #[test]
    fn collection_types_are_recognised() {
        let ty: Type = syn::parse_str("soroban_sdk::Vec<Address>").unwrap();
        assert_eq!(collection_type_of(&ty), Some(CollectionTy::Vec));
        let ty: Type = syn::parse_str("Map<Address, i128>").unwrap();
        assert_eq!(collection_type_of(&ty), Some(CollectionTy::Map));
        let ty: Type = syn::parse_str("i128").unwrap();
        assert_eq!(collection_type_of(&ty), None);
    }
}
