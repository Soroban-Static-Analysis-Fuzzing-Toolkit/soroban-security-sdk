//! Expression inspection helpers.

use syn::{Expr, Lit, UnOp};

/// Strip references, parentheses and groups: `&(&key)` becomes `key`.
pub fn unwrap_refs(expr: &Expr) -> &Expr {
    match expr {
        Expr::Reference(reference) => unwrap_refs(&reference.expr),
        Expr::Paren(paren) => unwrap_refs(&paren.expr),
        Expr::Group(group) => unwrap_refs(&group.expr),
        other => other,
    }
}

/// The method name of a method call, if this is one.
pub fn method_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::MethodCall(call) => Some(call.method.to_string()),
        _ => None,
    }
}

/// The receiver of a method call.
pub fn method_receiver(expr: &Expr) -> Option<&Expr> {
    match expr {
        Expr::MethodCall(call) => Some(&call.receiver),
        _ => None,
    }
}

/// Arguments of a method call or function call.
pub fn call_args(expr: &Expr) -> Vec<&Expr> {
    match expr {
        Expr::MethodCall(call) => call.args.iter().collect(),
        Expr::Call(call) => call.args.iter().collect(),
        _ => Vec::new(),
    }
}

/// The nth argument of a call, references stripped.
pub fn arg(expr: &Expr, index: usize) -> Option<&Expr> {
    call_args(expr).get(index).map(|argument| unwrap_refs(argument))
}

/// Whether the expression is an integer literal (`1`, `1_000u64`).
pub fn is_int_literal(expr: &Expr) -> bool {
    matches!(unwrap_refs(expr), Expr::Lit(syn::ExprLit { lit: Lit::Int(_), .. }))
}

/// Value of an integer literal, including a leading unary minus.
pub fn literal_int(expr: &Expr) -> Option<i128> {
    match unwrap_refs(expr) {
        Expr::Lit(syn::ExprLit { lit: Lit::Int(int), .. }) => parse_int_literal(int),
        Expr::Unary(unary) if matches!(unary.op, UnOp::Neg(_)) => {
            literal_int(&unary.expr).map(|value| -value)
        }
        Expr::Paren(_) | Expr::Group(_) | Expr::Reference(_) => literal_int(unwrap_refs(expr)),
        _ => None,
    }
}

/// Parse a `syn::LitInt`, ignoring its suffix.
pub fn parse_int_literal(int: &syn::LitInt) -> Option<i128> {
    let digits = int.base10_digits();
    let cleaned: String = digits.chars().filter(|c| *c != '_').collect();
    cleaned.parse::<i128>().ok()
}

/// Whether the expression is the identifier `name`.
pub fn is_ident_named(expr: &Expr, name: &str) -> bool {
    match unwrap_refs(expr) {
        Expr::Path(path) => path
            .path
            .get_ident()
            .map(|ident| ident == name)
            .unwrap_or(false),
        _ => false,
    }
}

/// The identifier of a plain path expression, if any.
pub fn ident_of(expr: &Expr) -> Option<&syn::Ident> {
    match unwrap_refs(expr) {
        Expr::Path(path) => path.path.get_ident(),
        Expr::Field(field) => match &field.member {
            syn::Member::Named(ident) => Some(ident),
            syn::Member::Unnamed(_) => None,
        },
        _ => None,
    }
}

/// Whether the expression is `()`.
pub fn is_unit(expr: &Expr) -> bool {
    matches!(unwrap_refs(expr), Expr::Tuple(tuple) if tuple.elems.is_empty())
}

/// Whether the expression is a literal string.
pub fn is_string_literal(expr: &Expr) -> bool {
    matches!(unwrap_refs(expr), Expr::Lit(syn::ExprLit { lit: Lit::Str(_), .. }))
}

/// The string value of a literal, if it is one.
pub fn literal_string(expr: &Expr) -> Option<String> {
    match unwrap_refs(expr) {
        Expr::Lit(syn::ExprLit { lit: Lit::Str(value), .. }) => Some(value.value()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(source: &str) -> Expr {
        syn::parse_str(source).unwrap()
    }

    #[test]
    fn unwrap_refs_strips_references_and_parens() {
        let expr = parse("&(&(key))");
        assert!(matches!(unwrap_refs(&expr), Expr::Path(_)));
    }

    #[test]
    fn reads_method_names_and_receivers() {
        let expr = parse("env.storage().persistent().set(&key, &value)");
        assert_eq!(method_name(&expr).as_deref(), Some("set"));
        assert_eq!(call_args(&expr).len(), 2);
        assert_eq!(super::super::paths::canonical(arg(&expr, 0).unwrap()), "key");
    }

    #[test]
    fn parses_integer_literals_with_suffixes() {
        assert_eq!(literal_int(&parse("1_000u64")), Some(1000));
        assert_eq!(literal_int(&parse("-5i128")), Some(-5));
        // syn normalises non-decimal literals, so `0x10` reports as 16.
        assert_eq!(literal_int(&parse("0x10")), Some(16));
        assert!(is_int_literal(&parse("42")));
        assert!(!is_int_literal(&parse("\"42\"")));
    }

    #[test]
    fn identifies_idents_and_strings() {
        assert!(is_ident_named(&parse("amount"), "amount"));
        assert!(!is_ident_named(&parse("other"), "amount"));
        assert_eq!(literal_string(&parse("\"hello\"")).as_deref(), Some("hello"));
        assert!(is_unit(&parse("()")));
    }

    #[test]
    fn ident_of_handles_field_access() {
        let expr = parse("state.balance");
        assert_eq!(ident_of(&expr).unwrap().to_string(), "balance");
    }
}
