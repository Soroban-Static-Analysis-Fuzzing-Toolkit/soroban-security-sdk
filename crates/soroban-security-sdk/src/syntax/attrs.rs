//! Attribute inspection.
//!
//! Attribute names are compared on their *last path segment*, so
//! `#[contractimpl]`, `#[soroban_sdk::contractimpl]` and
//! `#[soroban_sdk::contractimpl(export_if = "...")]` are all recognised.

use proc_macro2::TokenTree;
use syn::Attribute;

/// Name of an attribute: the last path segment, e.g. `contractimpl`.
pub fn attr_name(attr: &Attribute) -> Option<String> {
    attr.path().segments.last().map(|segment| segment.ident.to_string())
}

/// Whether any attribute is named `name`.
pub fn has_attr(attrs: &[Attribute], name: &str) -> bool {
    find_attr(attrs, name).is_some()
}

/// Find the first attribute named `name`.
pub fn find_attr<'a>(attrs: &'a [Attribute], name: &str) -> Option<&'a Attribute> {
    attrs.iter().find(|attr| attr_name(attr).as_deref() == Some(name))
}

/// Whether any attribute is named one of `names`.
pub fn has_any_attr(attrs: &[Attribute], names: &[&str]) -> bool {
    names.iter().any(|name| has_attr(attrs, name))
}

/// Whether an attribute is `#[test]`, `#[tokio::test]`, `#[cfg(test)]`, etc.
///
/// Test code is excluded from most detectors: it is allowed to panic, to use
/// unchecked arithmetic and to hard-code addresses.
pub fn is_test_attr(attr: &Attribute) -> bool {
    let Some(name) = attr_name(attr) else {
        return false;
    };
    if name == "test" {
        return true;
    }
    if name == "cfg" || name == "cfg_attr" {
        return meta_mentions_test(attr);
    }
    false
}

/// Whether any attribute marks the item as test-only.
pub fn is_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(is_test_attr)
}

/// Whether an attribute is a `#[cfg(...)]` disabling the item for non-test builds.
pub fn is_cfg_test(attr: &Attribute) -> bool {
    attr_name(attr).as_deref() == Some("cfg") && meta_mentions_test(attr)
}

/// Whether an item is annotated `#[deprecated]`.
pub fn is_deprecated(attrs: &[Attribute]) -> bool {
    has_attr(attrs, "deprecated")
}

/// Collect `#[doc = "..."]` lines.
pub fn doc_lines(attrs: &[Attribute]) -> Vec<String> {
    let mut lines = Vec::new();
    for attr in attrs {
        if attr_name(attr).as_deref() != Some("doc") {
            continue;
        }
        if let syn::Meta::NameValue(meta) = &attr.meta {
            if let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(value),
                ..
            }) = &meta.value
            {
                lines.push(value.value());
            }
        }
    }
    lines
}

/// Whether a path qualified name contains a segment.
pub fn path_has_segment(path: &syn::Path, name: &str) -> bool {
    path.segments
        .iter()
        .any(|segment| segment.ident == name)
}

/// Whether the attribute's token stream contains the identifier `test`.
fn meta_mentions_test(attr: &Attribute) -> bool {
    let tokens = match &attr.meta {
        syn::Meta::List(list) => list.tokens.clone(),
        syn::Meta::Path(_) | syn::Meta::NameValue(_) => return false,
    };
    walk_for_test(tokens.into_iter())
}

fn walk_for_test(tokens: impl Iterator<Item = TokenTree>) -> bool {
    for token in tokens {
        let found = match token {
            TokenTree::Ident(ident) => ident == "test",
            TokenTree::Group(group) => walk_for_test(group.stream().into_iter()),
            _ => false,
        };
        if found {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs_of(source: &str) -> Vec<Attribute> {
        let file = syn::parse_file(source).unwrap();
        match &file.items[0] {
            syn::Item::Fn(func) => func.attrs.clone(),
            _ => Vec::new(),
        }
    }

    #[test]
    fn matches_qualified_attribute_names() {
        let attrs = attrs_of("#[soroban_sdk::contractimpl]\nfn f() {}");
        assert!(has_attr(&attrs, "contractimpl"));
        assert_eq!(attr_name(&attrs[0]).as_deref(), Some("contractimpl"));
        assert!(!has_attr(&attrs, "contract"));
    }

    #[test]
    fn detects_test_items() {
        assert!(is_test(&attrs_of("#[test]\nfn f() {}")));
        assert!(is_test(&attrs_of("#[cfg(test)]\nfn f() {}")));
        assert!(is_test(&attrs_of("#[cfg(all(test, feature = \"x\"))]\nfn f() {}")));
        assert!(is_test(&attrs_of("#[tokio::test]\nfn f() {}")));
        assert!(!is_test(&attrs_of(
            "#[cfg(feature = \"testing\")]\nfn f() {}"
        )));
        assert!(!is_test(&attrs_of("fn f() {}")));
    }

    #[test]
    fn finds_attributes_with_arguments() {
        let attrs = attrs_of("#[contractimpl(export_if = \"x\")]\nfn f() {}");
        assert!(has_attr(&attrs, "contractimpl"));
        assert!(!is_test(&attrs));
    }

    #[test]
    fn collects_doc_lines() {
        let attrs = attrs_of("/// first\n/// second\nfn f() {}");
        assert_eq!(doc_lines(&attrs), vec![" first", " second"]);
    }
}
