//! Function-level views over the syntax tree.
//!
//! Detectors iterate [`FunctionView`]s rather than walking `syn::Item`s, which
//! means they get entrypoint/visibility/test classification and parameter types
//! for free.

use crate::source::FileId;
use crate::span::SourceSpan;
use crate::syntax::attrs::{has_attr, is_test_attr};
use crate::syntax::paths::{
    canonical, collection_type_of, integer_type_of, last_segment, CollectionTy, IntegerTy,
};

/// Where a function is defined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Container {
    /// A free function at module level.
    Module,
    /// A method in an inherent `impl`.
    InherentImpl,
    /// A method in a trait implementation.
    TraitImpl,
    /// A signature in a trait definition.
    TraitDeclaration,
}

/// Classification of a parameter type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamKind {
    /// The Soroban environment, `Env` or `&Env`.
    Env,
    /// A Soroban `Address`.
    Address,
    /// A `Val`, `Symbol` or other opaque host value.
    Host,
    /// An integer of known width.
    Integer(IntegerTy),
    /// An unbounded collection.
    Collection(CollectionTy),
    /// Anything else.
    Other,
}

/// A function parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    /// Parameter name (`arg0` when the pattern is not a simple binding).
    pub name: String,
    /// Canonical rendering of the parameter type.
    pub ty: String,
    /// Classification of the type.
    pub kind: ParamKind,
    /// Span of the typed pattern.
    pub span: SourceSpan,
}

impl Param {
    /// Whether the parameter is the environment.
    pub fn is_env(&self) -> bool {
        self.kind == ParamKind::Env
    }

    /// Whether the parameter is an `Address`.
    pub fn is_address(&self) -> bool {
        self.kind == ParamKind::Address
    }

    /// Whether the parameter is an integer.
    pub fn is_integer(&self) -> bool {
        matches!(self.kind, ParamKind::Integer(_))
    }

    /// Whether the parameter is a collection.
    pub fn is_collection(&self) -> bool {
        matches!(self.kind, ParamKind::Collection(_))
    }
}

/// A function under analysis.
#[derive(Debug, Clone)]
pub struct FunctionView<'a> {
    /// File the function lives in.
    pub file: FileId,
    /// Where the function is defined.
    pub container: Container,
    /// Attributes on the function itself.
    pub attrs: &'a [syn::Attribute],
    /// Attributes on the enclosing `impl`, if any.
    pub impl_attrs: &'a [syn::Attribute],
    /// Name of the function.
    pub ident: &'a syn::Ident,
    /// Signature.
    pub sig: &'a syn::Signature,
    /// Body, absent for trait declarations without a default implementation.
    pub block: Option<&'a syn::Block>,
    /// Whether the function is `pub`.
    pub is_public: bool,
    /// `Self` type of the enclosing `impl`.
    pub impl_self_ty: Option<&'a syn::Type>,
    /// Trait being implemented, for trait impls.
    pub trait_path: Option<&'a syn::Path>,
    /// Whether a body is present.
    pub has_body: bool,
}

impl<'a> FunctionView<'a> {
    /// Function name.
    pub fn name(&self) -> String {
        self.ident.to_string()
    }

    /// Span of the function name.
    pub fn span(&self) -> SourceSpan {
        SourceSpan::of(self.ident)
    }

    /// Statements of the body, empty for declarations.
    pub fn stmts(&self) -> &'a [syn::Stmt] {
        match self.block {
            Some(block) => block.stmts.as_slice(),
            None => &[],
        }
    }

    /// Span of the body, when there is one.
    pub fn body_span(&self) -> Option<SourceSpan> {
        self.block.map(SourceSpan::of)
    }

    /// Span including attributes and signature.
    pub fn full_span(&self) -> SourceSpan {
        let mut span = SourceSpan::of(self.ident);
        span = span.merge(SourceSpan::of(self.sig));
        if let Some(block) = self.block {
            span = span.merge(SourceSpan::of(block));
        }
        for attr in self.attrs {
            span = span.merge(SourceSpan::of(attr));
        }
        for attr in self.impl_attrs {
            span = span.merge(SourceSpan::of(attr));
        }
        span
    }

    /// `(file, name span)` for building locations.
    pub fn locate(&self) -> (FileId, SourceSpan) {
        (self.file, self.span())
    }

    /// Whether the function is `pub`.
    pub fn is_public(&self) -> bool {
        self.is_public
    }

    /// Whether the function is test-only.
    pub fn is_test(&self) -> bool {
        self.attrs.iter().any(is_test_attr) || self.impl_attrs.iter().any(is_test_attr)
    }

    /// Whether the function is defined inside a `#[contractimpl]` block.
    pub fn in_contract_impl(&self) -> bool {
        has_attr(self.impl_attrs, "contractimpl")
    }

    /// Whether the function is exported as a contract entrypoint.
    pub fn is_entrypoint(&self) -> bool {
        self.has_body
            && self.in_contract_impl()
            && self.is_public()
            && !self.is_test()
            && self.sig.receiver().is_none()
    }

    /// Whether the function is the constructor or an auth hook.
    pub fn is_special_entrypoint(&self) -> bool {
        matches!(self.name().as_str(), "__constructor")
    }

    /// Whether the function implements `__check_auth` of a custom account.
    pub fn is_check_auth(&self) -> bool {
        self.name() == "__check_auth"
    }

    /// Name of the contract the function belongs to.
    pub fn contract_name(&self) -> Option<String> {
        let ty = self.impl_self_ty?;
        match ty {
            syn::Type::Path(path) => last_segment(&path.path).map(|ident| ident.to_string()),
            _ => None,
        }
    }

    /// Whether the function is a module-level `fn`.
    pub fn is_free(&self) -> bool {
        self.container == Container::Module
    }

    /// Whether the function is a private helper of a contract implementation.
    pub fn is_private_helper(&self) -> bool {
        self.in_contract_impl() && !self.is_public()
    }

    /// Parameters, with their classifications.
    pub fn params(&self) -> Vec<Param> {
        params_of(self.sig)
    }

    /// Canonical rendering of the return type.
    pub fn return_type(&self) -> Option<String> {
        match &self.sig.output {
            syn::ReturnType::Default => None,
            syn::ReturnType::Type(_, ty) => Some(canonical(ty)),
        }
    }

    /// Attributes of the function and its enclosing impl.
    pub fn all_attrs(&self) -> impl Iterator<Item = &'a syn::Attribute> {
        self.attrs.iter().chain(self.impl_attrs.iter())
    }
}

/// Extract parameters and their classifications from a signature.
///
/// Receiver parameters (`&self`) are skipped: contract entrypoints never have one.
pub fn params_of(signature: &syn::Signature) -> Vec<Param> {
    let mut params = Vec::new();
    for (index, argument) in signature.inputs.iter().enumerate() {
        let syn::FnArg::Typed(typed) = argument else {
            continue;
        };
        let name = match &*typed.pat {
            syn::Pat::Ident(ident) => ident.ident.to_string(),
            other => {
                let rendered = canonical(other);
                let truncated: String = rendered.chars().take(12).collect();
                format!("arg{index}_{truncated}")
            }
        };
        params.push(Param {
            name,
            kind: classify_type(&typed.ty),
            ty: canonical(&typed.ty),
            span: SourceSpan::of(&typed.ty),
        });
    }
    params
}

/// Classify a type into the categories detectors care about.
pub fn classify_type(ty: &syn::Type) -> ParamKind {
    if let Some(integer) = integer_type_of(ty) {
        return ParamKind::Integer(integer);
    }
    if let Some(collection) = collection_type_of(ty) {
        return ParamKind::Collection(collection);
    }
    let name = match ty {
        syn::Type::Path(path) => last_segment(&path.path).map(|ident| ident.to_string()),
        syn::Type::Reference(reference) => match &*reference.elem {
            syn::Type::Path(path) => last_segment(&path.path).map(|ident| ident.to_string()),
            _ => None,
        },
        _ => None,
    };
    match name.as_deref() {
        Some("Env") => ParamKind::Env,
        Some("Address") => ParamKind::Address,
        Some("Val" | "Symbol" | "RawVal") => ParamKind::Host,
        Some(name) => crate::syntax::paths::integer_type_of_name(name)
            .map(ParamKind::Integer)
            .or_else(|| {
                crate::syntax::paths::collection_type_of_name(name).map(ParamKind::Collection)
            })
            .unwrap_or(ParamKind::Other),
        None => ParamKind::Other,
    }
}

/// Collect every function in a parsed file, including nested modules.
pub fn collect(file: &syn::File, file_id: FileId) -> Vec<FunctionView<'_>> {
    let mut out = Vec::new();
    collect_from_items(&file.items, file_id, &mut out);
    out
}

/// Collect functions from a slice of items.
pub fn collect_from_items<'a>(
    items: &'a [syn::Item],
    file_id: FileId,
    out: &mut Vec<FunctionView<'a>>,
) {
    for item in items {
        match item {
            syn::Item::Fn(func) => out.push(FunctionView {
                file: file_id,
                container: Container::Module,
                attrs: &func.attrs,
                impl_attrs: &[],
                ident: &func.sig.ident,
                sig: &func.sig,
                block: Some(&func.block),
                is_public: matches!(func.vis, syn::Visibility::Public(_)),
                impl_self_ty: None,
                trait_path: None,
                has_body: true,
            }),
            syn::Item::Impl(item_impl) => {
                for inner in &item_impl.items {
                    let syn::ImplItem::Fn(func) = inner else {
                        continue;
                    };
                    out.push(FunctionView {
                        file: file_id,
                        container: match &item_impl.trait_ {
                            Some(_) => Container::TraitImpl,
                            None => Container::InherentImpl,
                        },
                        attrs: &func.attrs,
                        impl_attrs: &item_impl.attrs,
                        ident: &func.sig.ident,
                        sig: &func.sig,
                        block: Some(&func.block),
                        is_public: matches!(func.vis, syn::Visibility::Public(_)),
                        impl_self_ty: Some(&item_impl.self_ty),
                        trait_path: item_impl.trait_.as_ref().map(|(path, _)| path),
                        has_body: true,
                    });
                }
            }
            syn::Item::Trait(item_trait) => {
                for inner in &item_trait.items {
                    let syn::TraitItem::Fn(func) = inner else {
                        continue;
                    };
                    let syn::TraitItemFn { attrs, sig, default, .. } = func;
                    out.push(FunctionView {
                        file: file_id,
                        container: Container::TraitDeclaration,
                        attrs,
                        impl_attrs: &item_trait.attrs,
                        ident: &sig.ident,
                        sig,
                        block: default.as_ref(),
                        is_public: false,
                        impl_self_ty: None,
                        trait_path: None,
                        has_body: default.is_some(),
                    });
                }
            }
            syn::Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    collect_from_items(nested, file_id, out);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn functions(source: &str) -> Vec<String> {
        let file = syn::parse_file(source).unwrap();
        collect(&file, FileId(0))
            .iter()
            .map(|function| {
                format!(
                    "{}:{}:{}",
                    function.name(),
                    function.is_entrypoint(),
                    function.is_test()
                )
            })
            .collect()
    }

    #[test]
    fn finds_entrypoints_only_in_contract_impls() {
        let found = functions(
            r#"
#[contractimpl]
impl Token {
    pub fn transfer(env: Env, from: Address, amount: i128) {}
    fn helper(env: Env) {}
    #[cfg(test)]
    pub fn test_only(env: Env) {}
}

impl Token {
    pub fn not_exported(env: Env) {}
}

pub fn free_function() {}
"#,
        );
        assert_eq!(
            found,
            vec![
                "transfer:true:false",
                "helper:false:false",
                "test_only:false:true",
                "not_exported:false:false",
                "free_function:false:false",
            ]
        );
    }

    #[test]
    fn recognises_contractimpl_on_trait_impls() {
        let file = syn::parse_file(
            r#"
#[contractimpl]
impl TokenInterface for Token {
    fn transfer(env: Env, from: Address) {}
}
"#,
        )
        .unwrap();
        let collected = collect(&file, FileId(0));
        assert_eq!(collected.len(), 1);
        assert!(collected[0].in_contract_impl());
        assert!(!collected[0].is_entrypoint(), "non-pub trait method is not exported");
        assert_eq!(collected[0].contract_name().as_deref(), Some("Token"));
        assert_eq!(
            collected[0].trait_path.map(|path| path.segments.last().unwrap().ident.to_string()),
            Some("TokenInterface".to_string())
        );
    }

    #[test]
    fn parses_parameter_classifications() {
        let file = syn::parse_file(
            "fn f(env: Env, from: Address, amount: i128, holders: Vec<Address>, other: Foo) {}",
        )
        .unwrap();
        let function = &collect(&file, FileId(0))[0];
        let params = function.params();
        let kinds: Vec<&str> = params
            .iter()
            .map(|param| match param.kind {
                ParamKind::Env => "env",
                ParamKind::Address => "address",
                ParamKind::Integer(_) => "int",
                ParamKind::Collection(_) => "collection",
                ParamKind::Host => "host",
                ParamKind::Other => "other",
            })
            .collect();
        assert_eq!(kinds, vec!["env", "address", "int", "collection", "other"]);
        assert_eq!(params[2].ty, "i128");
        assert!(params[1].is_address());
    }

    #[test]
    fn reads_return_types_and_spans() {
        let source = "fn f(env: Env) -> Result<i128, Error> {\n    Ok(1)\n}\n";
        let file = syn::parse_file(source).unwrap();
        let function = &collect(&file, FileId(0))[0];
        assert_eq!(function.return_type().as_deref(), Some("Result<i128,Error>"));
        assert_eq!(function.span().start_line, 1);
        assert!(function.body_span().unwrap().is_multiline());
        assert!(function.full_span().is_known());
        assert_eq!(function.stmts().len(), 1);
    }

    #[test]
    fn handles_nested_modules() {
        let found = functions("mod inner {\n    fn nested() {}\n}");
        assert_eq!(found, vec!["nested:false:false"]);
    }

    #[test]
    fn detects_check_auth_and_constructor() {
        let file = syn::parse_file(
            r#"
#[contractimpl]
impl Account {
    pub fn __constructor(env: Env) {}
    pub fn __check_auth(env: Env) {}
}
"#,
        )
        .unwrap();
        let collected = collect(&file, FileId(0));
        assert!(collected[0].is_special_entrypoint());
        assert!(collected[1].is_check_auth());
    }
}
