//! Derivation of [`ContractModel`] from syntax trees.
//!
//! The builder is a single `syn::visit::Visit` pass per file that tracks the
//! enclosing contract, function and loop nesting, plus a lightweight type
//! environment. That environment is what lets the arithmetic detectors say "this
//! `+` is on `i128`" without a compiler-grade type check: parameters, annotated
//! locals, casts and turbofish arguments are recorded, and anything that cannot be
//! resolved is marked untyped rather than guessed.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use syn::visit::Visit;

use crate::model::{
    ArithmeticSite, AuthCheck, AuthKind, CastSite, Contract, ContractCall, ContractModel,
    ContractType, ContractTypeKind, IntegerOp, LoopBound, LoopKind, LoopSite, PanicKind, PanicSite,
    RandomnessSite, RandomnessSource, RandomnessUse, Site, StorageAccess, StorageOp, StorageTier,
    UpgradeSite,
};
use crate::source::{FileId, SourceMap};
use crate::span::SourceSpan;
use crate::syntax::attrs::{has_attr, is_test};
use crate::syntax::exprs::{ident_of, literal_int, unwrap_refs};
use crate::syntax::functions::{classify_type, params_of};
use crate::syntax::paths::{
    canonical, collection_type_of, collection_type_of_name, integer_type_of,
    integer_type_of_name, last_segment, path_ends_with, CollectionTy, IntegerTy,
};
use crate::syntax::{Expr, ParamKind};

pub(crate) fn build(sources: &SourceMap, include_tests: bool) -> ContractModel {
    let mut builder = Builder::new(include_tests);
    for source in sources.iter() {
        builder.begin_file(source.id());
        builder.visit_file(source.syntax());
    }
    builder.finish()
}

/// Enclosing `impl` block context.
#[derive(Debug, Clone)]
struct ImplCtx {
    contract: Option<String>,
    in_contract_impl: bool,
    is_test: bool,
}

/// Enclosing function context, including the local type environment.
#[derive(Debug, Clone, Default)]
struct FnCtx {
    name: String,
    span: SourceSpan,
    contract: Option<String>,
    env: HashMap<String, ParamKind>,
    storage_idents: BTreeSet<String>,
    clients: HashMap<String, String>,
    parameters: BTreeSet<String>,
    key_types: HashMap<String, ParamKind>,
}

struct Builder {
    include_tests: bool,
    file: FileId,
    impl_ctx: Option<ImplCtx>,
    function: Option<FnCtx>,
    test_depth: usize,
    loop_depth: usize,
    guarded_depth: usize,
    model: ContractModel,
    entrypoints: Vec<crate::model::Entrypoint>,
    declared_contracts: Vec<(String, FileId, SourceSpan)>,
    impl_contracts: Vec<(String, FileId, SourceSpan)>,
    defined_functions: BTreeSet<String>,
}

impl Builder {
    fn new(include_tests: bool) -> Self {
        Builder {
            include_tests,
            file: FileId(0),
            impl_ctx: None,
            function: None,
            test_depth: 0,
            loop_depth: 0,
            guarded_depth: 0,
            model: ContractModel::default(),
            entrypoints: Vec::new(),
            declared_contracts: Vec::new(),
            impl_contracts: Vec::new(),
            defined_functions: BTreeSet::new(),
        }
    }

    fn begin_file(&mut self, file: FileId) {
        self.file = file;
        self.impl_ctx = None;
        self.function = None;
        self.test_depth = 0;
        self.loop_depth = 0;
        self.guarded_depth = 0;
    }

    /// Whether the current position is test-only code.
    fn skip(&self) -> bool {
        if self.include_tests {
            return false;
        }
        self.test_depth > 0 || self.impl_ctx.as_ref().is_some_and(|ctx| ctx.is_test)
    }

    fn site(&self, span: SourceSpan) -> Site {
        let (function, function_span, contract) = match &self.function {
            Some(ctx) => (ctx.name.clone(), ctx.span, ctx.contract.clone()),
            None => (String::new(), SourceSpan::UNKNOWN, None),
        };
        Site {
            file: self.file,
            contract,
            function,
            function_span,
            span,
            in_loop: self.loop_depth > 0,
        }
    }

    /// Infer the type of an expression from the local type environment.
    fn infer(&self, expr: &Expr) -> ParamKind {
        match &self.function {
            Some(ctx) => infer_expr_ty(expr, &ctx.env),
            None => ParamKind::Other,
        }
    }

    fn env_lookup(&self, name: &str) -> Option<ParamKind> {
        self.function.as_ref()?.env.get(name).copied()
    }

    /// Value type of a ledger key, inferred from annotated bindings.
    fn key_type(&self, key: &str) -> Option<ParamKind> {
        self.function.as_ref()?.key_types.get(key).copied()
    }

    fn is_storage_ident(&self, name: &str) -> bool {
        self.function
            .as_ref()
            .is_some_and(|ctx| ctx.storage_idents.contains(name))
    }

    fn current_parameters(&self) -> BTreeSet<String> {
        self.function
            .as_ref()
            .map(|ctx| ctx.parameters.clone())
            .unwrap_or_default()
    }

    fn push_call_graph_edge(&mut self, callee: String) {
        let Some(caller) = self.function.as_ref().map(|ctx| ctx.name.clone()) else {
            return;
        };
        self.model.call_graph.entry(caller).or_default().push(callee);
    }

    fn enter_function(
        &mut self,
        name: String,
        span: SourceSpan,
        signature: &syn::Signature,
        block: Option<&syn::Block>,
    ) {
        let contract = self.impl_ctx.as_ref().and_then(|ctx| ctx.contract.clone());
        let mut ctx = FnCtx {
            name,
            span,
            contract,
            ..FnCtx::default()
        };
        for param in params_of(signature) {
            ctx.env.insert(param.name.clone(), param.kind);
            ctx.parameters.insert(param.name.clone());
        }
        if let Some(block) = block {
            let mut collector = TypeEnvCollector::default();
            collector.visit_block(block);
            for (name, kind) in collector.env {
                ctx.env.entry(name).or_insert(kind);
            }
            ctx.storage_idents.extend(collector.storage_idents);
            ctx.clients.extend(collector.clients);
            ctx.key_types.extend(collector.key_types);
        }
        self.loop_depth = 0;
        self.guarded_depth = 0;
        self.function = Some(ctx);
    }

    fn exit_function(&mut self) {
        self.function = None;
        self.loop_depth = 0;
        self.guarded_depth = 0;
    }

    fn record_contract_type(
        &mut self,
        name: String,
        kind: ContractTypeKind,
        attrs: &[syn::Attribute],
        span: SourceSpan,
        variants: Vec<(String, bool)>,
        fields: Vec<String>,
    ) {
        if self.skip() {
            return;
        }
        let kind = if has_attr(attrs, "contracterror") {
            ContractTypeKind::Error
        } else if has_attr(attrs, "contractevent") {
            ContractTypeKind::Event
        } else if has_attr(attrs, "contracttype") {
            kind
        } else {
            return;
        };
        self.model.types.push(ContractType {
            name,
            kind,
            file: self.file,
            span,
            variants,
            fields,
        });
    }

    fn finish(mut self) -> ContractModel {
        // Drop call-graph edges that do not point at a function defined in the
        // analysed sources (method names such as `Vec::new` produce noise).
        let known = std::mem::take(&mut self.defined_functions);
        let graph = std::mem::take(&mut self.model.call_graph);
        let mut filtered: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (caller, callees) in graph {
            let mut unique: Vec<String> = Vec::new();
            for callee in callees {
                if known.contains(&callee) && !unique.contains(&callee) {
                    unique.push(callee);
                }
            }
            filtered.insert(caller, unique);
        }
        self.model.call_graph = filtered;

        let mut contracts: BTreeMap<String, Contract> = BTreeMap::new();
        for (name, file, span) in &self.declared_contracts {
            contracts.entry(name.clone()).or_insert_with(|| Contract {
                name: name.clone(),
                file: *file,
                span: *span,
                declared: true,
                entrypoints: Vec::new(),
            });
        }
        for (name, file, span) in &self.impl_contracts {
            let entry = contracts.entry(name.clone()).or_insert_with(|| Contract {
                name: name.clone(),
                file: *file,
                span: *span,
                declared: false,
                entrypoints: Vec::new(),
            });
            if entry.span == SourceSpan::UNKNOWN {
                entry.span = *span;
            }
        }
        for entrypoint in std::mem::take(&mut self.entrypoints) {
            if let Some(contract) = contracts.get_mut(&entrypoint.contract) {
                contract.entrypoints.push(entrypoint);
            }
        }
        self.model.contracts = contracts.into_values().collect();
        self.model.types.sort_by(|a, b| a.name.cmp(&b.name));
        self.model
    }

    /// Classify and record one method call.
    fn record_method_call(&mut self, node: &syn::ExprMethodCall) {
        let method = node.method.to_string();
        let span = SourceSpan::of(node);

        // Panicking calls.
        match method.as_str() {
            "unwrap" => {
                let on = canonical(&node.receiver);
                self.model.panics.push(PanicSite {
                    site: self.site(span),
                    kind: PanicKind::Unwrap,
                    on: Some(on),
                    text: canonical(node),
                    span,
                });
            }
            "expect" => {
                let on = canonical(&node.receiver);
                self.model.panics.push(PanicSite {
                    site: self.site(span),
                    kind: PanicKind::Expect,
                    on: Some(on),
                    text: canonical(node),
                    span,
                });
            }
            _ => {}
        }

        // Storage access.
        if let Some(access) = StorageAccess::from_method(&method) {
            if let Some(tier) = tier_of(node) {
                let key = storage_key_expr(node, tier, access);
                let value = storage_value_expr(node, access);
                let key_text = key.map(canonical);
                let key_span = key.map(SourceSpan::of);
                let value_text = value.map(canonical);
                let mut integer_ty = None;
                let mut collection_ty = None;
                for expr in [value, key].into_iter().flatten() {
                    match self.infer(expr) {
                        ParamKind::Integer(ty) => integer_ty = integer_ty.or(Some(ty)),
                        ParamKind::Collection(ty) => collection_ty = collection_ty.or(Some(ty)),
                        _ => {}
                    }
                }
                if let Some(ty) = turbofish_value_type(node) {
                    match ty {
                        ParamKind::Integer(ty) => integer_ty = integer_ty.or(Some(ty)),
                        ParamKind::Collection(ty) => collection_ty = collection_ty.or(Some(ty)),
                        _ => {}
                    }
                }
                // `let total: i128 = env.storage().persistent().get(&KEY).unwrap_or(0)`
                // carries the value type on the binding, not on the call.
                if integer_ty.is_none() && collection_ty.is_none() {
                    if let Some(key) = &key_text {
                        match self.key_type(key) {
                            Some(ParamKind::Integer(ty)) => integer_ty = Some(ty),
                            Some(ParamKind::Collection(kind)) => collection_ty = Some(kind),
                            _ => {}
                        }
                    }
                }
                let value_type = turbofish_text(node);
                let tier_span = SourceSpan::of(&node.receiver);
                self.model.storage_ops.push(StorageOp {
                    site: self.site(span),
                    tier,
                    access,
                    key: key_text,
                    key_span,
                    value: value_text,
                    value_type,
                    integer_type: integer_ty,
                    collection_type: collection_ty,
                    tier_span,
                });
            }
        }

        // Authorization.
        if method.starts_with("require_auth") {
            let receiver = &node.receiver;
            let receiver_ty = self.infer(receiver);
            let env_form = receiver_ty == ParamKind::Env || canonical(receiver) == "Address";
            let (target, target_span) = if env_form {
                let first = nth_arg(node, 0);
                (
                    first.map(canonical),
                    first.map(SourceSpan::of),
                )
            } else {
                (Some(canonical(receiver)), Some(SourceSpan::of(receiver)))
            };
            let kind = if env_form {
                AuthKind::EnvRequireAuth
            } else if method == "require_auth_for_args" {
                AuthKind::RequireAuthForArgs
            } else {
                AuthKind::RequireAuth
            };
            let args = (method == "require_auth_for_args")
                .then(|| nth_arg(node, 1).map(canonical))
                .flatten();
            self.model.auth_checks.push(AuthCheck {
                site: self.site(span),
                kind,
                target,
                target_span,
                args,
                call_span: span,
            });
        } else if is_verification_call(&method, receiver_chain_has(node, "crypto")) {
            self.model.auth_checks.push(AuthCheck {
                site: self.site(span),
                kind: AuthKind::VerifySignature,
                target: Some(canonical(&node.receiver)),
                target_span: Some(SourceSpan::of(&node.receiver)),
                args: None,
                call_span: span,
            });
        }

        // Cross-contract calls through generated clients.
        if let Some((interface, client_type)) = self.client_of(node) {
            self.model.calls.push(ContractCall {
                site: self.site(span),
                interface,
                client_type,
                method: method.clone(),
                args: node.args.iter().map(|arg| canonical(unwrap_refs(arg))).collect(),
                arg_spans: node.args.iter().map(SourceSpan::of).collect(),
                returns_result: method.starts_with("try_"),
                span,
            });
        }

        // Explicitly wrapping arithmetic, which opts out of overflow checking.
        if let Some(op) = IntegerOp::from_wrapping_method(&method) {
            let receiver_type = self.infer(&node.receiver);
            let right_type = nth_arg(node, 0).map(|arg| self.infer(arg)).unwrap_or(ParamKind::Other);
            let text = canonical(node);
            let untyped = !matches!(receiver_type, ParamKind::Integer(_));
            self.model.arithmetic.push(ArithmeticSite {
                site: self.site(span),
                op,
                left_type: receiver_type,
                right_type,
                untyped,
                guarded: self.guarded_depth > 0,
                text,
                span,
            });
        }

        // Upgrades and deployments.
        if is_upgrade_method(&method) {
            let argument = nth_arg(node, 0).map(canonical);
            let parameters = self.current_parameters();
            let argument_is_parameter = argument
                .as_ref()
                .is_some_and(|value| parameters.contains(value.trim_start_matches('&')));
            self.model.upgrades.push(UpgradeSite {
                site: self.site(span),
                method,
                argument,
                argument_is_parameter,
                span,
            });
        }
    }

    /// The interface of the client a method call goes through, if any.
    fn client_of(&self, node: &syn::ExprMethodCall) -> Option<(Option<String>, Option<String>)> {
        if let Some(ident) = ident_of(&node.receiver) {
            if let Some(ctx) = &self.function {
                if let Some(interface) = ctx.clients.get(&ident.to_string()) {
                    let interface = (!interface.is_empty()).then(|| interface.clone());
                    return Some((interface, None));
                }
            }
        }
        let Expr::Call(call) = unwrap_refs(&node.receiver) else {
            return None;
        };
        let Expr::Path(path) = &*call.func else {
            return None;
        };
        if !path_ends_with(&path.path, &["Client", "new"]) {
            return None;
        }
        let segments: Vec<String> = path
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        let interface = segments
            .iter()
            .rev()
            .nth(2)
            .filter(|name| name.as_str() != "soroban_sdk" && name.as_str() != "sdk")
            .cloned();
        let client_type = segments
            .iter()
            .take(segments.len() - 1)
            .cloned()
            .collect::<Vec<_>>()
            .join("::");
        Some((interface, Some(client_type)))
    }

    fn record_binary(&mut self, node: &syn::ExprBinary) {
        let span = SourceSpan::of(node);
        let comparison = matches!(
            node.op,
            syn::BinOp::Eq(_)
                | syn::BinOp::Ne(_)
                | syn::BinOp::Lt(_)
                | syn::BinOp::Le(_)
                | syn::BinOp::Gt(_)
                | syn::BinOp::Ge(_)
        );
        if comparison {
            if let Some((source, source_span)) =
                ledger_read(&node.left).or_else(|| ledger_read(&node.right))
            {
                self.model.randomness.push(RandomnessSite {
                    site: self.site(span),
                    source,
                    use_kind: RandomnessUse::Comparison,
                    text: canonical(node),
                    span: source_span,
                });
            }
            return;
        }

        let op = match &node.op {
            syn::BinOp::Add(_) => IntegerOp::Add,
            syn::BinOp::Sub(_) => IntegerOp::Sub,
            syn::BinOp::Mul(_) => IntegerOp::Mul,
            syn::BinOp::Div(_) => IntegerOp::Div,
            syn::BinOp::Rem(_) => IntegerOp::Rem,
            syn::BinOp::Shl(_) => IntegerOp::Shl,
            syn::BinOp::Shr(_) => IntegerOp::Shr,
            syn::BinOp::BitAnd(_) => IntegerOp::BitAnd,
            syn::BinOp::BitOr(_) => IntegerOp::BitOr,
            syn::BinOp::BitXor(_) => IntegerOp::BitXor,
            // Logical operators carry no arithmetic risk.
            syn::BinOp::And(_) | syn::BinOp::Or(_) => return,
            // Comparisons were handled above; the remaining operators are assignments.
            _ => return,
        };

        let left_type = self.infer(&node.left);
        let right_type = self.infer(&node.right);
        let typed = matches!(left_type, ParamKind::Integer(_))
            || matches!(right_type, ParamKind::Integer(_));

        if let Some((source, source_span)) =
            ledger_read(&node.left).or_else(|| ledger_read(&node.right))
        {
            self.model.randomness.push(RandomnessSite {
                site: self.site(span),
                source,
                use_kind: RandomnessUse::Arithmetic,
                text: canonical(node),
                span: source_span,
            });
        }

        self.model.arithmetic.push(ArithmeticSite {
            site: self.site(span),
            op,
            left_type,
            right_type,
            untyped: !typed,
            guarded: self.guarded_depth > 0,
            text: canonical(node),
            span,
        });
    }

    /// Where a `for` loop's iteration count comes from.
    fn loop_bound(&self, expr: &Expr) -> LoopBound {
        if let Expr::Range(range) = expr {
            if let Some(end) = range.end.as_deref() {
                if let Some(value) = literal_int(end) {
                    let start = range.start.as_deref().and_then(literal_int).unwrap_or(0);
                    let inclusive = matches!(range.limits, syn::RangeLimits::Closed(_));
                    let count = value - start + i128::from(inclusive);
                    return LoopBound::Literal(count.max(0) as u64);
                }
                if let Some(ident) = ident_of(end) {
                    return LoopBound::Parameter(ident.to_string());
                }
                if let Some(receiver) = method_receiver_ident(end) {
                    return LoopBound::Parameter(receiver.to_string());
                }
            }
            return LoopBound::Unknown;
        }

        if let Some(receiver) = iter_receiver(expr) {
            if let Some(ident) = ident_of(receiver) {
                let name = ident.to_string();
                if self.is_storage_ident(&name) {
                    return LoopBound::Storage;
                }
                if let Some(ParamKind::Collection(kind)) = self.env_lookup(&name) {
                    return LoopBound::Collection(kind);
                }
                return LoopBound::Unknown;
            }
            if expr_has_storage_access(receiver) {
                return LoopBound::Storage;
            }
        }
        if expr_has_storage_access(expr) {
            return LoopBound::Storage;
        }
        LoopBound::Unknown
    }
}

impl<'ast> Visit<'ast> for Builder {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let is_test_module = is_test(&node.attrs);
        if is_test_module {
            self.test_depth += 1;
        }
        syn::visit::visit_item_mod(self, node);
        if is_test_module {
            self.test_depth -= 1;
        }
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        self.record_contract_type(
            node.ident.to_string(),
            ContractTypeKind::Struct,
            &node.attrs,
            SourceSpan::of(node),
            Vec::new(),
            node.fields
                .iter()
                .map(|field| canonical(&field.ty))
                .collect(),
        );
        if has_attr(&node.attrs, "contract") && !self.skip() {
            self.declared_contracts
                .push((node.ident.to_string(), self.file, SourceSpan::of(node)));
        }
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        let variants: Vec<(String, bool)> = node
            .variants
            .iter()
            .map(|variant| {
                let has_data = match &variant.fields {
                    syn::Fields::Unit => false,
                    syn::Fields::Named(fields) => !fields.named.is_empty(),
                    syn::Fields::Unnamed(fields) => !fields.unnamed.is_empty(),
                };
                (variant.ident.to_string(), has_data)
            })
            .collect();
        self.record_contract_type(
            node.ident.to_string(),
            ContractTypeKind::Enum,
            &node.attrs,
            SourceSpan::of(node),
            variants,
            Vec::new(),
        );
        syn::visit::visit_item_enum(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.defined_functions.insert(node.sig.ident.to_string());
        if self.skip() {
            return;
        }
        self.enter_function(
            node.sig.ident.to_string(),
            SourceSpan::of(&node.sig.ident),
            &node.sig,
            Some(&node.block),
        );
        syn::visit::visit_item_fn(self, node);
        self.exit_function();
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let previous = self.impl_ctx.take();
        let contract = match &*node.self_ty {
            syn::Type::Path(path) => last_segment(&path.path).map(|ident| ident.to_string()),
            _ => None,
        };
        let in_contract_impl = has_attr(&node.attrs, "contractimpl");
        let inherited_test = previous.as_ref().is_some_and(|ctx| ctx.is_test);
        self.impl_ctx = Some(ImplCtx {
            contract: contract.clone(),
            in_contract_impl,
            is_test: is_test(&node.attrs) || inherited_test,
        });
        if in_contract_impl && !self.skip() {
            if let Some(name) = &contract {
                self.impl_contracts
                    .push((name.clone(), self.file, SourceSpan::of(node)));
            }
        }
        syn::visit::visit_item_impl(self, node);
        self.impl_ctx = previous;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.defined_functions.insert(node.sig.ident.to_string());
        if self.skip() {
            return;
        }
        let contract = self.impl_ctx.as_ref().and_then(|ctx| ctx.contract.clone());
        let in_contract_impl = self
            .impl_ctx
            .as_ref()
            .is_some_and(|ctx| ctx.in_contract_impl);
        let is_public = matches!(node.vis, syn::Visibility::Public(_));
        if in_contract_impl && is_public && node.sig.receiver().is_none() {
            let name = node.sig.ident.to_string();
            let params = params_of(&node.sig);
            self.entrypoints.push(crate::model::Entrypoint {
                is_constructor: name == "__constructor",
                is_check_auth: name == "__check_auth",
                return_type: match &node.sig.output {
                    syn::ReturnType::Default => None,
                    syn::ReturnType::Type(_, ty) => Some(canonical(ty)),
                },
                name,
                contract: contract.clone().unwrap_or_default(),
                file: self.file,
                span: SourceSpan::of(&node.sig.ident),
                full_span: SourceSpan::of(node),
                params,
            });
        }
        self.enter_function(
            node.sig.ident.to_string(),
            SourceSpan::of(&node.sig.ident),
            &node.sig,
            Some(&node.block),
        );
        syn::visit::visit_impl_item_fn(self, node);
        self.exit_function();
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if !self.skip() {
            self.record_method_call(node);
        }
        let method = node.method.to_string();
        let guarded = IntegerOp::from_wrapping_method(&method).is_some() || is_checked_arithmetic(&method);
        if guarded {
            self.guarded_depth += 1;
        }
        syn::visit::visit_expr_method_call(self, node);
        if guarded {
            self.guarded_depth -= 1;
        }
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if !self.skip() {
            self.record_binary(node);
        }
        syn::visit::visit_expr_binary(self, node);
    }

    fn visit_expr_unary(&mut self, node: &'ast syn::ExprUnary) {
        if !self.skip() && matches!(node.op, syn::UnOp::Neg(_)) {
            let operand = &node.expr;
            let operand_type = self.infer(operand);
            if matches!(operand_type, ParamKind::Integer(_)) {
                let span = SourceSpan::of(node);
                self.model.arithmetic.push(ArithmeticSite {
                    site: self.site(span),
                    op: IntegerOp::Neg,
                    left_type: operand_type,
                    right_type: ParamKind::Other,
                    untyped: false,
                    guarded: self.guarded_depth > 0,
                    text: canonical(node),
                    span,
                });
            }
        }
        syn::visit::visit_expr_unary(self, node);
    }

    fn visit_expr_cast(&mut self, node: &'ast syn::ExprCast) {
        if !self.skip() {
            let from = match self.infer(&node.expr) {
                ParamKind::Integer(ty) => Some(ty),
                _ => None,
            };
            let to = integer_type_of(&node.ty);
            if from.is_some() || to.is_some() {
                let lossy = match (from, to) {
                    (Some(from), Some(to)) => from.cast_is_lossy(to),
                    _ => false,
                };
                let span = SourceSpan::of(node);
                self.model.casts.push(CastSite {
                    site: self.site(span),
                    from,
                    to,
                    lossy,
                    text: canonical(node),
                    span,
                });
            }
        }
        syn::visit::visit_expr_cast(self, node);
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.guarded_depth += 1;
        self.visit_expr(&node.cond);
        self.guarded_depth -= 1;
        self.visit_block(&node.then_branch);
        if let Some((_, else_branch)) = &node.else_branch {
            self.visit_expr(else_branch);
        }
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        let bound = self.loop_bound(&node.expr);
        let iterates = canonical(&node.expr);
        let outer = self.loop_depth > 0;
        let site = self.site(SourceSpan::of(&node.for_token));
        let index = self.begin_loop(LoopSite {
            site: Site {
                in_loop: outer,
                ..site
            },
            kind: LoopKind::For,
            bound,
            iterates: Some(iterates),
            body_span: SourceSpan::of(&node.body),
            storage_ops: 0,
            contract_calls: 0,
        });
        // The iterator expression runs once, before the loop body.
        self.visit_expr(&node.expr);
        self.loop_depth += 1;
        self.visit_block(&node.body);
        self.loop_depth -= 1;
        self.end_loop(index);
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        let outer = self.loop_depth > 0;
        let site = self.site(SourceSpan::of(&node.while_token));
        let index = self.begin_loop(LoopSite {
            site: Site {
                in_loop: outer,
                ..site
            },
            kind: LoopKind::While,
            bound: LoopBound::Unknown,
            iterates: None,
            body_span: SourceSpan::of(&node.body),
            storage_ops: 0,
            contract_calls: 0,
        });
        self.loop_depth += 1;
        // The condition runs once per iteration, so its work counts as loop work.
        self.guarded_depth += 1;
        self.visit_expr(&node.cond);
        self.guarded_depth -= 1;
        self.visit_block(&node.body);
        self.loop_depth -= 1;
        self.end_loop(index);
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        let outer = self.loop_depth > 0;
        let site = self.site(SourceSpan::of(&node.loop_token));
        let index = self.begin_loop(LoopSite {
            site: Site {
                in_loop: outer,
                ..site
            },
            kind: LoopKind::Loop,
            bound: LoopBound::Unknown,
            iterates: None,
            body_span: SourceSpan::of(&node.body),
            storage_ops: 0,
            contract_calls: 0,
        });
        self.loop_depth += 1;
        self.visit_block(&node.body);
        self.loop_depth -= 1;
        self.end_loop(index);
    }

    fn visit_expr_index(&mut self, node: &'ast syn::ExprIndex) {
        if !self.skip() {
            let span = SourceSpan::of(node);
            self.model.panics.push(PanicSite {
                site: self.site(span),
                kind: PanicKind::Index,
                on: Some(canonical(&node.expr)),
                text: canonical(node),
                span,
            });
        }
        syn::visit::visit_expr_index(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if !self.skip() {
            if let Expr::Path(path) = &*node.func {
                if let Some(segment) = path.path.segments.last() {
                    self.push_call_graph_edge(segment.ident.to_string());
                }
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if !self.skip() {
            let name = node
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
                .unwrap_or_default();
            let kind = match name.as_str() {
                "panic" => Some(PanicKind::Panic),
                "todo" => Some(PanicKind::Todo),
                "unimplemented" => Some(PanicKind::Unimplemented),
                "unreachable" => Some(PanicKind::Unreachable),
                _ => None,
            };
            if let Some(kind) = kind {
                let span = SourceSpan::of(node);
                self.model.panics.push(PanicSite {
                    site: self.site(span),
                    kind,
                    on: None,
                    text: canonical(node),
                    span,
                });
            }
        }
        syn::visit::visit_macro(self, node);
    }
}

impl Builder {
    fn begin_loop(&mut self, site: LoopSite) -> (usize, usize, usize) {
        let index = self.model.loops.len();
        let storage = self.model.storage_ops.len();
        let calls = self.model.calls.len();
        self.model.loops.push(site);
        (index, storage, calls)
    }

    fn end_loop(&mut self, counters: (usize, usize, usize)) {
        let (index, storage, calls) = counters;
        let storage_ops = self.model.storage_ops.len() - storage;
        let contract_calls = self.model.calls.len() - calls;
        if let Some(site) = self.model.loops.get_mut(index) {
            site.storage_ops = storage_ops;
            site.contract_calls = contract_calls;
        }
    }
}

/// Collects `let` bindings, storage-derived identifiers and client handles.
#[derive(Default)]
struct TypeEnvCollector {
    env: HashMap<String, ParamKind>,
    storage_idents: BTreeSet<String>,
    clients: HashMap<String, String>,
    key_types: HashMap<String, ParamKind>,
}

impl<'ast> Visit<'ast> for TypeEnvCollector {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let Some((name, annotation)) = binding_of(&node.pat) {
            match (annotation, &node.init) {
                (Some(ty), init) => {
                    let kind = classify_type(ty);
                    self.env.insert(name.clone(), kind);
                    // `let balance: i128 = storage.get(&KEY)` teaches us the type of
                    // the value stored under KEY.
                    if matches!(kind, ParamKind::Integer(_) | ParamKind::Collection(_)) {
                        if let Some(key) = init.as_ref().and_then(|init| first_storage_key(&init.expr)) {
                            self.key_types.insert(key, kind);
                        }
                    }
                }
                (None, Some(init)) => {
                    let inferred = infer_expr_ty(&init.expr, &self.env);
                    if inferred != ParamKind::Other {
                        self.env.insert(name.clone(), inferred);
                    }
                }
                (None, None) => {}
            }
            // Record where the binding came from regardless of how it was typed, so
            // `let keys: Vec<Address> = storage.get(..)` is still known to come from
            // storage.
            if let Some(init) = &node.init {
                if expr_has_storage_access(&init.expr) {
                    self.storage_idents.insert(name.clone());
                }
                if let Some(interface) = client_interface_of_expr(&init.expr) {
                    self.clients.insert(name, interface);
                }
            }
        }
        syn::visit::visit_local(self, node);
    }
}

/// Name and optional type annotation of a `let` binding.
///
/// `syn` 3 stores `let x: i128 = ..` as a typed pattern, so both shapes are
/// handled here.
fn binding_of(pat: &syn::Pat) -> Option<(String, Option<&syn::Type>)> {
    match pat {
        syn::Pat::Ident(ident) => Some((ident.ident.to_string(), None)),
        syn::Pat::Type(typed) => match &*typed.pat {
            syn::Pat::Ident(ident) => Some((ident.ident.to_string(), Some(&typed.ty))),
            _ => None,
        },
        _ => None,
    }
}

/// Infer a type for an expression from the local type environment.
fn infer_expr_ty(expr: &Expr, env: &HashMap<String, ParamKind>) -> ParamKind {
    match expr {
        Expr::Path(path) => path
            .path
            .get_ident()
            .and_then(|ident| env.get(&ident.to_string()).copied())
            .unwrap_or(ParamKind::Other),
        Expr::Lit(lit) => match &lit.lit {
            syn::Lit::Int(int) => {
                let suffix = int.suffix();
                let ty = if suffix.is_empty() {
                    // Soroban amounts are overwhelmingly `i128`; unsuffixed literals
                    // are inferred through the surrounding expression.
                    IntegerTy::I128
                } else {
                    match integer_type_of_name(suffix) {
                        Some(ty) => ty,
                        None => IntegerTy::I128,
                    }
                };
                ParamKind::Integer(ty)
            }
            _ => ParamKind::Other,
        },
        Expr::Unary(unary) => infer_expr_ty(&unary.expr, env),
        Expr::Paren(paren) => infer_expr_ty(&paren.expr, env),
        Expr::Group(group) => infer_expr_ty(&group.expr, env),
        Expr::Reference(reference) => infer_expr_ty(&reference.expr, env),
        Expr::Cast(cast) => integer_type_of(&cast.ty)
            .map(ParamKind::Integer)
            .or_else(|| collection_type_of(&cast.ty).map(ParamKind::Collection))
            .unwrap_or(ParamKind::Other),
        Expr::Binary(binary) => {
            let left = infer_expr_ty(&binary.left, env);
            let right = infer_expr_ty(&binary.right, env);
            match (left, right) {
                (ParamKind::Integer(a), ParamKind::Integer(b)) => {
                    ParamKind::Integer(if b.bits() > a.bits() { b } else { a })
                }
                (ParamKind::Integer(ty), _) | (_, ParamKind::Integer(ty)) => ParamKind::Integer(ty),
                (ParamKind::Collection(kind), _) | (_, ParamKind::Collection(kind)) => {
                    ParamKind::Collection(kind)
                }
                _ => ParamKind::Other,
            }
        }
        Expr::MethodCall(call) => {
            let method = call.method.to_string();
            if is_checked_arithmetic(&method)
                || matches!(
                    method.as_str(),
                    "clone" | "unwrap_or" | "unwrap_or_else" | "unwrap_or_default" | "as_ref"
                )
            {
                return infer_expr_ty(&call.receiver, env);
            }
            if method == "len" {
                return ParamKind::Integer(IntegerTy::USize);
            }
            if let Some(arguments) = &call.turbofish {
                for argument in arguments.args.iter().rev() {
                    if let syn::GenericArgument::Type(ty) = argument {
                        if let Some(integer) = integer_type_of(ty) {
                            return ParamKind::Integer(integer);
                        }
                        if let Some(collection) = collection_type_of(ty) {
                            return ParamKind::Collection(collection);
                        }
                    }
                }
            }
            ParamKind::Other
        }
        Expr::Call(call) => {
            let Expr::Path(path) = &*call.func else {
                return ParamKind::Other;
            };
            let segments: Vec<String> = path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect();
            let last = segments.last().cloned().unwrap_or_default();
            let previous = segments.iter().rev().nth(1).cloned().unwrap_or_default();
            if last == "new" {
                if let Some(collection) = collection_type_of_name(&previous) {
                    return ParamKind::Collection(collection);
                }
                return ParamKind::Other;
            }
            if let Some(integer) = integer_type_of_name(&previous) {
                return ParamKind::Integer(integer);
            }
            let _ = last;
            ParamKind::Other
        }
        Expr::Macro(mac) => {
            if mac.mac.path.is_ident("vec") {
                return ParamKind::Collection(CollectionTy::Vec);
            }
            ParamKind::Other
        }
        _ => ParamKind::Other,
    }
}

/// Whether a method name is one of the explicitly checked arithmetic families.
fn is_checked_arithmetic(name: &str) -> bool {
    name.starts_with("checked_")
        || name.starts_with("saturating_")
        || name.starts_with("overflowing_")
        || name.starts_with("wrapping_")
}

/// The Nth argument of a method call, with references stripped.
fn nth_arg(node: &syn::ExprMethodCall, index: usize) -> Option<&Expr> {
    node.args.get(index).map(unwrap_refs)
}

/// Storage tier of a method call, resolved through the call chain.
fn tier_of(node: &syn::ExprMethodCall) -> Option<StorageTier> {
    let name = node.method.to_string();
    if let Some(tier) = StorageTier::from_method(&name) {
        return is_storage_root(&node.receiver).then_some(tier);
    }
    tier_of_expr(&node.receiver)
}

fn tier_of_expr(expr: &Expr) -> Option<StorageTier> {
    match expr {
        Expr::MethodCall(call) => tier_of(call),
        _ => None,
    }
}

fn is_storage_root(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(call) => call.method == "storage" || tier_of(call).is_some(),
        _ => false,
    }
}

/// Ledger key expression of a storage call.
fn storage_key_expr(
    node: &syn::ExprMethodCall,
    tier: StorageTier,
    access: StorageAccess,
) -> Option<&Expr> {
    match access {
        StorageAccess::Set | StorageAccess::Get | StorageAccess::Has | StorageAccess::Remove
        | StorageAccess::GetTtl => nth_arg(node, 0),
        // `instance().extend_ttl(threshold, extend_to)` takes no key; the other tiers do.
        StorageAccess::ExtendTtl => {
            if tier == StorageTier::Instance {
                None
            } else {
                nth_arg(node, 0)
            }
        }
    }
}

/// Value expression of a storage write.
fn storage_value_expr(node: &syn::ExprMethodCall, access: StorageAccess) -> Option<&Expr> {
    match access {
        StorageAccess::Set => nth_arg(node, 1),
        _ => None,
    }
}

/// Canonical text of the last type argument of a turbofish, e.g. `i128`.
fn turbofish_text(node: &syn::ExprMethodCall) -> Option<String> {
    let arguments = node.turbofish.as_ref()?;
    arguments.args.iter().rev().find_map(|argument| match argument {
        syn::GenericArgument::Type(ty) => Some(canonical(ty)),
        _ => None,
    })
}

/// Declared value type from a turbofish such as `get::<_, i128>(&key)`.
fn turbofish_value_type(node: &syn::ExprMethodCall) -> Option<ParamKind> {
    let arguments = node.turbofish.as_ref()?;
    for argument in arguments.args.iter().rev() {
        if let syn::GenericArgument::Type(ty) = argument {
            if let Some(integer) = integer_type_of(ty) {
                return Some(ParamKind::Integer(integer));
            }
            if let Some(collection) = collection_type_of(ty) {
                return Some(ParamKind::Collection(collection));
            }
        }
    }
    None
}

/// Whether a method call is a signature or crypto verification.
fn is_verification_call(method: &str, crypto_chain: bool) -> bool {
    crypto_chain
        || matches!(
            method,
            "verify"
                | "verify_sig"
                | "verify_signature"
                | "ed25519_verify"
                | "secp256k1_recover"
                | "recover"
                | "recover_key"
        )
}

/// Whether the receiver chain contains a call to `name`.
fn receiver_chain_has(node: &syn::ExprMethodCall, name: &str) -> bool {
    let mut current: Option<&Expr> = Some(&node.receiver);
    while let Some(expr) = current {
        match expr {
            Expr::MethodCall(call) => {
                if call.method == name {
                    return true;
                }
                current = Some(&call.receiver);
            }
            _ => return false,
        }
    }
    false
}

/// Whether a method name is a contract upgrade or deployment.
fn is_upgrade_method(method: &str) -> bool {
    matches!(
        method,
        "update_current_contract_wasm"
            | "extend_current_contract_wasm_ttl"
            | "upload_contract_wasm"
            | "upload_wasm"
            | "install_contract"
            | "create_contract"
            | "create_contract_with_constructor"
            | "deploy"
            | "deploy_v2"
            | "deploy_v2_with_constructor"
    )
}

/// Receiver of an iterator constructor, e.g. `items` in `items.iter()`.
fn iter_receiver(expr: &Expr) -> Option<&Expr> {
    let Expr::MethodCall(call) = expr else {
        return None;
    };
    let method = call.method.to_string();
    if matches!(
        method.as_str(),
        "iter" | "iter_mut" | "into_iter" | "iter_rev" | "chunks" | "windows"
    ) {
        return Some(&call.receiver);
    }
    None
}

/// The receiver identifier of a method call, e.g. `items` in `items.len()`.
fn method_receiver_ident(expr: &Expr) -> Option<&syn::Ident> {
    let Expr::MethodCall(call) = expr else {
        return None;
    };
    ident_of(&call.receiver)
}

/// Client interface of a `let x = token::Client::new(..)` initializer.
fn client_interface_of_expr(expr: &Expr) -> Option<String> {
    let Expr::Call(call) = unwrap_refs(expr) else {
        return None;
    };
    let Expr::Path(path) = &*call.func else {
        return None;
    };
    if !path_ends_with(&path.path, &["Client", "new"]) {
        return None;
    }
    let segments: Vec<String> = path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    Some(
        segments
            .iter()
            .rev()
            .nth(2)
            .cloned()
            .unwrap_or_default(),
    )
}

/// Canonical text of the first ledger key read or written in an expression.
fn first_storage_key(expr: &Expr) -> Option<String> {
    struct Probe {
        key: Option<String>,
    }
    impl<'ast> Visit<'ast> for Probe {
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            if self.key.is_some() {
                return;
            }
            let method = node.method.to_string();
            if let Some(access) = StorageAccess::from_method(&method) {
                if let Some(tier) = tier_of(node) {
                    if let Some(key) = storage_key_expr(node, tier, access) {
                        self.key = Some(canonical(key));
                        return;
                    }
                }
            }
            syn::visit::visit_expr_method_call(self, node);
        }
    }
    let mut probe = Probe { key: None };
    probe.visit_expr(expr);
    probe.key
}

/// Whether an expression contains a storage access anywhere.
fn expr_has_storage_access(expr: &Expr) -> bool {
    struct Probe {
        found: bool,
    }
    impl<'ast> Visit<'ast> for Probe {
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            if self.found {
                return;
            }
            let method = node.method.to_string();
            if method == "storage"
                || tier_of(node).is_some()
                || StorageAccess::from_method(&method).is_some()
            {
                self.found = true;
                return;
            }
            syn::visit::visit_expr_method_call(self, node);
        }
    }
    let mut probe = Probe { found: false };
    probe.visit_expr(expr);
    probe.found
}

/// Find a ledger read inside an expression.
fn ledger_read(expr: &Expr) -> Option<(RandomnessSource, SourceSpan)> {
    struct Probe {
        found: Option<(RandomnessSource, SourceSpan)>,
    }
    impl<'ast> Visit<'ast> for Probe {
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            if self.found.is_some() {
                return;
            }
            let method = node.method.to_string();
            if let Some(source) = RandomnessSource::from_method(&method) {
                if receiver_chain_has(node, "ledger") {
                    self.found = Some((source, SourceSpan::of(node)));
                    return;
                }
            }
            syn::visit::visit_expr_method_call(self, node);
        }
    }
    let mut probe = Probe { found: None };
    probe.visit_expr(expr);
    probe.found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::SourceFile;

    fn model_of(source: &str) -> ContractModel {
        let file = SourceFile::parse(FileId(0), "src/lib.rs", "src/lib.rs", source).unwrap();
        build(&SourceMap::new(vec![file]), false)
    }

    #[test]
    fn records_storage_operations_with_tiers_and_keys() {
        let model = model_of(
            r#"
#[contractimpl]
impl Token {
    pub fn f(env: Env) {
        let total: i128 = env.storage().instance().get(&DataKey::Total).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Balance, &total);
        env.storage().temporary().remove(&DataKey::Cache);
        env.storage().persistent().extend_ttl(&DataKey::Balance, 100, 1000);
        env.storage().instance().extend_ttl(100, 1000);
    }
}
"#,
        );
        let ops: Vec<String> = model.storage_ops.iter().map(StorageOp::describe).collect();
        assert_eq!(
            ops,
            vec![
                "instance.get(DataKey::Total)",
                "persistent.set(DataKey::Balance)",
                "temporary.remove(DataKey::Cache)",
                "persistent.extend_ttl(DataKey::Balance)",
                "instance.extend_ttl",
            ]
        );
        assert_eq!(model.storage_ops[0].integer_type, Some(IntegerTy::I128));
        assert_eq!(model.storage_ops[1].value.as_deref(), Some("total"));
        assert_eq!(model.storage_ops[1].tier, StorageTier::Persistent);
    }

    #[test]
    fn records_auth_checks_and_their_targets() {
        let model = model_of(
            r#"
#[contractimpl]
impl Token {
    pub fn f(env: Env, from: Address, to: Address) {
        from.require_auth();
        env.require_auth(&to);
        admin.require_auth_for_args(args);
    }
}
"#,
        );
        let checks: Vec<String> = model.auth_checks.iter().map(AuthCheck::describe).collect();
        assert_eq!(
            checks,
            vec![
                "require_auth(from)",
                "Env::require_auth(to)",
                "require_auth_for_args(admin)",
            ]
        );
        assert!(model.has_transitive_auth("f"));
    }

    #[test]
    fn records_typed_arithmetic_only_when_types_resolve() {
        let model = model_of(
            r#"
#[contractimpl]
impl Token {
    pub fn f(env: Env, amount: i128) {
        let total = amount + 1;
        let doubled = amount.checked_add(amount);
        let wrapped = amount.wrapping_mul(3);
        let unknown = a + b;
        if total > 0 { let _ = amount - 1; }
        let _ = doubled;
        let _ = wrapped;
        let _ = unknown;
    }
}
"#,
        );
        let ops: Vec<(String, bool)> = model
            .arithmetic
            .iter()
            .map(|site| (site.op.as_str().to_string(), site.untyped))
            .collect();
        assert!(ops.contains(&("wrapping_mul".into(), false)), "wrapping op: {ops:?}");
        assert!(ops.contains(&("+".into(), false)), "typed add: {ops:?}");
        assert!(ops.contains(&("-".into(), false)), "typed subtract: {ops:?}");
        assert!(ops.contains(&("+".into(), true)), "untyped add is marked: {ops:?}");
        let guarded: Vec<bool> = model
            .arithmetic
            .iter()
            .map(|site| site.guarded)
            .collect();
        assert!(guarded.iter().all(|flag| !flag), "no site is inside a condition");
    }

    #[test]
    fn records_lossy_casts() {
        let model = model_of(
            r#"
#[contractimpl]
impl Token {
    pub fn f(env: Env, amount: i128) {
        let small = amount as u32;
        let wide = amount as i64;
        let _ = (small, wide);
    }
}
"#,
        );
        let lossy: Vec<String> = model
            .casts
            .iter()
            .map(|cast| format!("{}:{}", cast.describe(), cast.lossy))
            .collect();
        assert_eq!(lossy, vec!["i128 as u32:true", "i128 as i64:true"]);
    }

    #[test]
    fn records_loops_with_bounds_and_work() {
        let model = model_of(
            r#"
#[contractimpl]
impl Token {
    pub fn f(env: Env, holders: Vec<Address>) {
        for i in 0..8 {
            env.storage().persistent().set(&i, &i);
        }
        for holder in holders.iter() {
            env.storage().persistent().set(holder, &0);
        }
        let keys: Vec<Address> = env.storage().persistent().get(&KEY).unwrap();
        for key in keys.iter() {
            env.storage().persistent().get(key);
        }
        while running {
            env.storage().instance().set(&X, &1);
        }
    }
}
"#,
        );
        let summaries: Vec<String> = model
            .loops
            .iter()
            .map(|site| {
                format!(
                    "{}:{}:{}/{}",
                    site.kind.as_str(),
                    site.bound.describe(),
                    site.storage_ops,
                    site.contract_calls
                )
            })
            .collect();
        assert_eq!(
            summaries,
            vec![
                "for:8 iterations:1/0",
                "for:over a Vec:1/0",
                "for:over collection state:1/0",
                "while:unknown bound:1/0",
            ]
        );
        assert!(!model.loops[0].is_risky(), "literal loop is bounded");
        assert!(model.loops[1].is_risky(), "loop over a caller collection touches storage");
        assert!(model.loops[2].is_risky(), "loop over storage state touches storage");
    }

    #[test]
    fn records_panics() {
        let model = model_of(
            r#"
#[contractimpl]
impl Token {
    pub fn f(env: Env) {
        let value = env.storage().persistent().get(&KEY).unwrap();
        let other = env.storage().persistent().get(&KEY).expect("missing");
        todo!();
        panic!("nope");
        let _ = (value, other);
    }
}
"#,
        );
        let kinds: Vec<String> = model
            .panics
            .iter()
            .map(|site| site.kind.as_str().to_string())
            .collect();
        assert_eq!(kinds, vec!["unwrap", "expect", "todo!", "panic!"]);
        assert!(model.panics[0].on_storage_read());
    }

    #[test]
    fn records_contract_calls_and_upgrades() {
        let model = model_of(
            r#"
#[contractimpl]
impl Vault {
    pub fn deposit(env: Env, from: Address, amount: i128) {
        from.require_auth();
        let token = token::Client::new(&env, &self.token);
        token.transfer(&from, &env.current_contract_address(), &amount);
    }

    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}
"#,
        );
        let calls: Vec<String> = model.calls.iter().map(ContractCall::qualified_name).collect();
        assert_eq!(calls, vec!["token::transfer"]);
        assert_eq!(model.calls[0].arg(0), Some("from"));
        assert_eq!(model.upgrades.len(), 1);
        assert!(model.upgrades[0].argument_is_parameter);
        assert!(model.upgrades[0].replaces_current_contract());
    }

    #[test]
    fn records_randomness_only_when_used_as_entropy() {
        let model = model_of(
            r#"
#[contractimpl]
impl Lottery {
    pub fn draw(env: Env) {
        let winner = env.ledger().timestamp() % 10;
        let plain = env.ledger().sequence();
        let _ = (winner, plain);
    }
}
"#,
        );
        assert_eq!(model.randomness.len(), 1);
        assert_eq!(model.randomness[0].source, RandomnessSource::Timestamp);
        assert_eq!(model.randomness[0].use_kind, RandomnessUse::Arithmetic);
    }

    #[test]
    fn records_contract_types() {
        let model = model_of(
            r#"
#[contract]
pub struct Token;

#[contracttype]
pub enum DataKey {
    Admin,
    Balance(Address),
}

#[contracterror]
pub enum Error {
    NotAuthorized = 1,
}

#[contractevent]
pub struct Transfer {
    pub amount: i128,
}
"#,
        );
        let types: Vec<String> = model
            .types
            .iter()
            .map(|ty| format!("{:?}:{}:{}", ty.kind, ty.name, ty.variants.len()))
            .collect();
        assert_eq!(
            types,
            vec!["Enum:DataKey:2", "Error:Error:1", "Event:Transfer:0"]
        );
        assert_eq!(model.types[1].variants[0], ("NotAuthorized".to_string(), false));
        assert_eq!(model.types[0].variants[1], ("Balance".to_string(), true));
    }

    #[test]
    fn ignores_test_code_by_default() {
        let source = r#"
#[contractimpl]
impl Token {
    pub fn real(env: Env) {
        env.storage().instance().set(&KEY, &1);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn works() {
        let value = env.storage().instance().get(&KEY).unwrap();
        let _ = value;
    }
}
"#;
        let without = model_of(source);
        let with = {
            let file = SourceFile::parse(FileId(0), "src/lib.rs", "src/lib.rs", source).unwrap();
            build(&SourceMap::new(vec![file]), true)
        };
        assert_eq!(without.panics.len(), 0);
        assert_eq!(with.panics.len(), 1);
    }

    #[test]
    fn call_graph_is_limited_to_known_functions() {
        let model = model_of(
            r#"
#[contractimpl]
impl Token {
    pub fn f(env: Env) {
        let v = Vec::new(&env);
        helper(&env);
        let _ = v;
    }

    fn helper(env: &Env) {}
}
"#,
        );
        assert_eq!(model.callees("f"), ["helper"]);
    }

    #[test]
    fn sites_carry_function_and_contract() {
        let model = model_of(
            r#"
#[contractimpl]
impl Token {
    pub fn f(env: Env) {
        env.storage().instance().set(&KEY, &1);
    }
}
"#,
        );
        let site = &model.storage_ops[0].site;
        assert_eq!(site.function, "f");
        assert_eq!(site.contract.as_deref(), Some("Token"));
        assert_eq!(site.file, FileId(0));
        assert!(site.span.is_known());
    }
}
