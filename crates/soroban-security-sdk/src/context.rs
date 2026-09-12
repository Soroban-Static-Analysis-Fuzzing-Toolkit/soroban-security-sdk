//! The analysis context.
//!
//! [`AnalysisContext`] is the read-only view detectors get of a project: the parsed
//! sources, the derived [`ContractModel`], the optional wasm module, the budget
//! report and the effective configuration. Everything it hands out is borrowed for
//! the lifetime of the context, so detectors never clone the project to inspect it.

use crate::budget::BudgetReport;
use crate::config::AnalysisConfig;
use crate::finding::Location;
use crate::manifest::PackageInfo;
use crate::model::{Contract, ContractModel, Entrypoint};
use crate::source::{FileId, SourceFile, SourceMap};
use crate::span::SourceSpan;
use crate::syntax::functions::{collect_from_items, FunctionView};
use crate::wasm::WasmModule;

/// Read-only view of everything under analysis.
#[derive(Debug)]
pub struct AnalysisContext<'a> {
    sources: &'a SourceMap,
    model: &'a ContractModel,
    wasm: Option<&'a WasmModule>,
    budget: &'a BudgetReport,
    config: &'a AnalysisConfig,
    package: Option<&'a PackageInfo>,
}

impl<'a> AnalysisContext<'a> {
    /// Build a context. Prefer [`crate::analyze`] outside tests.
    pub fn new(
        sources: &'a SourceMap,
        model: &'a ContractModel,
        wasm: Option<&'a WasmModule>,
        budget: &'a BudgetReport,
        config: &'a AnalysisConfig,
        package: Option<&'a PackageInfo>,
    ) -> Self {
        AnalysisContext {
            sources,
            model,
            wasm,
            budget,
            config,
            package,
        }
    }

    /// Every parsed source file.
    pub fn sources(&self) -> &'a SourceMap {
        self.sources
    }

    /// The derived contract model.
    pub fn model(&self) -> &'a ContractModel {
        self.model
    }

    /// The compiled module, when one was provided.
    pub fn wasm(&self) -> Option<&'a WasmModule> {
        self.wasm
    }

    /// Resource budget estimates.
    pub fn budget(&self) -> &'a BudgetReport {
        self.budget
    }

    /// Effective configuration.
    pub fn config(&self) -> &'a AnalysisConfig {
        self.config
    }

    /// Cargo manifest of the crate under analysis, when known.
    pub fn package(&self) -> Option<&'a PackageInfo> {
        self.package
    }

    /// Iterate over files.
    pub fn files(&self) -> impl Iterator<Item = &'a SourceFile> {
        self.sources.iter()
    }

    /// The syntax tree of a file.
    pub fn syntax(&self, file: FileId) -> Option<&'a syn::File> {
        self.sources.get(file).map(SourceFile::syntax)
    }

    /// Every function in the project, including non-entrypoints.
    ///
    /// The list is rebuilt per call, which keeps the context free of a second index
    /// and is cheap at contract scale.
    pub fn functions(&self) -> Vec<FunctionView<'a>> {
        let mut functions = Vec::new();
        for source in self.sources.iter() {
            collect_from_items(&source.syntax().items, source.id(), &mut functions);
        }
        functions
    }

    /// Functions defined in one file.
    pub fn functions_in(&self, file: FileId) -> Vec<FunctionView<'a>> {
        let mut functions = Vec::new();
        if let Some(source) = self.sources.get(file) {
            collect_from_items(&source.syntax().items, file, &mut functions);
        }
        functions
    }

    /// Contracts found in the project.
    pub fn contracts(&self) -> &'a [Contract] {
        &self.model.contracts
    }

    /// Every entrypoint.
    pub fn entrypoints(&self) -> impl Iterator<Item = &'a Entrypoint> {
        self.model.entrypoints()
    }

    /// Look up an entrypoint by name.
    pub fn entrypoint(&self, name: &str) -> Option<&'a Entrypoint> {
        self.model.entrypoint(name)
    }

    /// Whether a function name is an exported entrypoint.
    pub fn is_entrypoint(&self, name: &str) -> bool {
        self.model.is_entrypoint(name)
    }

    /// Build a [`Location`] in a file.
    pub fn location(&self, file: FileId, span: impl Into<Option<SourceSpan>>) -> Location {
        self.sources.location(file, span)
    }

    /// Exact source text of a span.
    pub fn text_of(&self, file: FileId, span: SourceSpan) -> Option<&'a str> {
        self.sources.get(file)?.text_of(span)
    }

    /// Single-line excerpt of a span, for messages.
    pub fn snippet(&self, file: FileId, span: SourceSpan) -> Option<String> {
        self.sources.snippet(file, span)
    }

    /// Display path of a file.
    pub fn path_of(&self, file: FileId) -> Option<&'a str> {
        self.sources.get(file).map(SourceFile::display_path)
    }

    /// The entrypoint a site belongs to, when the site is inside one.
    pub fn entrypoint_of(&self, function: &str) -> Option<&'a Entrypoint> {
        self.entrypoint(function)
    }

    /// Whether the project has any contract code at all.
    pub fn has_contracts(&self) -> bool {
        !self.model.contracts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::BudgetReport;
    use crate::config::{CostModel, NetworkLimits};
    use crate::model;

    fn context_with(source: &str) -> (SourceMap, ContractModel, BudgetReport, AnalysisConfig) {
        let file = SourceFile::parse(FileId(0), "src/lib.rs", "src/lib.rs", source).unwrap();
        let sources = SourceMap::new(vec![file]);
        let model = model::build(&sources, false);
        let budget = BudgetReport::estimate(
            &model,
            None,
            NetworkLimits::mainnet(),
            CostModel::conservative(),
        );
        (sources, model, budget, AnalysisConfig::default())
    }

    #[test]
    fn exposes_files_functions_and_entrypoints() {
        let (sources, model, budget, config) = context_with(
            r#"
#[contractimpl]
impl Token {
    pub fn transfer(env: Env) {}
    fn helper(env: &Env) {}
}
"#,
        );
        let ctx = AnalysisContext::new(&sources, &model, None, &budget, &config, None);
        assert_eq!(ctx.files().count(), 1);
        assert_eq!(ctx.entrypoints().count(), 1);
        assert!(ctx.is_entrypoint("transfer"));
        assert!(!ctx.is_entrypoint("helper"));
        let names: Vec<String> = ctx.functions().iter().map(FunctionView::name).collect();
        assert_eq!(names, vec!["transfer", "helper"]);
        assert_eq!(ctx.functions_in(FileId(0)).len(), 2);
        assert_eq!(ctx.path_of(FileId(0)), Some("src/lib.rs"));
        assert!(ctx.has_contracts());
        assert!(ctx.entrypoint("transfer").is_some());
        assert!(ctx.wasm().is_none());
    }

    #[test]
    fn resolves_spans_to_text() {
        let (sources, model, budget, config) = context_with("fn f() {\n    let x = 1;\n}\n");
        let ctx = AnalysisContext::new(&sources, &model, None, &budget, &config, None);
        let span = SourceSpan::new(2, 13, 2, 14);
        assert_eq!(ctx.text_of(FileId(0), span), Some("1"));
        assert_eq!(ctx.snippet(FileId(0), span).as_deref(), Some("1"));
        let location = ctx.location(FileId(0), span);
        assert_eq!(location.file, "src/lib.rs");
        assert_eq!(location.line(), Some(2));
    }
}
