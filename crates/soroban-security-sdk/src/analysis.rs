//! End-to-end analysis.
//!
//! [`Project`] owns the parsed sources and the derived [`ContractModel`]. [`analyze`]
//! runs every enabled detector from the global registry against a project and
//! returns an [`AnalysisReport`] containing findings, inline-suppression results,
//! non-fatal diagnostics and the resource-budget estimates.
//!
//! ```no_run
//! use soroban_security_sdk::prelude::*;
//!
//! let project = Project::from_dir(".")?;
//! let report = analyze(&project, &AnalysisConfig::default());
//! for finding in &report.findings {
//!     println!("{} {} {}", finding.severity, finding.headline_location(), finding.message);
//! }
//! # Ok::<(), soroban_security_sdk::Error>(())
//! ```
//!
//! Analysis is intentionally forgiving: a source file that fails to parse, a
//! manifest that cannot be read or a rule that needs a `.wasm` module all become
//! [`Diagnostic`]s rather than aborting the run, so the findings that *could* be
//! produced are still reported.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::budget::BudgetReport;
use crate::category::Category;
use crate::config::AnalysisConfig;
use crate::context::AnalysisContext;
use crate::error::{Error, Result};
use crate::finding::{Finding, FindingSink, Location};
use crate::manifest::PackageInfo;
use crate::model::{self, ContractModel};
use crate::rule::{DetectorMeta, RuleId};
use crate::severity::Severity;
use crate::source::{FileId, ParseFailure, SourceFile, SourceMap};
use crate::span::SourceSpan;
use crate::suppression;
use crate::wasm::WasmModule;

/// A source tree plus everything the SDK derived from it.
///
/// Build one with [`Project::from_dir`] for a real crate or [`Project::builder`]
/// (and [`ProjectBuilder`]) in tests. The model is derived once here and reused by
/// every analysis run that does not change the test-inclusion setting.
#[derive(Debug)]
pub struct Project {
    root: PathBuf,
    sources: SourceMap,
    model: ContractModel,
    wasm: Option<WasmModule>,
    package: Option<PackageInfo>,
    diagnostics: Vec<Diagnostic>,
}

impl Project {
    /// Load every Rust source under `root` and derive the contract model.
    ///
    /// `root` may be a crate directory or a single `.rs` file. `target/`, hidden
    /// directories and `.git` are skipped. A source file that fails to parse is
    /// recorded as a [`Diagnostic`] and does not abort the load; a tree with no
    /// Rust files at all is [`Error::NoContracts`].
    pub fn from_dir(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        if !root.exists() {
            return Err(Error::NotFound {
                path: root.to_path_buf(),
            });
        }
        let base = if root.is_file() {
            root.parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."))
        } else {
            root.to_path_buf()
        };

        let paths = if root.is_file() {
            vec![root.to_path_buf()]
        } else {
            collect_rust_files(root)?
        };
        if paths.is_empty() {
            return Err(Error::NoContracts {
                path: root.to_path_buf(),
            });
        }

        let mut diagnostics = Vec::new();
        let mut sources: Vec<SourceFile> = Vec::new();
        for path in paths {
            let display = display_path(&base, &path);
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    let id = FileId(sources.len() as u32);
                    match SourceFile::parse(id, &path, display, text) {
                        Ok(file) => sources.push(file),
                        Err(failure) => diagnostics.push(Diagnostic::from_parse_failure(&failure)),
                    }
                }
                Err(source) => diagnostics.push(Diagnostic::new(
                    DiagnosticKind::ParseFailure,
                    format!("could not read `{display}`: {source}"),
                )),
            }
        }
        if sources.is_empty() {
            return Err(Error::NoContracts { path: base.clone() });
        }

        let manifest_path = base.join("Cargo.toml");
        let package = if manifest_path.is_file() {
            match PackageInfo::load(&manifest_path) {
                Ok(info) => Some(info),
                Err(err) => {
                    diagnostics.push(Diagnostic::new(DiagnosticKind::Manifest, err.to_string()));
                    None
                }
            }
        } else {
            None
        };

        let sources = SourceMap::new(sources);
        let model = model::build(&sources, false);
        Ok(Project {
            root: base,
            sources,
            model,
            wasm: None,
            package,
            diagnostics,
        })
    }

    /// Build a project from already-parsed files. The project root is `.`.
    pub fn from_sources(files: Vec<SourceFile>) -> Self {
        let sources = SourceMap::new(files);
        let model = model::build(&sources, false);
        Project {
            root: PathBuf::from("."),
            sources,
            model,
            wasm: None,
            package: None,
            diagnostics: Vec::new(),
        }
    }

    /// Start building a project by hand, for tests and embedders.
    pub fn builder() -> ProjectBuilder {
        ProjectBuilder::default()
    }

    /// Project root, used to resolve relative wasm paths.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Every parsed source file.
    pub fn sources(&self) -> &SourceMap {
        &self.sources
    }

    /// The derived contract model, built without test code.
    pub fn model(&self) -> &ContractModel {
        &self.model
    }

    /// The derived contract model, optionally including `#[cfg(test)]` items.
    pub fn model_for(&self, include_tests: bool) -> ContractModel {
        if include_tests {
            model::build(&self.sources, true)
        } else {
            self.model.clone()
        }
    }

    /// The compiled module, when one was attached.
    pub fn wasm(&self) -> Option<&WasmModule> {
        self.wasm.as_ref()
    }

    /// Cargo manifest facts, when a manifest was found.
    pub fn package(&self) -> Option<&PackageInfo> {
        self.package.as_ref()
    }

    /// Non-fatal problems encountered while loading the project.
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Whether any contract code was found.
    pub fn has_contracts(&self) -> bool {
        !self.model.contracts.is_empty()
    }

    /// Attach a compiled module for the wasm-aware detectors.
    pub fn with_wasm(mut self, wasm: WasmModule) -> Self {
        self.wasm = Some(wasm);
        self
    }

    /// Attach a compiled module in place.
    pub fn set_wasm(&mut self, wasm: WasmModule) {
        self.wasm = Some(wasm);
    }

    /// Read and parse a `.wasm` file, resolving relative paths against the root.
    pub fn load_wasm(&self, path: impl AsRef<Path>) -> Result<WasmModule> {
        let path = path.as_ref();
        let resolved = if path.is_absolute() || path.exists() {
            path.to_path_buf()
        } else {
            self.root.join(path)
        };
        let bytes = std::fs::read(&resolved).map_err(Error::io(resolved.as_path()))?;
        WasmModule::parse(display_path(&self.root, &resolved), &bytes)
    }
}

/// Builder for [`Project`], primarily for tests and embedders that already have
/// sources in memory.
///
/// ```no_run
/// use soroban_security_sdk::prelude::*;
///
/// let project = ProjectBuilder::new()
///     .source("src/lib.rs", "pub fn f() {}").unwrap()
///     .build();
/// # Ok::<(), soroban_security_sdk::ParseFailure>(())
/// ```
#[derive(Debug, Default)]
pub struct ProjectBuilder {
    root: PathBuf,
    sources: Vec<SourceFile>,
    wasm: Option<WasmModule>,
    package: Option<PackageInfo>,
    diagnostics: Vec<Diagnostic>,
}

impl ProjectBuilder {
    /// An empty builder rooted at `.`.
    pub fn new() -> Self {
        ProjectBuilder::default()
    }

    /// Set the project root, used to resolve relative wasm paths.
    pub fn root(mut self, root: impl Into<PathBuf>) -> Self {
        self.root = root.into();
        self
    }

    /// Parse and add a source file. `display` is the path shown in reports.
    pub fn source(
        mut self,
        display: impl Into<String>,
        contents: impl Into<String>,
    ) -> std::result::Result<Self, ParseFailure> {
        let display = display.into();
        let id = FileId(self.sources.len() as u32);
        let file = SourceFile::parse(id, display.clone(), display, contents)?;
        self.sources.push(file);
        Ok(self)
    }

    /// Attach an already-parsed source file.
    pub fn add_source(mut self, file: SourceFile) -> Self {
        self.sources.push(file);
        self
    }

    /// Attach a compiled module.
    pub fn wasm(mut self, wasm: WasmModule) -> Self {
        self.wasm = Some(wasm);
        self
    }

    /// Attach Cargo manifest facts.
    pub fn package(mut self, package: PackageInfo) -> Self {
        self.package = Some(package);
        self
    }

    /// Parse manifest facts from TOML text, using `<root>/Cargo.toml`.
    pub fn manifest(mut self, text: &str) -> Result<Self> {
        let path = if self.root.as_os_str().is_empty() {
            PathBuf::from("Cargo.toml")
        } else {
            self.root.join("Cargo.toml")
        };
        self.package = Some(PackageInfo::parse(text, path)?);
        Ok(self)
    }

    /// Add a pre-existing diagnostic.
    pub fn diagnostic(mut self, diagnostic: Diagnostic) -> Self {
        self.diagnostics.push(diagnostic);
        self
    }

    /// Finish the project, deriving the contract model.
    pub fn build(self) -> Project {
        let root = if self.root.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            self.root
        };
        let sources = SourceMap::new(self.sources);
        let model = model::build(&sources, false);
        Project {
            root,
            sources,
            model,
            wasm: self.wasm,
            package: self.package,
            diagnostics: self.diagnostics,
        }
    }
}

/// Analyse `project` with every enabled detector from the global registry.
pub fn analyze(project: &Project, config: &AnalysisConfig) -> AnalysisReport {
    analyze_with(
        project,
        config,
        &crate::registry::DetectorRegistry::from_inventory(),
    )
}

/// Analyse `project` with a caller-supplied registry.
///
/// Use this to run a subset of detectors, or to embed detectors that are not
/// registered with the global inventory.
pub fn analyze_with(
    project: &Project,
    config: &AnalysisConfig,
    registry: &crate::registry::DetectorRegistry,
) -> AnalysisReport {
    let mut diagnostics = project.diagnostics.clone();

    for id in registry.unknown_enabled_rules(config) {
        diagnostics.push(Diagnostic::new(
            DiagnosticKind::UnknownRule,
            format!("no detector provides rule `{id}`"),
        ));
    }
    for id in registry.duplicates() {
        diagnostics.push(Diagnostic::new(
            DiagnosticKind::DuplicateRule,
            format!("rule `{id}` was registered more than once; keeping the first"),
        ));
    }

    let model = project.model_for(config.include_tests);
    let loaded_wasm = match &config.wasm_path {
        Some(path) => match project.load_wasm(path) {
            Ok(module) => Some(module),
            Err(err) => {
                diagnostics.push(Diagnostic::new(DiagnosticKind::Wasm, err.to_string()));
                None
            }
        },
        None => None,
    };
    let wasm = loaded_wasm.as_ref().or(project.wasm());

    let budget = BudgetReport::estimate(&model, wasm, config.limits, config.estimator);
    let ctx = AnalysisContext::new(
        project.sources(),
        &model,
        wasm,
        &budget,
        config,
        project.package(),
    );

    let mut findings: Vec<Finding> = Vec::new();
    let mut rules: Vec<DetectorMeta> = Vec::new();
    let mut skipped_without_wasm: Vec<&str> = Vec::new();
    for (meta, detector) in registry.selected(config) {
        if meta.requires_wasm && wasm.is_none() {
            skipped_without_wasm.push(meta.id.as_str());
            continue;
        }
        let mut sink = FindingSink::new(meta.clone(), project.sources());
        detector.detect(&ctx, &mut sink);
        findings.extend(sink.into_findings());
        rules.push(meta.clone());
    }
    if !skipped_without_wasm.is_empty() {
        skipped_without_wasm.sort_unstable();
        diagnostics.push(Diagnostic::new(
            DiagnosticKind::MissingWasm,
            format!(
                "no compiled contract was supplied, so wasm-only rule(s) did not run: {}",
                skipped_without_wasm.join(", ")
            ),
        ));
    }

    // User severity overrides are applied after the detectors run, so a detector
    // never needs to know how the project chose to rank its rule.
    for finding in &mut findings {
        if let Some(meta) = registry.meta(&finding.rule) {
            finding.severity = config.rules.severity_for(meta);
        }
    }

    let suppressions = suppression::collect(project.sources());
    for unused in suppression::unused(&suppressions, &findings) {
        let location = project
            .sources()
            .location(unused.file, SourceSpan::point(unused.comment_line, 1));
        diagnostics.push(
            Diagnostic::new(
                DiagnosticKind::UnusedSuppression,
                format!(
                    "suppression for {} on line {} matched no finding",
                    unused.describe(),
                    unused.comment_line
                ),
            )
            .at(location),
        );
    }
    let (mut kept, suppressed) = suppression::apply(findings, &suppressions);

    if !config.baseline.is_empty() {
        kept.retain(|finding| !config.baseline.contains(&finding.fingerprint()));
    }

    if config.report_suppressed {
        kept.extend(suppressed.iter().cloned());
    }

    kept.sort_by_key(Finding::sort_key);

    AnalysisReport {
        findings: kept,
        suppressed,
        diagnostics,
        budget,
        rules,
    }
}

/// A non-fatal problem encountered while loading or analysing a project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    /// What kind of problem this is.
    pub kind: DiagnosticKind,
    /// Human-readable description.
    pub message: String,
    /// Where the problem is, when that is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
}

impl Diagnostic {
    /// Build a diagnostic with no location.
    pub fn new(kind: DiagnosticKind, message: impl Into<String>) -> Self {
        Diagnostic {
            kind,
            message: message.into(),
            location: None,
        }
    }

    /// Attach a location.
    pub fn at(mut self, location: Location) -> Self {
        self.location = Some(location);
        self
    }

    /// Build a diagnostic from a failed parse.
    pub fn from_parse_failure(failure: &ParseFailure) -> Self {
        let location = Location {
            file: failure.file.clone(),
            file_id: None,
            span: failure.span.is_known().then_some(failure.span),
            function: None,
            label: None,
            wasm_offset: None,
        };
        Diagnostic {
            kind: DiagnosticKind::ParseFailure,
            message: failure.message.clone(),
            location: Some(location),
        }
    }
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.location {
            Some(location) => write!(f, "{location}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

/// The category of a [`Diagnostic`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum DiagnosticKind {
    /// A source file could not be read or parsed.
    ParseFailure,
    /// A suppression comment silenced nothing.
    UnusedSuppression,
    /// Configuration named a rule no detector provides.
    UnknownRule,
    /// Two detectors registered the same rule id.
    DuplicateRule,
    /// A rule that needs a compiled module was skipped.
    MissingWasm,
    /// A `.wasm` module could not be loaded.
    Wasm,
    /// A `Cargo.toml` could not be read or parsed.
    Manifest,
}

impl DiagnosticKind {
    /// Stable lowercase identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            DiagnosticKind::ParseFailure => "parse-failure",
            DiagnosticKind::UnusedSuppression => "unused-suppression",
            DiagnosticKind::UnknownRule => "unknown-rule",
            DiagnosticKind::DuplicateRule => "duplicate-rule",
            DiagnosticKind::MissingWasm => "missing-wasm",
            DiagnosticKind::Wasm => "wasm",
            DiagnosticKind::Manifest => "manifest",
        }
    }
}

/// The result of one analysis run.
#[derive(Debug)]
pub struct AnalysisReport {
    /// Findings that survived suppression and baseline filtering, ordered by
    /// severity then source position.
    pub findings: Vec<Finding>,
    /// Findings silenced by an inline suppression comment.
    pub suppressed: Vec<Finding>,
    /// Non-fatal problems encountered during the run.
    pub diagnostics: Vec<Diagnostic>,
    /// Per-entrypoint resource-budget estimates.
    pub budget: BudgetReport,
    /// Metadata of the detectors that ran, in rule-id order.
    pub rules: Vec<DetectorMeta>,
}

impl AnalysisReport {
    /// Whether the run produced no findings.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Number of findings.
    pub fn len(&self) -> usize {
        self.findings.len()
    }

    /// Whether any finding is at or above `severity`.
    pub fn has_findings_at_or_above(&self, severity: Severity) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity >= severity)
    }

    /// The most severe finding level present, if any.
    pub fn highest_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|finding| finding.severity).max()
    }

    /// Findings grouped by severity.
    pub fn count_by_severity(&self) -> BTreeMap<Severity, usize> {
        let mut counts = BTreeMap::new();
        for finding in &self.findings {
            *counts.entry(finding.severity).or_insert(0) += 1;
        }
        counts
    }

    /// Findings grouped by category.
    pub fn count_by_category(&self) -> BTreeMap<Category, usize> {
        let mut counts = BTreeMap::new();
        for finding in &self.findings {
            *counts.entry(finding.category).or_insert(0) += 1;
        }
        counts
    }

    /// Findings produced by one rule.
    pub fn findings_for<'a>(&'a self, rule: &RuleId) -> impl Iterator<Item = &'a Finding> + 'a {
        let rule = rule.clone();
        self.findings
            .iter()
            .filter(move |finding| finding.rule == rule)
    }

    /// Look up a rule's metadata, if it ran.
    pub fn rule(&self, id: &RuleId) -> Option<&DetectorMeta> {
        self.rules.iter().find(|meta| &meta.id == id)
    }

    /// One-line summary, e.g. `4 finding(s): 1 critical, 3 medium`.
    pub fn summary(&self) -> String {
        if self.findings.is_empty() {
            return "no findings".to_string();
        }
        let mut parts = Vec::new();
        for severity in Severity::ALL.iter().rev() {
            let count = self
                .findings
                .iter()
                .filter(|finding| finding.severity == *severity)
                .count();
            if count > 0 {
                parts.push(format!("{count} {}", severity.as_str()));
            }
        }
        format!("{} finding(s): {}", self.findings.len(), parts.join(", "))
    }
}

/// Recursively collect `.rs` files under `root`, skipping build and VCS output.
fn collect_rust_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let entries = std::fs::read_dir(&directory).map_err(Error::io(directory.as_path()))?;
        for entry in entries {
            let entry = entry.map_err(Error::io(directory.as_path()))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "target" || name == ".git" || name.starts_with('.') {
                continue;
            }
            let path = entry.path();
            let file_type = entry.file_type().map_err(Error::io(path.as_path()))?;
            if file_type.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

/// Path shown in reports: relative to the project root, with forward slashes.
fn display_path(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;
    use crate::config::NetworkLimits;
    use crate::detector::Detector;
    use crate::registry::DetectorRegistry;
    use crate::rule::RuleId;
    use crate::severity::Confidence;

    #[derive(Default)]
    struct Flagging;

    impl Detector for Flagging {
        const META: DetectorMeta =
            DetectorMeta::new(RuleId::new("SSDK970"), "flagging", "flags every entrypoint")
                .severity(Severity::Medium)
                .confidence(Confidence::High)
                .category(Category::BestPractice);

        fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
            for entrypoint in ctx.entrypoints() {
                sink.report("entrypoint")
                    .primary(entrypoint.file, entrypoint.span)
                    .emit();
            }
        }
    }

    fn project(source: &str) -> Project {
        ProjectBuilder::new()
            .source("src/lib.rs", source)
            .unwrap()
            .build()
    }

    fn registry() -> DetectorRegistry {
        let mut registry = DetectorRegistry::empty();
        registry.register::<Flagging>();
        registry
    }

    #[test]
    fn analyzes_with_a_custom_registry() {
        let project = project(
            r#"
#[contractimpl]
impl Token {
    pub fn a(env: Env) {}
    pub fn b(env: Env) {}
}
"#,
        );
        let report = analyze_with(&project, &AnalysisConfig::default(), &registry());
        assert_eq!(report.len(), 2);
        assert_eq!(report.rules.len(), 1);
        assert_eq!(report.highest_severity(), Some(Severity::Medium));
        assert_eq!(report.count_by_severity().get(&Severity::Medium), Some(&2));
        assert_eq!(
            report.count_by_category().get(&Category::BestPractice),
            Some(&2)
        );
        assert!(report.has_findings_at_or_above(Severity::Low));
        assert!(!report.has_findings_at_or_above(Severity::High));
        assert!(!report.summary().contains("no findings"));
    }

    #[test]
    fn severity_overrides_are_applied() {
        let project = project(
            r#"
#[contractimpl]
impl Token {
    pub fn a(env: Env) {}
}
"#,
        );
        let mut config = AnalysisConfig::default();
        config
            .rules
            .severity
            .insert(RuleId::new("SSDK970"), Severity::Critical);
        let report = analyze_with(&project, &config, &registry());
        assert_eq!(report.findings[0].severity, Severity::Critical);
    }

    #[test]
    fn baseline_filters_findings() {
        let project = project(
            r#"
#[contractimpl]
impl Token {
    pub fn a(env: Env) {}
}
"#,
        );
        let first = analyze_with(&project, &AnalysisConfig::default(), &registry());
        let fingerprint = first.findings[0].fingerprint();
        let config = AnalysisConfig {
            baseline: vec![fingerprint],
            ..AnalysisConfig::default()
        };
        let report = analyze_with(&project, &config, &registry());
        assert!(report.is_empty());
    }

    #[test]
    fn inline_suppressions_are_honoured_and_reported() {
        let project = project(
            r#"
#[contractimpl]
impl Token {
    pub fn a(env: Env) {}
    pub fn b(env: Env) {
        // soroban-sec: ignore SSDK970 -- intentionally exposed
    }
}
"#,
        );
        let report = analyze_with(&project, &AnalysisConfig::default(), &registry());
        assert_eq!(report.len(), 1);
        assert_eq!(report.suppressed.len(), 1);
        // The surviving finding is the unsuppressed `a` entrypoint.
        assert_eq!(report.findings[0].locations[0].line(), Some(4));
    }

    #[test]
    fn unused_suppressions_become_diagnostics() {
        let mut config = AnalysisConfig::default();
        config.rules.disabled.push(RuleId::new("SSDK970"));
        // No detector runs, so the ignore-comment has nothing to silence.
        let project = ProjectBuilder::new()
            .source(
                "src/lib.rs",
                "#[contractimpl]\nimpl Token {\n    // soroban-sec: ignore SSDK970\n    pub fn a(env: Env) {}\n}\n",
            )
            .unwrap()
            .build();
        let report = analyze_with(&project, &config, &registry());
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.kind == DiagnosticKind::UnusedSuppression }));
    }

    #[test]
    fn unknown_enabled_rules_are_diagnosed() {
        let project = project("pub fn f() {}");
        let config = AnalysisConfig::with_rules([RuleId::new("SSDK404")]);
        let report = analyze_with(&project, &config, &registry());
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == DiagnosticKind::UnknownRule));
    }

    #[test]
    fn parse_failures_do_not_abort_analysis() {
        let file = SourceFile::parse(
            FileId(0),
            "src/ok.rs",
            "src/ok.rs",
            "#[contractimpl]\nimpl T { pub fn a(env: Env) {} }\n",
        )
        .unwrap();
        let project = Project::from_sources(vec![file]);
        let report = analyze_with(&project, &AnalysisConfig::default(), &registry());
        assert_eq!(report.len(), 1);
        assert!(!report.is_empty());
    }

    #[test]
    fn budget_estimate_is_attached() {
        let project = project(
            r#"
#[contractimpl]
impl Token {
    pub fn a(env: Env) {
        env.storage().instance().set(&KEY, &1);
    }
}
"#,
        );
        let report = analyze_with(&project, &AnalysisConfig::default(), &registry());
        assert_eq!(report.budget.entrypoint("a").unwrap().writes.lower_bound, 1);
        let _ = NetworkLimits::mainnet();
    }

    #[test]
    fn from_dir_reports_missing_paths() {
        let error = Project::from_dir("definitely/not/here").unwrap_err();
        assert!(matches!(error, Error::NotFound { .. }));
    }

    #[test]
    fn builder_manifest_is_parsed() {
        let project = ProjectBuilder::new()
            .source("src/lib.rs", "#[contractimpl]\nimpl T { pub fn a(env: Env) {} }\n")
            .unwrap()
            .manifest("[package]\nname = \"x\"\n\n[lib]\ncrate-type = [\"cdylib\"]\n\n[dependencies]\nsoroban-sdk = \"27\"\n")
            .unwrap()
            .build();
        let package = project.package().unwrap();
        assert!(package.is_contract_crate());
        assert!(package.is_cdylib);
    }
}
