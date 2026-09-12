//! Findings produced by detectors.
//!
//! Detectors never build [`Finding`] structs by hand: they report through a
//! [`FindingSink`], which fills in the rule id, severity and category from the
//! detector's metadata. That keeps findings internally consistent and keeps
//! detector code focused on the pattern being matched.
//!
//! ```no_run
//! use soroban_security_sdk::prelude::*;
//!
//! fn detect<'a>(ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
//!     for entrypoint in ctx.entrypoints() {
//!         sink.report(format!("`{}` changes state without authorization", entrypoint.name))
//!             .primary(entrypoint.file, entrypoint.span)
//!             .note("Add `address.require_auth()` before the first write.")
//!             .help("See the Abstract Account guide in the Stellar docs.")
//!             .emit();
//!     }
//! }
//! ```

use serde::Serialize;

use crate::rule::DetectorMeta;
use crate::severity::{Confidence, Severity};
use crate::source::{FileId, SourceMap};
use crate::span::SourceSpan;

/// Where a finding was observed.
///
/// Locations are self-contained (they carry the display path) so that a finding
/// can be rendered without the [`SourceMap`] that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Location {
    /// Display path of the file, for example `src/lib.rs`.
    pub file: String,
    /// Index into the [`SourceMap`], when the location came from a source file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_id: Option<FileId>,
    /// Span inside the file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span: Option<SourceSpan>,
    /// Enclosing function or entrypoint name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// Short annotation shown next to the location, e.g. the storage key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Byte offset inside a compiled wasm module, for wasm-level findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wasm_offset: Option<u64>,
}

impl Location {
    /// A location with no position information.
    pub fn unknown() -> Self {
        Location {
            file: "<unknown>".to_string(),
            file_id: None,
            span: None,
            function: None,
            label: None,
            wasm_offset: None,
        }
    }

    /// 1-based line of the span start, if known.
    pub fn line(&self) -> Option<u32> {
        self.span.map(|span| span.start_line)
    }

    /// 1-based column of the span start, if known.
    pub fn column(&self) -> Option<u32> {
        self.span.map(|span| span.start_column)
    }

    /// Attach the enclosing function name.
    pub fn with_function(mut self, function: impl Into<String>) -> Self {
        self.function = Some(function.into());
        self
    }

    /// Attach a short label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Attach a wasm byte offset.
    pub fn with_wasm_offset(mut self, offset: u64) -> Self {
        self.wasm_offset = Some(offset);
        self
    }
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.span {
            Some(span) if span.is_known() => write!(f, "{}:{}", self.file, span),
            _ => f.write_str(&self.file),
        }
    }
}

/// A single textual replacement inside one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Edit {
    /// File the edit applies to. `None` means "the file of the primary location".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<FileId>,
    /// Range to replace.
    pub span: SourceSpan,
    /// Replacement text.
    pub replacement: String,
}

impl Edit {
    /// Build an edit in a known file.
    pub fn new(file: FileId, span: SourceSpan, replacement: impl Into<String>) -> Self {
        Edit {
            file: Some(file),
            span,
            replacement: replacement.into(),
        }
    }

    /// Build an edit that inherits the file of the finding's primary location.
    pub fn at(span: SourceSpan, replacement: impl Into<String>) -> Self {
        Edit {
            file: None,
            span,
            replacement: replacement.into(),
        }
    }
}

/// A suggested remediation.
///
/// Fixes describe edits; applying them is the caller's decision. The SDK ships
/// [`crate::fix::apply_edits`] for consumers that want to apply the non-overlapping
/// edits of a single file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Fix {
    /// Human-readable description of the change.
    pub description: String,
    /// Edits that implement the change.
    pub edits: Vec<Edit>,
}

impl Fix {
    /// Build a fix.
    pub fn new(description: impl Into<String>, edits: Vec<Edit>) -> Self {
        Fix {
            description: description.into(),
            edits,
        }
    }
}

/// One detected issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Rule that produced the finding.
    pub rule: crate::rule::RuleId,
    /// Kebab-case rule name.
    pub rule_name: String,
    /// Impact if the pattern is a true positive.
    pub severity: Severity,
    /// Likelihood that the pattern is a true positive.
    pub confidence: Confidence,
    /// Vulnerability class.
    pub category: crate::category::Category,
    /// What was observed and why it matters.
    pub message: String,
    /// Primary location first, then related locations.
    pub locations: Vec<Location>,
    /// Extra context.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// Remediation advice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    /// Machine-applicable remediation, when the detector can build one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<Fix>,
}

impl Finding {
    /// Build a finding directly. Prefer [`FindingSink::report`] inside a detector.
    pub fn new(meta: &DetectorMeta, message: impl Into<String>, location: Location) -> Self {
        Finding {
            rule: meta.id.clone(),
            rule_name: meta.name.to_string(),
            severity: meta.severity,
            confidence: meta.confidence,
            category: meta.category,
            message: message.into(),
            locations: vec![location],
            notes: Vec::new(),
            help: None,
            fix: None,
        }
    }

    /// The primary location, when one is present.
    pub fn primary_location(&self) -> Option<&Location> {
        self.locations.first()
    }

    /// Sort key giving a stable, human-friendly report order: severity descending,
    /// then file, then position.
    pub fn sort_key(&self) -> (std::cmp::Reverse<Severity>, String, u32, u32, String) {
        let location = self.primary_location();
        (
            std::cmp::Reverse(self.severity),
            location.map(|l| l.file.clone()).unwrap_or_default(),
            location.and_then(|l| l.line()).unwrap_or(u32::MAX),
            location.and_then(|l| l.column()).unwrap_or(u32::MAX),
            self.rule.to_string(),
        )
    }

    /// Stable identity of the finding, for baselines and SARIF fingerprints.
    ///
    /// Deliberately excludes the message so that re-worded rules do not invalidate
    /// existing baselines.
    pub fn fingerprint(&self) -> String {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        let mut feed = |bytes: &[u8]| {
            for byte in bytes {
                hash ^= *byte as u64;
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
        };
        feed(self.rule.as_str().as_bytes());
        feed(b"|");
        let location = self.primary_location();
        feed(location.map(|l| l.file.as_str()).unwrap_or("").as_bytes());
        feed(b"|");
        if let Some(span) = location.and_then(|l| l.span) {
            feed(&span.start_line.to_le_bytes());
            feed(&span.start_column.to_le_bytes());
        }
        feed(b"|");
        feed(
            location
                .and_then(|l| l.function.as_deref())
                .unwrap_or("")
                .as_bytes(),
        );
        format!("{hash:016x}")
    }

    /// The line reported in terminal output, e.g. `src/lib.rs:42:9`.
    pub fn headline_location(&self) -> String {
        match self.primary_location() {
            Some(location) => location.to_string(),
            None => "<no location>".to_string(),
        }
    }
}

/// Collects findings for one detector.
///
/// A sink is bound to a single detector's metadata so that every finding it
/// produces carries the right rule id, severity and category.
#[must_use = "a FindingSink only collects findings if it is passed to a detector and read back"]
pub struct FindingSink<'a> {
    meta: DetectorMeta,
    sources: &'a SourceMap,
    findings: Vec<Finding>,
}

impl<'a> FindingSink<'a> {
    /// Build a sink for `meta` over `sources`.
    ///
    /// The metadata is taken by value, which lets detectors keep their metadata in a
    /// plain associated constant.
    pub fn new(meta: DetectorMeta, sources: &'a SourceMap) -> Self {
        FindingSink {
            meta,
            sources,
            findings: Vec::new(),
        }
    }

    /// The metadata of the detector owning this sink.
    pub fn meta(&self) -> &DetectorMeta {
        &self.meta
    }

    /// Access to the source map, for detectors that want to build extra locations.
    pub fn sources(&self) -> &'a SourceMap {
        self.sources
    }

    /// Start building a finding.
    ///
    /// The returned builder is `#[must_use]`: dropping it without calling
    /// [`FindingBuilder::emit`] is a bug, so the compiler warns about it.
    pub fn report<'b>(&'b mut self, message: impl Into<String>) -> FindingBuilder<'b, 'a> {
        // Copy what the builder needs out of `self` before taking the mutable
        // borrow; the source map reference does not alias the sink.
        let sources = self.sources;
        let severity = self.meta.severity;
        let confidence = self.meta.confidence;
        let meta = self.meta.clone();
        FindingBuilder {
            sources,
            meta,
            sink: self,
            message: message.into(),
            severity,
            confidence,
            locations: Vec::new(),
            function: None,
            notes: Vec::new(),
            help: None,
            fix: None,
        }
    }

    /// Add an already-built finding (used by detectors that post-process).
    pub fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// How many findings have been collected.
    pub fn len(&self) -> usize {
        self.findings.len()
    }

    /// Whether nothing has been reported yet.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Consume the sink and return the findings.
    pub fn into_findings(self) -> Vec<Finding> {
        self.findings
    }
}

impl std::fmt::Debug for FindingSink<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FindingSink")
            .field("rule", &self.meta.id)
            .field("findings", &self.findings.len())
            .finish_non_exhaustive()
    }
}

/// Builder for a single [`Finding`].
#[must_use = "call .emit() to record the finding"]
pub struct FindingBuilder<'b, 'a> {
    sink: &'b mut FindingSink<'a>,
    sources: &'a SourceMap,
    meta: DetectorMeta,
    message: String,
    severity: Severity,
    confidence: Confidence,
    locations: Vec<Location>,
    function: Option<String>,
    notes: Vec<String>,
    help: Option<String>,
    fix: Option<Fix>,
}

impl<'b, 'a> FindingBuilder<'b, 'a> {
    /// Override the severity for this finding.
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Override the confidence for this finding.
    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Set the enclosing function, applied to this and every later location.
    pub fn in_function(mut self, function: impl Into<String>) -> Self {
        let function = function.into();
        for location in &mut self.locations {
            location.function.get_or_insert_with(|| function.clone());
        }
        self.function = Some(function);
        self
    }

    /// Add the primary location. The first call wins.
    pub fn primary(self, file: FileId, span: SourceSpan) -> Self {
        self.push_location(file, span, true)
    }

    /// Add a related location.
    pub fn secondary(self, file: FileId, span: SourceSpan) -> Self {
        self.push_location(file, span, false)
    }

    /// Add a primary location from a wasm byte offset.
    pub fn primary_wasm(mut self, offset: u64, label: impl Into<String>) -> Self {
        self.locations.push(
            Location::unknown()
                .with_wasm_offset(offset)
                .with_label(label),
        );
        self
    }

    /// Add a location.
    pub fn location(mut self, location: Location) -> Self {
        let location = self.apply_function(location);
        self.locations.push(location);
        self
    }

    /// Label the most recently added location.
    pub fn label(mut self, label: impl Into<String>) -> Self {
        if let Some(location) = self.locations.last_mut() {
            location.label = Some(label.into());
        }
        self
    }

    /// Add a note.
    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    /// Add remediation advice.
    pub fn help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    /// Offer a machine-applicable fix.
    pub fn fix(mut self, fix: Fix) -> Self {
        self.fix = Some(fix);
        self
    }

    /// Offer a fix consisting of a single replacement.
    pub fn replace_with(
        mut self,
        file: FileId,
        span: SourceSpan,
        replacement: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        self.fix = Some(Fix::new(
            description,
            vec![Edit::new(file, span, replacement)],
        ));
        self
    }

    /// Record the finding.
    pub fn emit(self) {
        let finding = Finding {
            rule: self.meta.id.clone(),
            rule_name: self.meta.name.to_string(),
            severity: self.severity,
            confidence: self.confidence,
            category: self.meta.category,
            message: self.message,
            locations: self.locations,
            notes: self.notes,
            help: self.help,
            fix: self.fix,
        };
        self.sink.findings.push(finding);
    }

    fn push_location(mut self, file: FileId, span: SourceSpan, primary: bool) -> Self {
        let location = self.sources.location(file, span);
        let location = self.apply_function(location);
        if primary && self.locations.is_empty() {
            self.locations.insert(0, location);
        } else {
            self.locations.push(location);
        }
        self
    }

    fn apply_function(&self, mut location: Location) -> Location {
        if location.function.is_none() {
            location.function = self.function.clone();
        }
        location
    }
}

impl std::fmt::Debug for FindingBuilder<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FindingBuilder")
            .field("rule", &self.meta.id)
            .field("message", &self.message)
            .field("severity", &self.severity)
            .field("locations", &self.locations.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;
    use crate::rule::RuleId;
    use crate::source::SourceFile;

    const META: DetectorMeta = DetectorMeta::new(RuleId::new("SSDK900"), "example", "summary")
        .severity(Severity::High)
        .confidence(Confidence::Medium)
        .category(Category::Auth);

    fn sources() -> SourceMap {
        let file = SourceFile::parse(
            FileId(0),
            "src/lib.rs",
            "src/lib.rs",
            "fn f() {\n    write();\n}\n",
        )
        .unwrap();
        SourceMap::new(vec![file])
    }

    #[test]
    fn sink_fills_metadata_from_detector() {
        let sources = sources();
        let mut sink = FindingSink::new(META, &sources);
        sink.report("something is wrong")
            .primary(FileId(0), SourceSpan::new(2, 5, 2, 12))
            .note("a note")
            .emit();
        let findings = sink.into_findings();
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.rule.as_str(), "SSDK900");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::Medium);
        assert_eq!(finding.category, Category::Auth);
        assert_eq!(finding.locations[0].file, "src/lib.rs");
        assert_eq!(finding.locations[0].line(), Some(2));
        assert_eq!(finding.notes, vec!["a note".to_string()]);
    }

    #[test]
    fn builder_overrides_severity_and_confidence() {
        let sources = sources();
        let mut sink = FindingSink::new(META, &sources);
        sink.report("m")
            .severity(Severity::Low)
            .confidence(Confidence::High)
            .primary(FileId(0), SourceSpan::point(1, 1))
            .in_function("f")
            .emit();
        let finding = &sink.into_findings()[0];
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.confidence, Confidence::High);
        assert_eq!(finding.locations[0].function.as_deref(), Some("f"));
    }

    #[test]
    fn first_primary_location_wins() {
        let sources = sources();
        let mut sink = FindingSink::new(META, &sources);
        sink.report("m")
            .primary(FileId(0), SourceSpan::point(1, 1))
            .primary(FileId(0), SourceSpan::point(2, 5))
            .emit();
        let finding = &sink.into_findings()[0];
        assert_eq!(finding.locations.len(), 2);
        assert_eq!(finding.locations[0].span, Some(SourceSpan::point(1, 1)));
    }

    #[test]
    fn fingerprints_are_stable_and_position_sensitive() {
        let sources = sources();
        let mut sink = FindingSink::new(META, &sources);
        sink.report("m")
            .primary(FileId(0), SourceSpan::point(2, 5))
            .emit();
        sink.report("a completely different message")
            .primary(FileId(0), SourceSpan::point(2, 5))
            .emit();
        sink.report("m")
            .primary(FileId(0), SourceSpan::point(3, 5))
            .emit();
        let findings = sink.into_findings();
        assert_eq!(findings[0].fingerprint(), findings[1].fingerprint());
        assert_ne!(findings[0].fingerprint(), findings[2].fingerprint());
        assert_eq!(findings[0].fingerprint().len(), 16);
    }

    #[test]
    fn sort_key_orders_by_severity_then_position() {
        let sources = sources();
        let mut sink = FindingSink::new(META, &sources);
        sink.report("low")
            .severity(Severity::Low)
            .primary(FileId(0), SourceSpan::point(1, 1))
            .emit();
        sink.report("high later")
            .severity(Severity::High)
            .primary(FileId(0), SourceSpan::point(9, 1))
            .emit();
        sink.report("high earlier")
            .severity(Severity::High)
            .primary(FileId(0), SourceSpan::point(2, 1))
            .emit();
        let mut findings = sink.into_findings();
        findings.sort_by_key(Finding::sort_key);
        let messages: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();
        assert_eq!(messages, vec!["high earlier", "high later", "low"]);
    }

    #[test]
    fn label_applies_to_last_location() {
        let sources = sources();
        let mut sink = FindingSink::new(META, &sources);
        sink.report("m")
            .primary(FileId(0), SourceSpan::point(1, 1))
            .secondary(FileId(0), SourceSpan::point(2, 1))
            .label("the key")
            .emit();
        let finding = &sink.into_findings()[0];
        assert_eq!(finding.locations[0].label, None);
        assert_eq!(finding.locations[1].label.as_deref(), Some("the key"));
    }
}
