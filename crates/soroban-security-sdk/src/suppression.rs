//! Inline suppressions.
//!
//! Audit findings are sometimes deliberate. Rather than disabling a rule for a
//! whole project, a suppression comment acknowledges a single finding in place:
//!
//! ```text
//! // soroban-sec: ignore SSDK003 -- overflow is impossible, amount <= MAX_SUPPLY
//! let total = balance + amount;
//! ```
//!
//! A comment inside a function silences findings in that function; a comment
//! directly above an item silences findings in that item; `ignore-file` silences
//! the whole file. Suppressions that silence nothing are reported as diagnostics so
//! stale ignores do not accumulate.

use crate::finding::Finding;
use crate::rule::RuleId;
use crate::source::{FileId, SourceMap};
use crate::span::SourceSpan;

/// Marker that starts a suppression directive.
pub const MARKER: &str = "soroban-sec:";

/// A parsed suppression comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suppression {
    /// File the comment lives in.
    pub file: FileId,
    /// Line the comment is on (1-based).
    pub comment_line: u32,
    /// Inclusive line range the suppression applies to.
    pub start_line: u32,
    /// Inclusive line range the suppression applies to.
    pub end_line: u32,
    /// Rules silenced, or `None` for every rule.
    pub rules: Option<Vec<RuleId>>,
    /// Whether the suppression applies to the whole file.
    pub file_wide: bool,
    /// Free-form justification, taken from the text after `--` or `;`.
    pub reason: Option<String>,
    /// The original comment text.
    pub raw: String,
}

impl Suppression {
    /// Whether this suppression covers `finding`.
    pub fn covers(&self, finding: &Finding) -> bool {
        let Some(location) = finding.primary_location() else {
            return false;
        };
        if location.file_id != Some(self.file) {
            return false;
        }
        if let Some(rules) = &self.rules {
            if !rules.contains(&finding.rule) {
                return false;
            }
        }
        match location.line() {
            Some(line) if !self.file_wide => line >= self.start_line && line <= self.end_line,
            // A file-wide suppression still needs the finding to be in this file,
            // which the file id check above established.
            _ => true,
        }
    }

    /// Human-readable description used in diagnostics.
    pub fn describe(&self) -> String {
        match &self.rules {
            Some(rules) if !rules.is_empty() => {
                let ids: Vec<&str> = rules.iter().map(RuleId::as_str).collect();
                ids.join(", ")
            }
            _ => "all rules".to_string(),
        }
    }
}

/// An item that a suppression comment can be attached to.
struct Item {
    file: FileId,
    span: SourceSpan,
}

/// Scan every file for suppression comments.
pub fn collect(sources: &SourceMap) -> Vec<Suppression> {
    let mut suppressions = Vec::new();
    for source in sources.iter() {
        let items = collect_items(source.syntax(), source.id());
        for (index, line) in source.source().lines().enumerate() {
            let line_number = index as u32 + 1;
            let trimmed = line.trim();
            if !is_comment(trimmed) || !trimmed.contains(MARKER) {
                continue;
            }
            let Some(directive) = directive_after_marker(trimmed) else {
                continue;
            };
            let (rules, file_wide) = match parse_directive(&directive) {
                Some(parsed) => parsed,
                // `soroban-sec: ...` with an unknown directive is not a suppression.
                None => continue,
            };
            let extent = match file_wide {
                true => (1, u32::MAX),
                false => scope_for(&items, source.id(), line_number),
            };
            suppressions.push(Suppression {
                file: source.id(),
                comment_line: line_number,
                start_line: extent.0,
                end_line: extent.1,
                rules,
                file_wide,
                reason: reason_from(&directive),
                raw: trimmed.to_string(),
            });
        }
    }
    suppressions
}

/// Filter findings against suppressions.
///
/// Returns `(kept, suppressed)`.
pub fn apply(findings: Vec<Finding>, suppressions: &[Suppression]) -> (Vec<Finding>, Vec<Finding>) {
    if suppressions.is_empty() {
        return (findings, Vec::new());
    }
    let mut kept = Vec::with_capacity(findings.len());
    let mut suppressed = Vec::new();
    for finding in findings {
        if suppressions.iter().any(|item| item.covers(&finding)) {
            suppressed.push(finding);
        } else {
            kept.push(finding);
        }
    }
    (kept, suppressed)
}

/// Suppressions that did not match any finding.
///
/// Pass every finding produced by the run (including ones that were suppressed),
/// otherwise a suppression that did its job looks unused.
pub fn unused<'a>(suppressions: &'a [Suppression], findings: &[Finding]) -> Vec<&'a Suppression> {
    suppressions
        .iter()
        .filter(|item| !findings.iter().any(|finding| item.covers(finding)))
        .collect()
}

fn is_comment(trimmed: &str) -> bool {
    trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*')
}

/// Text following the `soroban-sec:` marker.
fn directive_after_marker(trimmed: &str) -> Option<String> {
    let index = trimmed.find(MARKER)?;
    let rest = &trimmed[index + MARKER.len()..];
    Some(rest.trim().trim_end_matches("*/").trim().to_string())
}

/// Parse `ignore`, `ignore SSDK001, SSDK003` or `ignore-file`. Returns the rule
/// set (empty means "all rules") and whether the whole file is silenced.
fn parse_directive(directive: &str) -> Option<(Option<Vec<RuleId>>, bool)> {
    let (head, tail) = split_reason(directive);
    let mut words = head.split_whitespace();
    let keyword = words.next()?.to_ascii_lowercase();
    let file_wide = match keyword.as_str() {
        "ignore" | "allow" => false,
        "ignore-file" | "allow-file" => true,
        _ => return None,
    };
    let mut rules: Vec<RuleId> = words
        .flat_map(|word| word.split(','))
        .map(|word| word.trim())
        .filter(|word| !word.is_empty())
        .filter_map(|word| RuleId::parse(word).ok())
        .collect();
    rules.dedup();
    let _ = tail;
    if rules.is_empty() {
        Some((None, file_wide))
    } else {
        Some((Some(rules), file_wide))
    }
}

/// Split a directive into its head and justification.
fn split_reason(directive: &str) -> (String, Option<String>) {
    for separator in [" -- ", " ; ", "--", ";"] {
        if let Some((head, tail)) = directive.split_once(separator) {
            let tail = tail.trim();
            return (
                head.trim().to_string(),
                (!tail.is_empty()).then(|| tail.to_string()),
            );
        }
    }
    (directive.trim().to_string(), None)
}

fn reason_from(directive: &str) -> Option<String> {
    split_reason(directive).1
}

/// Find the line range a suppression inside an item applies to.
fn scope_for(items: &[Item], file: FileId, line: u32) -> (u32, u32) {
    let containing = items
        .iter()
        .filter(|item| item.file == file && item.span.contains_line(line))
        .min_by_key(|item| span_size(item.span));
    if let Some(item) = containing {
        return (item.span.start_line, item.span.end_line);
    }
    let following = items
        .iter()
        .filter(|item| {
            item.file == file && item.span.start_line > line && item.span.start_line <= line + 10
        })
        .min_by_key(|item| (item.span.start_line, span_size(item.span)));
    match following {
        Some(item) => (item.span.start_line, item.span.end_line),
        None => (1, u32::MAX),
    }
}

fn span_size(span: SourceSpan) -> (u32, u32) {
    (
        span.end_line.saturating_sub(span.start_line),
        span.end_column.saturating_sub(span.start_column),
    )
}

/// Collect spans of items a comment can be attached to.
fn collect_items(file: &syn::File, id: FileId) -> Vec<Item> {
    let mut items = Vec::new();
    collect_from_items(&file.items, id, &mut items);
    items
}

fn collect_from_items(items: &[syn::Item], id: FileId, out: &mut Vec<Item>) {
    for item in items {
        let span = SourceSpan::of(item);
        out.push(Item { file: id, span });
        match item {
            syn::Item::Impl(item_impl) => {
                for inner in &item_impl.items {
                    if let syn::ImplItem::Fn(func) = inner {
                        out.push(Item {
                            file: id,
                            span: SourceSpan::of(func),
                        });
                    }
                }
            }
            syn::Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    collect_from_items(nested, id, out);
                }
            }
            syn::Item::Trait(item_trait) => {
                for inner in &item_trait.items {
                    if let syn::TraitItem::Fn(func) = inner {
                        out.push(Item {
                            file: id,
                            span: SourceSpan::of(func),
                        });
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::DetectorMeta;
    use crate::severity::{Confidence, Severity};
    use crate::source::SourceFile;

    const META: DetectorMeta = DetectorMeta::new(RuleId::new("SSDK003"), "rule", "summary")
        .severity(Severity::Medium)
        .confidence(Confidence::Medium);

    fn source_map(source: &str) -> SourceMap {
        let file = SourceFile::parse(FileId(0), "src/lib.rs", "src/lib.rs", source).unwrap();
        SourceMap::new(vec![file])
    }

    fn finding_at(file: FileId, line: u32) -> Finding {
        let mut finding = Finding::new(&META, "message", crate::finding::Location::unknown());
        finding.locations = vec![crate::finding::Location {
            file: "src/lib.rs".to_string(),
            file_id: Some(file),
            span: Some(SourceSpan::point(line, 5)),
            function: None,
            label: None,
            wasm_offset: None,
        }];
        finding
    }

    #[test]
    fn parses_rules_and_reason() {
        let sources = source_map(
            "// soroban-sec: ignore SSDK003, SSDK010 -- amounts are bounded above\nfn f() {\n    let x = 1;\n}\n",
        );
        let suppressions = collect(&sources);
        assert_eq!(suppressions.len(), 1);
        let suppression = &suppressions[0];
        assert_eq!(
            suppression.rules.as_ref().unwrap(),
            &[RuleId::new("SSDK003"), RuleId::new("SSDK010")]
        );
        assert_eq!(
            suppression.reason.as_deref(),
            Some("amounts are bounded above")
        );
        assert!(!suppression.file_wide);
    }

    #[test]
    fn comment_above_item_scopes_to_that_item() {
        let sources = source_map(
            "fn a() {\n    let x = 1;\n}\n\n// soroban-sec: ignore\nfn b() {\n    let y = 2;\n}\n",
        );
        let suppression = &collect(&sources)[0];
        assert_eq!((suppression.start_line, suppression.end_line), (6, 8));
        assert!(suppression.covers(&finding_at(FileId(0), 7)));
        assert!(suppression.covers(&finding_at(FileId(0), 6)));
        assert!(!suppression.covers(&finding_at(FileId(0), 3)));
    }

    #[test]
    fn comment_inside_item_scopes_to_enclosing_item() {
        let sources = source_map(
            "fn a() {\n    // soroban-sec: ignore\n    let x = 1;\n}\nfn b() {\n    let y = 2;\n}\n",
        );
        let suppression = &collect(&sources)[0];
        assert_eq!((suppression.start_line, suppression.end_line), (1, 4));
        assert!(!suppression.covers(&finding_at(FileId(0), 6)));
    }

    #[test]
    fn ignore_file_covers_the_whole_file() {
        let sources = source_map("// soroban-sec: ignore-file\nfn a() {}\n");
        let suppression = &collect(&sources)[0];
        assert!(suppression.file_wide);
        assert!(suppression.covers(&finding_at(FileId(0), 99)));
        assert!(!suppression.covers(&finding_at(FileId(1), 2)));
    }

    #[test]
    fn bare_ignore_silences_every_rule_but_only_in_scope() {
        let sources = source_map(
            "fn a() {\n    // soroban-sec: ignore\n    x();\n}\nfn b() {\n    y();\n}\n",
        );
        let suppression = &collect(&sources)[0];
        assert!(suppression.rules.is_none());
        assert!(suppression.covers(&finding_at(FileId(0), 3)));
        assert!(!suppression.covers(&finding_at(FileId(0), 6)));
    }

    #[test]
    fn unknown_directives_are_ignored() {
        let sources = source_map("// soroban-sec: something-else\nfn a() {}\n");
        assert!(collect(&sources).is_empty());
    }

    #[test]
    fn mentions_without_a_comment_are_ignored() {
        let sources = source_map("fn a() {\n    let s = \"soroban-sec: ignore\";\n}\n");
        assert!(collect(&sources).is_empty());
    }

    #[test]
    fn apply_splits_kept_and_suppressed() {
        let sources = source_map(
            "fn a() {\n    // soroban-sec: ignore SSDK003\n    x();\n}\nfn b() {\n    y();\n}\n",
        );
        let suppressions = collect(&sources);
        let findings = vec![finding_at(FileId(0), 3), finding_at(FileId(0), 6)];
        let (kept, suppressed) = apply(findings.clone(), &suppressions);
        assert_eq!(kept.len(), 1);
        assert_eq!(suppressed.len(), 1);
        assert!(unused(&suppressions, &findings).is_empty());
        assert_eq!(unused(&suppressions, &kept).len(), 1);
    }

    #[test]
    fn unused_suppressions_are_reported() {
        let sources = source_map("fn a() {\n    // soroban-sec: ignore SSDK099\n    x();\n}\n");
        let suppressions = collect(&sources);
        let findings = vec![finding_at(FileId(0), 3)];
        assert_eq!(unused(&suppressions, &findings).len(), 1);
    }

    #[test]
    fn rule_specific_suppression_does_not_cover_other_rules() {
        let sources = source_map("fn a() {\n    // soroban-sec: ignore SSDK010\n    x();\n}\n");
        let suppression = &collect(&sources)[0];
        assert!(!suppression.covers(&finding_at(FileId(0), 3)));
    }
}
