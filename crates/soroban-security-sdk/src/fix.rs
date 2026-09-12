//! Applying suggested fixes.
//!
//! Detectors may attach a [`crate::Fix`] to a finding. This module turns collected
//! fixes into patched file contents. Nothing is written to disk here: callers (the
//! CLI, an editor integration, a CI bot) decide that.
//!
//! Fixes are applied all-or-nothing: if any edit of a fix overlaps an edit that was
//! already accepted, the whole fix is skipped and the reason recorded, so a patch
//! never ends up half-applied.

use crate::finding::{Edit, Finding};
use crate::source::{FileId, SourceFile, SourceMap};
use crate::span::SourceSpan;

/// Why edits could not be applied.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FixError {
    /// A span points outside the file it claims to belong to.
    #[error("edit at {span} is outside `{file}`")]
    OutOfRange {
        /// File display path.
        file: String,
        /// Offending span.
        span: SourceSpan,
    },
    /// Two edits touch the same bytes.
    #[error("edits at {first} and {second} overlap in `{file}`")]
    Overlap {
        /// File display path.
        file: String,
        /// First span.
        first: SourceSpan,
        /// Second span.
        second: SourceSpan,
    },
}

/// Patched content for one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePatch {
    /// File the patch belongs to.
    pub file: FileId,
    /// Display path, for reporting.
    pub display_path: String,
    /// Original content.
    pub original: String,
    /// Content after all accepted edits.
    pub patched: String,
    /// Descriptions of the fixes that were applied.
    pub applied: Vec<String>,
    /// Fixes that were skipped, with the reason.
    pub skipped: Vec<String>,
}

impl FilePatch {
    /// Whether the patched content differs from the original.
    pub fn changed(&self) -> bool {
        self.original != self.patched
    }
}

/// The result of planning fixes across a project.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FixPlan {
    /// One entry per file that had at least one fix.
    pub patches: Vec<FilePatch>,
    /// Fixes that could not be attributed to a file at all.
    pub skipped: Vec<String>,
}

impl FixPlan {
    /// Total number of fixes applied across all files.
    pub fn applied_count(&self) -> usize {
        self.patches.iter().map(|patch| patch.applied.len()).sum()
    }

    /// Total number of fixes skipped, including unattributable ones.
    pub fn skipped_count(&self) -> usize {
        self.patches
            .iter()
            .map(|patch| patch.skipped.len())
            .sum::<usize>()
            + self.skipped.len()
    }

    /// Whether anything would change on disk.
    pub fn is_empty(&self) -> bool {
        !self.patches.iter().any(FilePatch::changed)
    }
}

/// Apply `edits` to a file, returning the new content.
///
/// Spans are resolved to byte ranges through the file's line index; a span that
/// cannot be resolved is an error rather than a silent skip.
pub fn apply_edits(file: &SourceFile, edits: &[Edit]) -> Result<String, FixError> {
    if edits.is_empty() {
        return Ok(file.source().to_string());
    }
    let out_of_range = |span: SourceSpan| FixError::OutOfRange {
        file: file.display_path().to_string(),
        span,
    };

    let mut planned: Vec<(std::ops::Range<usize>, &Edit)> = Vec::with_capacity(edits.len());
    for edit in edits {
        if !edit.span.is_known() {
            return Err(out_of_range(edit.span));
        }
        let range = file
            .byte_range(edit.span)
            .ok_or_else(|| out_of_range(edit.span))?;
        if range.end > file.source().len() {
            return Err(out_of_range(edit.span));
        }
        planned.push((range, edit));
    }
    planned.sort_by_key(|(range, _)| (range.start, range.end));

    for pair in planned.windows(2) {
        let (left, left_edit) = &pair[0];
        let (right, right_edit) = &pair[1];
        if left.end > right.start {
            return Err(FixError::Overlap {
                file: file.display_path().to_string(),
                first: left_edit.span,
                second: right_edit.span,
            });
        }
    }

    let source = file.source();
    let mut output = String::with_capacity(source.len());
    let mut cursor = 0usize;
    for (range, edit) in planned {
        output.push_str(&source[cursor..range.start]);
        output.push_str(&edit.replacement);
        cursor = range.end;
    }
    output.push_str(&source[cursor..]);
    Ok(output)
}

/// Build a patch plan for every finding that carries a fix.
pub fn plan(sources: &SourceMap, findings: &[Finding]) -> FixPlan {
    struct Pending {
        file: FileId,
        description: String,
        edits: Vec<Edit>,
    }

    let mut pending: Vec<Pending> = Vec::new();
    let mut unattributed: Vec<String> = Vec::new();

    for finding in findings {
        let Some(fix) = &finding.fix else { continue };
        if fix.edits.is_empty() {
            continue;
        }
        let primary_file = finding.primary_location().and_then(|location| location.file_id);
        // A fix may span several files; group its edits per file.
        let mut by_file: Vec<(FileId, Vec<Edit>)> = Vec::new();
        for edit in &fix.edits {
            let Some(file) = edit.file.or(primary_file) else {
                unattributed.push(format!("{}: fix has no target file", finding.rule));
                continue;
            };
            if !edit.span.is_known() {
                unattributed.push(format!("{}: fix has no source span", finding.rule));
                continue;
            }
            let resolved = Edit::new(file, edit.span, edit.replacement.clone());
            match by_file.iter_mut().find(|(existing, _)| *existing == file) {
                Some((_, edits)) => edits.push(resolved),
                None => by_file.push((file, vec![resolved])),
            }
        }
        for (file, edits) in by_file {
            pending.push(Pending {
                file,
                description: format!("{} {}", finding.rule, fix.description),
                edits,
            });
        }
    }

    let mut files: Vec<FileId> = pending.iter().map(|item| item.file).collect();
    files.sort_unstable();
    files.dedup();

    let mut patches = Vec::new();
    for file in files {
        let Some(source) = sources.get(file) else {
            unattributed.push(format!("{file}: no such source file"));
            continue;
        };
        let mut accepted: Vec<Edit> = Vec::new();
        let mut applied = Vec::new();
        let mut skipped = Vec::new();

        for item in pending.iter().filter(|item| item.file == file) {
            let mut candidate = accepted.clone();
            candidate.extend(item.edits.iter().cloned());
            match apply_edits(source, &candidate) {
                Ok(_) => {
                    accepted = candidate;
                    applied.push(item.description.clone());
                }
                Err(err) => skipped.push(format!("{}: {err}", item.description)),
            }
        }

        let patched = match apply_edits(source, &accepted) {
            Ok(patched) => patched,
            Err(err) => {
                skipped.push(format!("internal error: {err}"));
                accepted.clear();
                applied.clear();
                source.source().to_string()
            }
        };

        patches.push(FilePatch {
            file,
            display_path: source.display_path().to_string(),
            original: source.source().to_string(),
            patched,
            applied,
            skipped,
        });
    }

    FixPlan {
        patches,
        skipped: unattributed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Fix, Location};
    use crate::rule::{DetectorMeta, RuleId};
    use crate::severity::{Confidence, Severity};

    const META: DetectorMeta = DetectorMeta::new(RuleId::new("SSDK900"), "r", "s")
        .severity(Severity::Medium)
        .confidence(Confidence::Medium);

    fn source_map() -> SourceMap {
        let file = SourceFile::parse(
            FileId(0),
            "src/lib.rs",
            "src/lib.rs",
            "fn f() {\n    let total = a + b;\n}\n",
        )
        .unwrap();
        SourceMap::new(vec![file])
    }

    #[test]
    fn applies_a_single_replacement() {
        let sources = source_map();
        let file = sources.get(FileId(0)).unwrap();
        let edits = vec![Edit::new(
            FileId(0),
            SourceSpan::new(2, 17, 2, 22),
            "a.checked_add(b)",
        )];
        let patched = apply_edits(file, &edits).unwrap();
        assert_eq!(patched, "fn f() {\n    let total = a.checked_add(b);\n}\n");
    }

    #[test]
    fn applies_multiple_edits_left_to_right() {
        let sources = source_map();
        let file = sources.get(FileId(0)).unwrap();
        let edits = vec![
            Edit::new(FileId(0), SourceSpan::point(1, 1), "// header\n"),
            Edit::new(FileId(0), SourceSpan::new(2, 17, 2, 18), "x"),
        ];
        let patched = apply_edits(file, &edits).unwrap();
        assert!(patched.starts_with("// header\nfn f() {"));
        assert!(patched.contains("let total = x + b;"));
    }

    #[test]
    fn rejects_overlapping_edits() {
        let sources = source_map();
        let file = sources.get(FileId(0)).unwrap();
        let edits = vec![
            Edit::new(FileId(0), SourceSpan::new(2, 17, 2, 20), "x"),
            Edit::new(FileId(0), SourceSpan::new(2, 19, 2, 22), "y"),
        ];
        assert!(matches!(
            apply_edits(file, &edits),
            Err(FixError::Overlap { .. })
        ));
    }

    #[test]
    fn rejects_unknown_spans() {
        let sources = source_map();
        let file = sources.get(FileId(0)).unwrap();
        let edits = vec![Edit::new(FileId(0), SourceSpan::UNKNOWN, "x")];
        assert!(matches!(
            apply_edits(file, &edits),
            Err(FixError::OutOfRange { .. })
        ));
    }

    #[test]
    fn plan_applies_compatible_fixes_and_skips_conflicts() {
        let sources = source_map();
        let location = sources.location(FileId(0), SourceSpan::point(2, 17));

        let mut first = Finding::new(&META, "m", location.clone());
        first.fix = Some(Fix::new(
            "use checked arithmetic",
            vec![Edit::new(
                FileId(0),
                SourceSpan::new(2, 17, 2, 22),
                "a.checked_add(b)",
            )],
        ));

        let mut second = Finding::new(&META, "m", location);
        second.fix = Some(Fix::new(
            "conflicting rename",
            vec![Edit::new(FileId(0), SourceSpan::new(2, 17, 2, 18), "z")],
        ));

        let plan = plan(&sources, &[first, second]);
        assert_eq!(plan.patches.len(), 1);
        assert_eq!(plan.applied_count(), 1);
        assert_eq!(plan.skipped_count(), 1);
        let patch = &plan.patches[0];
        assert!(patch.changed());
        assert!(patch.patched.contains("checked_add"));
        assert!(!plan.is_empty());
    }

    #[test]
    fn plan_inherits_the_primary_location_file() {
        let sources = source_map();
        let mut finding = Finding::new(&META, "m", sources.location(FileId(0), SourceSpan::point(1, 1)));
        finding.fix = Some(Fix::new(
            "insert a comment",
            vec![Edit::at(SourceSpan::point(1, 1), "// note\n")],
        ));
        let plan = plan(&sources, &[finding]);
        assert_eq!(plan.applied_count(), 1);
        assert!(plan.patches[0].patched.starts_with("// note\n"));
    }

    #[test]
    fn plan_ignores_findings_without_fixes() {
        let sources = source_map();
        let finding = Finding::new(&META, "m", Location::unknown());
        let plan = plan(&sources, &[finding]);
        assert!(plan.is_empty());
        assert_eq!(plan.applied_count(), 0);
    }

    #[test]
    fn plan_reports_unattributable_fixes() {
        let sources = source_map();
        let mut finding = Finding::new(&META, "m", Location::unknown());
        finding.fix = Some(Fix::new(
            "nowhere",
            vec![Edit::at(SourceSpan::point(1, 1), "x")],
        ));
        let plan = plan(&sources, &[finding]);
        assert_eq!(plan.skipped_count(), 1);
        assert!(plan.skipped[0].contains("no target file"));
    }
}
