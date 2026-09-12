//! Sources under analysis.
//!
//! A [`SourceMap`] owns every parsed Rust file in a project. Detectors receive it
//! through [`crate::AnalysisContext`] and use it to turn spans into text, byte
//! ranges and [`crate::Location`]s.
//!
//! Parsing never fails the analysis: a file that does not parse becomes a
//! [`ParseFailure`] which the project builder records as a diagnostic.

use std::fmt;
use std::ops::Range;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::finding::Location;
use crate::span::SourceSpan;

/// Index of a file inside a [`SourceMap`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize)]
#[serde(transparent)]
pub struct FileId(pub u32);

impl FileId {
    /// The id as a `usize` index.
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// Why a source file could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParseFailure {
    /// Display path of the file.
    pub file: String,
    /// Position of the syntax error, when known.
    pub span: SourceSpan,
    /// Parser message.
    pub message: String,
}

impl fmt::Display for ParseFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.span.is_known() {
            write!(f, "{}:{}: {}", self.file, self.span, self.message)
        } else {
            write!(f, "{}: {}", self.file, self.message)
        }
    }
}

/// A parsed Rust source file.
///
/// Owns both the original text (for snippets and fixes) and the `syn` syntax tree
/// (for detection).
pub struct SourceFile {
    id: FileId,
    path: PathBuf,
    display: String,
    source: String,
    syntax: syn::File,
    line_starts: Vec<u32>,
}

impl SourceFile {
    /// Parse a file from memory.
    ///
    /// `display` is the path shown in reports, normally relative to the project
    /// root; `path` is the absolute location used for fix application.
    pub fn parse(
        id: FileId,
        path: impl Into<PathBuf>,
        display: impl Into<String>,
        contents: impl Into<String>,
    ) -> Result<Self, ParseFailure> {
        let path = path.into();
        let display = display.into();
        let source = contents.into();
        let syntax = match syn::parse_file(&source) {
            Ok(syntax) => syntax,
            Err(err) => {
                let span = SourceSpan::from_proc_macro2(err.span());
                return Err(ParseFailure {
                    file: display,
                    span,
                    message: err.to_string(),
                });
            }
        };
        let line_starts = compute_line_starts(&source);
        Ok(SourceFile {
            id,
            path,
            display,
            source,
            syntax,
            line_starts,
        })
    }

    /// This file's id inside its [`SourceMap`].
    pub fn id(&self) -> FileId {
        self.id
    }

    /// Absolute or project-relative path on disk.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Path as displayed in reports.
    pub fn display_path(&self) -> &str {
        &self.display
    }

    /// The full original text.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The parsed syntax tree.
    pub fn syntax(&self) -> &syn::File {
        &self.syntax
    }

    /// Number of lines in the file.
    pub fn line_count(&self) -> usize {
        self.line_starts.len()
    }

    /// Text of a 1-based line, without its trailing newline.
    pub fn line_text(&self, line: u32) -> Option<&str> {
        let start = *self.line_starts.get(line.checked_sub(1)? as usize)? as usize;
        let end = self
            .line_starts
            .get(line as usize)
            .map(|value| *value as usize)
            .unwrap_or(self.source.len());
        Some(self.source[start..end].trim_end_matches(['\n', '\r']))
    }

    /// Byte offset of a 1-based line/column position.
    ///
    /// Columns past the end of a line clamp to the end of that line.
    pub fn byte_offset(&self, line: u32, column: u32) -> Option<usize> {
        let line_index = line.checked_sub(1)? as usize;
        let start = *self.line_starts.get(line_index)? as usize;
        let end = self
            .line_starts
            .get(line_index + 1)
            .map(|value| *value as usize)
            .unwrap_or(self.source.len());
        let text = self.source.get(start..end)?;
        if column <= 1 {
            return Some(start);
        }
        for (current, (offset, _)) in (1u32..).zip(text.char_indices()) {
            if current == column {
                return Some(start + offset);
            }
        }
        Some(start + text.trim_end_matches(['\n', '\r']).len())
    }

    /// Byte range covered by a span.
    pub fn byte_range(&self, span: SourceSpan) -> Option<Range<usize>> {
        if !span.is_known() {
            return None;
        }
        let start = self.byte_offset(span.start_line, span.start_column)?;
        let end = self
            .byte_offset(span.end_line, span.end_column)
            .unwrap_or(self.source.len());
        let end = end.min(self.source.len());
        if start > end {
            return Some(end..start.max(end));
        }
        Some(start..end)
    }

    /// The exact source text covered by a span.
    pub fn text_of(&self, span: SourceSpan) -> Option<&str> {
        let range = self.byte_range(span)?;
        self.source.get(range)
    }

    /// A single-line, length-limited excerpt of a span, for report messages.
    pub fn snippet(&self, span: SourceSpan) -> Option<String> {
        const MAX: usize = 160;
        let text = self.text_of(span)?;
        let single_line = text.lines().next().unwrap_or_default().trim();
        if single_line.is_empty() {
            return None;
        }
        if single_line.chars().count() > MAX {
            let truncated: String = single_line.chars().take(MAX).collect();
            return Some(format!("{truncated}…"));
        }
        Some(single_line.to_string())
    }

    /// Build a [`Location`] inside this file.
    pub fn location(&self, span: impl Into<Option<SourceSpan>>) -> Location {
        let span = span.into().unwrap_or(SourceSpan::UNKNOWN);
        Location {
            file: self.display.clone(),
            file_id: Some(self.id),
            span: span.is_known().then_some(span),
            function: None,
            label: None,
            wasm_offset: None,
        }
    }
}

impl fmt::Debug for SourceFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceFile")
            .field("id", &self.id)
            .field("display", &self.display)
            .field("lines", &self.line_starts.len())
            .finish_non_exhaustive()
    }
}

/// Every file under analysis, addressable by [`FileId`].
#[derive(Debug, Default)]
pub struct SourceMap {
    files: Vec<SourceFile>,
}

impl SourceMap {
    /// Build a source map from already-parsed files.
    pub fn new(files: Vec<SourceFile>) -> Self {
        SourceMap { files }
    }

    /// Look up a file.
    pub fn get(&self, id: FileId) -> Option<&SourceFile> {
        self.files.get(id.index())
    }

    /// Iterate over files in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &SourceFile> {
        self.files.iter()
    }

    /// Number of files.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Display paths of every file, in insertion order.
    pub fn display_paths(&self) -> Vec<&str> {
        self.files.iter().map(SourceFile::display_path).collect()
    }

    /// Build a [`Location`] in `file`.
    ///
    /// Unknown files produce a location that still carries the span, so a finding
    /// is never silently dropped.
    pub fn location(&self, file: FileId, span: impl Into<Option<SourceSpan>>) -> Location {
        match self.get(file) {
            Some(source) => source.location(span),
            None => Location {
                file: format!("<unknown file {file}>"),
                file_id: Some(file),
                span: span.into().filter(SourceSpan::is_known),
                function: None,
                label: None,
                wasm_offset: None,
            },
        }
    }

    /// Single-line excerpt of a span, for report messages.
    pub fn snippet(&self, file: FileId, span: SourceSpan) -> Option<String> {
        self.get(file)?.snippet(span)
    }
}

fn compute_line_starts(source: &str) -> Vec<u32> {
    let mut starts = Vec::with_capacity(64);
    starts.push(0u32);
    for (index, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            starts.push((index + 1) as u32);
        }
    }
    starts
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "fn main() {\n    let total = balance + amount;\n}\n";

    fn sample() -> SourceFile {
        SourceFile::parse(FileId(0), "src/lib.rs", "src/lib.rs", SAMPLE).unwrap()
    }

    #[test]
    fn parses_and_indexes_lines() {
        let file = sample();
        assert_eq!(file.line_count(), 4);
        assert_eq!(file.line_text(2), Some("    let total = balance + amount;"));
        assert_eq!(file.line_text(9), None);
    }

    #[test]
    fn byte_offsets_are_one_based_and_clamped() {
        let file = sample();
        assert_eq!(file.byte_offset(1, 1), Some(0));
        assert_eq!(file.byte_offset(2, 1), Some(12));
        assert_eq!(file.byte_offset(2, 5), Some(16));
        // Past the end of the line clamps to the end of that line (12 + 33 chars).
        assert_eq!(file.byte_offset(2, 500), Some(45));
    }

    #[test]
    fn text_of_returns_exactly_the_span() {
        let file = sample();
        let span = SourceSpan::new(2, 17, 2, 24);
        assert_eq!(file.text_of(span), Some("balance"));
        assert_eq!(file.snippet(span).as_deref(), Some("balance"));
        assert!(file.text_of(SourceSpan::UNKNOWN).is_none());
    }

    #[test]
    fn snippets_are_single_line_and_truncated() {
        let long = format!("fn f() {{ let x = {}1; }}", "1 + ".repeat(200));
        let file = SourceFile::parse(FileId(0), "f.rs", "f.rs", long).unwrap();
        let span = SourceSpan::of(&file.syntax().items[0]);
        let snippet = file.snippet(span).unwrap();
        assert!(!snippet.contains('\n'));
        assert!(snippet.chars().count() <= 161, "{}", snippet.chars().count());
    }

    #[test]
    fn parse_failure_reports_position() {
        let failure = SourceFile::parse(FileId(0), "bad.rs", "bad.rs", "fn f( { }").unwrap_err();
        assert_eq!(failure.file, "bad.rs");
        assert!(failure.span.is_known());
        assert!(!failure.message.is_empty());
    }

    #[test]
    fn multiline_spans_are_reported() {
        let file = sample();
        let span = SourceSpan::new(2, 5, 2, 40);
        assert!(!span.is_multiline());
        let block = match &file.syntax().items[0] {
            syn::Item::Fn(f) => &f.block,
            _ => unreachable!(),
        };
        let block_span = SourceSpan::of(block);
        assert!(block_span.is_multiline());
        assert!(file.byte_range(block_span).is_some());
    }

    #[test]
    fn source_map_location_keeps_span_for_unknown_file() {
        let map = SourceMap::default();
        let location = map.location(FileId(7), Some(SourceSpan::point(3, 4)));
        assert_eq!(location.span, Some(SourceSpan::point(3, 4)));
        assert!(location.file.contains("unknown"));
    }
}
