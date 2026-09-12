//! Source positions and spans.
//!
//! Lines and columns are 1-based so they can be printed directly and mapped to
//! SARIF without adjustment. Byte offsets are derived lazily by the owning
//! [`crate::source::SourceFile`].
//!
//! Line/column information comes from `proc-macro2`'s `span-locations` feature,
//! which this crate enables. That feature works for source parsed with `syn` at
//! runtime (it is a no-op inside a real proc-macro expansion).

use proc_macro2::{LineColumn, TokenStream, TokenTree};
use quote::ToTokens;
use serde::{Deserialize, Serialize};

/// A half-open range inside one source file.
///
/// The end position is exclusive. A span whose start and end are unknown is
/// represented by [`SourceSpan::UNKNOWN`] and reported as "no location".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourceSpan {
    /// 1-based first line.
    pub start_line: u32,
    /// 1-based first column.
    pub start_column: u32,
    /// 1-based last line (inclusive).
    pub end_line: u32,
    /// 1-based column just past the last character.
    pub end_column: u32,
}

impl SourceSpan {
    /// A span with no known position.
    pub const UNKNOWN: SourceSpan = SourceSpan {
        start_line: 0,
        start_column: 0,
        end_line: 0,
        end_column: 0,
    };

    /// Build a span from 1-based positions.
    pub const fn new(start_line: u32, start_column: u32, end_line: u32, end_column: u32) -> Self {
        SourceSpan {
            start_line,
            start_column,
            end_line,
            end_column,
        }
    }

    /// Build a single-position span.
    pub const fn point(line: u32, column: u32) -> Self {
        SourceSpan::new(line, column, line, column)
    }

    /// Whether this span carries usable position information.
    pub const fn is_known(&self) -> bool {
        self.start_line > 0
    }

    /// Whether the span covers more than one line.
    pub const fn is_multiline(&self) -> bool {
        self.end_line > self.start_line
    }

    /// Whether `line` falls inside the span (1-based).
    pub const fn contains_line(&self, line: u32) -> bool {
        self.is_known() && line >= self.start_line && line <= self.end_line
    }

    /// Whether `other` is entirely inside this span.
    pub const fn contains_span(&self, other: SourceSpan) -> bool {
        if !self.is_known() || !other.is_known() {
            return false;
        }
        let starts_after = other.start_line > self.start_line
            || (other.start_line == self.start_line && other.start_column >= self.start_column);
        let ends_before = other.end_line < self.end_line
            || (other.end_line == self.end_line && other.end_column <= self.end_column);
        starts_after && ends_before
    }

    /// The span with the end clamped to the start, for point-like reporting.
    pub const fn collapsed(self) -> Self {
        SourceSpan::point(self.start_line, self.start_column)
    }

    /// Convert from a `proc-macro2` span.
    ///
    /// `proc-macro2` columns are 0-based; this converts to 1-based.
    pub fn from_proc_macro2(span: proc_macro2::Span) -> Self {
        let start = span.start();
        let end = span.end();
        SourceSpan::from_line_columns(start, end)
    }

    /// Convert a `proc-macro2` start/end pair, normalising the bases.
    pub fn from_line_columns(start: LineColumn, end: LineColumn) -> Self {
        // Without the `span-locations` feature every position is zeroed; treat
        // that as "unknown" instead of reporting line 0.
        if start.line == 0 {
            return SourceSpan::UNKNOWN;
        }
        SourceSpan {
            start_line: start.line as u32,
            start_column: start.column as u32 + 1,
            end_line: end.line.max(start.line) as u32,
            end_column: end.column as u32 + 1,
        }
    }

    /// Compute the smallest span covering every token of `node`.
    ///
    /// `syn::spanned::Spanned::span` joins the tokens of a node, but joining is
    /// unavailable outside a proc-macro context, so a multi-token node would
    /// report only its first token. Walking the token stream gives accurate
    /// multi-line ranges instead.
    pub fn of<T: ToTokens + ?Sized>(node: &T) -> Self {
        let stream = node.to_token_stream();
        match span_of_stream(&stream) {
            Some(span) => span,
            None => SourceSpan::UNKNOWN,
        }
    }

    /// Merge two spans into the smallest span covering both.
    pub fn merge(self, other: SourceSpan) -> SourceSpan {
        if !self.is_known() {
            return other;
        }
        if !other.is_known() {
            return self;
        }
        let (start_line, start_column) =
            if (other.start_line, other.start_column) < (self.start_line, self.start_column) {
                (other.start_line, other.start_column)
            } else {
                (self.start_line, self.start_column)
            };
        let (end_line, end_column) =
            if (other.end_line, other.end_column) > (self.end_line, self.end_column) {
                (other.end_line, other.end_column)
            } else {
                (self.end_line, self.end_column)
            };
        SourceSpan::new(start_line, start_column, end_line, end_column)
    }
}

impl Default for SourceSpan {
    fn default() -> Self {
        SourceSpan::UNKNOWN
    }
}

impl std::fmt::Display for SourceSpan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.is_known() {
            return f.write_str("<unknown>");
        }
        if self.is_multiline() {
            write!(
                f,
                "{}:{}-{}:{}",
                self.start_line, self.start_column, self.end_line, self.end_column
            )
        } else {
            write!(f, "{}:{}", self.start_line, self.start_column)
        }
    }
}

/// Compute the smallest span covering every token in `stream`.
fn span_of_stream(stream: &TokenStream) -> Option<SourceSpan> {
    let mut span: Option<SourceSpan> = None;
    for token in stream.clone() {
        let candidate = match token {
            TokenTree::Group(group) => {
                let inner = span_of_stream(&group.stream());
                match inner {
                    Some(inner) => inner.merge(SourceSpan::from_proc_macro2(group.span())),
                    None => SourceSpan::from_proc_macro2(group.span()),
                }
            }
            other => SourceSpan::from_proc_macro2(other.span()),
        };
        span = Some(match span {
            Some(existing) => existing.merge(candidate),
            None => candidate,
        });
    }
    span
}

/// Extension trait adding [`SourceSpan`] construction to any syntax node.
pub trait Spanned {
    /// The smallest span covering this node's tokens.
    fn source_span(&self) -> SourceSpan;
}

impl<T: ToTokens + ?Sized> Spanned for T {
    fn source_span(&self) -> SourceSpan {
        SourceSpan::of(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_spans_are_not_known() {
        assert!(!SourceSpan::UNKNOWN.is_known());
        assert!(!SourceSpan::UNKNOWN.contains_line(1));
        assert_eq!(SourceSpan::UNKNOWN.to_string(), "<unknown>");
    }

    #[test]
    fn merge_picks_the_outer_bounds() {
        let a = SourceSpan::new(3, 1, 3, 10);
        let b = SourceSpan::new(5, 2, 7, 4);
        assert_eq!(a.merge(b), SourceSpan::new(3, 1, 7, 4));
        assert_eq!(a.merge(SourceSpan::UNKNOWN), a);
        assert_eq!(SourceSpan::UNKNOWN.merge(b), b);
    }

    #[test]
    fn token_walk_gives_multiline_spans() {
        let file = syn::parse_file("fn f() {\n    let x = 1;\n    x + 1\n}\n").unwrap();
        let func = match &file.items[0] {
            syn::Item::Fn(f) => f,
            _ => unreachable!(),
        };
        let span = SourceSpan::of(&func.block);
        assert!(
            span.is_known(),
            "span should be known with span-locations on"
        );
        assert_eq!(span.start_line, 1);
        assert!(span.is_multiline(), "block spans several lines: {span}");
    }

    #[test]
    fn expression_spans_start_at_the_first_token() {
        let source = "fn f() { let total = balance + amount; }\n";
        let file = syn::parse_file(source).unwrap();
        let func = match &file.items[0] {
            syn::Item::Fn(f) => f,
            _ => unreachable!(),
        };
        let binary = match &func.block.stmts[0] {
            syn::Stmt::Local(local) => match local.init.as_ref().map(|init| &*init.expr) {
                Some(syn::Expr::Binary(binary)) => binary,
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };
        let span = SourceSpan::of(binary);
        // Every character is ASCII, so the 1-based column equals the byte offset plus one.
        let expected_column = source.find("balance").unwrap() + 1;
        assert_eq!(span.start_line, 1);
        assert_eq!(span.start_column as usize, expected_column);
    }

    #[test]
    fn containment_is_inclusive() {
        let outer = SourceSpan::new(10, 1, 20, 2);
        assert!(outer.contains_span(SourceSpan::new(12, 3, 14, 9)));
        assert!(outer.contains_span(SourceSpan::point(10, 1)));
        assert!(!outer.contains_span(SourceSpan::new(9, 1, 12, 3)));
        assert!(!outer.contains_span(SourceSpan::UNKNOWN));
    }

    #[test]
    fn display_formats_lines_and_ranges() {
        assert_eq!(SourceSpan::point(4, 7).to_string(), "4:7");
        assert_eq!(SourceSpan::new(4, 7, 6, 2).to_string(), "4:7-6:2");
    }
}
