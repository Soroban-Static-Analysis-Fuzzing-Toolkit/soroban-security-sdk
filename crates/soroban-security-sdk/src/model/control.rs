//! Loops and panicking expressions.
//!
//! Two Soroban-specific facts drive these detectors: every ledger access consumes
//! one of the 200 read/write entries a transaction may declare, and an unbounded
//! loop that touches storage can exhaust that budget (or the instruction budget)
//! at runtime with no way to recover. Separately, a panic aborts the whole
//! transaction, so an `unwrap` on caller-controlled data is a denial-of-service
//! primitive rather than a bug report.

use crate::model::Site;
use crate::span::SourceSpan;
use crate::syntax::CollectionTy;

/// Which loop construct was used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopKind {
    /// `for`
    For,
    /// `while`
    While,
    /// `loop`
    Loop,
}

impl LoopKind {
    /// Keyword used in messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            LoopKind::For => "for",
            LoopKind::While => "while",
            LoopKind::Loop => "loop",
        }
    }
}

/// Where a loop's iteration count comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopBound {
    /// A literal range, e.g. `for i in 0..8`.
    Literal(u64),
    /// A range whose end is a function parameter or local variable.
    Parameter(String),
    /// The loop walks a collection.
    Collection(CollectionTy),
    /// The loop walks a collection whose origin is unknown, which includes anything
    /// read from storage.
    Storage,
    /// Nothing about the bound is statically visible.
    Unknown,
}

impl LoopBound {
    /// Whether the trip count is statically known.
    pub const fn is_statically_bounded(&self) -> bool {
        matches!(self, LoopBound::Literal(_))
    }

    /// Whether the loop walks a collection read from (or written to) storage.
    pub fn walks_storage_collection(&self) -> bool {
        matches!(self, LoopBound::Storage)
    }

    /// Trip count to use in cost estimates.
    ///
    /// Literal bounds are exact; everything else falls back to the model's assumed
    /// iteration count, which the report surfaces at reduced confidence.
    pub fn estimated_iterations(&self, assumed: u64) -> u64 {
        match self {
            LoopBound::Literal(count) => *count,
            _ => assumed,
        }
    }

    /// Human-readable description.
    pub fn describe(&self) -> String {
        match self {
            LoopBound::Literal(count) => format!("{count} iterations"),
            LoopBound::Parameter(name) => format!("bound by `{name}`"),
            LoopBound::Collection(kind) => format!("over a {}", kind.name()),
            LoopBound::Storage => "over collection state".to_string(),
            LoopBound::Unknown => "unknown bound".to_string(),
        }
    }
}

/// A loop found in the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopSite {
    /// Where the loop is.
    pub site: Site,
    /// Loop construct.
    pub kind: LoopKind,
    /// Where the iteration count comes from.
    pub bound: LoopBound,
    /// Canonical text of the iterated expression.
    pub iterates: Option<String>,
    /// Span of the loop body.
    pub body_span: SourceSpan,
    /// Storage operations lexically inside the loop body.
    pub storage_ops: usize,
    /// Cross-contract calls lexically inside the loop body.
    pub contract_calls: usize,
}

impl LoopSite {
    /// Whether the loop touches storage.
    pub fn touches_storage(&self) -> bool {
        self.storage_ops > 0
    }

    /// Whether the loop makes cross-contract calls.
    pub fn makes_calls(&self) -> bool {
        self.contract_calls > 0
    }

    /// Whether the loop can run an unbounded number of times.
    pub fn is_unbounded(&self) -> bool {
        !self.bound.is_statically_bounded()
    }

    /// Whether the loop is unbounded *and* does per-iteration work that costs
    /// ledger access or a cross-contract call.
    pub fn is_risky(&self) -> bool {
        self.is_unbounded() && (self.touches_storage() || self.makes_calls())
    }
}

/// The kind of panicking expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanicKind {
    /// `.unwrap()`
    Unwrap,
    /// `.expect("...")`
    Expect,
    /// `panic!(...)`
    Panic,
    /// `todo!(...)`
    Todo,
    /// `unimplemented!(...)`
    Unimplemented,
    /// `unreachable!(...)`
    Unreachable,
    /// `expr[index]`
    Index,
}

impl PanicKind {
    /// Name used in messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            PanicKind::Unwrap => "unwrap",
            PanicKind::Expect => "expect",
            PanicKind::Panic => "panic!",
            PanicKind::Todo => "todo!",
            PanicKind::Unimplemented => "unimplemented!",
            PanicKind::Unreachable => "unreachable!",
            PanicKind::Index => "indexing",
        }
    }

    /// Whether the construct is always a defect in production contract code.
    pub const fn is_always_defect(self) -> bool {
        matches!(
            self,
            PanicKind::Unwrap
                | PanicKind::Expect
                | PanicKind::Panic
                | PanicKind::Todo
                | PanicKind::Unimplemented
        )
    }
}

/// A panicking expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanicSite {
    /// Where the expression is.
    pub site: Site,
    /// What kind of panic it is.
    pub kind: PanicKind,
    /// Canonical text of the receiver (for `unwrap`) or indexed expression.
    pub on: Option<String>,
    /// Canonical text of the whole expression.
    pub text: String,
    /// Span of the expression.
    pub span: SourceSpan,
}

impl PanicSite {
    /// Description for messages, e.g. `unwrap` on `storage().persistent().get(..)`.
    pub fn describe(&self) -> String {
        match &self.on {
            Some(target) => format!("{} on `{}`", self.kind.as_str(), target),
            None => self.kind.as_str().to_string(),
        }
    }

    /// Whether the receiver looks like a storage read, i.e. caller-unreachable.
    pub fn on_storage_read(&self) -> bool {
        let Some(target) = &self.on else {
            return false;
        };
        target.contains("storage()") || target.contains("storage().")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::FileId;

    fn loop_site(bound: LoopBound, storage_ops: usize) -> LoopSite {
        LoopSite {
            site: Site::new(FileId(0), "f", SourceSpan::point(1, 1)),
            kind: LoopKind::For,
            bound,
            iterates: None,
            body_span: SourceSpan::UNKNOWN,
            storage_ops,
            contract_calls: 0,
        }
    }

    #[test]
    fn only_literal_bounds_are_statically_bounded() {
        assert!(LoopBound::Literal(3).is_statically_bounded());
        assert!(!LoopBound::Storage.is_statically_bounded());
        assert!(!LoopBound::Unknown.is_statically_bounded());
        assert!(LoopBound::Storage.walks_storage_collection());
        assert_eq!(LoopBound::Literal(7).estimated_iterations(100), 7);
        assert_eq!(LoopBound::Unknown.estimated_iterations(100), 100);
    }

    #[test]
    fn risky_loops_need_an_unbounded_bound_and_work() {
        assert!(loop_site(LoopBound::Storage, 1).is_risky());
        assert!(!loop_site(LoopBound::Literal(4), 5).is_risky());
        assert!(!loop_site(LoopBound::Storage, 0).is_risky());
    }

    #[test]
    fn bounds_describe_themselves() {
        assert_eq!(LoopBound::Literal(2).describe(), "2 iterations");
        assert_eq!(LoopBound::Parameter("n".into()).describe(), "bound by `n`");
        assert_eq!(
            LoopBound::Collection(CollectionTy::Vec).describe(),
            "over a Vec"
        );
    }

    #[test]
    fn panic_kinds_flag_defects() {
        assert!(PanicKind::Unwrap.is_always_defect());
        assert!(PanicKind::Todo.is_always_defect());
        assert!(!PanicKind::Index.is_always_defect());
        assert_eq!(PanicKind::Expect.as_str(), "expect");
    }

    #[test]
    fn storage_unwraps_are_recognised() {
        let site = PanicSite {
            site: Site::new(FileId(0), "f", SourceSpan::point(1, 1)),
            kind: PanicKind::Unwrap,
            on: Some("env.storage().persistent().get(&KEY)".into()),
            text: "env.storage().persistent().get(&KEY).unwrap()".into(),
            span: SourceSpan::UNKNOWN,
        };
        assert!(site.on_storage_read());
        assert!(site.describe().starts_with("unwrap on"));
    }
}
