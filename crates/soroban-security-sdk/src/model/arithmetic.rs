//! Arithmetic model.
//!
//! Rust's release profile disables overflow checks, and the official Soroban
//! contract template turns them back on with `overflow-checks = true` in
//! `Cargo.toml`. A contract that is built without that setting, or that wraps
//! arithmetic in `wrapping_*`, silently produces wrong balances. The model records
//! every integer operation and every lossy cast together with the surrounding
//! context needed to judge it.

use crate::model::Site;
use crate::span::SourceSpan;
use crate::syntax::{IntegerTy, ParamKind};

/// An integer operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegerOp {
    /// `+`
    Add,
    /// `-`
    Sub,
    /// `*`
    Mul,
    /// `/`
    Div,
    /// `%`
    Rem,
    /// unary `-`
    Neg,
    /// `<<`
    Shl,
    /// `>>`
    Shr,
    /// `&`
    BitAnd,
    /// `|`
    BitOr,
    /// `^`
    BitXor,
    /// `wrapping_add` and friends, which opt out of the panic on overflow.
    WrappingAdd,
    /// `wrapping_sub`
    WrappingSub,
    /// `wrapping_mul`
    WrappingMul,
    /// `wrapping_div`
    WrappingDiv,
}

impl IntegerOp {
    /// Symbol or method name used in messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            IntegerOp::Add => "+",
            IntegerOp::Sub => "-",
            IntegerOp::Mul => "*",
            IntegerOp::Div => "/",
            IntegerOp::Rem => "%",
            IntegerOp::Neg => "- (negation)",
            IntegerOp::Shl => "<<",
            IntegerOp::Shr => ">>",
            IntegerOp::BitAnd => "&",
            IntegerOp::BitOr => "|",
            IntegerOp::BitXor => "^",
            IntegerOp::WrappingAdd => "wrapping_add",
            IntegerOp::WrappingSub => "wrapping_sub",
            IntegerOp::WrappingMul => "wrapping_mul",
            IntegerOp::WrappingDiv => "wrapping_div",
        }
    }

    /// Whether the operation can silently wrap an integer.
    pub const fn can_overflow(self) -> bool {
        matches!(
            self,
            IntegerOp::Add | IntegerOp::Sub | IntegerOp::Mul | IntegerOp::Neg
        )
    }

    /// Whether the operation is an explicit opt-out from overflow checking.
    pub const fn is_wrapping(self) -> bool {
        matches!(
            self,
            IntegerOp::WrappingAdd
                | IntegerOp::WrappingSub
                | IntegerOp::WrappingMul
                | IntegerOp::WrappingDiv
        )
    }

    /// Whether the operation can panic or abort on a zero divisor.
    pub const fn is_division(self) -> bool {
        matches!(
            self,
            IntegerOp::Div | IntegerOp::Rem | IntegerOp::WrappingDiv
        )
    }

    /// Map a `wrapping_*` method name to an op.
    pub fn from_wrapping_method(name: &str) -> Option<Self> {
        match name {
            "wrapping_add" => Some(IntegerOp::WrappingAdd),
            "wrapping_sub" => Some(IntegerOp::WrappingSub),
            "wrapping_mul" => Some(IntegerOp::WrappingMul),
            "wrapping_div" => Some(IntegerOp::WrappingDiv),
            _ => None,
        }
    }
}

/// One integer operation found in the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArithmeticSite {
    /// Where the operation is.
    pub site: Site,
    /// Which operation.
    pub op: IntegerOp,
    /// Type of the left operand, when it could be inferred.
    pub left_type: ParamKind,
    /// Type of the right operand, when it could be inferred.
    pub right_type: ParamKind,
    /// Whether both operands failed to resolve to an integer type.
    pub untyped: bool,
    /// Whether the operation sits inside a condition (`if`, `while`, `assert!`), so
    /// a bounds check is likely nearby.
    pub guarded: bool,
    /// Canonical text of the operation.
    pub text: String,
    /// Span of the operation.
    pub span: SourceSpan,
}

impl ArithmeticSite {
    /// The widest integer type involved, when one could be inferred.
    pub fn integer_type(&self) -> Option<IntegerTy> {
        [self.left_type, self.right_type]
            .into_iter()
            .filter_map(|kind| match kind {
                ParamKind::Integer(ty) => Some(ty),
                _ => None,
            })
            .max_by_key(|ty| ty.bits())
    }

    /// Whether either operand resolved to an integer type.
    pub fn is_typed(&self) -> bool {
        !self.untyped
    }
}

/// One `as` cast between numeric types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CastSite {
    /// Where the cast is.
    pub site: Site,
    /// Source integer type, when known.
    pub from: Option<IntegerTy>,
    /// Target integer type, when known.
    pub to: Option<IntegerTy>,
    /// Whether the cast silently changes the value.
    pub lossy: bool,
    /// Canonical text of the cast.
    pub text: String,
    /// Span of the cast.
    pub span: SourceSpan,
}

impl CastSite {
    /// Description used in messages, e.g. `i128 as u32`.
    pub fn describe(&self) -> String {
        let from = self.from.map(IntegerTy::name).unwrap_or("?");
        let to = self.to.map(IntegerTy::name).unwrap_or("?");
        format!("{from} as {to}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::FileId;

    #[test]
    fn ops_report_behaviour() {
        assert!(IntegerOp::Add.can_overflow());
        assert!(IntegerOp::Neg.can_overflow());
        assert!(!IntegerOp::Div.can_overflow());
        assert!(IntegerOp::Div.is_division());
        assert!(IntegerOp::WrappingAdd.is_wrapping());
        assert!(!IntegerOp::Add.is_wrapping());
        assert_eq!(IntegerOp::as_str(IntegerOp::Mul), "*");
    }

    #[test]
    fn wrapping_methods_map_to_ops() {
        assert_eq!(
            IntegerOp::from_wrapping_method("wrapping_add"),
            Some(IntegerOp::WrappingAdd)
        );
        assert_eq!(IntegerOp::from_wrapping_method("checked_add"), None);
    }

    #[test]
    fn site_reports_its_integer_type() {
        let site = ArithmeticSite {
            site: Site::new(FileId(0), "transfer", SourceSpan::point(1, 1)),
            op: IntegerOp::Add,
            left_type: ParamKind::Integer(IntegerTy::I128),
            right_type: ParamKind::Integer(IntegerTy::U32),
            untyped: false,
            guarded: false,
            text: "a+b".to_string(),
            span: SourceSpan::UNKNOWN,
        };
        assert_eq!(site.integer_type(), Some(IntegerTy::I128));
        assert!(site.is_typed());
    }

    #[test]
    fn cast_descriptions_are_readable() {
        let cast = CastSite {
            site: Site::new(FileId(0), "f", SourceSpan::point(1, 1)),
            from: Some(IntegerTy::I128),
            to: Some(IntegerTy::U32),
            lossy: true,
            text: "amount as u32".to_string(),
            span: SourceSpan::UNKNOWN,
        };
        assert_eq!(cast.describe(), "i128 as u32");
    }
}
