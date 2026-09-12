//! Authorization model.
//!
//! Soroban has no reentrancy and no `msg.sender`: a contract must ask the host to
//! authorize an `Address` explicitly with `require_auth`, and a custom account can
//! additionally implement `__check_auth`. The detectors in this crate build on
//! three facts about that design:
//!
//! - `require_auth` authorizes the *whole call* for that address, so it can be
//!   hoisted into a helper, but it also means a check on the wrong address
//!   authorizes nothing;
//! - a check performed after a state change still leaves the intermediate state
//!   observable to the caller;
//! - `__check_auth` receives caller-supplied signature payloads and context, so an
//!   implementation that never verifies a signature authorizes everything.

use crate::model::Site;
use crate::span::SourceSpan;

/// The kind of authorization-related call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    /// `address.require_auth()`
    RequireAuth,
    /// `address.require_auth_for_args(args)`
    RequireAuthForArgs,
    /// `env.require_auth(&address)` (older SDK surface)
    EnvRequireAuth,
    /// A signature or crypto verification, e.g. `ed25519_verify`.
    VerifySignature,
}

impl AuthKind {
    /// Whether this check actually establishes authorization.
    pub const fn establishes_authorization(self) -> bool {
        matches!(
            self,
            AuthKind::RequireAuth | AuthKind::RequireAuthForArgs | AuthKind::EnvRequireAuth
        )
    }

    /// Whether the check authorizes specific arguments rather than the whole call.
    pub const fn is_argument_bound(self) -> bool {
        matches!(self, AuthKind::RequireAuthForArgs)
    }

    /// Name used in messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            AuthKind::RequireAuth => "require_auth",
            AuthKind::RequireAuthForArgs => "require_auth_for_args",
            AuthKind::EnvRequireAuth => "Env::require_auth",
            AuthKind::VerifySignature => "verify signature",
        }
    }
}

/// One authorization check or verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthCheck {
    /// Where the check is.
    pub site: Site,
    /// What kind of check it is.
    pub kind: AuthKind,
    /// Canonical text of the authorized expression, e.g. `from`.
    pub target: Option<String>,
    /// Span of the authorized expression.
    pub target_span: Option<SourceSpan>,
    /// For `require_auth_for_args`, the arguments the signature covers.
    pub args: Option<String>,
    /// Span of the whole call.
    pub call_span: SourceSpan,
}

impl AuthCheck {
    /// Whether this check authorizes `expression`.
    ///
    /// Matching is textual: `from` binds to `from`, `self.owner` to `self.owner`.
    /// A field access also binds to its base identifier, so
    /// `state.owner.require_auth()` binds to `state` as well as `state.owner`.
    pub fn binds_to(&self, expression: &str) -> bool {
        let Some(target) = &self.target else {
            return false;
        };
        if target == expression {
            return true;
        }
        // `from.clone()` / `(&from)` should still bind to `from`.
        let simplified = target
            .trim_start_matches('&')
            .split(".clone()")
            .next()
            .unwrap_or(target);
        if simplified == expression {
            return true;
        }
        // `state.owner` binds to `owner` as well.
        if let Some(last) = simplified.rsplit('.').next() {
            if last == expression {
                return true;
            }
        }
        false
    }

    /// Human-readable description of the check.
    pub fn describe(&self) -> String {
        match &self.target {
            Some(target) => format!("{}({target})", self.kind.as_str()),
            None => self.kind.as_str().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::FileId;

    fn check(target: &str) -> AuthCheck {
        AuthCheck {
            site: Site::new(FileId(0), "transfer", SourceSpan::point(1, 1)),
            kind: AuthKind::RequireAuth,
            target: Some(target.to_string()),
            target_span: None,
            args: None,
            call_span: SourceSpan::UNKNOWN,
        }
    }

    #[test]
    fn binds_exact_and_simplified_targets() {
        assert!(check("from").binds_to("from"));
        assert!(check("&from").binds_to("from"));
        assert!(check("from.clone()").binds_to("from"));
        assert!(check("state.owner").binds_to("owner"));
        assert!(check("state.owner").binds_to("state.owner"));
        assert!(!check("from").binds_to("to"));
    }

    #[test]
    fn auth_kinds_establish_authorization_selectively() {
        assert!(AuthKind::RequireAuth.establishes_authorization());
        assert!(AuthKind::RequireAuthForArgs.establishes_authorization());
        assert!(AuthKind::EnvRequireAuth.establishes_authorization());
        assert!(!AuthKind::VerifySignature.establishes_authorization());
        assert!(AuthKind::RequireAuthForArgs.is_argument_bound());
    }

    #[test]
    fn describes_checks() {
        assert_eq!(check("from").describe(), "require_auth(from)");
    }
}
