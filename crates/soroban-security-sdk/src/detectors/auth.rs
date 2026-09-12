//! Authorization detectors (`SSDK001`, `SSDK010`).

use crate::category::Category;
use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::finding::FindingSink;
use crate::model::AuthKind;
use crate::rule::{DetectorMeta, Reference, RuleId};
use crate::severity::{Confidence, Severity};

use super::writes_state;

/// `SSDK001`: a state-changing entrypoint with no authorization check.
///
/// Soroban has no implicit sender. A contract that mutates ledger state without
/// calling `require_auth` on some `Address` lets any caller perform the mutation.
#[derive(Debug, Default)]
pub struct MissingRequireAuth;

impl Detector for MissingRequireAuth {
    const META: DetectorMeta = DetectorMeta::new(
        RuleId::new("SSDK001"),
        "missing-require-auth",
        "A state-changing entrypoint never authorizes a caller.",
    )
    .severity(Severity::High)
    .confidence(Confidence::Medium)
    .category(Category::Auth)
    .description(
        "Soroban does not expose a caller identity the way most chains do; a contract \
         must ask the host to authorize an `Address` explicitly. An entrypoint that \
         writes to storage but never calls `require_auth` (directly or through a \
         helper) is therefore callable by anyone.",
    )
    .tags(&["auth", "require-auth", "authorization"])
    .references(&[Reference::new(
        "Stellar docs: Authorization",
        "https://developers.stellar.org/docs/learn/encyclopedia/security/authorization",
    )]);

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        let model = ctx.model();
        for entrypoint in ctx.entrypoints() {
            // The constructor runs at deploy time and `__check_auth` is the
            // authorization hook itself, so neither is expected to authorize.
            if entrypoint.is_constructor || entrypoint.is_check_auth {
                continue;
            }
            if !writes_state(model, &entrypoint.name) {
                continue;
            }
            if model.has_transitive_auth(&entrypoint.name) {
                continue;
            }
            sink.report(format!(
                "`{}` changes ledger state without authorizing any address",
                entrypoint.name
            ))
            .primary(entrypoint.file, entrypoint.span)
            .in_function(entrypoint.name.clone())
            .note(
                "No `require_auth` call is reachable from this entrypoint, so any \
                 caller can invoke it.",
            )
            .help(
                "Add `<address>.require_auth()` (or `env.require_auth(&address)`) before \
                 the first state change.",
            )
            .emit();
        }
    }
}

crate::declare_detector!(MissingRequireAuth);

/// `SSDK010`: a custom-account `__check_auth` that never verifies a signature.
///
/// `__check_auth` receives caller-supplied signature payloads. An implementation
/// that does not verify them authorizes every operation, which turns the account
/// into a public wallet.
#[derive(Debug, Default)]
pub struct CheckAuthWithoutVerification;

impl Detector for CheckAuthWithoutVerification {
    const META: DetectorMeta = DetectorMeta::new(
        RuleId::new("SSDK010"),
        "check-auth-without-verification",
        "`__check_auth` does not verify a signature or credential.",
    )
    .severity(Severity::Critical)
    .confidence(Confidence::Medium)
    .category(Category::AccessControl)
    .description(
        "A custom account implements `__check_auth` to validate the signatures the \
         host forwards with an authorization entry. If the hook returns success \
         without verifying anything, every operation on the account is authorized.",
    )
    .tags(&["auth", "custom-account", "check-auth"])
    .references(&[Reference::new(
        "Stellar docs: Custom accounts",
        "https://developers.stellar.org/docs/learn/encyclopedia/security/authorization",
    )]);

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        let model = ctx.model();
        for entrypoint in ctx.entrypoints().filter(|entry| entry.is_check_auth) {
            let verifies = model.has_transitive(&entrypoint.name, |name| {
                model
                    .auth_in(name)
                    .any(|check| check.kind == AuthKind::VerifySignature)
            });
            if verifies {
                continue;
            }
            sink.report(format!(
                "`{}` never verifies a signature or credential",
                entrypoint.name
            ))
            .primary(entrypoint.file, entrypoint.span)
            .in_function(entrypoint.name.clone())
            .note(
                "Returning without verifying the supplied signature payloads makes the \
                 account authorize every operation.",
            )
            .help(
                "Verify each signature against the signer's key (for example with \
                 `env.crypto().ed25519_verify`) before returning success.",
            )
            .emit();
        }
    }
}

crate::declare_detector!(CheckAuthWithoutVerification);
