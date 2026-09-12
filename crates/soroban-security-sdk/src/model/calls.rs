//! Cross-contract calls, upgrades and ledger-derived values.

use crate::model::Site;
use crate::span::SourceSpan;

/// A call made through a generated Soroban client, e.g.
/// `token::Client::new(&env, &token_id).transfer(&from, &to, &amount)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractCall {
    /// Where the call is.
    pub site: Site,
    /// Interface the client was generated from, e.g. `token`.
    pub interface: Option<String>,
    /// Type the client was created from, e.g. `token::Client`.
    pub client_type: Option<String>,
    /// Method that was called, e.g. `transfer`.
    pub method: String,
    /// Canonical text of each argument.
    pub args: Vec<String>,
    /// Spans of each argument.
    pub arg_spans: Vec<SourceSpan>,
    /// Whether the call returns a `Result` (the `try_*` variants).
    pub returns_result: bool,
    /// Span of the whole call.
    pub span: SourceSpan,
}

impl ContractCall {
    /// Canonical text of the nth argument.
    pub fn arg(&self, index: usize) -> Option<&str> {
        self.args.get(index).map(String::as_str)
    }

    /// Span of the nth argument.
    pub fn arg_span(&self, index: usize) -> Option<SourceSpan> {
        self.arg_spans.get(index).copied()
    }

    /// Qualified name of the call, e.g. `token::transfer`.
    pub fn qualified_name(&self) -> String {
        match &self.interface {
            Some(interface) => format!("{interface}::{}", self.method),
            None => self.method.clone(),
        }
    }

    /// Whether the call looks like a token value transfer.
    pub fn is_value_transfer(&self) -> bool {
        matches!(
            self.method.as_str(),
            "transfer" | "transfer_from" | "transfer_from_and_approve" | "approve" | "burn"
        )
    }

    /// Whether the client was created for a contract id supplied by the caller.
    pub fn target_text(&self) -> Option<&str> {
        self.args.first().map(String::as_str)
    }
}

/// A contract upgrade or deployment call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeSite {
    /// Where the call is.
    pub site: Site,
    /// Method that was called, e.g. `update_current_contract_wasm`.
    pub method: String,
    /// Canonical text of the wasm hash or deployment argument.
    pub argument: Option<String>,
    /// Whether that argument is a function parameter (caller-controlled).
    pub argument_is_parameter: bool,
    /// Span of the call.
    pub span: SourceSpan,
}

impl UpgradeSite {
    /// Whether the call replaces the running contract's code.
    pub fn replaces_current_contract(&self) -> bool {
        matches!(
            self.method.as_str(),
            "update_current_contract_wasm" | "extend_current_contract_wasm_ttl"
        )
    }

    /// Whether the call deploys a new contract.
    pub fn deploys(&self) -> bool {
        self.method.starts_with("deploy")
            || self.method.starts_with("create_contract")
            || self.method.starts_with("upload_contract")
            || self.method.starts_with("install")
    }
}

/// Where a ledger-derived value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandomnessSource {
    /// `env.ledger().timestamp()`
    Timestamp,
    /// `env.ledger().sequence()`
    Sequence,
    /// `env.ledger().close_time()`
    CloseTime,
    /// Anything else read from `env.ledger()`.
    Other,
}

impl RandomnessSource {
    /// Map a method name to a source.
    pub fn from_method(name: &str) -> Option<Self> {
        match name {
            "timestamp" => Some(RandomnessSource::Timestamp),
            "sequence" => Some(RandomnessSource::Sequence),
            "close_time" | "close_time_seconds" => Some(RandomnessSource::CloseTime),
            "ledger_version" | "protocol_version" | "network_id" | "max_ttl" | "min_ttl" => {
                Some(RandomnessSource::Other)
            }
            _ => None,
        }
    }

    /// Name used in messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            RandomnessSource::Timestamp => "ledger().timestamp()",
            RandomnessSource::Sequence => "ledger().sequence()",
            RandomnessSource::CloseTime => "ledger().close_time()",
            RandomnessSource::Other => "ledger()",
        }
    }

    /// Whether the value is fully predictable to a transaction submitter.
    pub const fn is_predictable(self) -> bool {
        true
    }
}

/// How a ledger value was used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandomnessUse {
    /// Used in integer arithmetic, e.g. `timestamp() % 100`.
    Arithmetic,
    /// Used in a comparison, e.g. `sequence() > deadline`.
    Comparison,
}

/// A ledger-derived value used in a way that suggests entropy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RandomnessSite {
    /// Where the value is read.
    pub site: Site,
    /// Which ledger field.
    pub source: RandomnessSource,
    /// How it is used.
    pub use_kind: RandomnessUse,
    /// Canonical text of the enclosing expression.
    pub text: String,
    /// Span of the ledger read.
    pub span: SourceSpan,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::FileId;

    fn call(method: &str, args: &[&str]) -> ContractCall {
        ContractCall {
            site: Site::new(FileId(0), "transfer", SourceSpan::point(1, 1)),
            interface: Some("token".to_string()),
            client_type: Some("token::Client".to_string()),
            method: method.to_string(),
            args: args.iter().map(|arg| arg.to_string()).collect(),
            arg_spans: vec![SourceSpan::UNKNOWN; args.len()],
            returns_result: false,
            span: SourceSpan::UNKNOWN,
        }
    }

    #[test]
    fn exposes_arguments_by_position() {
        let call = call("transfer", &["from", "to", "amount"]);
        assert_eq!(call.arg(0), Some("from"));
        assert_eq!(call.arg(2), Some("amount"));
        assert_eq!(call.arg(3), None);
        assert_eq!(call.qualified_name(), "token::transfer");
    }

    #[test]
    fn identifies_value_transfers() {
        assert!(call("transfer", &[]).is_value_transfer());
        assert!(call("transfer_from", &[]).is_value_transfer());
        assert!(!call("decimals", &[]).is_value_transfer());
    }

    #[test]
    fn identifies_upgrade_calls() {
        let upgrade = UpgradeSite {
            site: Site::new(FileId(0), "upgrade", SourceSpan::point(1, 1)),
            method: "update_current_contract_wasm".to_string(),
            argument: Some("new_wasm_hash".to_string()),
            argument_is_parameter: true,
            span: SourceSpan::UNKNOWN,
        };
        assert!(upgrade.replaces_current_contract());
        assert!(!upgrade.deploys());
    }

    #[test]
    fn maps_ledger_methods_to_sources() {
        assert_eq!(
            RandomnessSource::from_method("timestamp"),
            Some(RandomnessSource::Timestamp)
        );
        assert_eq!(
            RandomnessSource::from_method("sequence"),
            Some(RandomnessSource::Sequence)
        );
        assert_eq!(RandomnessSource::from_method("sequence_number"), None);
        assert!(RandomnessSource::Timestamp.is_predictable());
    }
}
