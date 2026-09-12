//! Ledger storage model.
//!
//! Soroban exposes three storage tiers with the same interface:
//!
//! | tier | lifetime on TTL expiry | loaded | rent |
//! |------|------------------------|--------|------|
//! | `instance` | archived with the contract instance | on every invocation | full |
//! | `persistent` | archived per key, restorable | only when in the footprint | full |
//! | `temporary` | deleted forever | only when in the footprint | half |
//!
//! Four mistakes follow from that table and are what the storage detectors look
//! for: reading and writing the same key through different tiers, using
//! `temporary` for data that must survive, never extending a TTL, and growing a
//! single entry without bound (the 64 KiB entry cap).

use crate::model::Site;
use crate::span::SourceSpan;
use crate::syntax::{CollectionTy, IntegerTy};

/// Which storage tier an operation targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StorageTier {
    /// `env.storage().instance()`
    Instance,
    /// `env.storage().persistent()`
    Persistent,
    /// `env.storage().temporary()`
    Temporary,
    /// Tier could not be determined.
    Unknown,
}

impl StorageTier {
    /// Tier name as written in code.
    pub const fn as_str(self) -> &'static str {
        match self {
            StorageTier::Instance => "instance",
            StorageTier::Persistent => "persistent",
            StorageTier::Temporary => "temporary",
            StorageTier::Unknown => "unknown",
        }
    }

    /// Parse a tier from an API method name.
    pub fn from_method(name: &str) -> Option<Self> {
        match name {
            "instance" => Some(StorageTier::Instance),
            "persistent" => Some(StorageTier::Persistent),
            "temporary" => Some(StorageTier::Temporary),
            _ => None,
        }
    }

    /// Whether entries in this tier are deleted (not archived) when the TTL lapses.
    pub const fn is_destructive_on_expiry(self) -> bool {
        matches!(self, StorageTier::Temporary)
    }

    /// Whether the tier is shared by every call to the contract.
    pub const fn is_instance(self) -> bool {
        matches!(self, StorageTier::Instance)
    }

    /// Order used to report the "canonical" tier of a key.
    pub const fn rank(self) -> u8 {
        match self {
            StorageTier::Instance => 0,
            StorageTier::Persistent => 1,
            StorageTier::Temporary => 2,
            StorageTier::Unknown => 3,
        }
    }
}

impl std::fmt::Display for StorageTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which storage method was called.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StorageAccess {
    /// `get` – footprint read.
    Get,
    /// `has` – footprint read.
    Has,
    /// `get_ttl` – footprint read.
    GetTtl,
    /// `set` – footprint write.
    Set,
    /// `remove` – footprint write.
    Remove,
    /// `extend_ttl` / `bump` – footprint read and write.
    ExtendTtl,
}

impl StorageAccess {
    /// Parse an access from an API method name.
    pub fn from_method(name: &str) -> Option<Self> {
        match name {
            "get" => Some(StorageAccess::Get),
            "has" => Some(StorageAccess::Has),
            "get_ttl" => Some(StorageAccess::GetTtl),
            "set" => Some(StorageAccess::Set),
            "remove" => Some(StorageAccess::Remove),
            "extend_ttl" | "bump" => Some(StorageAccess::ExtendTtl),
            _ => None,
        }
    }

    /// Method name.
    pub const fn as_str(self) -> &'static str {
        match self {
            StorageAccess::Get => "get",
            StorageAccess::Has => "has",
            StorageAccess::GetTtl => "get_ttl",
            StorageAccess::Set => "set",
            StorageAccess::Remove => "remove",
            StorageAccess::ExtendTtl => "extend_ttl",
        }
    }

    /// Counts against the read-entry budget.
    pub const fn is_read(self) -> bool {
        matches!(
            self,
            StorageAccess::Get
                | StorageAccess::Has
                | StorageAccess::GetTtl
                | StorageAccess::ExtendTtl
        )
    }

    /// Counts against the write-entry budget.
    pub const fn is_write(self) -> bool {
        matches!(
            self,
            StorageAccess::Set | StorageAccess::Remove | StorageAccess::ExtendTtl
        )
    }

    /// Whether the call extends an entry's time to live.
    pub const fn is_ttl_extension(self) -> bool {
        matches!(self, StorageAccess::ExtendTtl)
    }

    /// Whether the call creates or replaces a value.
    pub const fn is_mutation(self) -> bool {
        matches!(self, StorageAccess::Set | StorageAccess::Remove)
    }
}

impl std::fmt::Display for StorageAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single storage operation found in the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageOp {
    /// Where the operation is.
    pub site: Site,
    /// Tier the operation targets.
    pub tier: StorageTier,
    /// Method that was called.
    pub access: StorageAccess,
    /// Canonical text of the ledger key, when there is one.
    pub key: Option<String>,
    /// Span of the key expression.
    pub key_span: Option<SourceSpan>,
    /// Canonical text of the stored value, for writes.
    pub value: Option<String>,
    /// Declared value type from a turbofish, e.g. `i128` in `get::<_, i128>`.
    pub value_type: Option<String>,
    /// Integer type of the value, when known.
    pub integer_type: Option<IntegerTy>,
    /// Collection type of the value, when known.
    pub collection_type: Option<CollectionTy>,
    /// Span of the tier selector, e.g. `.persistent()`.
    pub tier_span: SourceSpan,
}

impl StorageOp {
    /// Whether this operation is a mutation (a write, not a TTL extension).
    pub fn is_mutation(&self) -> bool {
        self.access.is_mutation()
    }

    /// The enum a key belongs to, e.g. `DataKey` for `DataKey::Balance(addr)`.
    pub fn key_enum(&self) -> Option<&str> {
        let key = self.key.as_deref()?;
        let (prefix, _) = key.split_once("::")?;
        Some(prefix)
    }

    /// The enum variant name of the key, e.g. `Balance` for `DataKey::Balance(addr)`.
    pub fn key_variant(&self) -> Option<&str> {
        let key = self.key.as_deref()?;
        let (_, variant) = key.split_once("::")?;
        let variant = variant.split('(').next().unwrap_or(variant);
        (!variant.is_empty()).then_some(variant)
    }

    /// Human-readable summary, e.g. `persistent.get(DataKey::Admin)`.
    pub fn describe(&self) -> String {
        match &self.key {
            Some(key) => format!("{}.{}({})", self.tier, self.access, key),
            None => format!("{}.{}", self.tier, self.access),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::FileId;

    fn op(key: &str) -> StorageOp {
        StorageOp {
            site: Site::new(FileId(0), "f", SourceSpan::point(1, 1)),
            tier: StorageTier::Persistent,
            access: StorageAccess::Set,
            key: Some(key.to_string()),
            key_span: None,
            value: None,
            value_type: None,
            integer_type: None,
            collection_type: None,
            tier_span: SourceSpan::UNKNOWN,
        }
    }

    #[test]
    fn parses_access_from_method_names() {
        assert_eq!(StorageAccess::from_method("set"), Some(StorageAccess::Set));
        assert_eq!(
            StorageAccess::from_method("bump"),
            Some(StorageAccess::ExtendTtl)
        );
        assert_eq!(StorageAccess::from_method("iter"), None);
    }

    #[test]
    fn access_kinds_map_to_budgets() {
        assert!(StorageAccess::Get.is_read() && !StorageAccess::Get.is_write());
        assert!(StorageAccess::Set.is_write() && !StorageAccess::Set.is_read());
        assert!(StorageAccess::ExtendTtl.is_read() && StorageAccess::ExtendTtl.is_write());
        assert!(StorageAccess::Remove.is_mutation());
    }

    #[test]
    fn tiers_report_expiry_behaviour() {
        assert!(StorageTier::Temporary.is_destructive_on_expiry());
        assert!(!StorageTier::Persistent.is_destructive_on_expiry());
        assert!(StorageTier::Instance.is_instance());
        assert_eq!(
            StorageTier::from_method("persistent"),
            Some(StorageTier::Persistent)
        );
    }

    #[test]
    fn extracts_enum_and_variant_from_keys() {
        let operation = op("DataKey::Balance(addr)");
        assert_eq!(operation.key_enum(), Some("DataKey"));
        assert_eq!(operation.key_variant(), Some("Balance"));
        assert_eq!(
            operation.describe(),
            "persistent.set(DataKey::Balance(addr))"
        );
        let simple = op("DataKey::Total");
        assert_eq!(simple.key_variant(), Some("Total"));
        assert_eq!(simple.key_enum(), Some("DataKey"));
    }

    #[test]
    fn keys_without_enum_have_no_variant() {
        let operation = op("KEY");
        assert_eq!(operation.key_enum(), None);
        assert_eq!(operation.key_variant(), None);
        assert_eq!(operation.describe(), "persistent.set(KEY)");
    }
}
