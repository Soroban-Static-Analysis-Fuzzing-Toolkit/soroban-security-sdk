//! Detector discovery and selection.
//!
//! Every call to [`crate::declare_detector!`] submits a [`DetectorRegistration`]
//! into the linker's `inventory`, including registrations from other crates that
//! depend on this SDK. [`DetectorRegistry::from_inventory`] picks them all up, so a
//! downstream team can ship private rules without forking the built-in catalogue.
//!
//! The registry is deterministic: detectors are sorted by rule id, duplicate ids are
//! reported rather than silently dropped.

use std::collections::BTreeMap;

use crate::config::AnalysisConfig;
use crate::context::AnalysisContext;
use crate::detector::{Detector, DynDetector};
use crate::finding::FindingSink;
use crate::rule::{DetectorMeta, RuleId};

/// A detector registered with the global inventory.
///
/// Created by [`crate::declare_detector!`]; there is rarely a reason to build one by
/// hand.
#[derive(Clone, Copy)]
pub struct DetectorRegistration {
    /// Constructs a fresh detector instance.
    pub factory: fn() -> Box<dyn DynDetector>,
    /// Returns the detector's metadata.
    pub meta: fn() -> DetectorMeta,
}

impl DetectorRegistration {
    /// Build a registration.
    pub const fn new(factory: fn() -> Box<dyn DynDetector>, meta: fn() -> DetectorMeta) -> Self {
        DetectorRegistration { factory, meta }
    }

    /// Instantiate the detector.
    pub fn build(&self) -> Box<dyn DynDetector> {
        (self.factory)()
    }

    /// Metadata of the detector.
    pub fn meta(&self) -> DetectorMeta {
        (self.meta)()
    }
}

impl std::fmt::Debug for DetectorRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetectorRegistration")
            .field("rule", &self.meta().id)
            .finish()
    }
}

inventory::collect!(DetectorRegistration);

/// The set of detectors an analysis run will use.
pub struct DetectorRegistry {
    entries: Vec<Entry>,
    duplicates: Vec<RuleId>,
}

struct Entry {
    meta: DetectorMeta,
    build: Box<dyn Fn() -> Box<dyn DynDetector>>,
}

impl DetectorRegistry {
    /// An empty registry.
    pub fn empty() -> Self {
        DetectorRegistry {
            entries: Vec::new(),
            duplicates: Vec::new(),
        }
    }

    /// Collect every detector registered through [`crate::declare_detector!`].
    ///
    /// With the `detectors` feature (on by default) this includes the built-in
    /// catalogue plus any detector registered by a dependent crate.
    pub fn from_inventory() -> Self {
        let mut registry = DetectorRegistry::empty();
        for registration in inventory::iter::<DetectorRegistration> {
            registry.register_registration(*registration);
        }
        registry.sort();
        registry
    }

    /// Register a detector type that can be constructed with [`Default`].
    pub fn register<D: Detector + Default>(&mut self) {
        self.push(Entry {
            meta: D::META.clone(),
            build: Box::new(|| -> Box<dyn DynDetector> { Box::new(D::default()) }),
        });
    }

    /// Register a detector value directly.
    pub fn register_value<D: Detector>(&mut self, detector: D) {
        let detector = std::sync::Arc::new(detector);
        let meta = D::META.clone();
        self.push(Entry {
            meta,
            build: Box::new(move || -> Box<dyn DynDetector> {
                Box::new(ArcDetector(detector.clone()))
            }),
        });
    }

    /// Register a detector through a factory, for detectors that are not `Default`.
    pub fn register_factory(&mut self, meta: DetectorMeta, factory: fn() -> Box<dyn DynDetector>) {
        self.push(Entry {
            meta,
            build: Box::new(factory),
        });
    }

    fn register_registration(&mut self, registration: DetectorRegistration) {
        self.push(Entry {
            meta: registration.meta(),
            build: Box::new(move || (registration.factory)()),
        });
    }

    fn push(&mut self, entry: Entry) {
        if let Some(existing) = self
            .entries
            .iter()
            .find(|item| item.meta.id == entry.meta.id)
        {
            if !self.duplicates.contains(&existing.meta.id) {
                self.duplicates.push(existing.meta.id.clone());
            }
            return;
        }
        self.entries.push(entry);
    }

    fn sort(&mut self) {
        self.entries.sort_by(|a, b| a.meta.id.cmp(&b.meta.id));
        self.duplicates.sort();
    }

    /// Metadata of every registered detector, in rule-id order.
    pub fn metas(&self) -> Vec<&DetectorMeta> {
        self.entries.iter().map(|entry| &entry.meta).collect()
    }

    /// Look up metadata by rule id.
    pub fn meta(&self, id: &RuleId) -> Option<&DetectorMeta> {
        self.entries
            .iter()
            .find(|entry| &entry.meta.id == id)
            .map(|entry| &entry.meta)
    }

    /// Rule ids that were registered more than once, keeping the first registration.
    pub fn duplicates(&self) -> &[RuleId] {
        &self.duplicates
    }

    /// Number of registered detectors.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Instantiate every registered detector, in rule-id order.
    pub fn detectors(&self) -> Vec<Box<dyn DynDetector>> {
        self.entries.iter().map(|entry| (entry.build)()).collect()
    }

    /// The subset of detectors that the configuration enables, with their metadata.
    pub fn selected(&self, config: &AnalysisConfig) -> Vec<(&DetectorMeta, Box<dyn DynDetector>)> {
        self.entries
            .iter()
            .filter(|entry| config.rules.is_enabled(&entry.meta))
            .map(|entry| (&entry.meta, (entry.build)()))
            .collect()
    }

    /// Rule ids the configuration enables but that no detector provides.
    pub fn unknown_enabled_rules(&self, config: &AnalysisConfig) -> Vec<RuleId> {
        config
            .rules
            .enabled
            .iter()
            .filter(|id| self.meta(id).is_none())
            .cloned()
            .collect()
    }

    /// Catalogue of every rule, keyed by category then rule id.
    pub fn catalogue(&self) -> BTreeMap<&'static str, Vec<&DetectorMeta>> {
        let mut catalogue: BTreeMap<&'static str, Vec<&DetectorMeta>> = BTreeMap::new();
        for entry in &self.entries {
            catalogue
                .entry(entry.meta.category.as_str())
                .or_default()
                .push(&entry.meta);
        }
        catalogue
    }
}

impl std::fmt::Debug for DetectorRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetectorRegistry")
            .field("detectors", &self.len())
            .field("duplicates", &self.duplicates)
            .finish()
    }
}

/// Wrapper that lets a shared detector instance be handed out as a boxed trait
/// object, so stateful detectors can be registered by value.
struct ArcDetector<D: Detector>(std::sync::Arc<D>);

impl<D: Detector> Detector for ArcDetector<D> {
    const META: DetectorMeta = D::META;

    fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
        Detector::detect(&*self.0, ctx, sink);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;
    use crate::context::AnalysisContext;
    use crate::finding::FindingSink;
    use crate::severity::{Confidence, Severity};

    #[derive(Default)]
    struct Alpha;
    #[derive(Default)]
    struct Beta;

    impl Detector for Alpha {
        const META: DetectorMeta =
            DetectorMeta::new(RuleId::new("SSDK902"), "alpha", "a").category(Category::Auth);
        fn detect<'a>(&self, _ctx: &AnalysisContext<'a>, _sink: &mut FindingSink<'a>) {}
    }

    impl Detector for Beta {
        const META: DetectorMeta =
            DetectorMeta::new(RuleId::new("SSDK901"), "beta", "b").category(Category::Storage);
        fn detect<'a>(&self, _ctx: &AnalysisContext<'a>, _sink: &mut FindingSink<'a>) {}
    }

    #[test]
    fn registers_and_orders_by_rule_id() {
        let mut registry = DetectorRegistry::empty();
        registry.register::<Alpha>();
        registry.register::<Beta>();
        registry.sort();
        let ids: Vec<&str> = registry
            .metas()
            .iter()
            .map(|meta| meta.id.as_str())
            .collect();
        assert_eq!(ids, vec!["SSDK901", "SSDK902"]);
        assert_eq!(registry.len(), 2);
        assert!(!registry.is_empty());
    }

    #[test]
    fn duplicate_ids_keep_the_first_registration() {
        let mut registry = DetectorRegistry::empty();
        registry.register::<Alpha>();
        registry.register::<Alpha>();
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.duplicates(), [RuleId::new("SSDK902")]);
    }

    #[test]
    fn selection_honours_configuration() {
        let mut registry = DetectorRegistry::empty();
        registry.register::<Alpha>();
        registry.register::<Beta>();

        let all = AnalysisConfig::default();
        assert_eq!(registry.selected(&all).len(), 2);

        let only_beta = AnalysisConfig::with_rules([RuleId::new("SSDK901")]);
        let selected = registry.selected(&only_beta);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].0.id.as_str(), "SSDK901");

        let by_category = AnalysisConfig {
            rules: crate::config::RuleConfig {
                categories: vec![Category::Auth],
                ..Default::default()
            },
            ..AnalysisConfig::default()
        };
        let selected = registry.selected(&by_category);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].0.id.as_str(), "SSDK902");
    }

    #[test]
    fn unknown_enabled_rules_are_reported() {
        let mut registry = DetectorRegistry::empty();
        registry.register::<Alpha>();
        let config = AnalysisConfig::with_rules([RuleId::new("SSDK001"), RuleId::new("SSDK902")]);
        assert_eq!(
            registry.unknown_enabled_rules(&config),
            vec![RuleId::new("SSDK001")]
        );
    }

    #[test]
    fn catalogue_groups_by_category() {
        let mut registry = DetectorRegistry::empty();
        registry.register::<Alpha>();
        registry.register::<Beta>();
        let catalogue = registry.catalogue();
        assert!(catalogue.contains_key("auth"));
        assert!(catalogue.contains_key("storage"));
        assert_eq!(catalogue["auth"][0].severity, Severity::Info);
        assert_eq!(catalogue["auth"][0].confidence, Confidence::Low);
    }

    #[test]
    fn detector_instances_are_constructible() {
        let mut registry = DetectorRegistry::empty();
        registry.register::<Alpha>();
        registry.register_factory(Beta::META.clone(), || -> Box<dyn DynDetector> {
            Box::new(Beta)
        });
        registry.register_value(Beta);
        assert_eq!(registry.detectors().len(), 2);
        assert_eq!(registry.meta(&RuleId::new("SSDK901")).unwrap().name, "beta");
        assert_eq!(registry.duplicates(), [RuleId::new("SSDK901")]);
    }
}
