//! Macros for detector authors.

/// Register a detector so that [`crate::DetectorRegistry::from_inventory`] finds it.
///
/// Put the invocation at module level in the same module as the detector. No other
/// file needs to change, which is what makes a new rule a single-file change.
///
/// ```
/// use soroban_security_sdk::prelude::*;
/// use soroban_security_sdk::declare_detector;
///
/// pub struct MyRule;
///
/// impl Detector for MyRule {
///     const META: DetectorMeta = DetectorMeta::new(
///         RuleId::new("SSDK990"),
///         "my-rule",
///         "Short summary of what is wrong.",
///     )
///     .severity(Severity::Medium)
///     .confidence(Confidence::High)
///     .category(Category::BestPractice);
///
///     fn detect<'a>(&self, ctx: &AnalysisContext<'a>, sink: &mut FindingSink<'a>) {
///         let _ = (ctx, sink);
///     }
/// }
///
/// declare_detector!(MyRule);
/// ```
///
/// The one-argument form builds the detector by value, so the type must be a unit
/// struct (or any expression that produces one, such as an enum variant). Use the
/// two-argument form to call a constructor:
///
/// ```
/// # use soroban_security_sdk::prelude::*;
/// # use soroban_security_sdk::declare_detector;
/// # pub struct Configured;
/// # impl Detector for Configured {
/// #     const META: DetectorMeta = DetectorMeta::new(RuleId::new("SSDK991"), "c", "s");
/// #     fn detect<'a>(&self, _ctx: &AnalysisContext<'a>, _sink: &mut FindingSink<'a>) {}
/// # }
/// # impl Configured { fn new() -> Self { Configured } }
/// declare_detector!(Configured, Configured::new());
/// ```
#[macro_export]
macro_rules! declare_detector {
    ($ty:ident) => {
        $crate::declare_detector!($ty, $ty);
    };
    ($ty:ident, $ctor:expr) => {
        $crate::__private::inventory::submit! {
            $crate::registry::DetectorRegistration::new(
                || -> ::std::boxed::Box<dyn $crate::detector::DynDetector> {
                    ::std::boxed::Box::new($ctor)
                },
                || <$ty as $crate::detector::Detector>::META,
            )
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::context::AnalysisContext;
    use crate::detector::Detector;
    use crate::finding::FindingSink;
    use crate::registry::DetectorRegistry;
    use crate::rule::{DetectorMeta, RuleId};

    struct Declared;

    impl Detector for Declared {
        const META: DetectorMeta = DetectorMeta::new(RuleId::new("SSDK960"), "declared", "d");
        fn detect<'a>(&self, _ctx: &AnalysisContext<'a>, _sink: &mut FindingSink<'a>) {}
    }

    declare_detector!(Declared);

    #[test]
    fn macro_registers_the_detector_in_the_inventory() {
        let registry = DetectorRegistry::from_inventory();
        assert_eq!(
            registry.meta(&RuleId::new("SSDK960")).map(|meta| meta.name),
            Some("declared")
        );
    }
}
