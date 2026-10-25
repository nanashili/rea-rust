//! The part of `JavaScriptAnalysisAccumulator`
//! (`javascriptStaticAnalysisState.ts`) the bundler inspectors write. The
//! static-analysis orchestrator (port plan H6) owns the remaining finding
//! collections and extends this struct rather than wrapping it.

use std::collections::{BTreeSet, HashSet};

use super::findings::ModuleRangeIndex;
use crate::javascript::contracts::static_analysis::BundlerRegistration;

/// Mutable state for one source analysis.
pub struct StaticAccumulator {
    pub registrations: Vec<BundlerRegistration>,
    pub module_range_index: ModuleRangeIndex,
    /// Binding identities proven as loaders of recovered factories.
    pub factory_require_binding_ids: BTreeSet<String>,
    pub seen: HashSet<String>,
    pub unknown_findings: u64,
}

impl StaticAccumulator {
    /// `createJavaScriptAnalysisAccumulator(sourceLength)` (UTF-16 length).
    pub fn new(source_length: usize) -> Self {
        Self {
            registrations: Vec::new(),
            module_range_index: ModuleRangeIndex::new(source_length),
            factory_require_binding_ids: BTreeSet::new(),
            seen: HashSet::new(),
            unknown_findings: 0,
        }
    }
}
