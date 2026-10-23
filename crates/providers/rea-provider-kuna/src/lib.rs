//! Kuna deep-analysis provider.
use rea_analysis::AnalysisProvider;
use std::collections::HashMap;
use std::sync::Arc;

/// Deep-analysis providers contributed by this crate for one environment snapshot.
pub fn providers(_environment: &HashMap<String, String>) -> Vec<Arc<dyn AnalysisProvider>> {
    Vec::new()
}
