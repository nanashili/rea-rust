//! Canonical JSON string and digest helpers for artifact comparison.
//!
//! Compatibility owners: `comparisonSemantics.canonicalJson` and
//! `canonicalDigest.digestCanonicalValue`.

use rea_core::analysis_error::AnalysisError;
use rea_core::canonical_json;
use serde_json::Value;

/// A `TypeError`-equivalent raised while parsing artifact comparison inputs.
///
/// Inside `runDerivedOperation` a thrown `TypeError` becomes an
/// `AnalysisInputError`; this mirrors that with the original message text.
pub fn type_error(message: impl Into<String>) -> AnalysisError {
    crate::derived::invalid_value("compare_artifacts", message)
}

/// `canonicalJson(value, context)`.
pub fn canonical_json(value: &Value, context: &str) -> Result<String, AnalysisError> {
    let raw =
        serde_json::value::to_raw_value(value).map_err(|error| type_error(error.to_string()))?;
    let mut bytes = Vec::new();
    canonical_json::write(&raw, &mut bytes)
        .map_err(|_| type_error(format!("{context} could not canonicalize data")))?;
    Ok(String::from_utf8(bytes).expect("canonical JSON is valid UTF-8"))
}

/// `digestCanonicalValue(value, context)`.
pub fn digest_canonical_value(value: &Value, context: &str) -> Result<String, AnalysisError> {
    canonical_json::digest(value)
        .map_err(|_| type_error(format!("{context} could not canonicalize data")))
}
