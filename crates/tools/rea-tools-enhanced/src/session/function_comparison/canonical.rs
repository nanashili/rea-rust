//! Canonical JSON string and digest helpers for function comparison.
//!
//! Compatibility owners: `comparisonSemantics.canonicalJson` (string owner,
//! the `canonicalize` library) and `canonicalDigest.digestCanonicalValue`
//! (hashing owner). Both follow RFC 8785 key ordering, matched by
//! [`rea_core::canonical_json`].

use rea_core::analysis_error::AnalysisError;
use rea_core::canonical_json;
use serde_json::Value;

/// `canonicalJson(value, context)`: canonical JSON text or a `TypeError`-style
/// input failure under `operation`.
pub fn canonical_json(value: &Value, operation: &str) -> Result<String, AnalysisError> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| crate::derived::invalid_value(operation, error.to_string()))?;
    let mut bytes = Vec::new();
    canonical_json::write(&raw, &mut bytes).map_err(|_| {
        crate::derived::invalid_value(
            operation,
            format!("{operation} could not canonicalize data"),
        )
    })?;
    Ok(String::from_utf8(bytes).expect("canonical JSON is valid UTF-8"))
}

/// `digestCanonicalValue(value, context)`: SHA-256 hex over canonical JSON.
pub fn digest_canonical_value(value: &Value, operation: &str) -> Result<String, AnalysisError> {
    canonical_json::digest(value).map_err(|_| {
        crate::derived::invalid_value(
            operation,
            format!("{operation} could not canonicalize data"),
        )
    })
}
