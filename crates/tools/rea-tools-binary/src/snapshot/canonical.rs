//! Canonical-JSON helpers shared by the analysis-snapshot domain.
//!
//! Compatibility owners: `src/domain/canonicalJsonDigestSteps.ts`,
//! `src/domain/unicodeCodePointOrder.ts`, `src/domain/analysisSnapshot.ts`
//! (`canonicalJson`). Every digest is RFC 8785 canonical JSON hashed with
//! SHA-256, byte-for-byte compatible with the TypeScript `canonicalize` +
//! `createHash("sha256")` pipeline through `rea_core::canonical_json`.
use rea_core::canonical_json;
use serde_json::Value;

/// Canonical JSON encoding of an owned JSON value (TS `canonicalJson`).
///
/// # Errors
/// Fails when the value cannot be represented as RFC 8785 canonical JSON
/// (for example a non-finite number), mirroring the TS `TypeError`.
pub(crate) fn canonical_json_string(value: &Value) -> Result<String, String> {
    let raw = serde_json::value::to_raw_value(value).map_err(|error| error.to_string())?;
    let mut output: Vec<u8> = Vec::new();
    canonical_json::write(&raw, &mut output)
        .map_err(|_| "RFC 8785 canonicalization rejected snapshot data".to_owned())?;
    String::from_utf8(output).map_err(|error| error.to_string())
}

/// SHA-256 over the canonical JSON of an owned value (TS `contentDigest`).
///
/// # Errors
/// Fails when the value cannot be canonicalized.
pub(crate) fn content_digest(value: &Value) -> Result<String, String> {
    let raw = serde_json::value::to_raw_value(value).map_err(|error| error.to_string())?;
    canonical_json::digest_raw(&raw).map_err(|error| error.to_string())
}

/// Compare strings lexicographically by Unicode code point (TS
/// `compareUnicodeCodePoints`). Returns negative, zero, or positive like the
/// TypeScript difference of code points, so the sign matches exactly.
pub(crate) fn compare_unicode_code_points(left: &str, right: &str) -> std::cmp::Ordering {
    let mut l = left.chars();
    let mut r = right.chars();
    loop {
        match (l.next(), r.next()) {
            (Some(a), Some(b)) => {
                let diff = (a as i64) - (b as i64);
                if diff != 0 {
                    return if diff < 0 {
                        std::cmp::Ordering::Less
                    } else {
                        std::cmp::Ordering::Greater
                    };
                }
            }
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
        }
    }
}

/// Collision-free composite key for deduplication and sorting (TS
/// `compositeKey`): a JSON tuple of the string components.
pub(crate) fn composite_key(parts: &[&str]) -> String {
    Value::Array(
        parts
            .iter()
            .map(|part| Value::String((*part).to_owned()))
            .collect(),
    )
    .to_string()
}
