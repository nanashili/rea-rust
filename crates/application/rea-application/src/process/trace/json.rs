//! Canonical JSON helpers shared by process-capture validation and comparison.
//!
//! Compatibility owners: `canonicalize` equality (`sameJsonValue` in
//! `processComparison.ts`, `canonicalTraceJson` in
//! `processTraceSpecification.ts`) and `digestProcessCommitment`
//! (`processScenario.ts`).
use rea_core::canonical_json;
use serde_json::Value;

/// Canonical JSON text, or `None` when the value cannot be canonicalized
/// (the original `canonicalize` returning `undefined`).
pub fn canonical(value: &Value) -> Option<String> {
    let raw = serde_json::value::to_raw_value(value).ok()?;
    let mut output = Vec::new();
    canonical_json::write(&raw, &mut output).ok()?;
    String::from_utf8(output).ok()
}

/// Field of an object value, if present.
pub fn field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.as_object().and_then(|object| object.get(key))
}

/// Array field, or an empty slice when absent.
pub fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    field(value, key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// String field.
pub fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    field(value, key).and_then(Value::as_str)
}

/// `Number.isSafeInteger` for a JSON number.
pub fn safe_integer(value: &Value) -> Option<i64> {
    const MAX_SAFE: i64 = 9_007_199_254_740_991;
    if let Some(integer) = value.as_i64() {
        return (-MAX_SAFE..=MAX_SAFE).contains(&integer).then_some(integer);
    }
    if value.as_u64().is_some() {
        return None;
    }
    let number = value.as_f64()?;
    (number.is_finite() && number.fract() == 0.0 && number.abs() <= MAX_SAFE as f64)
        .then_some(number as i64)
}

/// Boolean field.
pub fn boolean(value: &Value, key: &str) -> Option<bool> {
    field(value, key).and_then(Value::as_bool)
}
