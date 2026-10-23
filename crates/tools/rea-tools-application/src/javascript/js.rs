//! JavaScript value semantics shared by the application graph workflows.
use serde_json::Value;
use std::collections::BTreeSet;

/// `uniqueSorted`: deduplicate and sort by Unicode code point (UTF-8 byte
/// order is code-point order).
pub fn unique_sorted(values: impl IntoIterator<Item = String>) -> Vec<String> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// `uniqueSorted` over JSON strings; non-string members are ignored.
pub fn unique_sorted_values(values: &[Value]) -> Vec<String> {
    unique_sorted(values.iter().filter_map(Value::as_str).map(str::to_owned))
}

/// JavaScript `===` over JSON values: numbers compare numerically, objects
/// and arrays never compare equal (distinct parsed references).
pub fn strict_equals(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => left.as_f64() == right.as_f64(),
        (Value::String(left), Value::String(right)) => left == right,
        (Value::Bool(left), Value::Bool(right)) => left == right,
        (Value::Null, Value::Null) => true,
        _ => false,
    }
}

/// RFC 8785 canonical JSON text (`canonicalize`).
pub fn canonical(value: &Value) -> Result<String, String> {
    let raw = serde_json::value::to_raw_value(value).map_err(|error| error.to_string())?;
    let mut output = Vec::new();
    rea_core::canonical_json::write(&raw, &mut output).map_err(|error| error.to_string())?;
    String::from_utf8(output).map_err(|error| error.to_string())
}

/// SHA-256 hex digest of the canonical JSON text.
pub fn digest(value: &Value) -> Result<String, String> {
    rea_core::canonical_json::digest(value).map_err(|error| error.to_string())
}

/// Members of a JSON array (empty when absent).
pub fn array(value: &Value) -> &[Value] {
    value.as_array().map(Vec::as_slice).unwrap_or_default()
}

/// A string member (empty when absent).
pub fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or_default()
}

/// JavaScript `String(number)` for JSON numbers.
pub fn number_string(value: &Value) -> String {
    match value {
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                return integer.to_string();
            }
            if let Some(integer) = number.as_u64() {
                return integer.to_string();
            }
            let float = number.as_f64().unwrap_or(f64::NAN);
            if float.fract() == 0.0 && float.abs() < 1e21 {
                format!("{float:.0}")
            } else {
                float.to_string()
            }
        }
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}
