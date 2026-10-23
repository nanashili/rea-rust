//! Native symbol inventory projection.
//!
//! Providers use more than one transport shape for a name inventory: a
//! direct array, an address-to-name map, or an Evidence result wrapped in
//! `result`/`normalized_result`.  This boundary owns that representation
//! conversion.  It does not sort, deduplicate, truncate, or reinterpret
//! provider records.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "list_names";
pub const MAX_RECORDS: usize = 200_000;

/// Validate an input inventory before it is passed to the application layer.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let _ = parse_inventory(input)?;
    Ok(())
}

/// Normalize a provider inventory into the Ghidra-compatible symbol shape.
pub fn project(input: &Value) -> Result<Value, Failure> {
    Ok(Value::Array(parse_inventory(input)?))
}

/// Alias used by runtimes whose adapter boundary names this phase normalize.
pub fn normalize(input: &Value) -> Result<Value, Failure> {
    project(input)
}

/// Operation-oriented alias used by adapters that call projections uniformly.
pub fn list_names(input: &Value) -> Result<Value, Failure> {
    project(input)
}

/// Validate and retain a result before the runtime wraps it in Evidence.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    validate_result(&result)?;
    Ok(result)
}

fn parse_inventory(input: &Value) -> Result<Vec<Value>, Failure> {
    let source = unwrap_inventory(input);
    if let Some(records) = source.as_array() {
        if records.len() > MAX_RECORDS {
            return Err(invalid("name inventory exceeds the 200000 record limit"));
        }

        return records
            .iter()
            .enumerate()
            .map(|(index, record)| parse_record(record, index))
            .collect();
    }

    let object = source
        .as_object()
        .ok_or_else(|| invalid("name inventory must be an array or address-to-name map"))?;
    if let Some(wrapped) = object.get("names").or_else(|| object.get("items")) {
        return parse_inventory(wrapped);
    }

    if object.values().all(|value| value.as_str().is_some()) {
        if object.len() > MAX_RECORDS {
            return Err(invalid("name inventory exceeds the 200000 record limit"));
        }

        // JSON object iteration is deterministic in serde_json, but the map
        // form has no provider order to preserve.  Its insertion order is the
        // only order available to this boundary and is retained by iteration.
        return object
            .iter()
            .enumerate()
            .map(|(index, (address, name))| {
                parse_record(&json!({"address": address, "name": name}), index)
            })
            .collect();
    }

    Err(invalid("name inventory must contain address/name records"))
}

fn unwrap_inventory(value: &Value) -> &Value {
    value
        .get("normalized_result")
        .or_else(|| value.get("result"))
        .or_else(|| value.get("value"))
        .unwrap_or(value)
}

fn parse_record(value: &Value, index: usize) -> Result<Value, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(&format!("name inventory entry {index} must be an object")))?;

    let allowed_fields = if object.contains_key("symbol") {
        &["address", "value", "name", "symbol"][..]
    } else {
        &[
            "address", "value", "name", "primary", "dynamic", "external", "type", "kind", "source",
        ][..]
    };
    reject_unknown_fields(
        object,
        allowed_fields,
        &format!("name inventory entry {index}"),
    )?;

    let address = object
        .get("address")
        .and_then(Value::as_str)
        .filter(|address| is_canonical_address(address))
        .ok_or_else(|| {
            invalid(&format!(
                "name inventory entry {index} has an invalid address"
            ))
        })?;
    let name = object
        .get("name")
        .or_else(|| object.get("value"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            invalid(&format!(
                "name inventory entry {index} requires a string name"
            ))
        })?;

    let inline_symbol = object
        .iter()
        .filter(|(field, _)| !matches!(field.as_str(), "address" | "value" | "name"))
        .map(|(field, value)| (field.clone(), value.clone()))
        .collect::<Map<String, Value>>();
    let symbol = match object.get("symbol") {
        Some(symbol) => symbol.as_object().ok_or_else(|| {
            invalid(&format!(
                "name inventory entry {index} symbol facts must be an object"
            ))
        })?,
        None => &inline_symbol,
    };
    Ok(json!({
        "address": address,
        "value": name,
        "symbol": parse_symbol_facts(symbol, index)?,
    }))
}

fn parse_symbol_facts(object: &Map<String, Value>, index: usize) -> Result<Value, Failure> {
    reject_unknown_fields(
        object,
        &["primary", "dynamic", "external", "type", "kind", "source"],
        &format!("name inventory entry {index} symbol"),
    )?;

    let primary = boolean_fact(object, "primary", index)?;
    let dynamic = boolean_fact(object, "dynamic", index)?;
    let external = boolean_fact(object, "external", index)?;
    let symbol_type = object
        .get("type")
        .or_else(|| object.get("kind"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            invalid(&format!(
                "name inventory entry {index} requires a symbol type"
            ))
        })?;
    let source = object
        .get("source")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            invalid(&format!(
                "name inventory entry {index} requires a symbol source"
            ))
        })?;
    if !matches!(
        source,
        "default" | "analysis" | "ai" | "imported" | "user_defined"
    ) {
        return Err(invalid(&format!(
            "name inventory entry {index} has an invalid symbol source"
        )));
    }

    Ok(json!({
        "primary": primary,
        "dynamic": dynamic,
        "external": external,
        "type": symbol_type,
        "source": source,
    }))
}

fn boolean_fact(object: &Map<String, Value>, field: &str, index: usize) -> Result<bool, Failure> {
    object.get(field).and_then(Value::as_bool).ok_or_else(|| {
        invalid(&format!(
            "name inventory entry {index} requires boolean symbol.{field}"
        ))
    })
}

fn reject_unknown_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    context: &str,
) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(invalid(&format!(
            "{context} contains undeclared field {field}"
        )));
    }

    Ok(())
}

fn validate_result(result: &Value) -> Result<(), Failure> {
    let records = result
        .as_array()
        .ok_or_else(|| invalid("list_names result must be an array"))?;
    if records.len() > MAX_RECORDS {
        return Err(invalid("list_names result exceeds the 200000 record limit"));
    }
    records
        .iter()
        .enumerate()
        .try_for_each(|(index, record)| parse_record(record, index).map(|_| ()))
}

fn is_canonical_address(address: &str) -> bool {
    let Some((space, offset)) = address.split_once(':') else {
        return address.starts_with("0x") && is_lower_hex(&address[2..]);
    };
    !space.is_empty()
        && space.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'~' | b'-')
                || (byte == b'%' && valid_percent_escape(space, index))
        })
        && offset.starts_with("0x")
        && is_lower_hex(&offset[2..])
}

fn valid_percent_escape(value: &str, index: usize) -> bool {
    let bytes = value.as_bytes();
    index + 2 < bytes.len()
        && bytes[index + 1].is_ascii_hexdigit()
        && bytes[index + 2].is_ascii_hexdigit()
}

fn is_lower_hex(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn invalid(reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide a complete list_names symbol inventory and retry.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
