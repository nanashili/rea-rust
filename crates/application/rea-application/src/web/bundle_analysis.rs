//! Contract boundary for static analysis of captured web JavaScript bundles.

use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "analyze_web_bundle";

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("web bundle analysis input must be an object"))?;
    for field in object.keys() {
        if !matches!(
            field.as_str(),
            "cdp_endpoint"
                | "allowed_origins"
                | "target_id"
                | "observation_ms"
                | "include_accessibility_text"
                | "include_console_text"
                | "include_json_body_shapes"
                | "include_websocket_shapes"
                | "include_storage_keys"
                | "include_storage_fingerprints"
                | "include_script_sources"
                | "fetch_source_maps"
                | "max_heap_mb"
                | "analysis_timeout_ms"
                | "total_analysis_timeout_ms"
        ) {
            return Err(invalid(&format!("unknown input field: {field}")));
        }
    }
    let endpoint = object
        .get("cdp_endpoint")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|endpoint| !endpoint.is_empty())
        .ok_or_else(|| invalid("cdp_endpoint must be a non-empty string"))?;
    validate_cdp_endpoint(endpoint)?;
    non_empty_trimmed(object.get("target_id"), "target_id")?;

    if let Some(origins) = object.get("allowed_origins") {
        let origins = origins
            .as_array()
            .ok_or_else(|| invalid("allowed_origins must be an array"))?;
        for origin in origins {
            let origin = origin
                .as_str()
                .map(str::trim)
                .filter(|origin| !origin.is_empty())
                .ok_or_else(|| invalid("allowed_origins must contain non-empty strings"))?;
            validate_origin(origin)?;
        }
    }

    for field in [
        "include_script_sources",
        "include_accessibility_text",
        "include_console_text",
        "include_json_body_shapes",
        "include_websocket_shapes",
        "include_storage_keys",
        "include_storage_fingerprints",
        "fetch_source_maps",
    ] {
        if let Some(value) = object.get(field) {
            if !value.is_boolean() {
                return Err(invalid(&format!("{field} must be a boolean")));
            }
        }
    }
    if object
        .get("include_script_sources")
        .and_then(Value::as_bool)
        == Some(false)
    {
        return Err(invalid(
            "include_script_sources must be true for web bundle analysis",
        ));
    }
    if object
        .get("include_storage_fingerprints")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && !object
            .get("include_storage_keys")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return Err(invalid(
            "include_storage_fingerprints requires include_storage_keys",
        ));
    }

    if let Some(value) = object.get("observation_ms") {
        bounded_duration(value, "observation_ms", true)?;
    }
    for field in ["analysis_timeout_ms", "total_analysis_timeout_ms"] {
        if let Some(value) = object.get(field) {
            bounded_duration(value, field, false)?;
        }
    }
    if let Some(heap) = object.get("max_heap_mb") {
        let heap = heap
            .as_u64()
            .ok_or_else(|| invalid("max_heap_mb must be an integer"))?;
        if !(128..=16_384).contains(&heap) {
            return Err(invalid("max_heap_mb must be between 128 and 16384"));
        }
    }
    Ok(())
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("web bundle analysis result must be an object"));
    }
    Ok(result)
}

fn bounded_duration(value: &Value, field: &str, allow_zero: bool) -> Result<(), Failure> {
    let duration = value
        .as_u64()
        .ok_or_else(|| invalid(&format!("{field} must be a non-negative integer")))?;
    if (!allow_zero && duration == 0) || duration > 2_147_483_647 {
        return Err(invalid(&format!(
            "{field} must be between {} and 2147483647",
            if allow_zero { 0 } else { 1 }
        )));
    }
    Ok(())
}

fn non_empty_trimmed<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a str, Failure> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty string")))
}

fn validate_cdp_endpoint(endpoint: &str) -> Result<(), Failure> {
    let (scheme, authority_and_path) = endpoint
        .split_once("://")
        .ok_or_else(|| invalid("cdp_endpoint must be a loopback CDP endpoint"))?;
    if scheme == "http" {
        let authority = authority_and_path
            .strip_suffix('/')
            .unwrap_or(authority_and_path);
        validate_loopback_authority(authority)
    } else if scheme == "ws" {
        let (authority, path) = authority_and_path
            .split_once("/devtools/browser/")
            .ok_or_else(|| invalid("CDP browser WebSocket path is invalid"))?;
        validate_loopback_authority(authority)?;
        if path.is_empty() || path.contains('/') || path.contains('?') || path.contains('#') {
            return Err(invalid("CDP browser WebSocket identifier is invalid"));
        }
        Ok(())
    } else {
        Err(invalid(
            "cdp_endpoint must use loopback HTTP or browser WebSocket transport",
        ))
    }
}

fn validate_loopback_authority(authority: &str) -> Result<(), Failure> {
    if authority.contains('@') || authority.contains('?') || authority.contains('#') {
        return Err(invalid("CDP endpoint authority is invalid"));
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| invalid("CDP endpoint must include an explicit port"))?;
        (host, port)
    } else {
        authority
            .rsplit_once(':')
            .ok_or_else(|| invalid("CDP endpoint must include an explicit port"))?
    };
    if host != "127.0.0.1" && host != "::1" {
        return Err(invalid("CDP endpoint host must be 127.0.0.1 or ::1"));
    }
    if port.is_empty() || !port.chars().all(|character| character.is_ascii_digit()) {
        return Err(invalid("CDP endpoint port must be numeric"));
    }
    Ok(())
}

fn validate_origin(origin: &str) -> Result<(), Failure> {
    let (scheme, rest) = origin
        .split_once("://")
        .ok_or_else(|| invalid("allowed_origins must contain exact HTTP(S) origins"))?;
    if scheme != "http" && scheme != "https" {
        return Err(invalid(
            "allowed_origins must contain exact HTTP(S) origins",
        ));
    }
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.contains('/')
        || rest.contains('?')
        || rest.contains('#')
        || rest.contains('*')
        || rest.contains('@')
    {
        return Err(invalid(
            "allowed_origins must contain exact HTTP(S) origins",
        ));
    }
    if rest.is_empty() {
        return Err(invalid(
            "allowed_origins must contain exact HTTP(S) origins",
        ));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a caller-selected CDP page with source capture and bounded static bundle-analysis limits.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Value {
        serde_json::json!({
            "cdp_endpoint": "http://127.0.0.1:9222",
            "allowed_origins": [],
            "target_id": "TARGET_ID",
            "observation_ms": 500,
            "include_script_sources": true,
            "analysis_timeout_ms": 30000,
            "total_analysis_timeout_ms": 300000,
            "max_heap_mb": 1024
        })
    }

    #[test]
    fn accepts_bounded_bundle_analysis_request() {
        validate_input(&input()).expect("valid bundle analysis input");
        assert!(retain_result(&input(), serde_json::json!({"scripts": []})).is_ok());
    }

    #[test]
    fn accepts_explicit_source_capture_choice() {
        let mut invalid_input = input();
        invalid_input["include_script_sources"] = serde_json::json!(false);
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_heap_above_limit() {
        let mut invalid_input = input();
        invalid_input["max_heap_mb"] = serde_json::json!(16385);
        assert!(validate_input(&invalid_input).is_err());
    }
}
