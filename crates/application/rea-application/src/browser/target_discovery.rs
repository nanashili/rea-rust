//! Contract boundary for passive browser target discovery.
//!
//! CDP discovery and target filtering remain provider responsibilities.  This
//! boundary keeps the endpoint and caller-selected origin filter explicit
//! before the provider result is retained.

use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "list_browser_targets";

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    validate_scope(input, OPERATION)
}

/// Validate the loopback browser and origin scope shared by read-only tools.
pub fn validate_scope(input: &Value, operation: &str) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid_for(operation, "browser target input must be an object"))?;
    let endpoint = non_empty(object.get("cdp_endpoint"), "cdp_endpoint", operation)?;

    validate_loopback_endpoint(endpoint, operation)?;
    if let Some(origins) = object.get("allowed_origins") {
        let origins = origins
            .as_array()
            .ok_or_else(|| invalid_for(operation, "allowed_origins must be an array"))?;
        for origin in origins {
            let origin = non_empty(Some(origin), "allowed_origins[]", operation)?;
            validate_origin(origin, operation)?;
        }
    }

    Ok(())
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("browser target result must be an object"));
    }
    Ok(result)
}

fn validate_loopback_endpoint(endpoint: &str, operation: &str) -> Result<(), Failure> {
    let is_http = endpoint.starts_with("http://");
    let has_extra_path = endpoint
        .split_once("://")
        .and_then(|(_, remainder)| remainder.split_once('/'))
        .is_some_and(|(_, path)| !path.is_empty() && path != "/");
    if has_extra_path || endpoint.contains('?') || endpoint.contains('#') {
        return Err(invalid_for(
            operation,
            "cdp_endpoint must be a bare loopback HTTP origin",
        ));
    }
    let authority = endpoint
        .split_once("://")
        .map(|(_, remainder)| remainder.split('/').next().unwrap_or_default())
        .unwrap_or_default();
    let hostname = authority
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or("");
    let port = authority
        .rsplit_once(':')
        .map(|(_, port)| port)
        .unwrap_or("");

    if !is_http || !matches!(hostname, "127.0.0.1" | "[::1]" | "::1") || port.is_empty() {
        return Err(invalid_for(
            operation,
            "cdp_endpoint must be an explicit-port loopback HTTP endpoint",
        ));
    }
    if !port.chars().all(|character| character.is_ascii_digit()) {
        return Err(invalid_for(operation, "cdp_endpoint port must be numeric"));
    }
    Ok(())
}

fn validate_origin(origin: &str, operation: &str) -> Result<(), Failure> {
    let is_http = origin.starts_with("http://") || origin.starts_with("https://");
    let remainder = origin
        .split_once("://")
        .map(|(_, remainder)| remainder)
        .unwrap_or_default();
    if !is_http
        || remainder.is_empty()
        || remainder.contains('/')
        || remainder.contains('?')
        || remainder.contains('#')
        || remainder.contains('@')
        || remainder.contains('*')
    {
        return Err(invalid_for(
            operation,
            "allowed_origins must contain exact HTTP(S) origins",
        ));
    }
    Ok(())
}

fn non_empty<'a>(
    value: Option<&'a Value>,
    field: &str,
    operation: &str,
) -> Result<&'a str, Failure> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_for(operation, &format!("{field} must be a non-empty string")))
}

fn invalid(reason: &str) -> Failure {
    invalid_for(OPERATION, reason)
}

fn invalid_for(operation: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide the caller-selected loopback CDP endpoint and optional exact origin filters."
            .into(),
        BTreeMap::from([("operation", Detail::Text(operation.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Value {
        serde_json::json!({
            "cdp_endpoint": "http://127.0.0.1:9222",
            "allowed_origins": ["https://app.example.test"]
        })
    }

    #[test]
    fn accepts_loopback_discovery_scope() {
        validate_input(&input()).expect("valid browser target input");
        assert!(retain_result(&input(), serde_json::json!({"targets": []})).is_ok());
    }

    #[test]
    fn rejects_non_loopback_endpoint() {
        let mut invalid_input = input();
        invalid_input["cdp_endpoint"] = serde_json::json!("http://192.0.2.1:9222");
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_origin_paths() {
        let mut invalid_input = input();
        invalid_input["allowed_origins"] = serde_json::json!(["https://app.example.test/path"]);
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn accepts_a_trailing_endpoint_slash() {
        let mut input = input();
        input["cdp_endpoint"] = serde_json::json!("http://127.0.0.1:9222/");
        assert!(validate_input(&input).is_ok());
    }

    #[test]
    fn rejects_origin_credentials_and_wildcards() {
        for origin in ["https://user@app.example.test", "https://*.example.test"] {
            let mut invalid_input = input();
            invalid_input["allowed_origins"] = serde_json::json!([origin]);
            assert!(validate_input(&invalid_input).is_err(), "{origin}");
        }
    }

    #[test]
    fn rejects_non_object_result() {
        assert!(retain_result(&input(), serde_json::json!([])).is_err());
    }
}
