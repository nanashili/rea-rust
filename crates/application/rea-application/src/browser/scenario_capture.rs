//! Contract boundary for controlled browser scenario captures.
//!
//! The browser provider owns action execution and event interpretation.  This
//! application boundary validates the caller's selections and retains the
//! provider result without rebuilding browser facts in an adapter.

use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "capture_browser_scenario";

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("browser scenario input must be an object"))?;

    validate_browser_selection(object.get("browser"))?;
    validate_start_url(object.get("start_url"))?;
    validate_actions(object.get("actions"))?;
    validate_optional_object(object.get("environment"), "environment")?;
    validate_optional_object(object.get("storage"), "storage")?;
    validate_optional_array(object.get("secrets"), "secrets")?;
    validate_capture(object.get("capture"))?;

    Ok(())
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("browser scenario capture result must be an object"));
    }
    validate_capture_invariants(&result)?;
    Ok(result)
}

/// Validate the cross-field invariants that make a complete capture safe to
/// consume. The provider owns the individual event facts; this boundary only
/// checks sequence, retention, omission, and step coverage accounting.
fn validate_capture_invariants(result: &Value) -> Result<(), Failure> {
    let Some(object) = result.as_object() else {
        return Ok(());
    };
    let Some(steps) = object.get("steps").and_then(Value::as_array) else {
        return Ok(());
    };
    let Some(events) = object.get("events").and_then(Value::as_object) else {
        return Ok(());
    };
    let action_count = object
        .get("scenario")
        .and_then(|scenario| scenario.get("action_count"))
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("scenario.action_count must be a non-negative integer"))?;
    let expected_steps = action_count
        .checked_add(1)
        .ok_or_else(|| invalid("scenario.action_count is too large"))?;
    if steps.len() as u64 != expected_steps {
        return Err(invalid(
            "capture must include initial state and one entry per action",
        ));
    }
    for (offset, step) in steps.iter().enumerate() {
        let index = step
            .get("step_index")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("each capture step must have a numeric step_index"))?;
        if index != offset as u64 {
            return Err(invalid("step indices must be contiguous from zero"));
        }
    }

    let items = events
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("events.items must be an array"))?;
    let retained = events
        .get("retained")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("events.retained must be a non-negative integer"))?;
    if retained != items.len() as u64 {
        return Err(invalid("events.retained must equal events.items length"));
    }
    let mut sequences = BTreeSet::new();
    for item in items {
        let sequence = item
            .get("sequence")
            .and_then(Value::as_u64)
            .filter(|sequence| *sequence > 0)
            .ok_or_else(|| invalid("each event must have a positive sequence"))?;
        if !sequences.insert(sequence) {
            return Err(invalid("event sequence numbers must be unique"));
        }
        let step_index = item
            .get("step_index")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("each event must have a numeric step_index"))?;
        if step_index >= steps.len() as u64 {
            return Err(invalid("event references an unknown step index"));
        }
    }
    let dropped = events
        .get("dropped")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("events.dropped must be a non-negative integer"))?;
    let omission_count = events
        .get("omissions")
        .and_then(|omissions| omissions.get("by_kind"))
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("events.omissions.by_kind must be an array"))?
        .iter()
        .try_fold(0u64, |total, omission| {
            let count = omission
                .get("count")
                .and_then(Value::as_u64)
                .ok_or_else(|| invalid("each event omission must have a non-negative count"))?;
            total
                .checked_add(count)
                .ok_or_else(|| invalid("event omission count is too large"))
        })?;
    if omission_count != dropped {
        return Err(invalid("event omission counts must equal events.dropped"));
    }
    Ok(())
}

fn validate_browser_selection(value: Option<&Value>) -> Result<(), Failure> {
    let browser = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("browser must be an object"))?;
    let mode = non_empty(browser.get("mode"), "browser.mode")?;

    match mode {
        "launch" => {
            let executable = non_empty(browser.get("executable_path"), "browser.executable_path")?;
            if !executable.starts_with('/') && !executable.contains(":\\") {
                return Err(invalid(
                    "browser.executable_path must be an absolute local path",
                ));
            }
        }
        "connect" => {
            let endpoint = non_empty(browser.get("cdp_endpoint"), "browser.cdp_endpoint")?;
            if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
                return Err(invalid("browser.cdp_endpoint must use HTTP or HTTPS"));
            }
            non_empty(browser.get("target_id"), "browser.target_id")?;
        }
        _ => return Err(invalid("browser.mode must be launch or connect")),
    }

    Ok(())
}

fn validate_start_url(value: Option<&Value>) -> Result<(), Failure> {
    let url = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("start_url must be an object"))?;
    let raw_url = non_empty(url.get("url"), "start_url.url")?;
    if !(raw_url.starts_with("http://") || raw_url.starts_with("https://")) {
        return Err(invalid("start_url.url must use HTTP or HTTPS"));
    }
    validate_optional_array(url.get("query"), "start_url.query")
}

fn validate_actions(value: Option<&Value>) -> Result<(), Failure> {
    let actions = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("actions must be a non-empty array"))?;
    if actions.is_empty() {
        return Err(invalid("actions must be a non-empty array"));
    }

    for action in actions {
        let action = action
            .as_object()
            .ok_or_else(|| invalid("each action must be an object"))?;
        non_empty(action.get("step_id"), "actions.step_id")?;
        non_empty(action.get("action"), "actions.action")?;
    }

    Ok(())
}

fn validate_optional_object(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if let Some(value) = value {
        if !value.is_object() {
            return Err(invalid(&format!("{field} must be an object")));
        }
    }
    Ok(())
}

fn validate_optional_array(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if let Some(value) = value {
        if !value.is_array() {
            return Err(invalid(&format!("{field} must be an array")));
        }
    }
    Ok(())
}

fn validate_capture(value: Option<&Value>) -> Result<(), Failure> {
    let Some(capture) = value else {
        return Ok(());
    };
    let capture = capture
        .as_object()
        .ok_or_else(|| invalid("capture must be an object"))?;
    for field in ["after_each_step", "at_end", "events"] {
        if let Some(values) = capture.get(field) {
            let values = values
                .as_array()
                .ok_or_else(|| invalid(&format!("capture.{field} must be an array")))?;
            for value in values {
                let name = value
                    .as_str()
                    .ok_or_else(|| invalid(&format!("capture.{field} must contain strings")))?;
                let allowed = if field == "events" {
                    matches!(
                        name,
                        "console"
                            | "page-errors"
                            | "network"
                            | "websockets"
                            | "frames"
                            | "workers"
                            | "popups"
                            | "downloads"
                    )
                } else {
                    matches!(
                        name,
                        "screenshot" | "dom" | "accessibility" | "url" | "history" | "storage"
                    )
                };
                if !allowed {
                    return Err(invalid(&format!(
                        "capture.{field} contains an unknown selection"
                    )));
                }
            }
        }
    }
    if let Some(network) = capture.get("network") {
        let network = network
            .as_object()
            .ok_or_else(|| invalid("capture.network must be an object"))?;
        for field in ["request_body", "response_body", "header_values"] {
            if let Some(value) = network.get(field) {
                if !value.is_boolean() {
                    return Err(invalid(&format!(
                        "capture.network.{field} must be a boolean"
                    )));
                }
            }
        }
    }
    if let Some(limits) = capture.get("limits") {
        let limits = limits
            .as_object()
            .ok_or_else(|| invalid("capture.limits must be an object"))?;
        for field in [
            "max_events",
            "max_event_allocation_bytes",
            "max_total_event_allocation_bytes",
            "max_network_transactions",
            "max_network_body_bytes",
            "max_network_body_allocation_bytes",
            "max_network_header_allocation_bytes",
            "max_network_metadata_allocation_bytes",
        ] {
            if let Some(value) = limits.get(field) {
                if value.as_u64().map_or(true, |number| number == 0) {
                    return Err(invalid(&format!("capture.limits.{field} must be positive")));
                }
            }
        }
    }
    Ok(())
}

fn non_empty<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a str, Failure> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty string")))
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a caller-selected browser launch or loopback connection, an HTTP(S) start URL, and at least one explicit action.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Value {
        serde_json::json!({
            "browser": {
                "mode": "connect",
                "cdp_endpoint": "http://127.0.0.1:9222",
                "target_id": "page-1"
            },
            "start_url": {"url": "https://example.test/", "query": []},
            "actions": [{
                "step_id": "settle",
                "action": "wait_for_timeout",
                "duration_ms": 10
            }],
            "capture": {"network": {"request_body": false}}
        })
    }

    #[test]
    fn accepts_connect_scenario() {
        validate_input(&input()).expect("valid browser scenario input");
        assert!(retain_result(&input(), serde_json::json!({"steps": []})).is_ok());
    }

    fn complete_result() -> Value {
        serde_json::json!({
            "scenario": {"action_count": 1},
            "steps": [
                {"step_index": 0},
                {"step_index": 1}
            ],
            "events": {
                "retained": 1,
                "dropped": 1,
                "items": [{"sequence": 1, "step_index": 0}],
                "omissions": {"by_kind": [{"kind": "console", "count": 1}]}
            }
        })
    }

    #[test]
    fn retains_complete_result_with_consistent_event_accounting() {
        assert!(retain_result(&input(), complete_result()).is_ok());
    }

    #[test]
    fn rejects_duplicate_event_sequences_in_complete_result() {
        let mut result = complete_result();
        result["events"]["items"] = serde_json::json!([
            {"sequence": 1, "step_index": 0},
            {"sequence": 1, "step_index": 1}
        ]);
        result["events"]["retained"] = serde_json::json!(2);
        assert!(retain_result(&input(), result).is_err());
    }

    #[test]
    fn rejects_event_omission_count_mismatch() {
        let mut result = complete_result();
        result["events"]["omissions"]["by_kind"][0]["count"] = serde_json::json!(0);
        assert!(retain_result(&input(), result).is_err());
    }

    #[test]
    fn rejects_non_http_start_url() {
        let mut invalid_input = input();
        invalid_input["start_url"]["url"] = serde_json::json!("file:///tmp/page.html");
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_empty_actions() {
        let mut invalid_input = input();
        invalid_input["actions"] = serde_json::json!([]);
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_relative_launch_executable() {
        let mut invalid_input = input();
        invalid_input["browser"] = serde_json::json!({
            "mode": "launch",
            "executable_path": "chromium"
        });
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_unknown_snapshot_selection() {
        let mut invalid_input = input();
        invalid_input["capture"]["after_each_step"] = serde_json::json!(["cookies"]);
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_zero_capture_limit() {
        let mut invalid_input = input();
        invalid_input["capture"]["limits"] = serde_json::json!({"max_events": 0});
        assert!(validate_input(&invalid_input).is_err());
    }
}
