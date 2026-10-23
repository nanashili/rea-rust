//! Caller-visible state for a retained browser scenario capture.
//!
//! The scenario provider owns browser facts and capture execution.  This
//! module owns the small, typed projection that callers need when deciding
//! whether a capture can participate in equality or regression comparison.
//! It deliberately keeps incomplete and truncated coverage distinct.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "classify_browser_scenario_capture";

/// Boundary used by adapters that already have a browser scenario provider.
/// The provider returns the complete capture; this module only validates and
/// projects its caller-visible coverage state.
pub trait ScenarioCapturePort {
    fn capture(&mut self, input: &Value) -> Result<Value, String>;
}

pub fn capture_state(input: &Value, port: &mut dyn ScenarioCapturePort) -> Result<Value, Failure> {
    let result = port
        .capture(input)
        .map_err(|reason| provider_failure(&reason))?;
    let retained = super::scenario_capture::retain_result(input, result)?;
    summarize_result(&retained)
}

/// Return stable completeness and step state without reinterpreting browser
/// facts.  Explicit provider sections are preserved and derived step/event
/// coverage is added only when the result makes that omission observable.
pub fn summarize_result(result: &Value) -> Result<Value, Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("browser scenario capture result must be an object"))?;
    let steps = object
        .get("steps")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("browser scenario capture result must contain steps"))?;
    let completeness = object
        .get("completeness")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("browser scenario capture result must contain completeness"))?;

    let mut missing = string_set(completeness, "missing_sections")?;
    let mut truncated = string_set(completeness, "truncated_sections")?;
    let mut completed_steps = 0u64;

    for step in steps {
        let status = step
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("each scenario step must have a status"))?;
        if status == "completed" {
            completed_steps += 1;
        } else if status == "failed" || status == "cancelled" {
            missing.insert("steps".into());
        } else {
            return Err(invalid("scenario step status is unknown"));
        }

        if let Some(step_completeness) = step.get("completeness").and_then(Value::as_object) {
            extend_sections(&mut missing, step_completeness, "missing_sections")?;
            extend_sections(&mut truncated, step_completeness, "truncated_sections")?;
        }
    }

    if object
        .get("browser")
        .and_then(|browser| browser.get("mode"))
        .and_then(Value::as_str)
        == Some("connect")
    {
        missing.insert("events".into());
    }

    if object
        .get("events")
        .and_then(|events| events.get("dropped"))
        .and_then(Value::as_u64)
        .is_some_and(|dropped| dropped > 0)
    {
        truncated.insert("events".into());
    }

    let status = if !truncated.is_empty() {
        "truncated"
    } else if !missing.is_empty() {
        "incomplete"
    } else {
        "complete"
    };

    Ok(json!({
        "status": status,
        "equality_eligible": status == "complete",
        "missing_sections": missing.into_iter().collect::<Vec<_>>(),
        "truncated_sections": truncated.into_iter().collect::<Vec<_>>(),
        "completed_steps": completed_steps,
        "total_steps": steps.len() as u64,
    }))
}

fn string_set(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<BTreeSet<String>, Failure> {
    let values = object
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(&format!("completeness.{field} must be an array")))?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid(&format!("completeness.{field} must contain strings")))
        })
        .collect()
}

fn extend_sections(
    destination: &mut BTreeSet<String>,
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), Failure> {
    for section in string_set(object, field)? {
        destination.insert(section);
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a retained browser scenario capture with explicit completeness sections.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn provider_failure(reason: &str) -> Failure {
    Failure::new(
        "provider_error",
        "scenario_capture_failed",
        reason.to_owned(),
        true,
        "Retry the browser scenario capture after checking the selected browser target.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakePort {
        result: Value,
    }

    impl ScenarioCapturePort for FakePort {
        fn capture(&mut self, _input: &Value) -> Result<Value, String> {
            Ok(self.result.clone())
        }
    }

    fn input() -> Value {
        json!({
            "browser": {"mode": "connect", "cdp_endpoint": "http://127.0.0.1:9222", "target_id": "tab"},
            "start_url": {"url": "https://example.test/"},
            "actions": [{"step_id": "load", "action": "wait"}]
        })
    }

    fn result(status: &str, dropped: u64) -> Value {
        let omissions = if dropped == 0 {
            json!([])
        } else {
            json!([{"kind": "console", "count": dropped}])
        };
        json!({
            "scenario": {"action_count": 1},
            "steps": [
                {"step_index": 0, "status": "completed"},
                {"step_index": 1, "status": status}
            ],
            "events": {"items": [], "retained": 0, "dropped": dropped, "omissions": {"by_kind": omissions}},
            "completeness": {"missing_sections": [], "truncated_sections": []}
        })
    }

    #[test]
    fn fake_port_projects_complete_capture_as_equality_eligible() {
        let mut port = FakePort {
            result: result("completed", 0),
        };
        let state = capture_state(&input(), &mut port).expect("capture state");
        assert_eq!(state["status"], "complete");
        assert_eq!(state["equality_eligible"], true);
        assert_eq!(state["completed_steps"], 2);
    }

    #[test]
    fn failed_step_is_incomplete_and_dropped_events_are_truncated() {
        let mut port = FakePort {
            result: result("failed", 2),
        };
        let state = capture_state(&input(), &mut port).expect("capture state");
        assert_eq!(state["status"], "truncated");
        assert_eq!(state["equality_eligible"], false);
        assert_eq!(state["missing_sections"], json!(["steps"]));
        assert_eq!(state["truncated_sections"], json!(["events"]));
    }

    #[test]
    fn step_completeness_and_shared_connection_event_gap_are_projected() {
        let mut capture = result("completed", 0);
        capture["browser"] = json!({"mode": "connect"});
        capture["steps"][1]["completeness"] = json!({
            "missing_sections": ["accessibility"],
            "truncated_sections": []
        });

        let state = summarize_result(&capture).expect("capture state");
        assert_eq!(state["status"], "incomplete");
        assert_eq!(state["equality_eligible"], false);
        assert_eq!(
            state["missing_sections"],
            json!(["accessibility", "events"])
        );
    }

    #[test]
    fn provider_failure_remains_typed() {
        struct FailingPort;
        impl ScenarioCapturePort for FailingPort {
            fn capture(&mut self, _input: &Value) -> Result<Value, String> {
                Err("browser disconnected".into())
            }
        }

        let error = capture_state(&input(), &mut FailingPort).expect_err("provider failure");
        assert_eq!(error.code(), "provider_error");
        assert_eq!(error.operation(), Some(OPERATION));
    }
}
