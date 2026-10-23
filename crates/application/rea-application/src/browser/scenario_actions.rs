//! Action sequencing for browser scenario captures.
//!
//! The provider owns browser execution and observation facts.  This boundary
//! owns only the workflow rule from the TypeScript provider: after an action
//! fails, later actions are retained as cancelled and are never executed.
//! Cancellation and failure remain distinct caller-visible step states.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "capture_browser_scenario_actions";

/// Provider-owned result for one executed action. Event sequence bounds are
/// retained alongside the provider observation rather than reconstructed here.
#[derive(Debug, Clone)]
pub struct ActionObservation {
    pub observation: Value,
    pub event_sequence_start: u64,
    pub event_sequence_end: u64,
}

pub trait ScenarioActionPort {
    fn capture_initial(&mut self) -> Result<ActionObservation, String>;

    fn execute(&mut self, step_index: u64, action: &Value) -> Result<ActionObservation, String>;
}

/// Capture the scenario-start observation before sequencing actions.
pub fn execute_capture(
    input: &Value,
    port: &mut dyn ScenarioActionPort,
    cancelled: bool,
) -> Result<Value, Failure> {
    execute_capture_with_cancel_check(input, port, &|| cancelled)
}

/// Capture a scenario while checking cancellation between provider operations.
/// A provider call remains synchronous and is bounded by its transport; once
/// it returns, later actions are represented as cancelled steps.
pub fn execute_capture_with_cancel_check(
    input: &Value,
    port: &mut dyn ScenarioActionPort,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Value, Failure> {
    super::scenario_capture::validate_input(input)?;
    if is_cancelled() {
        return Ok(json!({"steps": [], "partial": true, "cancelled": true}));
    }

    let initial = match port.capture_initial() {
        Ok(result) => json!({
            "step_index": 0,
            "step_id": "scenario_start",
            "action": "scenario_start",
            "status": "completed",
            "error": null,
            "event_sequence_start": result.event_sequence_start,
            "event_sequence_end": result.event_sequence_end,
            "observation": result.observation,
        }),
        Err(reason) => {
            return Ok(json!({
                "steps": [{
                    "step_index": 0,
                    "step_id": "scenario_start",
                    "action": "scenario_start",
                    "status": "failed",
                    "error": reason,
                    "event_sequence_start": null,
                    "event_sequence_end": null,
                    "observation": null,
                }],
                "partial": true,
                "cancelled": false,
            }));
        }
    };

    let mut result = execute_actions_with_cancel_check(input, port, is_cancelled)?;
    let action_steps = result
        .get_mut("steps")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid_result("action workflow did not return steps"))?;
    let mut steps = Vec::with_capacity(action_steps.len() + 1);
    steps.push(initial);
    steps.append(action_steps);
    result["steps"] = Value::Array(steps);
    Ok(result)
}

/// Execute the selected actions while preserving partial workflow state.
/// `cancelled` represents a request that was already cancelled before the
/// next action could start; it does not erase observations from prior steps.
pub fn execute_actions(
    input: &Value,
    port: &mut dyn ScenarioActionPort,
    cancelled: bool,
) -> Result<Value, Failure> {
    execute_actions_with_cancel_check(input, port, &|| cancelled)
}

fn execute_actions_with_cancel_check(
    input: &Value,
    port: &mut dyn ScenarioActionPort,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Value, Failure> {
    super::scenario_capture::validate_input(input)?;
    let actions = input
        .get("actions")
        .and_then(Value::as_array)
        .expect("validated actions");

    let mut steps = Vec::with_capacity(actions.len());
    let mut prior_failure = false;
    let mut cancellation_seen = false;

    for (offset, action) in actions.iter().enumerate() {
        let step_index = offset as u64 + 1;
        let request_cancelled = is_cancelled();
        cancellation_seen |= request_cancelled;

        if request_cancelled || prior_failure {
            steps.push(cancelled_step(
                step_index,
                action,
                prior_failure,
                unavailable_artifacts(input, step_index),
            ));
            continue;
        }

        match port.execute(step_index, action) {
            Ok(result) => steps.push(json!({
                "step_index": step_index,
                "step_id": action["step_id"],
                "action": action["action"],
                "status": "completed",
                "error": null,
                "event_sequence_start": result.event_sequence_start,
                "event_sequence_end": result.event_sequence_end,
                "observation": result.observation,
            })),
            Err(reason) => {
                prior_failure = true;
                steps.push(json!({
                    "step_index": step_index,
                    "step_id": action["step_id"],
                    "action": action["action"],
                    "status": "failed",
                    "error": reason,
                    "event_sequence_start": null,
                    "event_sequence_end": null,
                    "observation": null,
                }));
            }
        }
    }

    Ok(json!({
        "steps": steps,
        "partial": cancellation_seen || prior_failure,
        "cancelled": cancellation_seen,
    }))
}

fn invalid_result(reason: &str) -> Failure {
    Failure::new(
        "invalid_result",
        "application_error",
        reason.to_owned(),
        false,
        "Retry the browser scenario capture.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn cancelled_step(step_index: u64, action: &Value, after_failure: bool, artifacts: Value) -> Value {
    let error = if after_failure {
        "not executed after an earlier action failure"
    } else {
        "scenario request cancelled"
    };
    json!({
        "step_index": step_index,
        "step_id": action["step_id"],
        "action": action["action"],
        "status": "cancelled",
        "error": error,
        "event_sequence_start": null,
        "event_sequence_end": null,
        "observation": null,
        "artifacts": artifacts,
    })
}

fn unavailable_artifacts(input: &Value, step_index: u64) -> Value {
    let capture = input.get("capture").and_then(Value::as_object);
    let actions = input
        .get("actions")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let mut requested = capture
        .and_then(|value| value.get("after_each_step"))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    if step_index as usize == actions {
        if let Some(values) = capture
            .and_then(|value| value.get("at_end"))
            .and_then(Value::as_array)
        {
            requested.extend(values.iter().filter_map(Value::as_str));
        }
    }

    let state = |kind: &str| {
        if requested.contains(kind) {
            json!({"state": "missing", "reason": "scenario action was not executed"})
        } else {
            json!({"state": "not_requested"})
        }
    };
    json!({
        "screenshot": state("screenshot"),
        "dom": state("dom"),
        "accessibility": state("accessibility"),
        "url": state("url"),
        "history": state("history"),
        "storage": state("storage"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct FakePort {
        fail_at: Option<u64>,
        calls: Vec<u64>,
    }

    impl ScenarioActionPort for FakePort {
        fn capture_initial(&mut self) -> Result<ActionObservation, String> {
            self.calls.push(0);
            Ok(ActionObservation {
                observation: json!({"step": 0}),
                event_sequence_start: 1,
                event_sequence_end: 1,
            })
        }

        fn execute(
            &mut self,
            step_index: u64,
            _action: &Value,
        ) -> Result<ActionObservation, String> {
            self.calls.push(step_index);
            if self.fail_at == Some(step_index) {
                return Err("action failed".into());
            }
            Ok(ActionObservation {
                observation: json!({"step": step_index}),
                event_sequence_start: step_index * 2 - 1,
                event_sequence_end: step_index * 2,
            })
        }
    }

    fn input() -> Value {
        json!({
            "browser": {"mode": "connect", "cdp_endpoint": "http://127.0.0.1:9222", "target_id": "tab"},
            "start_url": {"url": "https://example.test/"},
            "actions": [
                {"step_id": "one", "action": "click"},
                {"step_id": "two", "action": "type"},
                {"step_id": "three", "action": "wait"}
            ]
        })
    }

    #[test]
    fn failed_action_cancels_later_actions_without_calling_provider() {
        let mut port = FakePort {
            fail_at: Some(2),
            calls: Vec::new(),
        };
        let result = execute_actions(&input(), &mut port, false).expect("action workflow");

        assert_eq!(port.calls, vec![1, 2]);
        assert_eq!(result["partial"], true);
        assert_eq!(result["steps"][1]["status"], "failed");
        assert_eq!(result["steps"][2]["status"], "cancelled");
        assert_eq!(
            result["steps"][2]["error"],
            "not executed after an earlier action failure"
        );
    }

    #[test]
    fn cancellation_retains_prior_provider_observations_and_skips_all_actions() {
        let mut port = FakePort {
            fail_at: None,
            calls: Vec::new(),
        };
        let result = execute_actions(&input(), &mut port, true).expect("cancelled workflow");

        assert!(port.calls.is_empty());
        assert_eq!(result["cancelled"], true);
        assert!(
            result["steps"]
                .as_array()
                .expect("steps")
                .iter()
                .all(|step| {
                    step["status"] == "cancelled" && step["error"] == "scenario request cancelled"
                })
        );
    }

    #[test]
    fn completed_step_retains_provider_event_bounds_and_observation() {
        let mut port = FakePort {
            fail_at: None,
            calls: Vec::new(),
        };
        let result = execute_actions(&input(), &mut port, false).expect("action workflow");

        assert_eq!(result["partial"], false);
        assert_eq!(result["steps"][0]["event_sequence_start"], 1);
        assert_eq!(result["steps"][0]["event_sequence_end"], 2);
        assert_eq!(result["steps"][0]["observation"]["step"], 1);
    }

    #[test]
    fn capture_entry_point_retains_initial_step_before_actions() {
        let mut port = FakePort {
            fail_at: Some(2),
            calls: Vec::new(),
        };
        let result = execute_capture(&input(), &mut port, false).expect("capture workflow");

        assert_eq!(port.calls, vec![0, 1, 2]);
        assert_eq!(result["steps"][0]["step_id"], "scenario_start");
        assert_eq!(result["steps"][1]["status"], "completed");
        assert_eq!(result["steps"][2]["status"], "failed");
        assert_eq!(result["steps"][3]["status"], "cancelled");
    }

    #[test]
    fn pre_cancelled_capture_does_not_call_provider() {
        let mut port = FakePort {
            fail_at: None,
            calls: Vec::new(),
        };
        let result = execute_capture(&input(), &mut port, true).expect("cancelled capture");

        assert!(port.calls.is_empty());
        assert_eq!(result["cancelled"], true);
        assert_eq!(result["steps"], json!([]));
    }

    #[test]
    fn cancellation_between_actions_preserves_completed_observation() {
        let mut port = FakePort {
            fail_at: None,
            calls: Vec::new(),
        };
        let checks = Cell::new(0);
        let result = execute_capture_with_cancel_check(&input(), &mut port, &|| {
            let check = checks.get() + 1;
            checks.set(check);
            check >= 3
        })
        .expect("cancelled capture");

        assert_eq!(port.calls, vec![0, 1]);
        assert_eq!(result["steps"][0]["status"], "completed");
        assert_eq!(result["steps"][1]["status"], "completed");
        assert_eq!(result["steps"][2]["status"], "cancelled");
        assert_eq!(result["cancelled"], true);
    }

    #[test]
    fn cancelled_steps_mark_requested_artifacts_missing_and_others_unrequested() {
        let mut scenario = input();
        scenario["capture"] = json!({
            "after_each_step": ["dom", "screenshot"],
            "at_end": ["storage"]
        });
        let mut port = FakePort {
            fail_at: Some(1),
            calls: Vec::new(),
        };
        let result = execute_actions(&scenario, &mut port, false).expect("action workflow");

        assert_eq!(result["steps"][0]["status"], "failed");
        assert_eq!(result["steps"][1]["status"], "cancelled");
        assert_eq!(result["steps"][1]["artifacts"]["dom"]["state"], "missing");
        assert_eq!(
            result["steps"][1]["artifacts"]["accessibility"]["state"],
            "not_requested"
        );
    }
}
