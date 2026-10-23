//! Finalization state for browser scenario captures.
//!
//! Cleanup is part of the caller-visible capture contract. A cleanup failure
//! retains collected steps and events while marking the observation partial.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "capture_browser_scenario_cleanup";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupOutcome {
    TerminatedOwnedProcess,
    DisconnectedExternal,
    Incomplete { reason: String },
}

pub fn finalize_capture(capture: &Value, outcome: CleanupOutcome) -> Result<Value, Failure> {
    let mut capture = capture
        .as_object()
        .cloned()
        .ok_or_else(|| invalid("browser scenario capture must be an object"))?;
    let mut limitations = capture
        .get("limitations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut completeness = capture
        .get("completeness")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut missing_sections = completeness
        .remove("missing_sections")
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let truncated_sections = completeness
        .remove("truncated_sections")
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();

    let (cleanup, cleanup_error) = match outcome {
        CleanupOutcome::TerminatedOwnedProcess => ("terminated-owned-process", None),
        CleanupOutcome::DisconnectedExternal => ("disconnected-external", None),
        CleanupOutcome::Incomplete { reason } => {
            if !missing_sections.iter().any(|value| value == "cleanup") {
                missing_sections.push(json!("cleanup"));
            }
            limitations.push(json!(
                "Scenario observations are partial because browser cleanup could not be confirmed."
            ));
            capture.insert("partial_observation".into(), json!(true));
            ("incomplete", Some(reason))
        }
    };

    let browser = capture.entry("browser").or_insert_with(|| json!({}));
    let browser = browser
        .as_object_mut()
        .ok_or_else(|| invalid("browser scenario capture browser must be an object"))?;
    browser.insert("cleanup".into(), json!(cleanup));
    if let Some(reason) = cleanup_error {
        browser.insert("cleanup_error".into(), json!(reason));
    }

    completeness.insert("missing_sections".into(), Value::Array(missing_sections));
    completeness.insert(
        "truncated_sections".into(),
        Value::Array(truncated_sections),
    );
    capture.insert("completeness".into(), Value::Object(completeness));
    capture.insert("limitations".into(), Value::Array(limitations));
    Ok(Value::Object(capture))
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a retained browser scenario capture before finalizing cleanup.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture() -> Value {
        json!({
            "browser": {"mode": "launch"},
            "steps": [{"step_index": 0, "status": "completed"}],
            "events": {"items": [], "retained": 0, "dropped": 0},
            "completeness": {"missing_sections": [], "truncated_sections": []},
            "limitations": ["events before attachment are unavailable"]
        })
    }

    #[test]
    fn owned_cleanup_preserves_observation() {
        let finalized = finalize_capture(&capture(), CleanupOutcome::TerminatedOwnedProcess)
            .expect("cleanup finalization");

        assert_eq!(finalized["browser"]["cleanup"], "terminated-owned-process");
        assert_eq!(finalized["steps"][0]["status"], "completed");
        assert_eq!(finalized["partial_observation"], Value::Null);
    }

    #[test]
    fn cleanup_failure_retains_partial_observation() {
        let finalized = finalize_capture(
            &capture(),
            CleanupOutcome::Incomplete {
                reason: "browser process did not acknowledge close".into(),
            },
        )
        .expect("cleanup finalization");

        assert_eq!(finalized["browser"]["cleanup"], "incomplete");
        assert_eq!(finalized["partial_observation"], true);
        assert_eq!(
            finalized["completeness"]["missing_sections"],
            json!(["cleanup"])
        );
        assert_eq!(finalized["steps"][0]["status"], "completed");
        assert_eq!(finalized["events"]["retained"], 0);
    }

    #[test]
    fn external_disconnect_has_distinct_identity() {
        let finalized = finalize_capture(&capture(), CleanupOutcome::DisconnectedExternal)
            .expect("cleanup finalization");

        assert_eq!(finalized["browser"]["cleanup"], "disconnected-external");
        assert_eq!(finalized["partial_observation"], Value::Null);
    }
}
