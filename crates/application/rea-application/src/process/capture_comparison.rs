//! Deterministic comparison of retained process-capture Evidence.
//!
//! The adapter owns Evidence authentication and transport. This module owns
//! the comparison semantics once the two retained results are available.

use rea_core::{canonical_json, failure::Failure};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

pub const OPERATION: &str = "compare_process_captures";
const DIMENSIONS: [&str; 5] = ["terminal", "interaction", "exit", "filesystem", "process"];

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("process capture comparison input must be an object"))?;

    for side in ["left", "right"] {
        let evidence = object
            .get(side)
            .and_then(Value::as_object)
            .ok_or_else(|| invalid(&format!("{side} Evidence is required")))?;
        let id = evidence
            .get("evidence_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| invalid(&format!("{side} Evidence must include evidence_id")))?;
        if !id.starts_with("ev_") {
            return Err(invalid(&format!(
                "{side}.evidence_id must be an Evidence identifier"
            )));
        }
        if evidence.get("predicate_type").and_then(Value::as_str) != Some("rea.process-capture") {
            return Err(invalid(&format!(
                "{side} Evidence must have predicate_type rea.process-capture"
            )));
        }
        if evidence.get("operation").and_then(Value::as_str) != Some("capture_process_scenario") {
            return Err(invalid(&format!(
                "{side} Evidence must come from capture_process_scenario"
            )));
        }
        capture(evidence, side)?;
    }

    if input
        .get("max_capture_age_ms")
        .is_some_and(|value| value.as_u64().is_none())
    {
        return Err(invalid("max_capture_age_ms must be a nonnegative integer"));
    }
    Ok(())
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid(
            "process capture comparison result must be an object",
        ));
    }
    Ok(result)
}

/// Compare two authenticated process-capture results and emit derived result JSON.
pub fn compare(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;

    let left_evidence = input["left"].as_object().expect("validated left Evidence");
    let right_evidence = input["right"]
        .as_object()
        .expect("validated right Evidence");
    let left = capture(left_evidence, "left")?;
    let right = capture(right_evidence, "right")?;

    check_comparison_contract(left, right)?;
    check_freshness(input, left, right)?;

    let same_normalization = left.get("normalization") == right.get("normalization");
    let mut dimensions = Map::new();
    for (dimension, scope, source) in [
        ("terminal", "terminal", "rendered_terminal"),
        ("interaction", "interaction", "interaction"),
        ("exit", "exit", "lifecycle"),
        ("filesystem", "filesystem", "filesystem"),
        ("process", "process", "process"),
    ] {
        dimensions.insert(
            dimension.into(),
            classify_dimension(left, right, dimension, scope, source, same_normalization),
        );
    }

    let trace_requested = input.get("trace_spec").is_some();
    let trace = input.get("trace_spec").map(|spec| json!({
        "verdict": "unknown",
        "reason": "Native trace-spec evaluation is not yet routed; the explicit specification is retained for adapter follow-up.",
        "specification": spec,
    }));
    let first = first_divergence(left, right, &dimensions, same_normalization);
    let status = derive_status(&dimensions, trace_requested);
    let mut semantic = json!({
        "status": status,
        "terminal": dimensions["terminal"],
        "interaction": dimensions["interaction"],
        "exit": dimensions["exit"],
        "filesystem": dimensions["filesystem"],
        "process": dimensions["process"],
        "first_divergence": first,
        "limitations": limitations(left, right, same_normalization),
        "evidence_links": [left_evidence["evidence_id"], right_evidence["evidence_id"]],
        "capture_identity": {
            "left_full_scenario_sha256": left["manifest"]["full_scenario_sha256"],
            "right_full_scenario_sha256": right["manifest"]["full_scenario_sha256"],
            "comparison_contract_sha256": left["manifest"]["comparison_contract_sha256"],
        },
    });
    if let Some(trace) = trace {
        semantic["trace"] = trace;
    }

    let digest = canonical_json::digest(&semantic).map_err(|error| invalid(&error.to_string()))?;
    semantic["comparison_id"] = Value::String(format!("pcc_{digest}"));
    Ok(semantic)
}

fn capture<'a>(
    evidence: &'a Map<String, Value>,
    side: &str,
) -> Result<&'a Map<String, Value>, Failure> {
    let capture = evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            invalid(&format!(
                "{side} Evidence must include a process capture result"
            ))
        })?;

    if capture
        .get("cleanup")
        .and_then(|cleanup| cleanup.get("owned_process_group"))
        .and_then(Value::as_str)
        != Some("verified")
    {
        return Err(invalid(&format!(
            "{side} process capture does not prove owned-process cleanup"
        )));
    }

    let manifest = capture
        .get("manifest")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(&format!("{side} process capture must include a manifest")))?;

    for field in ["full_scenario_sha256", "comparison_contract_sha256"] {
        if manifest.get(field).and_then(Value::as_str).is_none() {
            return Err(invalid(&format!("{side}.manifest.{field} is required")));
        }
    }
    Ok(capture)
}

fn check_comparison_contract(
    left: &Map<String, Value>,
    right: &Map<String, Value>,
) -> Result<(), Failure> {
    let left_hash = left["manifest"].get("comparison_contract_sha256");
    let right_hash = right["manifest"].get("comparison_contract_sha256");
    if left_hash != right_hash {
        return Err(invalid(
            "Process captures have incompatible comparison contracts",
        ));
    }

    Ok(())
}

fn check_freshness(
    input: &Value,
    left: &Map<String, Value>,
    right: &Map<String, Value>,
) -> Result<(), Failure> {
    let Some(limit) = input.get("max_capture_age_ms").and_then(Value::as_u64) else {
        return Ok(());
    };
    let Some(now) = input.get("now_ms").and_then(Value::as_i64) else {
        return Err(invalid(
            "now_ms is required when max_capture_age_ms is supplied",
        ));
    };

    for (side, capture) in [("left", left), ("right", right)] {
        let Some(completed) = capture["manifest"]
            .get("completed_at")
            .and_then(Value::as_str)
        else {
            continue;
        };
        let Some(timestamp) = parse_timestamp_ms(completed) else {
            return Err(invalid(
                "capture manifest completed_at is not a supported timestamp",
            ));
        };
        if now.saturating_sub(timestamp) > limit as i64 {
            return Err(invalid(&format!(
                "{side} process capture exceeds max_capture_age_ms {limit}"
            )));
        }
    }

    Ok(())
}

fn classify_dimension(
    left: &Map<String, Value>,
    right: &Map<String, Value>,
    dimension: &str,
    scope: &str,
    source: &str,
    same_normalization: bool,
) -> Value {
    if !same_normalization
        || has_unknown(left, scope)
        || has_unknown(right, scope)
        || source_truncated(left, source)
        || source_truncated(right, source)
    {
        return Value::String("unknown".into());
    }

    if dimension == "exit" {
        return if left.get("exit") == right.get("exit")
            && left.get("settlement") == right.get("settlement")
        {
            json!("unchanged")
        } else {
            json!("changed")
        };
    }

    let left_values = dimension_values(left, dimension);
    let right_values = dimension_values(right, dimension);
    if left_values == right_values {
        json!("unchanged")
    } else if left_values.is_empty() {
        json!("added")
    } else if right_values.is_empty() {
        json!("removed")
    } else {
        json!("changed")
    }
}

fn dimension_values(capture: &Map<String, Value>, dimension: &str) -> Vec<Value> {
    match dimension {
        "terminal" => {
            let raw_values = capture
                .get("frames")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mut values = raw_values
                .into_iter()
                .map(comparable_raw_frame)
                .collect::<Vec<_>>();
            values.extend(
                capture
                    .get("rendered_frames")
                    .and_then(Value::as_array)
                    .map(|frames| {
                        frames
                            .iter()
                            .cloned()
                            .map(comparable_rendered_frame)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
            );
            values.sort_by_key(|value| {
                (
                    event_time("terminal", value),
                    terminal_kind_order(value),
                    value.get("sequence").and_then(Value::as_u64).unwrap_or(0),
                )
            });
            values
        }
        "interaction" => capture
            .get("interaction_events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        "filesystem" => capture
            .get("filesystem_checkpoints")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        "process" => capture
            .get("process_samples")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        "exit" => vec![comparable_exit(capture)],
        _ => Vec::new(),
    }
}

fn terminal_kind_order(value: &Value) -> u8 {
    match value.get("kind").and_then(Value::as_str) {
        Some("raw") => 0,
        Some("rendered") => 1,
        _ => 2,
    }
}

fn comparable_exit(capture: &Map<String, Value>) -> Value {
    let mut exit = capture
        .get("exit")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    exit.insert(
        "settlement".into(),
        capture.get("settlement").cloned().unwrap_or(Value::Null),
    );
    Value::Object(exit)
}

fn comparable_raw_frame(value: Value) -> Value {
    let Some(frame) = value.as_object() else {
        return json!({ "kind": "raw", "value": value });
    };

    json!({
        "kind": "raw",
        "sequence": frame.get("sequence"),
        "at_ms": frame.get("at_ms"),
        "data": frame.get("data"),
    })
}

fn comparable_rendered_frame(value: Value) -> Value {
    let Some(mut frame) = value.as_object().cloned() else {
        return json!({ "kind": "rendered", "value": value });
    };
    frame.insert("kind".into(), json!("rendered"));
    Value::Object(frame)
}

fn has_unknown(capture: &Map<String, Value>, scope: &str) -> bool {
    capture
        .get("residual_unknowns")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items
                .iter()
                .any(|item| item.get("scope").and_then(Value::as_str) == Some(scope))
        })
}

fn source_truncated(capture: &Map<String, Value>, source: &str) -> bool {
    if capture.get("truncated").and_then(Value::as_bool) == Some(true) {
        return true;
    }

    let Some(details) = capture.get("truncation_details") else {
        return false;
    };
    match source {
        "process" => {
            details
                .get("process")
                .and_then(|value| value.get("sampling_partial"))
                .and_then(Value::as_bool)
                == Some(true)
        }
        "filesystem" => {
            details
                .pointer("/filesystem_before/enumeration_truncated")
                .and_then(Value::as_bool)
                == Some(true)
                || details
                    .pointer("/filesystem_after/enumeration_truncated")
                    .and_then(Value::as_bool)
                    == Some(true)
        }
        "rendered_terminal" => {
            let raw_observed = details
                .pointer("/raw_terminal/observed_frames")
                .and_then(Value::as_u64);
            let raw_retained = details
                .pointer("/raw_terminal/retained_frames")
                .and_then(Value::as_u64);
            let observed = details
                .pointer("/rendered_terminal/observed_frames")
                .and_then(Value::as_u64);
            let retained = details
                .pointer("/rendered_terminal/retained_frames")
                .and_then(Value::as_u64);
            matches!(
                (raw_observed, raw_retained),
                (Some(observed), Some(retained)) if observed > retained
            ) || matches!(
                (observed, retained),
                (Some(observed), Some(retained)) if observed > retained
            )
        }
        _ => false,
    }
}

fn derive_status(dimensions: &Map<String, Value>, trace_requested: bool) -> &'static str {
    if DIMENSIONS
        .iter()
        .any(|dimension| dimensions[*dimension] == "truncated")
    {
        return "truncated";
    }
    if DIMENSIONS.iter().any(|dimension| {
        matches!(
            dimensions[*dimension].as_str(),
            Some("changed" | "added" | "removed")
        )
    }) {
        return "changed";
    }
    if trace_requested
        || DIMENSIONS
            .iter()
            .any(|dimension| dimensions[*dimension] == "unknown")
    {
        "unknown"
    } else {
        "unchanged"
    }
}

fn first_divergence(
    left: &Map<String, Value>,
    right: &Map<String, Value>,
    dimensions: &Map<String, Value>,
    same_normalization: bool,
) -> Value {
    if left.get("truncated") == Some(&Value::Bool(true))
        || right.get("truncated") == Some(&Value::Bool(true))
    {
        return json!({
            "status": "unknown",
            "reason": "Incomplete observations prevent locating the first divergence; unaffected dimensions retain their comparisons."
        });
    }

    let mut candidates = Vec::new();
    for dimension in DIMENSIONS {
        if dimensions[dimension] == "unknown" {
            continue;
        }
        let left_values = dimension_values(left, dimension);
        let right_values = dimension_values(right, dimension);
        for index in 0..left_values.len().max(right_values.len()) {
            let left_value = left_values.get(index).cloned().unwrap_or(Value::Null);
            let right_value = right_values.get(index).cloned().unwrap_or(Value::Null);
            if left_value != right_value {
                candidates.push(json!({
                    "status": "found",
                    "dimension": dimension,
                    "index": index,
                    "left_at_ms": event_time(dimension, &left_value),
                    "right_at_ms": event_time(dimension, &right_value),
                    "left": left_value,
                    "right": right_value,
                }));
                break;
            }
        }
    }

    if candidates.is_empty() && (!same_normalization || has_residual_unknowns(left, right)) {
        return json!({
            "status": "unknown",
            "reason": "Residual unknowns prevent proving that no divergence occurred."
        });
    }

    candidates
        .into_iter()
        .min_by_key(|value| {
            let left_time = value["left_at_ms"].as_u64().unwrap_or(u64::MAX);
            let right_time = value["right_at_ms"].as_u64().unwrap_or(u64::MAX);
            left_time.min(right_time)
        })
        .unwrap_or_else(|| json!({ "status": "none" }))
}

fn event_time(dimension: &str, value: &Value) -> Option<u64> {
    let field = if dimension == "interaction" {
        "dispatched_at_ms"
    } else {
        "at_ms"
    };
    value.get(field).and_then(Value::as_u64)
}

fn has_residual_unknowns(left: &Map<String, Value>, right: &Map<String, Value>) -> bool {
    [left, right].into_iter().any(|capture| {
        capture
            .get("residual_unknowns")
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty())
    })
}

fn limitations(
    left: &Map<String, Value>,
    right: &Map<String, Value>,
    same_normalization: bool,
) -> Vec<Value> {
    let mut values = Vec::new();
    for capture in [left, right] {
        if let Some(items) = capture.get("limitations").and_then(Value::as_array) {
            values.extend(items.iter().cloned());
        }
        if let Some(items) = capture.get("residual_unknowns").and_then(Value::as_array) {
            values.extend(items.iter().filter_map(|item| item.get("reason").cloned()));
        }
    }
    if !same_normalization {
        values.push(json!("Capture normalization rules differ."));
    }

    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| {
            value
                .as_str()
                .is_some_and(|text| seen.insert(text.to_owned()))
        })
        .collect()
}

fn parse_timestamp_ms(value: &str) -> Option<i64> {
    let (date, time) = value.split_once('T')?;
    let mut date_parts = date.split('-').map(|part| part.parse::<i64>().ok());
    let year = date_parts.next()??;
    let month = date_parts.next()??;
    let day = date_parts.next()??;

    let time = time.trim_end_matches('Z');
    let (clock, milliseconds) = time.split_once('.').unwrap_or((time, "0"));
    let mut clock_parts = clock.split(':').map(|part| part.parse::<i64>().ok());
    let hour = clock_parts.next()??;
    let minute = clock_parts.next()??;
    let second = clock_parts.next()??;
    let milliseconds = milliseconds.parse::<u64>().ok().unwrap_or(0);

    Some(
        (((year * 365 + month * 31 + day) * 24 + hour) * 60 + minute) * 60 * 1000
            + second * 1000
            + milliseconds as i64,
    )
}

fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_input",
        "input",
        message.into(),
        false,
        "Correct the process capture comparison input and retry.".into(),
        std::collections::BTreeMap::new(),
    )
}
