//! `compareProcessCaptures` (`src/domain/process/processComparison.ts`).
//!
//! Compares two verified captures without treating absence as proof:
//! observed differences outrank residual unknowns, and incomplete
//! observations never compare as equivalent.
use crate::capture::validation::source_truncated;
use crate::json::{array, canonical, field, safe_integer, same, text};
use crate::trace::eval::{self, TraceComparison, comparable_terminal_frame};
use crate::trace::spec::Specification;
use rea_core::analysis_error::{AnalysisError, InputIssue};
use serde_json::{Map, Value, json};
use std::collections::HashSet;

const OPERATION: &str = "compare_process_captures";

/// Canonical dimension order.
pub const DIMENSIONS: [&str; 5] = ["terminal", "interaction", "exit", "filesystem", "process"];

/// Dimension statuses in canonical order.
#[derive(Clone)]
pub struct Dimensions([&'static str; 5]);

impl Dimensions {
    pub fn get(&self, dimension: &str) -> &'static str {
        DIMENSIONS
            .iter()
            .position(|name| *name == dimension)
            .map(|index| self.0[index])
            .unwrap_or("unknown")
    }
}

/// `deriveProcessComparisonStatus`.
pub fn derive_status(statuses: &[&str]) -> &'static str {
    if statuses.contains(&"truncated") {
        "truncated"
    } else if statuses
        .iter()
        .any(|status| matches!(*status, "changed" | "added" | "removed"))
    {
        "changed"
    } else if statuses.contains(&"unknown") {
        "unknown"
    } else {
        "unchanged"
    }
}

fn number(value: &Value, key: &str) -> f64 {
    field(value, key)
        .and_then(Value::as_f64)
        .unwrap_or(f64::NAN)
}

fn terminal_observations(capture: &Value) -> Vec<Value> {
    let mut observations = Vec::new();
    for frame in array(capture, "frames") {
        let mut object = Map::new();
        object.insert("kind".into(), json!("raw"));
        if let Value::Object(fields) = comparable_terminal_frame(frame) {
            object.extend(fields);
        }
        observations.push(Value::Object(object));
    }
    for frame in array(capture, "rendered_frames") {
        let mut object = Map::new();
        object.insert("kind".into(), json!("rendered"));
        if let Some(fields) = frame.as_object() {
            object.extend(fields.clone());
        }
        observations.push(Value::Object(object));
    }
    // Stable sort: time, raw before rendered, then sequence.
    observations.sort_by(|left, right| {
        let time = number(left, "at_ms") - number(right, "at_ms");
        if time != 0.0 {
            return time.partial_cmp(&0.0).unwrap_or(std::cmp::Ordering::Equal);
        }
        let left_kind = text(left, "kind");
        let right_kind = text(right, "kind");
        if left_kind != right_kind {
            return if left_kind == Some("raw") {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            };
        }
        (number(left, "sequence") - number(right, "sequence"))
            .partial_cmp(&0.0)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    observations
}

fn exit_observation(capture: &Value) -> Value {
    let mut object = capture["exit"].as_object().cloned().unwrap_or_default();
    object.insert("settlement".into(), capture["settlement"].clone());
    Value::Object(object)
}

/// `processDimensionObservations`.
fn observations(capture: &Value, dimension: &str) -> Vec<Value> {
    match dimension {
        "terminal" => terminal_observations(capture),
        "interaction" => array(capture, "interaction_events").to_vec(),
        "exit" => vec![exit_observation(capture)],
        "filesystem" => array(capture, "filesystem_checkpoints").to_vec(),
        _ => array(capture, "process_samples").to_vec(),
    }
}

fn classify_collection(left: &[Value], right: &[Value]) -> &'static str {
    if same(&Value::Array(left.to_vec()), &Value::Array(right.to_vec())) {
        "unchanged"
    } else if left.is_empty() {
        "added"
    } else if right.is_empty() {
        "removed"
    } else {
        "changed"
    }
}

fn has_unknown(capture: &Value, scope: &str) -> bool {
    array(capture, "residual_unknowns")
        .iter()
        .any(|unknown| text(unknown, "scope") == Some(scope))
}

fn compare_dimensions(left: &Value, right: &Value, same_normalization: bool) -> Dimensions {
    let classify = |scope: &str, dimension: &str, source: &str| {
        if !same_normalization
            || has_unknown(left, scope)
            || has_unknown(right, scope)
            || source_truncated(left, source)
            || source_truncated(right, source)
        {
            "unknown"
        } else {
            classify_collection(
                &observations(left, dimension),
                &observations(right, dimension),
            )
        }
    };
    let exit = if has_unknown(left, "exit") || has_unknown(right, "exit") {
        "unknown"
    } else if same(
        &json!({ "exit": left["exit"], "settlement": left["settlement"] }),
        &json!({ "exit": right["exit"], "settlement": right["settlement"] }),
    ) {
        "unchanged"
    } else {
        "changed"
    };
    Dimensions([
        classify("terminal", "terminal", "terminal_rendered"),
        classify("interaction", "interaction", "interaction"),
        exit,
        classify("filesystem", "filesystem", "filesystem"),
        classify("process", "process", "process"),
    ])
}

fn trace_dimensions(sources: &HashSet<&str>) -> HashSet<&'static str> {
    sources
        .iter()
        .filter_map(|source| {
            if source.starts_with("terminal_") {
                Some("terminal")
            } else {
                match *source {
                    "interaction" => Some("interaction"),
                    "lifecycle" => Some("exit"),
                    "filesystem" => Some("filesystem"),
                    "process" => Some("process"),
                    _ => None,
                }
            }
        })
        .collect()
}

fn covers_observed(dimension: &str, sources: &HashSet<&str>, left: &Value, right: &Value) -> bool {
    let any = |key: &str| !array(left, key).is_empty() || !array(right, key).is_empty();
    match dimension {
        "terminal" => {
            (!any("frames") || sources.contains("terminal_raw"))
                && (!any("rendered_frames") || sources.contains("terminal_rendered"))
        }
        "interaction" => sources.contains("interaction"),
        "exit" => sources.contains("lifecycle"),
        "filesystem" => sources.contains("filesystem"),
        _ => sources.contains("process"),
    }
}

fn location_source(collection: &str) -> &'static str {
    match collection {
        "frames" => "terminal_raw",
        "rendered_frames" => "terminal_rendered",
        "interaction_events" => "interaction",
        "lifecycle" => "lifecycle",
        "process_samples" => "process",
        _ => "filesystem",
    }
}

fn apply_trace_verdict(
    exact: &Dimensions,
    spec: &Specification,
    trace: &TraceComparison,
    left: &Value,
    right: &Value,
) -> Dimensions {
    let shows_difference = trace.outcomes_differ();
    let trace_status = if trace.verdict == "unknown" {
        "unknown"
    } else if trace.verdict == "equivalent" || !shows_difference {
        "unchanged"
    } else {
        "changed"
    };
    let sources = eval::sources(spec).into_iter().collect::<HashSet<_>>();
    let covered = trace_dimensions(&sources);
    let mut diagnostic_sources = HashSet::new();
    if let Some((_, diagnostic)) = &trace.diagnostic {
        for event in &spec.events {
            if diagnostic.event_ids.contains(&event.id) {
                diagnostic_sources.insert(event.source.as_str());
            }
        }
        for location in &diagnostic.locations {
            diagnostic_sources.insert(location_source(&location.collection));
        }
    }
    let attributed = if diagnostic_sources.is_empty() {
        covered.clone()
    } else {
        trace_dimensions(&diagnostic_sources)
    };
    let status_for = |dimension: &str| -> &'static str {
        let exact = exact.get(dimension);
        if !covered.contains(dimension) || trace.verdict == "nonconforming" {
            return exact;
        }
        if trace.verdict == "different" {
            return if shows_difference && attributed.contains(dimension) {
                "changed"
            } else {
                exact
            };
        }
        if trace.verdict == "unknown" && matches!(exact, "changed" | "added" | "removed") {
            return exact;
        }
        if covers_observed(dimension, &sources, left, right) {
            trace_status
        } else {
            exact
        }
    };
    Dimensions(DIMENSIONS.map(status_for))
}

fn event_time(dimension: &str, value: &Value) -> Option<i64> {
    let key = if dimension == "interaction" {
        "dispatched_at_ms"
    } else {
        "at_ms"
    };
    value
        .as_object()
        .and_then(|object| object.get(key))
        .and_then(safe_integer)
        .filter(|time| *time >= 0)
}

fn first_collection_divergence(
    dimension: &'static str,
    left: &[Value],
    right: &[Value],
) -> Option<Value> {
    let length = left.len().max(right.len());
    for index in 0..length {
        let left_value = left.get(index).cloned().unwrap_or(Value::Null);
        let right_value = right.get(index).cloned().unwrap_or(Value::Null);
        if same(&left_value, &right_value) {
            continue;
        }
        return Some(json!({
            "status": "found",
            "dimension": dimension,
            "index": index,
            "left_at_ms": event_time(dimension, &left_value),
            "right_at_ms": event_time(dimension, &right_value),
            "left": left_value,
            "right": right_value,
        }));
    }
    None
}

fn choose_first(candidates: Vec<Value>) -> Value {
    const MAX_SAFE: i64 = 9_007_199_254_740_991;
    let time = |candidate: &Value| {
        let left = candidate["left_at_ms"].as_i64().unwrap_or(MAX_SAFE);
        let right = candidate["right_at_ms"].as_i64().unwrap_or(MAX_SAFE);
        left.min(right)
    };
    let mut candidates = candidates;
    candidates.sort_by_key(time);
    candidates
        .into_iter()
        .next()
        .unwrap_or_else(|| json!({ "status": "none" }))
}

fn differing_contract_fields(left: &Value, right: &Value) -> Vec<String> {
    let empty = Map::new();
    let left = left.as_object().unwrap_or(&empty);
    let right = right.as_object().unwrap_or(&empty);
    let mut fields = left
        .keys()
        .chain(right.keys())
        .cloned()
        .collect::<HashSet<_>>()
        .into_iter()
        .filter(|field| match (left.get(field), right.get(field)) {
            (Some(left), Some(right)) => canonical(left) != canonical(right),
            _ => true,
        })
        .collect::<Vec<_>>();
    fields.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
    fields
}

/// Milliseconds since the epoch for a validated `z.iso.datetime()` value
/// (`Date.parse`).
pub fn parse_timestamp_ms(text: &str) -> Option<i64> {
    let body = text.strip_suffix('Z')?;
    let number = |range: std::ops::Range<usize>| body.get(range)?.parse::<i64>().ok();
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute) = (number(11..13)?, number(14..16)?);
    let rest = body.get(16..)?;
    let (second, millisecond) = match rest.strip_prefix(':') {
        None => (0, 0),
        Some(seconds) => {
            let second = seconds.get(0..2)?.parse::<i64>().ok()?;
            let fraction = seconds.get(2..)?.strip_prefix('.').unwrap_or("");
            let digits = format!("{fraction:0<3}");
            (second, digits.get(0..3)?.parse::<i64>().ok()?)
        }
    };
    // Days from the civil calendar (Howard Hinnant's algorithm).
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000 + millisecond)
}

fn assert_comparable(
    left: &Value,
    right: &Value,
    max_capture_age_ms: Option<u64>,
    now_ms: i64,
) -> Result<(), AnalysisError> {
    let left_manifest = &left["manifest"];
    let right_manifest = &right["manifest"];
    if left_manifest["comparison_contract_sha256"] != right_manifest["comparison_contract_sha256"] {
        let fields = differing_contract_fields(
            &left_manifest["comparison_contract"],
            &right_manifest["comparison_contract"],
        );
        let message = format!(
            "Process captures have incompatible comparison contracts{}. Capture both scenarios with the same values for these fields, then compare them.",
            if fields.is_empty() {
                String::new()
            } else {
                format!("; these scenario fields differ: {}", fields.join(", "))
            }
        );
        return Err(AnalysisError::input(
            OPERATION,
            vec![InputIssue {
                path: vec![json!("right")],
                reason: "invalid_value",
                message: Some(message),
                expected: Some(json!(fields)),
                minimum: None,
                maximum: None,
            }],
        ));
    }
    let Some(maximum) = max_capture_age_ms else {
        return Ok(());
    };
    let stale = [("left", left_manifest), ("right", right_manifest)]
        .into_iter()
        .filter_map(|(side, manifest)| {
            let completed = text(manifest, "completed_at").unwrap_or_default();
            // `Date.parse` of an unparsable value is NaN; `NaN > max` is false.
            let age = now_ms - parse_timestamp_ms(completed)?;
            (age > maximum as i64)
                .then(|| format!("{side} completed at {completed} ({age} ms ago)"))
        })
        .collect::<Vec<_>>();
    if stale.is_empty() {
        return Ok(());
    }
    Err(AnalysisError::input(
        OPERATION,
        vec![InputIssue {
            path: vec![json!("max_capture_age_ms")],
            reason: "out_of_range",
            message: Some(format!(
                "Process capture exceeds max_capture_age_ms {maximum}: {}. Recapture the stale scenario or raise max_capture_age_ms.",
                stale.join("; ")
            )),
            expected: None,
            minimum: None,
            maximum: None,
        }],
    ))
}

/// The derived comparison and its status summary.
pub struct Comparison {
    pub value: Value,
    pub status: &'static str,
    pub dimensions: Dimensions,
    pub limitations: Vec<String>,
}

/// `compareProcessCaptures`.
pub fn compare(
    left: &Value,
    right: &Value,
    max_capture_age_ms: Option<u64>,
    now_ms: i64,
    spec: Option<&Specification>,
) -> Result<Comparison, AnalysisError> {
    assert_comparable(left, right, max_capture_age_ms, now_ms)?;
    let same_normalization = same(&left["normalization"], &right["normalization"]);
    let exact = compare_dimensions(left, right, same_normalization);
    let trace = spec.map(|spec| eval::compare(left, right, spec));
    let dimensions = match (&trace, spec) {
        (Some(trace), Some(spec)) => apply_trace_verdict(&exact, spec, trace, left, right),
        _ => exact,
    };
    let equivalent = trace
        .as_ref()
        .is_some_and(|trace| trace.verdict == "equivalent");
    let candidates = DIMENSIONS
        .iter()
        .filter(|dimension| dimensions.get(dimension) != "unknown")
        .filter_map(|dimension| {
            first_collection_divergence(
                dimension,
                &observations(left, dimension),
                &observations(right, dimension),
            )
        })
        .filter(|candidate| {
            !(equivalent
                && candidate["dimension"]
                    .as_str()
                    .is_some_and(|dimension| dimensions.get(dimension) == "unchanged"))
        })
        .collect::<Vec<_>>();
    let observed_first = choose_first(candidates);
    let status = derive_status(&dimensions.0);
    let has_residual = !array(left, "residual_unknowns").is_empty()
        || !array(right, "residual_unknowns").is_empty();
    let first_divergence = if left["truncated"] == json!(true) || right["truncated"] == json!(true)
    {
        json!({
            "status": "unknown",
            "reason": "Incomplete observations prevent locating the first divergence; unaffected dimensions retain their comparisons.",
        })
    } else if equivalent && status == "unchanged" {
        json!({ "status": "none" })
    } else if observed_first["status"] == "found" {
        observed_first
    } else if !same_normalization || has_residual {
        json!({
            "status": "unknown",
            "reason": "Residual unknowns prevent proving that no divergence occurred.",
        })
    } else {
        observed_first
    };
    let mut limitations = Vec::new();
    for capture in [left, right] {
        limitations.extend(
            array(capture, "limitations")
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned),
        );
    }
    for capture in [left, right] {
        limitations.extend(
            array(capture, "residual_unknowns")
                .iter()
                .filter_map(|unknown| text(unknown, "reason"))
                .map(str::to_owned),
        );
    }
    if !same_normalization {
        limitations.push("Capture normalization rules differ.".to_owned());
    }
    let mut value = Map::new();
    value.insert("status".into(), json!(status));
    for (dimension, dimension_status) in DIMENSIONS.iter().zip(dimensions.0) {
        value.insert((*dimension).to_owned(), json!(dimension_status));
    }
    value.insert("first_divergence".into(), first_divergence);
    if let Some(trace) = &trace {
        value.insert("trace".into(), trace.to_value());
    }
    value.insert("limitations".into(), json!(limitations));
    Ok(Comparison {
        value: Value::Object(value),
        status,
        dimensions,
        limitations,
    })
}
