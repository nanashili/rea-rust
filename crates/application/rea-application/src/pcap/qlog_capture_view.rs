//! Bounded views over retained qlog capture facts.
//!
//! The producer has already decoded and retained the qlog facts.  This module
//! only selects those facts; it never reopens the capture or interprets event
//! records a second time.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_analysis_view";
const PARENT_OPERATION: &str = "inspect_web_network_capture";

/// Project one qlog facet from retained capture Evidence.
pub fn project(parent: &Value, view: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let raw =
        serde_json::value::to_raw_value(parent).map_err(|error| invalid(&error.to_string()))?;
    let record = EvidenceRecord::parse(&raw).map_err(|error| invalid(&error.to_string()))?;

    if !record.operation_matches(PARENT_OPERATION) {
        return Err(invalid(
            "Qlog views require inspect_web_network_capture Evidence.",
        ));
    }

    let capture: Value =
        serde_json::from_str(record.normalized_result().get()).map_err(|error| {
            invalid(&format!(
                "web capture normalized result is invalid: {error}"
            ))
        })?;
    let qlog = capture
        .get("qlog")
        .ok_or_else(|| invalid("Qlog views require retained qlog facts."))?;
    validate_qlog_capture(&capture, qlog)?;

    let requested = parse_view(view)?;
    let (page, total) = project_page(qlog, &requested)?;
    let examined = page_len(&page);
    let mut body = json!({
        "kind": "qlog",
        "view": requested.normalized,
        "context": qlog_context(qlog),
        "page": page,
        "coverage": page_coverage(requested.offset, examined, total),
        "parent_evidence_id": record.evidence_id(),
        "parent_operation": PARENT_OPERATION,
        "parent_digest": record.evidence_id().strip_prefix("ev_").unwrap_or(record.evidence_id()),
        "artifact": {
            "path": capture["artifact"]["path"],
            "sha256": capture["artifact"]["sha256"],
        },
        "limitations": [
            "Qlog fact pages retain all-recorded-events-before-selection scope. Exhausting a page does not establish network completeness, body recovery, retransmission or actual loss."
        ],
        "unknowns": [
            "Qlog lengths and FIN do not expose original HTTP body bytes or establish network completeness."
        ],
    });
    extend_parent_limitations(&mut body, parent, &capture);

    create_view_evidence(&record, view, body)
}

struct RequestedView {
    facet: String,
    trace_index: Option<u64>,
    stream_id: Option<String>,
    direction: Option<String>,
    offset: usize,
    limit: usize,
    normalized: Value,
}

fn parse_view(view: &Value) -> Result<RequestedView, Failure> {
    let object = view
        .as_object()
        .ok_or_else(|| invalid("Qlog view must be an object."))?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "kind" | "facet" | "trace_index" | "stream_id" | "direction" | "offset" | "limit"
        ) {
            return Err(invalid("Qlog view contains an unknown field."));
        }
    }
    if object.get("kind").and_then(Value::as_str) != Some("qlog") {
        return Err(invalid("Qlog view kind must be qlog."));
    }

    let facet = object
        .get("facet")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Qlog view facet is required."))?;
    if !matches!(
        facet,
        "traces"
            | "streams"
            | "loss-declarations"
            | "incomplete-records"
            | "contributions"
            | "ranges"
            | "final-sizes"
    ) {
        return Err(invalid("Unknown qlog view facet."));
    }

    let offset = parse_nonnegative(object.get("offset"), "offset")?.unwrap_or(0);
    let limit = parse_nonnegative(object.get("limit"), "limit")?.unwrap_or(64);
    if limit == 0 {
        return Err(invalid("Qlog view limit must be positive."));
    }

    let trace_index = object
        .get("trace_index")
        .map(parse_trace_index)
        .transpose()?;
    let stream_id = object
        .get("stream_id")
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| invalid("stream_id must be a non-empty string."))
        })
        .transpose()?;
    let direction = object
        .get("direction")
        .map(|value| {
            let direction = value
                .as_str()
                .ok_or_else(|| invalid("direction must be a string."))?;
            if !matches!(direction, "sent" | "received") {
                return Err(invalid("direction must be sent or received."));
            }
            Ok(direction.to_owned())
        })
        .transpose()?;

    let needs_trace = facet != "traces";
    if needs_trace && trace_index.is_none() {
        return Err(invalid("This qlog facet requires trace_index."));
    }
    let needs_stream = matches!(facet, "contributions" | "ranges" | "final-sizes");
    if needs_stream && (stream_id.is_none() || direction.is_none()) {
        return Err(invalid("This qlog facet requires stream_id and direction."));
    }
    if !needs_stream && (stream_id.is_some() || direction.is_some()) {
        return Err(invalid(
            "stream_id and direction are only valid for stream fact facets.",
        ));
    }

    let mut normalized = Map::new();
    normalized.insert("kind".into(), json!("qlog"));
    normalized.insert("facet".into(), json!(facet));
    normalized.insert("offset".into(), json!(offset));
    normalized.insert("limit".into(), json!(limit));
    if let Some(trace_index) = trace_index {
        normalized.insert("trace_index".into(), json!(trace_index));
    }
    if let Some(stream_id) = &stream_id {
        normalized.insert("stream_id".into(), json!(stream_id));
    }
    if let Some(direction) = &direction {
        normalized.insert("direction".into(), json!(direction));
    }
    Ok(RequestedView {
        facet: facet.to_owned(),
        trace_index,
        stream_id,
        direction,
        offset,
        limit,
        normalized: Value::Object(normalized),
    })
}

fn parse_nonnegative(value: Option<&Value>, name: &str) -> Result<Option<usize>, Failure> {
    let Some(value) = value else { return Ok(None) };
    let number = value
        .as_u64()
        .ok_or_else(|| invalid(&format!("Qlog view {name} must be non-negative.")))?;
    usize::try_from(number)
        .map(Some)
        .map_err(|_| invalid(&format!("Qlog view {name} is too large.")))
}

fn parse_trace_index(value: &Value) -> Result<u64, Failure> {
    value
        .as_u64()
        .ok_or_else(|| invalid("trace_index must be a non-negative integer."))
}

fn validate_qlog_capture(capture: &Value, qlog: &Value) -> Result<(), Failure> {
    if capture.get("format").and_then(Value::as_str) != Some("qlog") {
        return Err(invalid("Qlog views require a qlog capture."));
    }
    if qlog.get("profile").and_then(Value::as_str) != Some("aioquic-1.5.0-json-0.3")
        || qlog.get("scope").and_then(Value::as_str) != Some("all-recorded-events-before-selection")
        || qlog.get("traces").and_then(Value::as_array).is_none()
    {
        return Err(invalid("Retained qlog facts have an unsupported shape."));
    }
    if capture
        .get("artifact")
        .and_then(Value::as_object)
        .and_then(|artifact| artifact.get("path"))
        .and_then(Value::as_str)
        .is_none()
    {
        return Err(invalid("Qlog capture artifact path is missing."));
    }
    Ok(())
}

fn project_page(qlog: &Value, view: &RequestedView) -> Result<(Value, usize), Failure> {
    let traces = qlog["traces"].as_array().expect("validated qlog traces");
    if view.facet == "traces" {
        let items = traces
            .iter()
            .skip(view.offset)
            .take(view.limit)
            .map(summarize_trace)
            .collect::<Vec<_>>();
        return Ok((json!({"facet": "traces", "items": items}), traces.len()));
    }

    let trace = select_trace(traces, view.trace_index.expect("trace selector validated"))?;
    let (items, total) = match view.facet.as_str() {
        "streams" => {
            let rows = trace["streams"]
                .as_array()
                .ok_or_else(|| invalid("Retained qlog trace streams are missing."))?;
            (
                rows.iter()
                    .skip(view.offset)
                    .take(view.limit)
                    .map(summarize_stream)
                    .collect(),
                rows.len(),
            )
        }
        "loss-declarations" => page_array(trace, "loss_declarations", view)?,
        "incomplete-records" => page_array(trace, "incomplete_fact_records", view)?,
        "contributions" | "ranges" | "final-sizes" => {
            let stream = select_stream(trace, view)?;
            let field = match view.facet.as_str() {
                "contributions" => "contributions",
                "ranges" => "covered_ranges",
                _ => "reported_final_sizes",
            };
            page_array(stream, field, view)?
        }
        _ => return Err(invalid("Unknown qlog view facet.")),
    };
    Ok((json!({"facet": view.facet, "items": items}), total))
}

fn page_array<'a>(
    object: &'a Value,
    field: &str,
    view: &RequestedView,
) -> Result<(Vec<Value>, usize), Failure> {
    let rows = object
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("Retained qlog fact array is missing."))?;
    Ok((
        rows.iter()
            .skip(view.offset)
            .take(view.limit)
            .cloned()
            .collect(),
        rows.len(),
    ))
}

fn select_trace<'a>(traces: &'a [Value], index: u64) -> Result<&'a Value, Failure> {
    let matches = traces
        .iter()
        .filter(|trace| trace["trace_index"].as_u64() == Some(index))
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        Ok(matches[0])
    } else {
        Err(invalid("Select one unambiguous retained trace index."))
    }
}

fn select_stream<'a>(trace: &'a Value, view: &RequestedView) -> Result<&'a Value, Failure> {
    let streams = trace["streams"]
        .as_array()
        .ok_or_else(|| invalid("Retained qlog trace streams are missing."))?;
    let matches = streams
        .iter()
        .filter(|stream| {
            stream["stream_id"].as_str() == view.stream_id.as_deref()
                && stream["direction"].as_str() == view.direction.as_deref()
        })
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        Ok(matches[0])
    } else {
        Err(invalid(
            "Select one unambiguous retained stream ID and direction within the trace.",
        ))
    }
}

fn summarize_trace(trace: &Value) -> Value {
    let mut summary = trace.as_object().cloned().unwrap_or_default();
    let streams = summary
        .remove("streams")
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let losses = summary
        .remove("loss_declarations")
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let incomplete = summary
        .remove("incomplete_fact_records")
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    summary.insert("stream_count".into(), json!(streams.len()));
    summary.insert("loss_declaration_count".into(), json!(losses.len()));
    summary.insert(
        "incomplete_fact_record_count".into(),
        json!(incomplete.len()),
    );
    Value::Object(summary)
}

fn summarize_stream(stream: &Value) -> Value {
    let mut summary = stream.as_object().cloned().unwrap_or_default();
    let contributions = summary
        .remove("contributions")
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let ranges = summary
        .remove("covered_ranges")
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let sizes = summary
        .remove("reported_final_sizes")
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    summary.insert("contribution_count".into(), json!(contributions.len()));
    summary.insert("covered_range_count".into(), json!(ranges.len()));
    summary.insert("reported_final_size_count".into(), json!(sizes.len()));
    Value::Object(summary)
}

fn qlog_context(qlog: &Value) -> Value {
    let mut context = qlog.as_object().cloned().unwrap_or_default();
    context.remove("traces");
    Value::Object(context)
}

fn page_len(page: &Value) -> usize {
    page["items"].as_array().map_or(0, Vec::len)
}

fn page_coverage(offset: usize, examined: usize, total: usize) -> Value {
    let exhausted = offset >= total || offset.saturating_add(examined) >= total;
    json!({
        "status": if examined == 0 { "empty" } else { "page" },
        "examined": examined,
        "total": total,
        "next_offset": if exhausted { Value::Null } else { json!(offset + examined) },
        "exhausted": exhausted,
    })
}

fn extend_parent_limitations(body: &mut Value, parent: &Value, capture: &Value) {
    let mut limitations = Vec::new();
    for source in [parent.get("limitations"), capture.get("limitations")] {
        if let Some(values) = source.and_then(Value::as_array) {
            limitations.extend(values.iter().filter_map(Value::as_str).map(str::to_owned));
        }
    }
    limitations.extend(
        body["limitations"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned),
    );
    limitations.sort();
    limitations.dedup();
    body["limitations"] = json!(limitations);
}

fn create_view_evidence(
    record: &EvidenceRecord,
    view: &Value,
    body: Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let unsigned = json!({
        "subject": null,
        "provider": {"id":"analysis-view","name":"REA retained analysis view","version":"1"},
        "analysis_profile": null,
        "predicate_type": "rea.analysis-view",
        "operation": OPERATION,
        "parameters": {"parent_evidence_id": record.evidence_id(), "view": view},
        "raw_result": null,
        "normalized_result": body,
        "confidence": "derived",
        "authority": "analyst-inference",
        "environment": null,
        "limitations": [],
        "relationship_coverage": null,
        "locations": [],
        "evidence_links": [record.evidence_id()]
    });
    let raw =
        serde_json::value::to_raw_value(&unsigned).map_err(|error| invalid(&error.to_string()))?;
    let derived =
        EvidenceRecord::create_unsigned(&raw).map_err(|error| invalid(&error.to_string()))?;
    Ok(
        serde_json::value::RawValue::from_string(derived.raw().get().to_owned())
            .expect("validated Evidence"),
    )
}

fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Correct the qlog view and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(message.into())),
        ]),
    )
}
