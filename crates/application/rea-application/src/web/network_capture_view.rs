//! Views over retained web-network capture Evidence.
//!
//! This module only pages facts already authenticated by the capture
//! producer. It never reopens a capture, contacts a recorded destination, or
//! attempts to recover omitted payloads.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_analysis_view";
const CAPTURE_OPERATION: &str = "inspect_web_network_capture";

pub fn project(parent: &Value, view: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    if view.get("kind").and_then(Value::as_str) == Some("qlog") {
        return crate::pcap::qlog_capture_view::project(parent, view);
    }

    let raw =
        serde_json::value::to_raw_value(parent).map_err(|error| invalid(&error.to_string()))?;
    let record = EvidenceRecord::parse(&raw).map_err(|error| invalid(&error.to_string()))?;

    if !record.operation_matches(CAPTURE_OPERATION) {
        return Err(invalid(
            "Web network capture views require inspect_web_network_capture Evidence.",
        ));
    }

    let report: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| invalid(&format!("capture normalized result is invalid: {error}")))?;
    validate_parent_subject(&record, &report)?;
    let body = project_body(&record, &report, view)?;

    let unsigned = json!({
        "subject": null,
        "provider": {"id":"analysis-view","name":"REA retained analysis view","version":"1"},
        "analysis_profile": null,
        "predicate_type":"rea.analysis-view",
        "operation":OPERATION,
        "parameters":{"parent_evidence_id":record.evidence_id(),"view":view},
        "raw_result":null,
        "normalized_result":body,
        "confidence":"derived",
        "authority":"analyst-inference",
        "environment":null,
        "limitations":[],
        "relationship_coverage":null,
        "locations":[],
        "evidence_links":[record.evidence_id()]
    });
    let unsigned_raw =
        serde_json::value::to_raw_value(&unsigned).map_err(|error| invalid(&error.to_string()))?;
    let derived = EvidenceRecord::create_unsigned(&unsigned_raw)
        .map_err(|error| invalid(&error.to_string()))?;
    Ok(
        serde_json::value::RawValue::from_string(derived.raw().get().to_owned())
            .expect("validated Evidence"),
    )
}

fn validate_parent_subject(record: &EvidenceRecord, report: &Value) -> Result<(), Failure> {
    let digest = report["artifact"]["sha256"].as_str();
    if digest.is_none() {
        return Ok(());
    }
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let matches = subject["local_path"].as_str() == report["artifact"]["path"].as_str()
        && subject["digest"]["sha256"].as_str() == digest;
    if matches {
        Ok(())
    } else {
        Err(invalid(
            "Capture parent subject must identify the report's exact path and SHA-256.",
        ))
    }
}

fn project_body(record: &EvidenceRecord, report: &Value, view: &Value) -> Result<Value, Failure> {
    let shared = shared_context(record, report);
    match view["kind"].as_str() {
        Some("summary") => Ok(summary(report, shared)),
        Some("capture") => capture_page(report, view, shared),
        _ => Err(invalid(
            "Historical captures support summary, capture, and qlog views.",
        )),
    }
}

fn shared_context(record: &EvidenceRecord, report: &Value) -> Value {
    let mut limitations = report["limitations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    limitations.push(json!("Capture record pages cover records selected into the parent Evidence, in selected order; total_records counts the original decoded capture."));
    let mut unknowns = vec![json!(
        "Historical records do not establish live runtime attribution or deployment authenticity."
    )];
    if report["artifact"]["sha256"].is_null() {
        unknowns.push(json!(
            "The explicitly excluded artifact digest remains unknown."
        ));
    }
    json!({
        "parent_evidence_id":record.evidence_id(),
        "parent_operation":CAPTURE_OPERATION,
        "parent_digest":record.evidence_id().strip_prefix("ev_").unwrap_or(record.evidence_id()),
        "artifact":{"path":report["artifact"]["path"],"sha256":report["artifact"]["sha256"]},
        "limitations":deduplicate_values(limitations),
        "unknowns":unknowns
    })
}

fn summary(report: &Value, shared: Value) -> Value {
    let mut body = json!({
        "kind":"summary",
        "view":{"kind":"summary"},
        "summary":{
            "artifact":report["artifact"],
            "decoder":report["decoder"],
            "format":report["format"],
            "total_records":report["total_records"],
            "retained_records":report["records"].as_array().map_or(0, Vec::len),
            "runtime_attribution":report["runtime_attribution"]
        },
        "coverage":complete_coverage(report["records"].as_array().map_or(0, Vec::len))
    });
    if report["format"] == "qlog" {
        body["summary"]["qlog"] = qlog_summary(report.get("qlog"));
    }
    merge_shared(&mut body, shared);
    body
}

fn capture_page(report: &Value, view: &Value, shared: Value) -> Result<Value, Failure> {
    let records = report["records"]
        .as_array()
        .ok_or_else(|| invalid("Capture records are missing."))?;
    let offset = page_number(view, "offset");
    let limit = page_limit(view)?;
    let detail = view["detail"].as_str().unwrap_or("preview");
    if detail != "preview" && detail != "complete" {
        return Err(invalid("Capture detail must be preview or complete."));
    }
    let items = records
        .iter()
        .skip(offset)
        .take(limit)
        .map(|record| {
            if detail == "complete" {
                record.clone()
            } else {
                preview_record(record, report["format"].as_str().unwrap_or(""))
            }
        })
        .collect::<Vec<_>>();
    let mut body = json!({
        "kind":"capture","view":view,"items":items,
        "coverage":page_coverage(offset, items.len(), records.len())
    });
    merge_shared(&mut body, shared);
    if detail == "preview" {
        body["limitations"].as_array_mut().expect("shared limitations array").push(json!("Preview selects recorded headline fields and byte descriptors; headers, bodies, message data and other fields remain in complete record pages."));
    }
    Ok(body)
}

fn preview_record(record: &Value, format: &str) -> Value {
    let Some(object) = record.as_object() else {
        return record.clone();
    };
    let mut preview = object.clone();
    if let Some(reported) = object.get("reported") {
        preview.insert("reported".into(), preview_reported(reported, format));
    }
    if let Some(fields) = preview
        .get_mut("binary_fields")
        .and_then(Value::as_array_mut)
    {
        for field in fields {
            field.as_object_mut().map(|object| {
                object.remove("content_base64");
            });
        }
    }
    if let Some(literals) = preview.get("numeric_literals").and_then(Value::as_array) {
        preview.insert(
            "numeric_literals".into(),
            Value::Array(
                literals
                    .iter()
                    .filter(|literal| preview_pointer(literal, &preview["reported"]))
                    .cloned()
                    .collect(),
            ),
        );
    }
    Value::Object(preview)
}

fn preview_reported(value: &Value, format: &str) -> Value {
    let Some(source) = value.as_object() else {
        return value.clone();
    };
    let mut selected = Map::new();
    for key in ["session_id", "name", "time", "startedDateTime", "type"] {
        if let Some(value) = source.get(key) {
            selected.insert(key.into(), value.clone());
        }
    }
    for key in ["request", "response"] {
        let Some(fields) = source.get(key).and_then(Value::as_object) else {
            continue;
        };
        let names: &[&str] = if format == "mitmproxy" && key == "request" {
            &[
                "method",
                "scheme",
                "host",
                "port",
                "authority",
                "path",
                "url",
                "http_version",
            ]
        } else if format == "mitmproxy" && key == "response" {
            &["status", "statusText", "reason", "status_code"]
        } else {
            &[
                "method",
                "url",
                "httpVersion",
                "http_version",
                "status",
                "statusText",
                "reason",
            ]
        };
        let mut selected_fields = Map::new();
        for name in names {
            if let Some(value) = fields.get(*name) {
                if preview_value_is_safe(name, value) {
                    selected_fields.insert((*name).into(), value.clone());
                }
            }
        }
        selected.insert(key.into(), Value::Object(selected_fields));
    }
    Value::Object(selected)
}

fn preview_value_is_safe(field: &str, value: &Value) -> bool {
    match field {
        "port" => value.as_u64().is_some_and(|v| v <= 65_535),
        "status_code" => value.as_u64().is_some_and(|v| (100..=999).contains(&v)),
        "path" => value
            .as_str()
            .is_some_and(|v| v.len() <= 2048 && v.starts_with('/') && !v.contains('@')),
        _ => value.is_string() || value.is_number(),
    }
}

fn preview_pointer(value: &Value, reported: &Value) -> bool {
    value["pointer"]
        .as_str()
        .is_some_and(|pointer| pointer == "/" || reported_pointer_exists(reported, pointer))
}
fn reported_pointer_exists(value: &Value, pointer: &str) -> bool {
    pointer
        .strip_prefix('/')
        .and_then(|path| {
            path.split('/')
                .try_fold(value, |current, key| current.get(key))
        })
        .is_some()
}

fn qlog_summary(qlog: Option<&Value>) -> Value {
    let qlog = qlog.unwrap_or(&Value::Null);
    let traces = qlog["traces"].as_array().cloned().unwrap_or_default();
    json!({"trace_count":traces.len(),"retained_stream_count":traces.iter().map(|t| t["streams"].as_array().map_or(0, Vec::len)).sum::<usize>(),"loss_declaration_count":traces.iter().map(|t| t["loss_declarations"].as_array().map_or(0, Vec::len)).sum::<usize>(),"incomplete_fact_record_count":traces.iter().map(|t| t["incomplete_fact_records"].as_array().map_or(0, Vec::len)).sum::<usize>()})
}

fn merge_shared(body: &mut Value, shared: Value) {
    if let (Some(body), Some(shared)) = (body.as_object_mut(), shared.as_object()) {
        body.extend(shared.clone());
    }
}
fn deduplicate_values(values: Vec<Value>) -> Vec<Value> {
    let mut result = Vec::new();
    for value in values {
        if !result.contains(&value) {
            result.push(value);
        }
    }
    result
}
fn page_number(view: &Value, key: &str) -> usize {
    view[key].as_u64().unwrap_or(0) as usize
}
fn page_limit(view: &Value) -> Result<usize, Failure> {
    let limit = view["limit"].as_u64().unwrap_or(64) as usize;
    if limit == 0 {
        Err(invalid("View limit must be positive."))
    } else {
        Ok(limit)
    }
}
fn complete_coverage(total: usize) -> Value {
    json!({"status":"complete-within-view","examined":total,"total":total,"next_offset":null,"exhausted":true})
}
fn page_coverage(offset: usize, examined: usize, total: usize) -> Value {
    let exhausted = offset >= total || offset.saturating_add(examined) >= total;
    json!({"status":if examined == 0 {"empty"} else {"page"},"examined":examined,"total":total,"next_offset":if exhausted {Value::Null} else {json!(offset + examined)},"exhausted":exhausted})
}
fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Correct the view and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(message.into())),
        ]),
    )
}
