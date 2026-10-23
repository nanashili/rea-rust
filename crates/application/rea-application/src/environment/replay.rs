//! Replay of an authenticated environment manifest against retained capture data.
//!
//! This module owns record selection and response projection.  Adapters only provide
//! the already-authenticated manifest, parent capture and caller arguments.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "environment-serve";
const BODY_LIMIT: usize = 256 * 1024;
const METADATA_LIMIT: usize = 1024;

pub fn replay(
    manifest: &Value,
    capture: &Value,
    tool_name: &str,
    arguments: &Value,
    evidence_id: &str,
) -> Result<Value, Failure> {
    let tool = manifest
        .get("tools")
        .and_then(Value::as_array)
        .and_then(|tools| tools.iter().find(|tool| tool["name"] == tool_name))
        .ok_or_else(|| invalid("tool is not present in the environment manifest"))?;
    let records = capture
        .get("records")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("retained capture has no records"))?;
    let ordinals = tool["record_ordinals"]
        .as_array()
        .ok_or_else(|| invalid("manifest tool has no record ordinals"))?;
    let selected = ordinals
        .iter()
        .filter_map(Value::as_u64)
        .filter_map(|ordinal| records.iter().find(|record| record["ordinal"] == ordinal))
        .map(|record| (record, score(record, tool, arguments)))
        .max_by_key(|(_, score)| *score)
        .ok_or_else(|| invalid("tool cites no retained record to replay"))?;
    let record = selected.0;
    let request = record.get("reported").unwrap_or(record);
    let response = request.get("response").unwrap_or(&Value::Null);
    let content = response.get("content").unwrap_or(&Value::Null);
    let body = content.get("text").cloned().unwrap_or(Value::Null);
    let body = truncate_body(body);
    let path = request
        .get("request")
        .and_then(|request| request.get("url"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let status = response.get("status").cloned().unwrap_or(Value::Null);
    let content_type = content.get("mimeType").cloned().unwrap_or(Value::Null);
    Ok(json!({
        "status": status,
        "content_type": truncate_metadata(content_type),
        "body": body.0,
        "replay": {
            "record_ordinal": record["ordinal"],
            "evidence_id": evidence_id,
            "exact_match": selected.1 > 0,
            "recorded_path": truncate_metadata(Value::String(path.to_owned())),
            "recorded_query": Value::Null,
            "recorded_line_truncated": path.len() > METADATA_LIMIT,
            "content_type_truncated": false,
            "body_recorded": !content.get("text").unwrap_or(&Value::Null).is_null(),
            "body_encoding": "utf-8",
            "truncated": body.1,
        }
    }))
}

fn score(record: &Value, tool: &Value, arguments: &Value) -> usize {
    let url = record
        .pointer("/reported/request/url")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let template = tool["path_template"].as_str().unwrap_or_default();
    let mut score = usize::from(
        record.pointer("/reported/request/method") == tool.get("method")
            || record
                .pointer("/reported/request/method")
                .and_then(Value::as_str)
                == tool.get("method").and_then(Value::as_str),
    );
    if template.is_empty() || url.contains(template.trim_start_matches('/')) {
        score += 1;
    }
    if let Some(object) = arguments.as_object() {
        for value in object.values().filter_map(Value::as_str) {
            if url.contains(value) {
                score += 1;
            }
        }
    }
    score
}

fn truncate_metadata(value: Value) -> Value {
    match value {
        Value::String(text) => Value::String(text.chars().take(METADATA_LIMIT).collect()),
        other => other,
    }
}

fn truncate_body(value: Value) -> (Value, bool) {
    match value {
        Value::String(text) => {
            let truncated = text.len() > BODY_LIMIT;
            (
                Value::String(text.chars().take(BODY_LIMIT).collect()),
                truncated,
            )
        }
        other => (other, false),
    }
}

fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Correct the environment manifest, retained capture and arguments, then retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("reason".into(), Detail::Text(message.into())),
        ]),
    )
}
