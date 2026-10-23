//! Authenticated, non-rerunning views over retained WASM Evidence.
//!
//! This projection only reads the completed artifact report. It never opens a
//! path, invokes WABT, executes a module, or acquires network content.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

pub const OPERATION: &str = "inspect_analysis_view";
const PARENT_OPERATION: &str = "inspect_wasm_artifact";
const DEFAULT_LIMIT: usize = 64;

/// Project a summary or bounded WASM facet from authenticated retained Evidence.
pub fn project(parent: &Value, view: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let parent_raw =
        serde_json::value::to_raw_value(parent).map_err(|error| invalid(error.to_string()))?;
    let record = EvidenceRecord::parse(&parent_raw).map_err(|error| invalid(error.to_string()))?;
    project_record(&record, view)
}

fn project_record(
    record: &EvidenceRecord,
    view: &Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    if !record.operation_matches(PARENT_OPERATION) {
        return Err(invalid(
            "WASM view requires inspect_wasm_artifact Evidence.",
        ));
    }

    let report: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| invalid(format!("WASM normalized result is invalid: {error}")))?;
    validate_parent_subject(record, &report)?;

    let requested = parse_view(view)?;
    let limitations = merged_limitations(record, &report)?;
    let shared = shared_fields(record, &report, &limitations);
    let body = match requested {
        RequestedView::Summary => summary(&report, &limitations, shared),
        RequestedView::Facet {
            facet: facet_name,
            offset,
            limit,
        } => facet(&report, facet_name, offset, limit, shared)?,
    };

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
    let raw =
        serde_json::value::to_raw_value(&unsigned).map_err(|error| invalid(error.to_string()))?;
    let derived =
        EvidenceRecord::create_unsigned(&raw).map_err(|error| invalid(error.to_string()))?;
    serde_json::value::RawValue::from_string(derived.raw().get().to_owned())
        .map_err(|error| invalid(error.to_string()))
}

enum RequestedView {
    Summary,
    Facet {
        facet: String,
        offset: usize,
        limit: usize,
    },
}

fn parse_view(view: &Value) -> Result<RequestedView, Failure> {
    let object = view
        .as_object()
        .ok_or_else(|| invalid("WASM view must be an object."))?;
    reject_unknown_fields(object, &["kind", "facet", "offset", "limit"])?;
    let kind = required_string(object, "kind")?;

    match kind {
        "summary" => {
            if object.len() != 1 {
                return Err(invalid("Summary WASM view only accepts kind."));
            }
            Ok(RequestedView::Summary)
        }
        "wasm" => {
            let facet = required_string(object, "facet")?;
            if !matches!(
                facet,
                "sections"
                    | "imports"
                    | "exports"
                    | "candidates"
                    | "glue"
                    | "wat"
                    | "headers"
                    | "details"
                    | "tool_profile"
            ) {
                return Err(invalid("Unknown WASM facet."));
            }
            let offset = nonnegative_integer(object, "offset", 0)?;
            let limit = positive_integer(object, "limit", DEFAULT_LIMIT)?;
            Ok(RequestedView::Facet {
                facet: facet.to_owned(),
                offset,
                limit,
            })
        }
        _ => Err(invalid("WASM Evidence supports summary and wasm views.")),
    }
}

fn validate_parent_subject(record: &EvidenceRecord, report: &Value) -> Result<(), Failure> {
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| invalid(format!("WASM Evidence subject is invalid: {error}")))?;
    let artifact = report
        .get("artifact")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("WASM report is missing artifact identity."))?;
    let matches = subject.get("format").and_then(Value::as_str) == Some("file")
        && subject.get("local_path").and_then(Value::as_str)
            == artifact.get("path").and_then(Value::as_str)
        && subject
            .get("digest")
            .and_then(|digest| digest.get("sha256"))
            .and_then(Value::as_str)
            == artifact.get("sha256").and_then(Value::as_str);
    if matches {
        Ok(())
    } else {
        Err(invalid(
            "WASM parent subject must identify the report's exact path and SHA-256.",
        ))
    }
}

fn merged_limitations(record: &EvidenceRecord, report: &Value) -> Result<Vec<String>, Failure> {
    let mut values = BTreeSet::new();
    let parent: Value = serde_json::from_str(record.raw().get())
        .map_err(|error| invalid(format!("WASM Evidence envelope is invalid: {error}")))?;
    let parent_limitations = parent
        .get("limitations")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("WASM Evidence limitations are missing."))?;
    for value in parent_limitations {
        values.insert(required_value_string(value, "WASM Evidence limitation")?);
    }

    let report_limitations = report
        .get("limitations")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("WASM report limitations are missing."))?;
    for value in report_limitations {
        values.insert(required_value_string(value, "WASM limitation")?);
    }

    Ok(values.into_iter().collect())
}

fn shared_fields(record: &EvidenceRecord, report: &Value, limitations: &[String]) -> Value {
    let unknowns = if report
        .get("glue")
        .and_then(Value::as_array)
        .is_some_and(|glue| {
            glue.iter()
                .any(|entry| entry.get("parse_status").and_then(Value::as_str) != Some("complete"))
        }) {
        vec![
            "Decoded WAT is not original source. Runtime behavior and network acquisition were not performed.".to_owned(),
            "Selected glue parsing is incomplete; unmatched references do not establish absence.".to_owned(),
        ]
    } else {
        vec![
            "Decoded WAT is not original source. Runtime behavior and network acquisition were not performed.".to_owned(),
        ]
    };
    json!({
        "parent_evidence_id": record.evidence_id(),
        "parent_operation": PARENT_OPERATION,
        "parent_digest": record.evidence_id().strip_prefix("ev_").unwrap_or(record.evidence_id()),
        "artifact": {"path": report["artifact"]["path"], "sha256": report["artifact"]["sha256"]},
        "limitations": limitations,
        "unknowns": unknowns,
    })
}

fn summary(report: &Value, limitations: &[String], shared: Value) -> Value {
    let wat = report.get("wat").cloned().unwrap_or(Value::Null);
    let stdout_units = wat
        .get("text")
        .and_then(Value::as_str)
        .map(utf16_len)
        .unwrap_or(0);
    let mut output = json!({
        "kind":"summary",
        "view":{"kind":"summary"},
        "summary": {
            "bytes": report["artifact"]["bytes"],
            "validation": report["validation"],
            "available_counts": {
                "sections": array_len(report, "sections"),
                "imports": array_len(report, "imports"),
                "exports": array_len(report, "exports"),
                "candidates": array_len(report, "candidates"),
                "glue": array_len(report, "glue"),
            },
            "wat": {"sha256": wat["sha256"], "representation": wat["representation"], "code_units": stdout_units},
            "tool_profile": report["tool_profile"],
            "runtime_execution": report["runtime_execution"],
            "network_fetch": report["network_fetch"],
            "limitation_count": limitations.len(),
        },
        "coverage": complete_coverage(array_len(report, "sections") + array_len(report, "imports") + array_len(report, "exports")),
    });
    output
        .as_object_mut()
        .expect("summary object")
        .extend(shared.as_object().expect("shared object").clone());
    output
}

fn facet(
    report: &Value,
    facet: String,
    offset: usize,
    limit: usize,
    shared: Value,
) -> Result<Value, Failure> {
    let mut output =
        json!({"kind":"wasm","view":{"kind":"wasm","facet":facet,"offset":offset,"limit":limit}});
    if facet == "tool_profile" {
        if offset != 0 {
            return Err(invalid("Singleton tool_profile requires offset 0."));
        }
        output["item"] = report["tool_profile"].clone();
        output["coverage"] = complete_coverage(1);
    } else if matches!(facet.as_str(), "wat" | "headers" | "details") {
        let text = if facet == "wat" {
            report["wat"]["text"].as_str()
        } else {
            report[facet.as_str()].as_str()
        }
        .ok_or_else(|| invalid(format!("WASM {facet} text is missing.")))?;
        let (page, examined) = utf16_page(text, offset, limit, &facet)?;
        output["item"] = json!({"text":page,"unit":"utf16-code-units"});
        output["coverage"] = page_coverage(offset.min(utf16_len(text)), examined, utf16_len(text));
    } else {
        let rows = report
            .get(&facet)
            .and_then(Value::as_array)
            .ok_or_else(|| invalid(format!("WASM {facet} collection is missing.")))?;
        let start = offset.min(rows.len());
        let item = rows
            .iter()
            .skip(start)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        output["item"] = json!(item);
        output["coverage"] = page_coverage(offset, item.len(), rows.len());
    }
    output
        .as_object_mut()
        .expect("facet object")
        .extend(shared.as_object().expect("shared object").clone());
    Ok(output)
}

fn utf16_page(
    text: &str,
    offset: usize,
    limit: usize,
    label: &str,
) -> Result<(String, usize), Failure> {
    let units = text.encode_utf16().collect::<Vec<_>>();
    let start = offset.min(units.len());
    if start > 0 && start < units.len() && is_low(units[start]) && is_high(units[start - 1]) {
        return Err(invalid(format!(
            "WASM {label} offset splits a UTF-16 surrogate pair."
        )));
    }
    let mut end = start.saturating_add(limit).min(units.len());
    if end > start && end < units.len() && is_high(units[end - 1]) && is_low(units[end]) {
        end -= 1;
    }
    if end == start && start < units.len() {
        return Err(invalid(format!(
            "Increase {} limit to include the next complete Unicode character.",
            label.to_lowercase()
        )));
    }
    Ok((String::from_utf16_lossy(&units[start..end]), end - start))
}

fn reject_unknown_fields(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(invalid(format!("Unexpected WASM view field: {field}.")));
    }
    Ok(())
}

fn required_string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("WASM view requires {field}.")))
}

fn required_value_string(value: &Value, label: &str) -> Result<String, Failure> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid(format!("{label} must be a string.")))
}

fn nonnegative_integer(
    object: &Map<String, Value>,
    field: &str,
    default: usize,
) -> Result<usize, Failure> {
    match object.get(field) {
        None => Ok(default),
        Some(value) => value
            .as_u64()
            .and_then(|number| usize::try_from(number).ok())
            .ok_or_else(|| invalid(format!("WASM {field} must be a nonnegative integer."))),
    }
}

fn positive_integer(
    object: &Map<String, Value>,
    field: &str,
    default: usize,
) -> Result<usize, Failure> {
    let value = nonnegative_integer(object, field, default)?;
    if value == 0 {
        return Err(invalid(format!("WASM {field} must be positive.")));
    }
    Ok(value)
}

fn array_len(report: &Value, field: &str) -> usize {
    report
        .get(field)
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

fn is_high(unit: u16) -> bool {
    (0xD800..=0xDBFF).contains(&unit)
}

fn is_low(unit: u16) -> bool {
    (0xDC00..=0xDFFF).contains(&unit)
}

fn complete_coverage(total: usize) -> Value {
    json!({"status":"complete-within-view","examined":total,"total":total,"next_offset":null,"exhausted":true})
}

fn page_coverage(offset: usize, examined: usize, total: usize) -> Value {
    let exhausted = offset >= total || offset.saturating_add(examined) >= total;
    json!({"status":if examined == 0 {"empty"} else {"page"},"examined":examined,"total":total,"next_offset":if exhausted {Value::Null} else {json!(offset + examined)},"exhausted":exhausted})
}

fn invalid(message: impl Into<String>) -> Failure {
    let message = message.into();
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.clone().into(),
        false,
        "Correct the view and retry.".into(),
        [
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(message)),
        ]
        .into_iter()
        .collect(),
    )
}
