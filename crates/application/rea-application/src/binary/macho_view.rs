//! Authenticated, non-rerunning views over retained Mach-O Evidence.
//!
//! The projection keeps the source collections and their producer coverage
//! intact. It never reopens the artifact or invokes a native decoder.

use rea_core::{
    canonical_json,
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_analysis_view";
const PARENT_OPERATION: &str = "inspect_macho";
const COLLECTIONS: [&str; 8] = [
    "entrypoints",
    "architectures",
    "build_metadata",
    "load_commands",
    "dependencies",
    "imports",
    "exports",
    "segments",
];

/// Project a summary or bounded Mach-O collection without rerunning analysis.
pub fn project(parent: &Value, view: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let parent_raw =
        serde_json::value::to_raw_value(parent).map_err(|error| invalid(&error.to_string()))?;
    let record = EvidenceRecord::parse(&parent_raw).map_err(|error| invalid(&error.to_string()))?;
    if !record.operation_matches(PARENT_OPERATION) {
        return Err(invalid("Mach-O view requires inspect_macho Evidence."));
    }

    let report: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| invalid(&format!("Mach-O normalized result is invalid: {error}")))?;
    validate_subject(&record)?;
    let request = parse_view(view)?;
    let shared = shared_fields(&record, &report)?;
    let body = match request {
        RequestedView::Summary => summary(&report, shared)?,
        RequestedView::Facet {
            facet,
            offset,
            limit,
        } => facet_page(&report, facet, offset, limit, shared)?,
    };

    create_view_evidence(&record, view.clone(), body)
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
    match view.get("kind").and_then(Value::as_str) {
        Some("summary") => Ok(RequestedView::Summary),
        Some("macho") => {
            let facet = view
                .get("facet")
                .and_then(Value::as_str)
                .filter(|facet| *facet == "provenance" || COLLECTIONS.contains(facet))
                .ok_or_else(|| invalid("Mach-O view facet is unknown."))?
                .to_owned();
            let offset = parse_usize(view, "offset", 0)?;
            let limit = parse_usize(view, "limit", 64)?;
            if limit == 0 {
                return Err(invalid("Mach-O view limit must be positive."));
            }
            Ok(RequestedView::Facet {
                facet,
                offset,
                limit,
            })
        }
        _ => Err(invalid("Mach-O Evidence supports summary and macho views.")),
    }
}

fn parse_usize(view: &Value, field: &str, default: u64) -> Result<usize, Failure> {
    let value = view.get(field).and_then(Value::as_u64).unwrap_or(default);
    usize::try_from(value).map_err(|_| invalid(&format!("Mach-O view {field} is too large.")))
}

fn validate_subject(record: &EvidenceRecord) -> Result<(), Failure> {
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| invalid(&format!("Mach-O subject is invalid: {error}")))?;
    let Some(format) = subject.get("format").and_then(Value::as_str) else {
        return Ok(());
    };
    if matches!(format, "mach-o" | "mach-o-universal") {
        Ok(())
    } else {
        Err(invalid(
            "Mach-O parent Evidence subject must identify a Mach-O.",
        ))
    }
}

fn shared_fields(record: &EvidenceRecord, report: &Value) -> Result<Value, Failure> {
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| invalid(&format!("Mach-O subject is invalid: {error}")))?;
    let artifact = json!({
        "path": subject.get("local_path").and_then(Value::as_str).unwrap_or(""),
        "sha256": subject.pointer("/digest/sha256").cloned().unwrap_or(Value::Null),
    });
    let mut unknowns = Vec::new();
    let incomplete = COLLECTIONS
        .iter()
        .filter(|name| {
            collection(report, name)
                .and_then(|value| value.get("exhaustive"))
                .and_then(Value::as_bool)
                == Some(false)
        })
        .count();
    if incomplete > 0 {
        unknowns.push("One or more retained Mach-O collections are incomplete; page exhaustion does not establish absence of unreturned rows.".to_owned());
    }
    if subject.is_null() {
        unknowns.push("The parent has no recorded subject, so the inspected artifact path and SHA-256 are unknown.".to_owned());
    }

    Ok(json!({
        "parent_evidence_id": record.evidence_id(),
        "parent_operation": PARENT_OPERATION,
        "parent_digest": record.evidence_id().strip_prefix("ev_").unwrap_or(record.evidence_id()),
        "artifact": artifact,
        "limitations": merged_limitations(record, report)?,
        "unknowns": unknowns,
    }))
}

fn summary(report: &Value, shared: Value) -> Result<Value, Failure> {
    let limitations = shared["limitations"].clone();
    let mut collections = Map::new();
    let mut returned = 0usize;
    for name in COLLECTIONS {
        let source = collection(report, name)
            .ok_or_else(|| invalid(&format!("Mach-O collection {name} is missing.")))?;
        let items = source["items"].as_array().map_or(0, Vec::len);
        returned += items;
        collections.insert(
            name.to_owned(),
            json!({
                "returned": items,
                "total": source.get("total").cloned().unwrap_or_else(|| json!(items)),
                "exhaustive": source.get("exhaustive").and_then(Value::as_bool).unwrap_or(true),
            }),
        );
    }
    let summary = json!({
        "format": report.get("format").cloned().unwrap_or_else(|| json!("mach-o")),
        "selected_architecture": report.get("selected_architecture").cloned().unwrap_or(Value::Null),
        "endian": report.get("endian").cloned().unwrap_or(Value::Null),
        "word_size": report.get("word_size").cloned().unwrap_or(Value::Null),
        "file_type": report.get("file_type").cloned().or_else(|| report.get("file_type_name").cloned()).unwrap_or(Value::Null),
        "flags": report.get("flags").cloned().unwrap_or_else(|| json!([])),
        "uuid": report.get("uuid").cloned().unwrap_or(Value::Null),
        "collections": collections,
        "provenance_count": report.get("provenance").and_then(Value::as_array).map_or(0, Vec::len),
        "limitation_count": limitations.as_array().map_or(0, Vec::len),
    });
    let mut output = json!({"kind":"summary", "view":{"kind":"summary"}, "summary":summary, "coverage":complete_coverage(returned)});
    merge_shared(&mut output, shared);
    Ok(output)
}

fn facet_page(
    report: &Value,
    facet: String,
    offset: usize,
    limit: usize,
    shared: Value,
) -> Result<Value, Failure> {
    let source = if facet == "provenance" {
        json!({"items": report.get("provenance").and_then(Value::as_array).cloned().unwrap_or_default(), "total": report.get("provenance").and_then(Value::as_array).map_or(0, Vec::len), "exhaustive": true, "limitations": []})
    } else {
        collection(report, &facet)
            .cloned()
            .ok_or_else(|| invalid(&format!("Mach-O collection {facet} is missing.")))?
    };
    let rows = source["items"]
        .as_array()
        .ok_or_else(|| invalid("Mach-O collection items are missing."))?;
    let start = offset.min(rows.len());
    let end = start.saturating_add(limit).min(rows.len());
    let items = rows[start..end].to_vec();
    let mut output = json!({
        "kind":"macho", "view":{"kind":"macho", "facet":facet, "offset":offset, "limit":limit}, "item":items,
        "source_total":source.get("total").cloned().unwrap_or_else(|| json!(rows.len())),
        "source_exhaustive":source.get("exhaustive").and_then(Value::as_bool).unwrap_or(true),
        "coverage":page_coverage(offset, end - start, rows.len()),
    });
    merge_shared(&mut output, shared);
    Ok(output)
}

fn collection<'a>(report: &'a Value, name: &str) -> Option<&'a Value> {
    let value = report.get(name)?;
    if value.get("items").is_some() {
        Some(value)
    } else {
        None
    }
}

fn merged_limitations(record: &EvidenceRecord, report: &Value) -> Result<Value, Failure> {
    let envelope: Value =
        serde_json::from_str(record.raw().get()).map_err(|error| invalid(&error.to_string()))?;
    let mut values = Vec::new();
    for source in [envelope.get("limitations"), report.get("limitations")] {
        if let Some(items) = source.and_then(Value::as_array) {
            values.extend(items.iter().filter_map(Value::as_str).map(str::to_owned));
        }
    }
    for name in COLLECTIONS {
        if let Some(items) = collection(report, name)
            .and_then(|source| source.get("limitations"))
            .and_then(Value::as_array)
        {
            values.extend(items.iter().filter_map(Value::as_str).map(str::to_owned));
        }
    }
    values.sort();
    values.dedup();
    Ok(json!(values))
}

fn merge_shared(output: &mut Value, shared: Value) {
    if let (Some(target), Some(fields)) = (output.as_object_mut(), shared.as_object()) {
        target.extend(fields.clone());
    }
}

fn create_view_evidence(
    record: &EvidenceRecord,
    view: Value,
    mut body: Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let digest = canonical_json::digest(&body).map_err(|error| invalid(&error.to_string()))?;
    body["view_digest"] = json!(digest);
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let authority: Value = serde_json::from_str(record.authority().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let path = body["artifact"]["path"]
        .as_str()
        .filter(|path| !path.is_empty());
    let limitations = body["limitations"].clone();
    let unsigned = json!({"subject":subject,"provider":{"id":"rea-analysis-view","name":"REA analysis view projection","version":"1"},"analysis_profile":null,"predicate_type":"rea.analysis-view","operation":OPERATION,"parameters":{"parent_evidence_id":record.evidence_id(),"view":view},"raw_result":null,"normalized_result":body,"confidence":"derived","authority":authority,"environment":null,"limitations":limitations,"relationship_coverage":null,"locations":path.map(|path| vec![json!({"kind":"artifact-path","path":path})]).unwrap_or_default(),"evidence_links":[record.evidence_id()]});
    let raw =
        serde_json::value::to_raw_value(&unsigned).map_err(|error| invalid(&error.to_string()))?;
    let derived =
        EvidenceRecord::create_unsigned(&raw).map_err(|error| invalid(&error.to_string()))?;
    Ok(
        serde_json::value::RawValue::from_string(derived.raw().get().to_owned())
            .expect("validated Evidence"),
    )
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
