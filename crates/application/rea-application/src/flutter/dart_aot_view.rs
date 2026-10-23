//! Authenticated, non-rerunning views over retained Dart AOT Evidence.
//!
//! This projection only reads the producer's retained report. It never opens
//! the APK, rescans `libapp.so`, or interprets byte-pattern strings as typed
//! Dart declarations.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_analysis_view";
const PARENT_OPERATION: &str = "inspect_dart_aot";
const DEFAULT_LIMIT: usize = 64;

/// Project a summary or bounded string-pool page from authenticated Evidence.
pub fn project(parent: &Value, view: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let parent_raw =
        serde_json::value::to_raw_value(parent).map_err(|error| invalid(error.to_string()))?;
    let record = EvidenceRecord::parse(&parent_raw).map_err(|error| invalid(error.to_string()))?;

    if !record.operation_matches(PARENT_OPERATION) {
        return Err(invalid("Dart AOT view requires inspect_dart_aot Evidence."));
    }

    let report: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| invalid(format!("Dart AOT normalized result is invalid: {error}")))?;
    let request = parse_view(view)?;
    let shared = shared_fields(&record, &report)?;
    let body = match request {
        RequestedView::Summary => summary(&report, &shared)?,
        RequestedView::Collection {
            collection,
            offset,
            limit,
        } => collection_page(&report, view, &shared, collection, offset, limit)?,
    };

    create_view_evidence(&record, view.clone(), body)
}

enum RequestedView {
    Summary,
    Collection {
        collection: String,
        offset: usize,
        limit: usize,
    },
}

fn parse_view(view: &Value) -> Result<RequestedView, Failure> {
    let object = view
        .as_object()
        .ok_or_else(|| invalid("Dart AOT view must be an object."))?;
    reject_unknown_fields(object, &["kind", "collection", "offset", "limit"])?;
    let kind = required_string(object, "kind")?;

    match kind {
        "summary" if object.len() == 1 => Ok(RequestedView::Summary),
        "summary" => Err(invalid("Summary Dart AOT view only accepts kind.")),
        "dart-aot" => {
            let collection = required_string(object, "collection")?;
            if !matches!(
                collection,
                "package_uris" | "dart_uris" | "class_like_tokens"
            ) {
                return Err(invalid("Unknown Dart AOT string collection."));
            }
            Ok(RequestedView::Collection {
                collection: collection.to_owned(),
                offset: nonnegative_integer(object, "offset", 0)?,
                limit: positive_integer(object, "limit", DEFAULT_LIMIT)?,
            })
        }
        _ => Err(invalid(
            "Dart AOT Evidence supports summary and string-pool pages.",
        )),
    }
}

fn shared_fields(record: &EvidenceRecord, report: &Value) -> Result<Value, Failure> {
    let target = report
        .get("target")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("Dart AOT report is missing target identity."))?;
    let path = required_object_string(target, "path", "Dart AOT target path")?;
    let sha256 = required_object_string(target, "sha256", "Dart AOT target digest")?;

    let mut unknowns = vec![
        "String-pool entries are byte-pattern observations, not recovered typed classes or functions."
            .to_owned(),
        "Counts ending in _at_least remain lower bounds; exhausting returned strings does not establish a complete snapshot inventory."
            .to_owned(),
    ];
    if !record_has_subject(record)? {
        unknowns.push(
            "The parent has no recorded subject; its normalized target identity cannot be cross-checked against a subject digest."
                .to_owned(),
        );
    }

    Ok(json!({
        "parent_evidence_id": record.evidence_id(),
        "parent_operation": PARENT_OPERATION,
        "parent_digest": record.evidence_id().strip_prefix("ev_").unwrap_or(record.evidence_id()),
        "artifact": {"path": path, "sha256": sha256},
        "limitations": parent_limitations(record)?,
        "unknowns": unknowns,
    }))
}

fn record_has_subject(record: &EvidenceRecord) -> Result<bool, Failure> {
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| invalid(format!("Dart AOT Evidence subject is invalid: {error}")))?;
    Ok(!subject.is_null())
}

fn summary(report: &Value, shared: &Value) -> Result<Value, Failure> {
    let pool = report
        .get("string_pool")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("Dart AOT report is missing string_pool."))?;
    let mut compact_pool = pool.clone();
    let package_count = array_len(pool, "package_uris");
    let dart_count = array_len(pool, "dart_uris");
    let token_count = array_len(pool, "class_like_tokens");
    compact_pool.remove("package_uris");
    compact_pool.remove("dart_uris");
    compact_pool.remove("class_like_tokens");
    compact_pool.insert(
        "returned_counts".into(),
        json!({
            "package_uris": package_count,
            "dart_uris": dart_count,
            "class_like_tokens": token_count,
        }),
    );

    let mut compact_report = report.clone();
    compact_report["string_pool"] = Value::Object(compact_pool);
    let mut output = json!({
        "kind": "summary",
        "view": {"kind": "summary"},
        "summary": compact_report,
        "coverage": complete_coverage(1),
    });
    merge_shared(&mut output, shared);
    Ok(output)
}

fn collection_page(
    report: &Value,
    view: &Value,
    shared: &Value,
    collection: String,
    offset: usize,
    limit: usize,
) -> Result<Value, Failure> {
    let pool = report
        .get("string_pool")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("Dart AOT report is missing string_pool."))?;
    let rows = pool
        .get(&collection)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(format!("Dart AOT collection {collection} is missing.")))?;
    let start = offset.min(rows.len());
    let items = rows
        .iter()
        .skip(start)
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    let mut output = json!({
        "kind": "dart-aot",
        "view": view,
        "items": items,
        "abi": report["abi"],
        "libapp": report["libapp"],
        "source_coverage": report["coverage"],
        "string_pool": compact_pool(pool),
        "coverage": page_coverage(offset, items.len(), rows.len()),
    });
    merge_shared(&mut output, shared);
    Ok(output)
}

fn compact_pool(pool: &Map<String, Value>) -> Value {
    let mut compact = pool.clone();
    let counts = json!({
        "package_uris": array_len(pool, "package_uris"),
        "dart_uris": array_len(pool, "dart_uris"),
        "class_like_tokens": array_len(pool, "class_like_tokens"),
    });
    for name in ["package_uris", "dart_uris", "class_like_tokens"] {
        compact.remove(name);
    }
    compact.insert("returned_counts".into(), counts);
    Value::Object(compact)
}

fn create_view_evidence(
    record: &EvidenceRecord,
    view: Value,
    body: Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
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

fn parent_limitations(record: &EvidenceRecord) -> Result<Value, Failure> {
    let envelope: Value = serde_json::from_str(record.raw().get())
        .map_err(|error| invalid(format!("Dart AOT Evidence is invalid: {error}")))?;
    envelope
        .get("limitations")
        .cloned()
        .ok_or_else(|| invalid("Dart AOT Evidence limitations are missing."))
}

fn required_string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("Dart AOT view requires {field}.")))
}

fn required_object_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    label: &str,
) -> Result<&'a str, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{label} is missing.")))
}

fn reject_unknown_fields(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(invalid(format!("Unexpected Dart AOT view field: {field}.")));
    }
    Ok(())
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
            .ok_or_else(|| invalid(format!("Dart AOT {field} must be a nonnegative integer."))),
    }
}

fn positive_integer(
    object: &Map<String, Value>,
    field: &str,
    default: usize,
) -> Result<usize, Failure> {
    let value = nonnegative_integer(object, field, default)?;
    if value == 0 {
        return Err(invalid(format!("Dart AOT {field} must be positive.")));
    }
    Ok(value)
}

fn array_len(object: &Map<String, Value>, field: &str) -> usize {
    object
        .get(field)
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

fn merge_shared(output: &mut Value, shared: &Value) {
    output
        .as_object_mut()
        .expect("Dart AOT view output is an object")
        .extend(
            shared
                .as_object()
                .expect("shared fields are an object")
                .clone(),
        );
}

fn complete_coverage(total: usize) -> Value {
    json!({"status":"complete-within-view","examined":total,"total":total,"next_offset":null,"exhausted":true})
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

fn invalid(message: impl Into<String>) -> Failure {
    let message = message.into();
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.clone().into(),
        false,
        "Correct the view and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("reason".into(), Detail::Text(message)),
        ]),
    )
}
