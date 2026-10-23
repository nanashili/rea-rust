//! Authenticated, bounded views over retained managed-member Evidence.
//!
//! The member inspection owns metadata decoding.  This module only validates
//! the retained report and projects a summary or one bounded collection page.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "inspect_analysis_view";
const MEMBERS_OPERATION: &str = "inspect_managed_members";

const COLLECTIONS: [&str; 8] = [
    "types",
    "exported_types",
    "fields",
    "methods",
    "member_refs",
    "call_edges",
    "field_accesses",
    "user_strings",
];

/// Project a summary or bounded managed-member collection page.
pub fn project(parent: &Value, view: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let parent_raw =
        serde_json::value::to_raw_value(parent).map_err(|error| invalid(&error.to_string()))?;
    let record = EvidenceRecord::parse(&parent_raw).map_err(|error| invalid(&error.to_string()))?;
    if !record.operation_matches(MEMBERS_OPERATION) {
        return Err(invalid(
            "Managed member views require inspect_managed_members Evidence.",
        ));
    }

    let report = parse_report(&record)?;
    let kind = view.get("kind").and_then(Value::as_str).ok_or_else(|| {
        invalid("Managed member Evidence supports summary and managed-members views.")
    })?;
    let shared = shared(&record, &report, parent);
    let body = match kind {
        "summary" => summary(&report, shared),
        "managed-members" => page(&report, view, shared)?,
        _ => {
            return Err(invalid(
                "Managed member Evidence supports summary and managed-members views.",
            ));
        }
    };

    create_view_evidence(&record, view, body)
}

fn parse_report(record: &EvidenceRecord) -> Result<Value, Failure> {
    let normalized: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| invalid(&format!("managed member result is invalid JSON: {error}")))?;
    let object = normalized
        .as_object()
        .ok_or_else(|| invalid("managed member result must be an object"))?;

    // Rust captures retain the member report under `members`; the established
    // application contract stores the same fields directly in the result.
    let report = match object.get("members").cloned() {
        Some(mut members) => {
            let report_object = members
                .as_object_mut()
                .ok_or_else(|| invalid("managed member report must be an object"))?;
            report_object.entry("artifact".to_owned()).or_insert_with(
                || json!({"path": object.get("path"), "sha256": object.get("sha256")}),
            );
            members
        }
        None => normalized,
    };
    if !report.is_object() {
        return Err(invalid("managed member report must be an object"));
    }
    for collection in COLLECTIONS {
        // `null` and omission both mean that these optional tables were not
        // examined; an empty array remains the producer's explicit empty
        // result. Keep that distinction at the view boundary.
        if collection_value(&report, collection).is_none()
            && collection != "exported_types"
            && collection != "user_strings"
        {
            return Err(invalid("managed member report is missing a collection"));
        }
    }
    Ok(report)
}

fn collection_value<'a>(report: &'a Value, collection: &str) -> Option<&'a Value> {
    let key = match collection {
        "member_refs" => "member_refs",
        "user_strings" => "user_strings",
        value => value,
    };
    if let Some(value) = report.get(key).filter(|value| !value.is_null()) {
        return Some(value);
    }
    if collection == "member_refs" {
        return report
            .get("member_references")
            .filter(|value| !value.is_null());
    }
    None
}

fn shared(record: &EvidenceRecord, report: &Value, parent: &Value) -> Value {
    let mut limitations = BTreeSet::new();
    extend_strings(&mut limitations, parent.get("limitations"));
    extend_strings(&mut limitations, report.get("limitations"));

    let selection = report.get("selection").cloned().unwrap_or(Value::Null);
    let mut unknowns = vec![
        "Collection counts and pages cover producer-returned rows; member completeness remains the original coverage, not an absence claim about unreturned rows.".to_owned(),
    ];
    if !selection.is_null() {
        unknowns.push(
            "Exported types and member references cover the whole assembly; the other collections cover only the selected declaring types.".to_owned(),
        );
    }
    if let Some(identity_scope) = report.get("identity_scope") {
        if identity_scope.get("requires_mvid") == Some(&Value::Bool(true)) {
            unknowns.push(
                "Managed metadata tokens remain build-local and require the reported artifact SHA-256 and MVID.".to_owned(),
            );
        }
    }

    let artifact = report
        .get("artifact")
        .cloned()
        .unwrap_or_else(|| json!({"path": parent["path"], "sha256": parent["sha256"]}));
    json!({
        "parent_evidence_id": record.evidence_id(),
        "parent_operation": MEMBERS_OPERATION,
        "parent_digest": record.evidence_id().strip_prefix("ev_").unwrap_or(record.evidence_id()),
        "artifact": {"path": artifact["path"], "sha256": artifact["sha256"]},
        "limitations": limitations.into_iter().collect::<Vec<_>>(),
        "unknowns": unknowns,
    })
}

fn summary(report: &Value, shared: Value) -> Value {
    let mut identity = report.as_object().cloned().unwrap_or_default();
    let mut counts = Map::new();
    for collection in COLLECTIONS {
        let value = collection_value(report, collection);
        let count = if collection == "user_strings" {
            value
                .and_then(|item| item.get("literals"))
                .and_then(Value::as_array)
                .map_or(Value::Null, |rows| json!(rows.len()))
        } else {
            value
                .and_then(Value::as_array)
                .map_or(Value::Null, |rows| json!(rows.len()))
        };
        counts.insert(collection.to_owned(), count);
        identity.remove(collection);
        if collection == "member_refs" {
            identity.remove("member_references");
        }
    }
    let user_strings = collection_value(report, "user_strings")
        .map(|value| json!({"state": value["state"], "issues": value["issues"]}));
    identity.insert(
        "user_strings".to_owned(),
        user_strings.unwrap_or(Value::Null),
    );
    for field in ["nesting_read", "selection"] {
        identity.entry(field.to_owned()).or_insert(Value::Null);
    }
    identity.insert("reported_counts".to_owned(), Value::Object(counts));

    let total = identity["reported_counts"]
        .as_object()
        .map(|values| values.values().filter_map(Value::as_u64).sum::<u64>())
        .unwrap_or(0) as usize;
    let mut output = json!({
        "kind": "summary",
        "view": {"kind": "summary"},
        "summary": Value::Object(identity),
        "coverage": complete_coverage(total),
    });
    output
        .as_object_mut()
        .unwrap()
        .extend(shared.as_object().unwrap().clone());
    output
}

fn page(report: &Value, view: &Value, shared: Value) -> Result<Value, Failure> {
    let collection = view
        .get("collection")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Managed member collection is required."))?;
    if !COLLECTIONS.contains(&collection) {
        return Err(invalid("Unknown managed member collection."));
    }
    let offset = view.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
    let limit = view.get("limit").and_then(Value::as_u64).unwrap_or(64) as usize;
    if limit == 0 {
        return Err(invalid("Managed member view limit must be positive."));
    }

    let rows = match collection_value(report, collection) {
        Some(value) if collection == "user_strings" => value
            .get("literals")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("Managed member user_strings literals are missing."))?,
        Some(value) => value
            .as_array()
            .ok_or_else(|| invalid("Managed member collection must be an array."))?,
        None => {
            return Err(invalid(&format!(
                "The parent Evidence did not examine {collection}; repeat inspect_managed_members with the current runtime to record it."
            )));
        }
    };
    let items = rows
        .iter()
        .skip(offset)
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    let mut normalized_view = view.clone();
    if let Some(view_object) = normalized_view.as_object_mut() {
        view_object.insert("offset".to_owned(), json!(offset));
        view_object.insert("limit".to_owned(), json!(limit));
    }
    let mut output = json!({
        "kind": "managed-members",
        "view": normalized_view,
        "page": {"collection": collection, "rows": items},
        "signature_resolution": report["signature_resolution"],
        "nesting_read": report["nesting_read"],
        "identity_scope": report["identity_scope"],
        "selection": report["selection"],
        "source_metadata_status": report["metadata"]["status"],
        "source_coverage": if collection == "user_strings" { collection_value(report, collection).map(|value| json!({"state":value["state"],"issues":value["issues"]})).unwrap_or(report["coverage"].clone()) } else { report["coverage"].clone() },
        "coverage": page_coverage(offset, items.len(), rows.len()),
    });
    output
        .as_object_mut()
        .unwrap()
        .extend(shared.as_object().unwrap().clone());
    Ok(output)
}

fn create_view_evidence(
    record: &EvidenceRecord,
    view: &Value,
    body: Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let authority: Value = serde_json::from_str(record.authority().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let limitations = body
        .get("limitations")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let unsigned = json!({
        "subject": subject,
        "provider": {"id":"analysis-view","name":"REA retained analysis view","version":"1"},
        "analysis_profile": null,
        "predicate_type":"rea.analysis-view",
        "operation":OPERATION,
        "parameters":{"parent_evidence_id":record.evidence_id(),"view":view},
        "raw_result":null,
        "normalized_result":body,
        "confidence":"derived",
        "authority":authority,
        "environment":null,
        "limitations":limitations,
        "relationship_coverage":null,
        "locations":[],
        "evidence_links":[record.evidence_id()]
    });
    let raw =
        serde_json::value::to_raw_value(&unsigned).map_err(|error| invalid(&error.to_string()))?;
    let derived =
        EvidenceRecord::create_unsigned(&raw).map_err(|error| invalid(&error.to_string()))?;
    serde_json::value::RawValue::from_string(derived.raw().get().to_owned())
        .map_err(|error| invalid(&error.to_string()))
}

fn extend_strings(target: &mut BTreeSet<String>, value: Option<&Value>) {
    if let Some(values) = value.and_then(Value::as_array) {
        target.extend(values.iter().filter_map(Value::as_str).map(str::to_owned));
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
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Correct the retained Evidence or view and retry.".into(),
        BTreeMap::from([
            ("operation".to_owned(), Detail::Text(OPERATION.into())),
            ("reason".to_owned(), Detail::Text(message.into())),
        ]),
    )
}
