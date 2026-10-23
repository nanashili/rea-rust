//! Authenticated, bounded views over retained managed-artifact Evidence.
//!
//! The source report is parsed once at this boundary. Views only project
//! retained rows and never reopen or execute the assembly.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const OPERATION: &str = "inspect_analysis_view";
const PARENT_OPERATION: &str = "inspect_managed_artifact";

/// Project a managed-artifact summary or one bounded metadata collection page.
pub fn project(parent: &Value, view: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let raw =
        serde_json::value::to_raw_value(parent).map_err(|error| invalid(&error.to_string()))?;
    let record = EvidenceRecord::parse(&raw).map_err(|error| invalid(&error.to_string()))?;
    if !record.operation_matches(PARENT_OPERATION) {
        return Err(invalid(
            "Managed artifact views require inspect_managed_artifact Evidence.",
        ));
    }

    let report: Value =
        serde_json::from_str(record.normalized_result().get()).map_err(|error| {
            invalid(&format!(
                "Managed artifact normalized result is invalid: {error}"
            ))
        })?;
    validate_parent_subject(&record, &report)?;

    let request = parse_request(view)?;
    let identity_scope = identity_scope(&report);
    let shared = shared_fields(parent, &record, &report, &identity_scope)?;
    let body = match request {
        Request::Summary => summary(&report, shared, identity_scope),
        Request::Page {
            collection,
            offset,
            limit,
            view,
        } => page(
            &report,
            shared,
            identity_scope,
            collection,
            offset,
            limit,
            view,
        )?,
    };

    create_view_evidence(&record, view, body)
}

#[derive(Clone, Copy)]
enum Collection {
    References,
    Resources,
    Attributes,
}

enum Request {
    Summary,
    Page {
        collection: Collection,
        offset: usize,
        limit: usize,
        view: Value,
    },
}

fn parse_request(view: &Value) -> Result<Request, Failure> {
    let kind = view
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Managed artifact views support summary and managed kinds."))?;
    if kind == "summary" {
        return Ok(Request::Summary);
    }
    if kind != "managed" {
        return Err(invalid(
            "Managed artifact views support summary and managed kinds.",
        ));
    }

    let collection = match view.get("collection").and_then(Value::as_str) {
        Some("references") => Collection::References,
        Some("resources") => Collection::Resources,
        Some("attributes") => Collection::Attributes,
        _ => return Err(invalid("Managed artifact collection is invalid.")),
    };
    let offset = nonnegative_integer(view.get("offset")).unwrap_or(0);
    let limit = nonnegative_integer(view.get("limit")).unwrap_or(64);
    if view.get("offset").is_some() && nonnegative_integer(view.get("offset")).is_none() {
        return Err(invalid("Managed artifact view offset must be nonnegative."));
    }
    if view.get("limit").is_some()
        && (limit == 0 || nonnegative_integer(view.get("limit")).is_none())
    {
        return Err(invalid("Managed artifact view limit must be positive."));
    }
    Ok(Request::Page {
        collection,
        offset,
        limit,
        view: view.clone(),
    })
}

fn nonnegative_integer(value: Option<&Value>) -> Option<usize> {
    let value = value?;
    let number = value.as_u64()?;
    usize::try_from(number).ok()
}

fn identity_scope(report: &Value) -> Value {
    let artifact = artifact_identity(report);
    let mvid = report["module"]["mvid"].clone();
    json!({
        "token_identity": "build-local",
        "requires_artifact_sha256": artifact["sha256"],
        "requires_mvid": if mvid.is_null() { Value::Null } else { mvid },
    })
}

fn shared_fields(
    parent: &Value,
    record: &EvidenceRecord,
    report: &Value,
    identity_scope: &Value,
) -> Result<Value, Failure> {
    let mut limitations = string_array(
        parent.get("limitations").unwrap_or(&Value::Null),
        "parent limitations",
    )?;
    limitations.extend(string_array(
        report.get("limitations").unwrap_or(&Value::Null),
        "report limitations",
    )?);
    let unique = BTreeSet::from_iter(limitations);
    let mut unknowns = vec![
        "Collection counts and pages cover producer-returned rows; metadata completeness remains the original metadata status and coverage, not an absence claim about unreturned rows.".to_owned(),
        "Metadata tokens are build-local coordinates bound to the recorded artifact SHA-256 and module MVID; this view does not load or execute the assembly.".to_owned(),
    ];
    if record.subject().get().trim() == "null" {
        unknowns.push("The parent has no recorded subject; its normalized artifact identity cannot be cross-checked against a subject digest.".into());
    }
    if identity_scope["requires_mvid"].is_null() {
        unknowns.push(
            "The module MVID is unknown; tokens cannot establish a cross-observation module match."
                .into(),
        );
    }
    Ok(json!({
        "parent_evidence_id": record.evidence_id(),
        "parent_operation": PARENT_OPERATION,
        "parent_digest": record.evidence_id().strip_prefix("ev_").unwrap_or(record.evidence_id()),
        "artifact": artifact_identity(report),
        "limitations": unique.into_iter().collect::<Vec<_>>(),
        "unknowns": unknowns,
    }))
}

fn summary(report: &Value, shared: Value, identity_scope: Value) -> Value {
    let references = rows(report, Collection::References);
    let resources = rows(report, Collection::Resources);
    let attributes = rows(report, Collection::Attributes);
    let total = references.len() + resources.len() + attributes.len();
    let mut summary = report.clone();
    if let Some(object) = summary.as_object_mut() {
        object.remove("references");
        object.remove("manifest_resources");
        object.remove("custom_attributes");
    }
    summary["reported_counts"] = json!({
        "references": references.len(),
        "resources": resources.len(),
        "attributes": attributes.len(),
    });
    summary["identity_scope"] = identity_scope;
    let mut output = json!({"kind":"summary", "view":{"kind":"summary"}, "summary":summary, "coverage":complete_coverage(total)});
    output
        .as_object_mut()
        .unwrap()
        .extend(shared.as_object().unwrap().clone());
    output
}

fn page(
    report: &Value,
    shared: Value,
    identity_scope: Value,
    collection: Collection,
    offset: usize,
    limit: usize,
    view: Value,
) -> Result<Value, Failure> {
    let source = rows(report, collection);
    let start = offset.min(source.len());
    let end = start.saturating_add(limit).min(source.len());
    let item = source[start..end].to_vec();
    let mut output = json!({
        "kind":"managed", "view":view, "item":item,
        "identity_scope":identity_scope,
        "source_metadata_status":report["metadata"]["status"],
        "source_coverage":report["coverage"],
        "coverage":page_coverage(offset, end - start, source.len()),
    });
    output
        .as_object_mut()
        .unwrap()
        .extend(shared.as_object().unwrap().clone());
    Ok(output)
}

fn rows(report: &Value, collection: Collection) -> Vec<Value> {
    let key = match collection {
        Collection::References => "references",
        Collection::Resources => "manifest_resources",
        Collection::Attributes => "custom_attributes",
    };
    report[key].as_array().cloned().unwrap_or_default()
}

fn validate_parent_subject(record: &EvidenceRecord, report: &Value) -> Result<(), Failure> {
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| invalid(&error.to_string()))?;
    if subject.is_null() {
        return Ok(());
    }
    let artifact = artifact_identity(report);
    let matches = subject["format"] == "pe"
        && subject["local_path"] == artifact["path"]
        && subject["digest"]["sha256"] == artifact["sha256"];
    if matches {
        Ok(())
    } else {
        Err(invalid(
            "Managed artifact parent subject must identify the report's exact carrier path and SHA-256.",
        ))
    }
}

fn artifact_identity(report: &Value) -> Value {
    let artifact = report.get("artifact").cloned().unwrap_or(Value::Null);
    json!({
        "path": artifact.get("path").cloned().unwrap_or_else(|| report["path"].clone()),
        "sha256": artifact.get("sha256").cloned().unwrap_or_else(|| report["sha256"].clone()),
    })
}

fn string_array(value: &Value, field: &str) -> Result<Vec<String>, Failure> {
    value
        .as_array()
        .ok_or_else(|| invalid(&format!("Managed artifact {field} must be an array.")))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid(&format!("Managed artifact {field} must contain strings.")))
        })
        .collect()
}

fn complete_coverage(total: usize) -> Value {
    json!({"status":"complete-within-view","examined":total,"total":total,"next_offset":null,"exhausted":true})
}

fn page_coverage(offset: usize, examined: usize, total: usize) -> Value {
    let exhausted = offset >= total || offset.saturating_add(examined) >= total;
    json!({"status":if examined == 0 {"empty"} else {"page"},"examined":examined,"total":total,"next_offset":if exhausted {Value::Null} else {json!(offset + examined)},"exhausted":exhausted})
}

fn create_view_evidence(
    parent: &EvidenceRecord,
    view: &Value,
    body: Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let subject: Value = serde_json::from_str(parent.subject().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let unsigned = json!({"subject":subject,"provider":{"id":"analysis-view","name":"REA retained analysis view","version":"1"},"analysis_profile":null,"predicate_type":"rea.analysis-view","operation":OPERATION,"parameters":{"parent_evidence_id":parent.evidence_id(),"view":view},"raw_result":null,"normalized_result":body,"confidence":"derived","authority":"analyst-inference","environment":null,"limitations":[],"relationship_coverage":null,"locations":[],"evidence_links":[parent.evidence_id()]});
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
        "Correct the view and retry.".into(),
        std::collections::BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(message.into())),
        ]),
    )
}
