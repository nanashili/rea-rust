//! Authenticated, non-rerunning views over retained Android package Evidence.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_analysis_view";
const PARENT_OPERATION: &str = "inspect_android_package";

/// Project a summary or bounded manifest page without reopening the APK.
pub fn project(parent: &Value, view: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let parent_raw =
        serde_json::value::to_raw_value(parent).map_err(|error| invalid(&error.to_string()))?;
    let record = EvidenceRecord::parse(&parent_raw).map_err(|error| invalid(&error.to_string()))?;

    if !record.operation_matches(PARENT_OPERATION) {
        return Err(invalid(
            "Android package view requires inspect_android_package Evidence.",
        ));
    }

    let report: Value =
        serde_json::from_str(record.normalized_result().get()).map_err(|error| {
            invalid(&format!(
                "Android package normalized result is invalid: {error}"
            ))
        })?;
    let subject = validate_parent_subject(&record)?;
    let requested = parse_view(view)?;
    let shared = shared_fields(&record, &report, &subject)?;
    let body = match requested {
        RequestedView::Summary => summary(&report, shared)?,
        RequestedView::Manifest { offset, limit } => {
            manifest_page(&report, view, offset, limit, shared)?
        }
    };

    create_view_evidence(&record, view.clone(), body)
}

enum RequestedView {
    Summary,
    Manifest { offset: usize, limit: usize },
}

fn parse_view(view: &Value) -> Result<RequestedView, Failure> {
    let kind = view
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Android package Evidence supports summary and manifest views."))?;

    match kind {
        "summary" => Ok(RequestedView::Summary),
        "android" => {
            if view.get("facet").and_then(Value::as_str) != Some("manifest") {
                return Err(invalid("Android package views support the manifest facet."));
            }
            let offset = view.get("offset").and_then(Value::as_u64).unwrap_or(0);
            let limit = view
                .get("limit")
                .and_then(Value::as_u64)
                .ok_or_else(|| invalid("Android manifest view limit is required."))?;
            if limit == 0 {
                return Err(invalid("Android manifest view limit must be positive."));
            }
            Ok(RequestedView::Manifest {
                offset: usize::try_from(offset)
                    .map_err(|_| invalid("Android manifest view offset is too large."))?,
                limit: usize::try_from(limit)
                    .map_err(|_| invalid("Android manifest view limit is too large."))?,
            })
        }
        _ => Err(invalid(
            "Android package Evidence supports summary and manifest views.",
        )),
    }
}

fn validate_parent_subject(record: &EvidenceRecord) -> Result<Value, Failure> {
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| invalid(&format!("Android package subject is invalid: {error}")))?;
    let is_apk = subject.get("format").and_then(Value::as_str) == Some("apk");
    let has_path = subject
        .get("local_path")
        .and_then(Value::as_str)
        .is_some_and(|path| !path.is_empty());
    let has_digest = subject
        .get("digest")
        .and_then(|digest| digest.get("sha256"))
        .and_then(Value::as_str)
        .is_some_and(|digest| !digest.is_empty());
    if is_apk && has_path && has_digest {
        Ok(subject)
    } else {
        Err(invalid(
            "Android package views require the recorded APK subject identity.",
        ))
    }
}

fn shared_fields(
    record: &EvidenceRecord,
    report: &Value,
    subject: &Value,
) -> Result<Value, Failure> {
    let path = subject["local_path"]
        .as_str()
        .ok_or_else(|| invalid("Android package subject path is missing."))?;
    let digest = subject["digest"]["sha256"]
        .as_str()
        .ok_or_else(|| invalid("Android package subject digest is missing."))?;
    let mut unknowns = vec![
        "APK signatures were not verified; package declarations do not establish authenticity or runtime behavior."
            .to_owned(),
    ];
    if report["manifest"]["status"].as_str() == Some("partial") {
        unknowns.push(
            "The decoded manifest is partial; exhausting retained text does not establish complete manifest coverage."
                .to_owned(),
        );
    }

    Ok(json!({
        "parent_evidence_id": record.evidence_id(),
        "parent_operation": PARENT_OPERATION,
        "parent_digest": record.evidence_id().strip_prefix("ev_").unwrap_or(record.evidence_id()),
        "artifact": {"path": path, "sha256": digest},
        "limitations": parent_limitations(record)?,
        "unknowns": unknowns,
    }))
}

fn parent_limitations(record: &EvidenceRecord) -> Result<Value, Failure> {
    let envelope: Value = serde_json::from_str(record.raw().get())
        .map_err(|error| invalid(&format!("Android package Evidence is invalid: {error}")))?;
    Ok(envelope["limitations"].clone())
}

fn summary(report: &Value, shared: Value) -> Result<Value, Failure> {
    let mut report = report.clone();
    // The native producer keeps artifact identity beside the flattened package
    // report. The public package summary carries that identity in `artifact`
    // at the view level, so do not duplicate it inside `summary`.
    if let Some(report) = report.as_object_mut() {
        report.remove("artifact");
    }
    let manifest = report
        .get_mut("manifest")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| invalid("Android package manifest is missing."))?;
    let text = manifest
        .remove("text")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| invalid("Android package manifest text is missing."))?;
    manifest.insert("text_code_units".into(), json!(text.encode_utf16().count()));
    manifest.insert("text_included".into(), Value::Bool(false));

    let mut output = json!({
        "kind": "summary",
        "view": {"kind": "summary"},
        "summary": report,
        "coverage": complete_coverage(1),
    });
    merge_shared(&mut output, shared);
    Ok(output)
}

fn manifest_page(
    report: &Value,
    view: &Value,
    offset: usize,
    limit: usize,
    shared: Value,
) -> Result<Value, Failure> {
    let manifest = report
        .get("manifest")
        .ok_or_else(|| invalid("Android package manifest is missing."))?;
    let text = manifest
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Android package manifest text is missing."))?;
    let (page, examined) = utf16_page(text, offset, limit)?;
    let total = text.encode_utf16().count();
    let mut output = json!({
        "kind": "android",
        "view": view,
        "item": {
            "text": page,
            "unit": "utf16-code-units",
            "source_status": manifest["status"],
            "reported_total_bytes": manifest["reported_total_bytes"],
        },
        "coverage": page_coverage(offset, examined, total),
    });
    merge_shared(&mut output, shared);
    Ok(output)
}

fn utf16_page(text: &str, offset: usize, limit: usize) -> Result<(String, usize), Failure> {
    let units = text.encode_utf16().collect::<Vec<_>>();
    let start = offset.min(units.len());
    let requested_end = start.saturating_add(limit).min(units.len());
    if start > 0
        && start < units.len()
        && (0xDC00..=0xDFFF).contains(&units[start])
        && (0xD800..=0xDBFF).contains(&units[start - 1])
    {
        return Err(invalid(
            "Android manifest offset splits a UTF-16 surrogate pair.",
        ));
    }
    let mut end = requested_end;
    if end < units.len()
        && end > start
        && (0xD800..=0xDBFF).contains(&units[end - 1])
        && (0xDC00..=0xDFFF).contains(&units[end])
    {
        end -= 1;
    }
    if end == start && start < units.len() {
        return Err(invalid(
            "Increase Android manifest text limit to include the next complete Unicode character.",
        ));
    }
    Ok((String::from_utf16_lossy(&units[start..end]), end - start))
}

fn create_view_evidence(
    parent: &EvidenceRecord,
    view: Value,
    body: Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let subject: Value = serde_json::from_str(parent.subject().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let limitations = body["limitations"].clone();
    let locations = body["artifact"]["path"]
        .as_str()
        .map(|path| vec![json!({"kind": "artifact-path", "path": path})])
        .unwrap_or_default();
    let unsigned = json!({
        "subject": subject,
        "provider": {"id":"rea-analysis-view","name":"REA analysis view projection","version":"1"},
        "analysis_profile": null,
        "predicate_type":"rea.analysis-view",
        "operation": OPERATION,
        "parameters":{"parent_evidence_id":parent.evidence_id(),"view":view},
        "raw_result":null,
        "normalized_result":body,
        "confidence":"derived",
        "authority":"analyst-inference",
        "environment":null,
        "limitations":limitations,
        "relationship_coverage":null,
        "locations":locations,
        "evidence_links":[parent.evidence_id()]
    });
    let raw =
        serde_json::value::to_raw_value(&unsigned).map_err(|error| invalid(&error.to_string()))?;
    let derived =
        EvidenceRecord::create_unsigned(&raw).map_err(|error| invalid(&error.to_string()))?;
    Ok(
        serde_json::value::RawValue::from_string(derived.raw().get().to_owned())
            .expect("validated Evidence is valid JSON"),
    )
}

fn merge_shared(output: &mut Value, shared: Value) {
    if let (Some(output), Some(shared)) = (output.as_object_mut(), shared.as_object()) {
        output.extend(shared.clone());
    }
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
