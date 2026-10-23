//! Authenticated, non-rerunning views over retained EVM Evidence.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "inspect_analysis_view";

/// Project a summary or bounded EVM facet and commit the result as derived Evidence.
pub fn project(parent: &Value, view: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let parent_raw =
        serde_json::value::to_raw_value(parent).map_err(|e| invalid(&e.to_string()))?;
    let record = EvidenceRecord::parse(&parent_raw).map_err(|e| invalid(&e.to_string()))?;
    if !record.operation_matches("inspect_evm_interface") {
        return Err(invalid("EVM view requires inspect_evm_interface Evidence."));
    }
    let report: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|e| invalid(&format!("EVM normalized result is invalid: {e}")))?;
    validate_parent_subject(&record, &report)?;

    let kind = view
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("EVM Evidence supports summary and evm views."))?;
    let limitations = merged_limitations(&record, &report)?;
    let shared = json!({
        "parent_evidence_id": record.evidence_id(),
        "parent_operation": "inspect_evm_interface",
        "parent_digest": record.evidence_id().strip_prefix("ev_").unwrap_or(record.evidence_id()),
        "artifact": {"path": report["artifact"]["path"], "sha256": report["artifact"]["sha256"]},
        "limitations": limitations,
        "unknowns": ["Candidates remain inferred; discovery completeness, bytecode kind, hardfork and deployment authenticity are unknown. Runtime execution was not performed."],
    });
    let derived_limitations = shared["limitations"].clone();
    let body = match kind {
        "summary" => summary(&report, shared),
        "evm" => facet(&report, view, shared)?,
        _ => return Err(invalid("EVM Evidence supports summary and evm views.")),
    };

    let unsigned = json!({
        "subject": null,
        "provider": {"id":"analysis-view","name":"REA retained analysis view","version":"1"},
        "analysis_profile": null,
        "predicate_type":"rea.analysis-view",
        "operation":OPERATION,
        "parameters":{"parent_evidence_id":record.evidence_id(),"view":view},
        "raw_result":null,"normalized_result":body,"confidence":"derived","authority":"analyst-inference","environment":null,
        "limitations":derived_limitations,"relationship_coverage":null,"locations":[],"evidence_links":[record.evidence_id()]
    });
    let raw = serde_json::value::to_raw_value(&unsigned).map_err(|e| invalid(&e.to_string()))?;
    let derived = EvidenceRecord::create_unsigned(&raw).map_err(|e| invalid(&e.to_string()))?;
    Ok(
        serde_json::value::RawValue::from_string(derived.raw().get().to_owned())
            .expect("validated Evidence"),
    )
}

fn merged_limitations(record: &EvidenceRecord, report: &Value) -> Result<Value, Failure> {
    let envelope: Value =
        serde_json::from_str(record.raw().get()).map_err(|error| invalid(&error.to_string()))?;
    let mut limitations = BTreeSet::new();

    for source in [envelope.get("limitations"), report.get("limitations")] {
        if let Some(items) = source.and_then(Value::as_array) {
            limitations.extend(items.iter().filter_map(Value::as_str).map(str::to_owned));
        }
    }

    Ok(json!(limitations.into_iter().collect::<Vec<_>>()))
}

fn validate_parent_subject(record: &EvidenceRecord, report: &Value) -> Result<(), Failure> {
    let subject: Value =
        serde_json::from_str(record.subject().get()).map_err(|e| invalid(&e.to_string()))?;
    let path = report["artifact"]["path"].as_str();
    let digest = report["artifact"]["sha256"].as_str();
    let matches = subject["format"].as_str() == Some("file")
        && subject["local_path"].as_str() == path
        && subject["digest"]["sha256"].as_str() == digest;
    if matches {
        Ok(())
    } else {
        Err(invalid(
            "EVM parent subject must identify the report's exact carrier path and SHA-256.",
        ))
    }
}

fn summary(report: &Value, shared: Value) -> Value {
    let mut bytecode = report["bytecode"].clone();
    if let Some(object) = bytecode.as_object_mut() {
        object.remove("hex");
    }
    let stdout = report["diagnostics"]["stdout"].as_str().unwrap_or_default();
    let mut output = json!({"kind":"summary","view":{"kind":"summary"},"summary":{"artifact":report["artifact"],"bytecode":bytecode,"evidence_kind":report["evidence_kind"],"functions":report["functions"],"discovery_completeness":report["discovery_completeness"],"runtime_execution":report["runtime_execution"],"diagnostics":{"stderr":report["diagnostics"]["stderr"],"truncated":report["diagnostics"]["truncated"],"stdout_code_units":stdout.encode_utf16().count()},"limitations":report["limitations"]},"coverage":complete_coverage(report["functions"].as_array().map_or(0, Vec::len))});
    output
        .as_object_mut()
        .unwrap()
        .extend(shared.as_object().unwrap().clone());
    output
}

fn facet(report: &Value, view: &Value, shared: Value) -> Result<Value, Failure> {
    let facet = view
        .get("facet")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("EVM facet is required."))?;
    let offset = view.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
    let limit = view.get("limit").and_then(Value::as_u64).unwrap_or(64) as usize;
    if limit == 0 {
        return Err(invalid("EVM view limit must be positive."));
    }
    let mut output = json!({"kind":"evm","view":view});
    if facet == "functions" {
        let entries = report["functions"]
            .as_array()
            .ok_or_else(|| invalid("EVM functions are missing."))?;
        let item = entries
            .iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        output["item"] = json!(item);
        output["coverage"] = page_coverage(offset, item.len(), entries.len());
    } else {
        let text = report[if facet == "bytecode_hex" {
            "bytecode"
        } else {
            "diagnostics"
        }][if facet == "bytecode_hex" {
            "hex"
        } else {
            facet
        }]
        .as_str()
        .ok_or_else(|| invalid("Unknown EVM facet."))?;
        let (item, examined) = utf16_page(text, offset, limit)?;
        output["item"] = json!({"text":item,"unit":"utf16-code-units"});
        output["coverage"] = page_coverage(offset, examined, text.encode_utf16().count());
    }
    output
        .as_object_mut()
        .unwrap()
        .extend(shared.as_object().unwrap().clone());
    Ok(output)
}

fn utf16_page(text: &str, offset: usize, limit: usize) -> Result<(String, usize), Failure> {
    let units = text.encode_utf16().collect::<Vec<_>>();
    let start = offset.min(units.len());
    let end = (start + limit).min(units.len());
    if start > 0
        && start < units.len()
        && (0xDC00..=0xDFFF).contains(&units[start])
        && (0xD800..=0xDBFF).contains(&units[start - 1])
    {
        return Err(invalid("EVM text offset splits a UTF-16 surrogate pair."));
    }
    let mut end = end;
    if end < units.len()
        && end > start
        && (0xD800..=0xDBFF).contains(&units[end - 1])
        && (0xDC00..=0xDFFF).contains(&units[end])
    {
        end -= 1;
    }
    if end == start && start < units.len() {
        return Err(invalid(
            "Increase EVM text limit to include the next complete Unicode character.",
        ));
    }
    Ok((String::from_utf16_lossy(&units[start..end]), end - start))
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_non_evm_parent() {
        let parent = json!({"evidence_id":"ev_".to_owned()+&"a".repeat(64),"subject":null});
        assert!(project(&parent, &json!({"kind":"summary"})).is_err());
    }
}
