//! Views over retained `decode_interface_builder` Evidence.
//!
//! Compatibility owner: `src/domain/analysisView/interfaceBuilderView.ts`.
use crate::common::json::{self, object, unique_sorted};
use crate::common::view::{
    Parent, complete_within_view, offset_limit, page, page_coverage, view_error, view_kind,
};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};

/// `projectInterfaceBuilderView`.
pub fn project(parent: &Parent<'_>, view: &Value) -> Result<Value, AnalysisError> {
    let kind = view_kind(view);
    if kind != "summary" && kind != "interface-builder" {
        return Err(view_error(
            &["view"],
            "invalid_value",
            "Interface Builder decoding supports summary and interface-builder views.",
        ));
    }
    let report = parse_interface_builder_report(parent)?;
    let graph = report.get("graph").unwrap_or(&Value::Null);
    let target_sha256 = report.get("target_sha256").cloned().unwrap_or(Value::Null);

    let limitations = unique_sorted(parent.limitations.iter().cloned().chain(json::strings(
        report.get("limitations").unwrap_or(&Value::Null),
    )));

    let truncated = graph
        .get("truncated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut unknowns = vec![
        "Rows describe recognized archive objects and connections only; unrecognized classes, fields and runtime-created UI remain unknown.".to_owned(),
    ];
    if truncated {
        unknowns.push(
            "The decoded graph is incomplete (see coverage and limitations for the cause); page exhaustion does not establish absence of undecoded objects or connections.".to_owned(),
        );
    }

    let local_path = parent
        .subject
        .get("local_path")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let shared = [
        ("parent_evidence_id", json!(parent.evidence_id)),
        ("parent_operation", json!("decode_interface_builder")),
        ("parent_digest", json!(parent.digest())),
        (
            "artifact",
            json!({ "path": local_path, "sha256": target_sha256.clone() }),
        ),
        ("limitations", json!(limitations)),
        ("unknowns", json!(unknowns)),
    ];

    if kind == "summary" {
        let summary = summarize(&report, graph, limitations.len());
        let total = report
            .get("documents")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0)
            + json::array_at(graph, "nodes").len()
            + json::array_at(graph, "edges").len()
            + json::array_at(graph, "coverage").len();
        let mut out = Map::new();
        out.insert("kind".into(), json!("summary"));
        out.insert("view".into(), view.clone());
        for (key, value) in shared {
            out.insert(key.into(), value);
        }
        out.insert("summary".into(), summary);
        out.insert("coverage".into(), complete_within_view(total, total));
        return Ok(Value::Object(out));
    }

    // interface-builder page view.
    let collection = json::str_at(view, "collection").unwrap_or_default();
    let document = if collection == "nodes" || collection == "edges" {
        view.get("document").and_then(Value::as_str)
    } else {
        None
    };
    if let Some(document) = document {
        let present = report
            .get("documents")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .any(|row| row.get("relative_path").and_then(Value::as_str) == Some(document));
        if !present {
            return Err(view_error(
                &["view", "document"],
                "invalid_value",
                "Select an exact documents[].relative_path from this decoded report.",
            ));
        }
    }

    let documents = report
        .get("documents")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let rows: Vec<Value> = match collection {
        "documents" => documents.to_vec(),
        "coverage" => json::array_at(graph, "coverage").to_vec(),
        "nodes" => in_document(json::array_at(graph, "nodes"), document),
        // "edges"
        _ => in_document(json::array_at(graph, "edges"), document),
    };
    let (offset, limit) = offset_limit(view);
    let items = page(&rows, offset, limit);
    let examined = items.len();

    let mut out = Map::new();
    out.insert("kind".into(), json!("interface-builder"));
    out.insert("view".into(), view.clone());
    out.insert("items".into(), Value::Array(items));
    for (key, value) in shared {
        out.insert(key.into(), value);
    }
    out.insert("source_truncated".into(), json!(truncated));
    out.insert(
        "coverage".into(),
        page_coverage(offset, examined, rows.len()),
    );
    Ok(Value::Object(out))
}

/// Filter graph rows whose evidence names `document`, or all rows when absent.
fn in_document(candidates: &[Value], document: Option<&str>) -> Vec<Value> {
    match document {
        None => candidates.to_vec(),
        Some(document) => candidates
            .iter()
            .filter(|row| {
                json::array_at(row, "evidence").iter().any(|evidence| {
                    evidence.get("artifact_path").and_then(Value::as_str) == Some(document)
                })
            })
            .cloned()
            .collect(),
    }
}

/// `parseInterfaceBuilderReport`: admit a report bound to its recorded target.
fn parse_interface_builder_report(
    parent: &Parent<'_>,
) -> Result<std::sync::Arc<Value>, AnalysisError> {
    let report = parent.parse_result("decode_interface_builder")?;
    let graph = report.get("graph").unwrap_or(&Value::Null);
    let target = report.get("target_sha256");
    let graph_target = graph.get("target_sha256");
    let subject_mismatch = parent.subject.is_object()
        && parent
            .subject
            .get("digest")
            .and_then(|digest| digest.get("sha256"))
            != target;
    if graph_target != target || subject_mismatch {
        return Err(view_error(
            &["source", "subject"],
            "invalid_value",
            "Interface Builder parent Evidence subject and graph must identify the report's target SHA-256.",
        ));
    }
    Ok(report)
}

/// `summarizeInterfaceBuilder`: documents with graph tallies.
fn summarize(report: &Value, graph: &Value, limitation_count: usize) -> Value {
    object([
        (
            "target_sha256",
            report.get("target_sha256").cloned().unwrap_or(Value::Null),
        ),
        (
            "provider",
            graph.get("provider").cloned().unwrap_or(Value::Null),
        ),
        (
            "documents",
            report.get("documents").cloned().unwrap_or(Value::Null),
        ),
        (
            "available_counts",
            json!({
                "nodes": json::array_at(graph, "nodes").len(),
                "edges": json::array_at(graph, "edges").len(),
                "coverage": json::array_at(graph, "coverage").len(),
            }),
        ),
        ("node_kinds", tally(json::array_at(graph, "nodes"), "kind")),
        (
            "edge_relations",
            tally(json::array_at(graph, "edges"), "relation"),
        ),
        (
            "coverage_statuses",
            tally(json::array_at(graph, "coverage"), "status"),
        ),
        (
            "truncated",
            json!(
                graph
                    .get("truncated")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            ),
        ),
        ("limitation_count", json!(limitation_count)),
    ])
}

/// `tally`: count each value of `field`, ordered by key (code-point order).
fn tally(rows: &[Value], field: &str) -> Value {
    let mut counts: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    for row in rows {
        if let Some(value) = row.get(field).and_then(Value::as_str) {
            *counts.entry(value.to_owned()).or_insert(0) += 1;
        }
    }
    let mut map = Map::new();
    for (key, count) in counts {
        map.insert(key, json!(count));
    }
    Value::Object(map)
}
