//! Application boundary for static JavaScript application analysis.
//!
//! This boundary enforces caller selection and integrity policy before
//! preserving a provider's complete or summary result. Reconstruction
//! assembly is owned by [`super::reconstruction`].

use rea_core::{
    canonical_json,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "analyze_javascript_application";
const MAX_RECORDS: usize = 4_096;
const MAX_SEMANTIC_ITEMS: u64 = 1_000_000;

const INPUT_FIELDS: &[&str] = &[
    "input_path",
    "format",
    "integrity_policy",
    "source_paths",
    "detail",
    "max_semantic_nodes",
    "max_semantic_nodes_per_file",
    "max_semantic_unknowns",
    "max_semantic_unknowns_per_file",
    "max_heap_mb",
    "analysis_timeout_ms",
];

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("JavaScript application input must be an object"))?;
    if let Some(field) = object
        .keys()
        .find(|field| !INPUT_FIELDS.contains(&field.as_str()))
    {
        return Err(invalid(&format!(
            "JavaScript application input contains unknown field: {field}"
        )));
    }
    let path = object
        .get("input_path")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("input_path must be a non-empty local path"))?;
    if path.contains('\0') {
        return Err(invalid("input_path must not contain NUL bytes"));
    }
    if let Some(detail) = object.get("detail") {
        if detail.as_str() != Some("complete") && detail.as_str() != Some("summary") {
            return Err(invalid("detail must be complete or summary"));
        }
    }
    if let Some(format) = object.get("format") {
        if !matches!(format.as_str(), Some("auto" | "asar" | "directory")) {
            return Err(invalid("format must be auto, asar, or directory"));
        }
    }
    if let Some(policy) = object.get("integrity_policy") {
        if !matches!(policy.as_str(), Some("fail" | "record-and-continue")) {
            return Err(invalid(
                "integrity_policy must be fail or record-and-continue",
            ));
        }
    }
    if let Some(paths) = object.get("source_paths") {
        let paths = paths
            .as_array()
            .ok_or_else(|| invalid("source_paths must be an array"))?;
        if paths.is_empty() {
            return Err(invalid("source_paths must contain at least one path"));
        }

        for path in paths {
            path.as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| invalid("source_paths must contain non-empty strings"))?;
        }
    }

    for field in [
        "max_semantic_nodes",
        "max_semantic_nodes_per_file",
        "max_semantic_unknowns",
        "max_semantic_unknowns_per_file",
    ] {
        if let Some(value) = object.get(field) {
            let value = value
                .as_u64()
                .ok_or_else(|| invalid(&format!("{field} must be an integer")))?;
            if !(1..=MAX_SEMANTIC_ITEMS).contains(&value) {
                return Err(invalid(&format!(
                    "{field} must be between 1 and {MAX_SEMANTIC_ITEMS}"
                )));
            }
        }
    }
    if let Some(value) = object.get("max_heap_mb") {
        let value = value
            .as_u64()
            .ok_or_else(|| invalid("max_heap_mb must be an integer"))?;
        if !(128..=16_384).contains(&value) {
            return Err(invalid("max_heap_mb must be between 128 and 16384"));
        }
    }
    if let Some(value) = object.get("analysis_timeout_ms") {
        let value = value
            .as_u64()
            .ok_or_else(|| invalid("analysis_timeout_ms must be an integer"))?;
        if !(1..=2_147_483_647).contains(&value) {
            return Err(invalid(
                "analysis_timeout_ms must be between 1 and 2147483647",
            ));
        }
    }
    Ok(())
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("JavaScript application result must be an object"));
    }
    Ok(result)
}

/// Produce a bounded application inventory from one selected analysis Evidence.
///
/// The producer only projects facts already authenticated by the selected
/// Evidence. It does not reinterpret source text, resolve imports, or infer
/// runtime loading from graph absence.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let evidence = selected_evidence(input)?;
    let result = evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .ok_or_else(|| invalid("selected Evidence has no normalized_result"))?;
    let result_object = result
        .as_object()
        .ok_or_else(|| invalid("selected JavaScript Evidence result must be an object"))?;
    let graph = result_object
        .get("graph")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("selected JavaScript Evidence has no graph"))?;
    let nodes = graph
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("selected JavaScript graph nodes must be an array"))?;

    let (scripts, omitted_scripts) =
        records_for_kinds(nodes, &["javascript-asset", "javascript-chunk"]);
    let (modules, omitted_modules) =
        records_for_kinds(nodes, &["javascript-module", "source-module"]);
    let graph_coverage = graph.get("coverage").cloned().unwrap_or_else(|| {
        json!({
            "status": "partial",
            "truncated": true,
            "omitted_count": 0,
            "limits": ["Selected graph did not declare coverage."]
        })
    });
    let mut limitations = string_array(graph.get("limitations"));
    limitations.extend(string_array(result_object.get("limitations")));
    if omitted_scripts > 0 || omitted_modules > 0 {
        limitations.push("Application records exceeded the projection record limit; omitted records remain unknown.".into());
    }
    limitations.sort();
    limitations.dedup();

    let source_evidence_id = evidence
        .get("evidence_id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("selected Evidence must include evidence_id"))?;
    let coverage_status = if omitted_scripts == 0
        && omitted_modules == 0
        && graph_coverage.get("status").and_then(Value::as_str) == Some("complete")
    {
        "complete-within-input"
    } else {
        "partial"
    };
    let mut output = json!({
        "input_path": result_object.get("input_path").cloned().unwrap_or(Value::Null),
        "format": result_object.get("format").cloned().unwrap_or(Value::Null),
        "root_artifact_sha256": result_object.get("root_artifact_sha256").cloned().unwrap_or(Value::Null),
        "source_evidence_ids": [source_evidence_id],
        "scripts": scripts,
        "modules": modules,
        "coverage": {
            "status": coverage_status,
            "source": graph_coverage,
            "omitted_scripts": omitted_scripts,
            "omitted_modules": omitted_modules,
        },
        "limitations": limitations,
    });
    let digest = canonical_json::digest(&output).map_err(|error| invalid(&error.to_string()))?;
    output["projection_id"] = Value::String(format!("jap_{digest}"));
    Ok(output)
}

fn selected_evidence(input: &Value) -> Result<&Map<String, Value>, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("JavaScript application projection input must be an object"))?;
    let evidence = object
        .get("application_evidence")
        .or_else(|| object.get("analysis_evidence"))
        .or_else(|| object.get("evidence"))
        .ok_or_else(|| invalid("input must include selected application Evidence"))?;
    evidence
        .as_object()
        .ok_or_else(|| invalid("selected application Evidence must be an object"))
}

fn records_for_kinds(nodes: &[Value], kinds: &[&str]) -> (Vec<Value>, usize) {
    let mut records = nodes
        .iter()
        .filter(|node| {
            node.get("kind")
                .and_then(Value::as_str)
                .is_some_and(|kind| kinds.contains(&kind))
        })
        .cloned()
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        left.get("node_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .cmp(right.get("node_id").and_then(Value::as_str).unwrap_or(""))
    });
    let omitted = records.len().saturating_sub(MAX_RECORDS);
    records.truncate(MAX_RECORDS);
    (records, omitted)
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a supported local JavaScript application input and selection.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_selected_sources_and_preserves_provider_result() {
        let input = serde_json::json!({
            "input_path": "/tmp/app.asar",
            "format": "auto",
            "integrity_policy": "fail",
            "source_paths": ["package.json", "main.js"],
            "detail": "summary"
        });
        validate_input(&input).expect("valid application selection");
        let result = retain_result(
            &input,
            serde_json::json!({"coverage": {"status": "partial"}}),
        )
        .expect("provider result is retained");
        assert_eq!(result["coverage"]["status"], "partial");
    }

    #[test]
    fn preserves_repeated_source_selection_and_rejects_empty_selection() {
        let duplicate = serde_json::json!({
            "input_path": "/tmp/app.asar",
            "source_paths": ["main.js", "main.js"]
        });
        validate_input(&duplicate).expect("repeated exact paths remain caller selections");

        let empty = serde_json::json!({
            "input_path": "/tmp/app.asar",
            "source_paths": []
        });
        assert!(validate_input(&empty).is_err());
    }

    #[test]
    fn rejects_unknown_integrity_policy() {
        let unknown = serde_json::json!({
            "input_path": "/tmp/app.asar",
            "integrity_policy": "ignore"
        });
        assert!(validate_input(&unknown).is_err());
    }

    #[test]
    fn projects_selected_evidence_into_deterministic_script_and_module_records() {
        let input = serde_json::json!({
            "application_evidence": {
                "evidence_id": "ev_application",
                "normalized_result": {
                    "input_path": "/tmp/app",
                    "format": "directory",
                    "root_artifact_sha256": "root",
                    "graph": {
                        "nodes": [
                            {"node_id":"jag_node_b","kind":"javascript-module","observations":[]},
                            {"node_id":"jag_node_a","kind":"javascript-asset","observations":[]},
                            {"node_id":"jag_node_x","kind":"package","observations":[]}
                        ],
                        "coverage": {"status":"complete"},
                        "limitations": []
                    },
                    "limitations": []
                }
            }
        });

        let result = project(&input).expect("selected Evidence is projected");
        assert_eq!(
            result["source_evidence_ids"],
            serde_json::json!(["ev_application"])
        );
        assert_eq!(result["scripts"][0]["node_id"], "jag_node_a");
        assert_eq!(result["modules"][0]["node_id"], "jag_node_b");
        assert_eq!(result["coverage"]["status"], "complete-within-input");
        assert!(
            result["projection_id"]
                .as_str()
                .unwrap()
                .starts_with("jap_")
        );
    }

    #[test]
    fn projects_partial_graph_coverage_and_rejects_missing_selected_evidence() {
        let missing = serde_json::json!({});
        assert!(project(&missing).is_err());

        let input = serde_json::json!({
            "evidence": {
                "evidence_id": "ev_partial",
                "normalized_result": {
                    "graph": {
                        "nodes": [],
                        "coverage": {"status":"partial"},
                        "limitations": ["source selection omitted vendor files"]
                    }
                }
            }
        });
        let result = project(&input).expect("partial Evidence is projected");
        assert_eq!(result["coverage"]["status"], "partial");
        assert_eq!(
            result["limitations"][0],
            "source selection omitted vendor files"
        );
    }
}
