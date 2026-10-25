//! Correlates caller-declared static comparison findings with process evidence.
//!
//! The workflow only evaluates supplied Evidence.  It does not infer a causal
//! relationship, execute a target, or search for an unrequested mapping.

use rea_core::{
    canonical_json,
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "correlate_static_and_runtime";

const FUNCTION_DIMENSIONS: [&str; 8] = [
    "identity",
    "pseudocode",
    "assembly",
    "comments",
    "calls",
    "references",
    "strings_names",
    "cfg",
];
const RUNTIME_DIMENSIONS: [&str; 5] = ["interaction", "exit", "filesystem", "process", "terminal"];

/// Evaluate explicit static/runtime hypotheses and return derived Evidence.
pub fn correlate(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;
    let statics = required_array(object, "static_comparisons")?;
    let runtimes = required_array(object, "runtime_comparisons")?;
    let mappings = required_array(object, "mappings")?;
    if statics.is_empty() || runtimes.is_empty() || mappings.is_empty() {
        return Err(invalid(
            "static_comparisons, runtime_comparisons, and mappings must be non-empty",
        ));
    }

    let static_records = parse_static(statics)?;
    let runtime_records = parse_runtime(runtimes)?;
    reject_duplicate_ids(&static_records, "static comparison Evidence")?;
    reject_duplicate_ids(&runtime_records, "runtime comparison Evidence")?;
    let static_by_id = index(&static_records);
    let runtime_by_id = index(&runtime_records);

    let mut items = Vec::with_capacity(mappings.len());
    for mapping in mappings {
        items.push(correlate_mapping(mapping, &static_by_id, &runtime_by_id)?);
    }
    items.sort_by(|left, right| {
        left["correlation_id"]
            .as_str()
            .cmp(&right["correlation_id"].as_str())
    });
    let mut seen = BTreeSet::new();
    for item in &items {
        if !seen.insert(item["correlation_id"].as_str().unwrap_or_default()) {
            return Err(invalid(
                "Static/runtime correlation rejects duplicate mappings",
            ));
        }
    }

    let unresolved = items
        .iter()
        .filter(|item| item["classification"] == "unresolved_branch")
        .count();
    let contradictions = items
        .iter()
        .filter(|item| item["classification"] == "contradiction")
        .count();
    let truncated = items
        .iter()
        .any(|item| item["observed_pattern"] == "truncated");
    let mut links = BTreeSet::new();
    for item in &items {
        if let Some(values) = item["evidence_links"].as_array() {
            for value in values.iter().filter_map(Value::as_str) {
                links.insert(value.to_owned());
            }
        }
    }
    let status = if truncated {
        "truncated"
    } else if unresolved > 0 {
        "unknown"
    } else if contradictions > 0 {
        "contradicted"
    } else {
        "correlated"
    };
    Ok(json!({
        "status": status,
        "summary": {"hypotheses": items.len().saturating_sub(unresolved + contradictions), "contradictions": contradictions, "unresolved": unresolved},
        "correlations": {"items": items},
        "evidence_links": links.into_iter().map(Value::String).collect::<Vec<_>>(),
        "limitations": [
            "Mappings are caller-declared hypotheses; consistency does not establish causality.",
            "Only explicit mappings were evaluated; similar unmapped observations were not correlated."
        ]
    }))
}

fn correlate_mapping(
    mapping: &Value,
    statics: &BTreeMap<String, Evidence>,
    runtimes: &BTreeMap<String, Evidence>,
) -> Result<Value, Failure> {
    let object = mapping
        .as_object()
        .ok_or_else(|| invalid("mapping must be an object"))?;
    reject_unknown_fields(
        object,
        &["static", "runtime", "side_alignment", "hypothesis"],
        "mapping",
    )?;
    let static_ref = object
        .get("static")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("mapping.static must be an object"))?;
    let runtime_ref = object
        .get("runtime")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("mapping.runtime must be an object"))?;
    reject_unknown_fields(
        static_ref,
        &["comparison_evidence_id", "selector"],
        "mapping.static",
    )?;
    reject_unknown_fields(
        runtime_ref,
        &["comparison_evidence_id", "dimension"],
        "mapping.runtime",
    )?;
    let static_id = string_field(static_ref, "comparison_evidence_id")?;
    let runtime_id = string_field(runtime_ref, "comparison_evidence_id")?;
    let static_record = statics
        .get(static_id)
        .ok_or_else(|| invalid("Mapping references absent static comparison Evidence"))?;
    let runtime_record = runtimes
        .get(runtime_id)
        .ok_or_else(|| invalid("Mapping references absent runtime comparison Evidence"))?;
    let side_alignment = object
        .get("side_alignment")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "left_to_left" | "left_to_right"))
        .ok_or_else(|| invalid("mapping.side_alignment is invalid"))?;
    let dimension = string_field(runtime_ref, "dimension")?;
    if !RUNTIME_DIMENSIONS.contains(&dimension) {
        return Err(invalid(
            "mapping.runtime.dimension is not a process comparison dimension",
        ));
    }
    let selector = static_ref
        .get("selector")
        .ok_or_else(|| invalid("mapping.static.selector is required"))?;
    if let Some(selector_object) = selector.as_object() {
        match selector_object.get("kind").and_then(Value::as_str) {
            Some("function") => reject_unknown_fields(
                selector_object,
                &["kind", "dimension"],
                "mapping.static.selector",
            )?,
            Some("artifact") => reject_unknown_fields(
                selector_object,
                &["kind", "logical_path"],
                "mapping.static.selector",
            )?,
            _ => {}
        }
    }
    let (static_status, conclusion, selected_limits) = select_static(static_record, selector)?;
    let runtime_status = runtime_record
        .normalized
        .pointer(&format!("/{dimension}"))
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("runtime comparison omitted its selected dimension"))?;
    if !matches!(
        runtime_status,
        "unchanged" | "changed" | "unknown" | "truncated"
    ) {
        return Err(invalid("runtime comparison dimension has invalid status"));
    }
    let expected = object
        .get("hypothesis")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("mapping.hypothesis must be an object"))?;
    reject_unknown_fields(
        expected,
        &["statement", "expected_pattern"],
        "mapping.hypothesis",
    )?;
    let statement = expected
        .get("statement")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("hypothesis.statement is required"))?;
    let expected_pattern = expected
        .get("expected_pattern")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("hypothesis.expected_pattern is required"))?;
    if !["cochanged", "static_only", "runtime_only", "both_unchanged"].contains(&expected_pattern) {
        return Err(invalid("hypothesis.expected_pattern is invalid"));
    }
    let observed = observed_pattern(&static_status, runtime_status);
    let classification = if matches!(observed, "unknown" | "truncated") {
        "unresolved_branch"
    } else if observed == expected_pattern {
        "hypothesis"
    } else {
        "contradiction"
    };
    let projection = json!({"static":{"comparison_evidence_id":static_id,"selector":selector},"runtime":{"comparison_evidence_id":runtime_id,"dimension":dimension},"side_alignment":side_alignment,"hypothesis":{"statement":statement,"expected_pattern":expected_pattern}});
    let digest =
        canonical_json::digest(&projection).map_err(|error| invalid(&error.to_string()))?;
    let mut links = BTreeSet::new();
    links.insert(static_record.id.clone());
    links.extend(static_record.links.iter().cloned());
    links.insert(runtime_record.id.clone());
    links.extend(runtime_record.links.iter().cloned());
    let mut limitations = BTreeSet::new();
    limitations.extend(static_record.limitations.iter().cloned());
    limitations.extend(selected_limits);
    limitations.extend(runtime_record.limitations.iter().cloned());
    if let Some(values) = runtime_record
        .normalized
        .get("limitations")
        .and_then(Value::as_array)
    {
        limitations.extend(values.iter().filter_map(Value::as_str).map(str::to_owned));
    }
    limitations.insert(
        "This correlation tests an explicit hypothesis and does not establish causality.".into(),
    );
    limitations.insert("Side alignment is caller-declared and was not independently validated against source subjects or environments.".into());
    Ok(json!({
        "correlation_id": format!("cor_{digest}"),
        "static": {"comparison_evidence_id":static_id,"selector":selector,"status":static_status,"conclusion_kind":conclusion},
        "runtime": {"comparison_evidence_id":runtime_id,"dimension":dimension,"status":runtime_status},
        "side_alignment":side_alignment,
        "hypothesis":{"statement":statement,"expected_pattern":expected_pattern},
        "observed_pattern":observed,
        "classification":classification,
        "evidence_links":links.into_iter().map(Value::String).collect::<Vec<_>>(),
        "limitations":limitations.into_iter().collect::<Vec<_>>()
    }))
}

fn select_static(
    record: &Evidence,
    selector: &Value,
) -> Result<(String, &'static str, Vec<String>), Failure> {
    let selector = selector
        .as_object()
        .ok_or_else(|| invalid("mapping.static.selector must be an object"))?;
    match selector.get("kind").and_then(Value::as_str) {
        Some("function") => {
            if record.operation != "compare_functions" {
                return Err(invalid(
                    "Function selector requires function comparison Evidence",
                ));
            }
            let dimension = selector
                .get("dimension")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("function selector dimension is required"))?;
            if !FUNCTION_DIMENSIONS.contains(&dimension) {
                return Err(invalid("function selector dimension is invalid"));
            }
            let dimensions = record
                .normalized
                .get("dimensions")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("function comparison omitted dimensions"))?;
            let matches = dimensions
                .iter()
                .filter(|item| item.get("dimension").and_then(Value::as_str) == Some(dimension))
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err(invalid("Function selector must resolve exactly once"));
            }
            let item = matches[0];
            let status = item
                .get("status")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("function dimension omitted status"))?;
            ensure_status(status)?;
            let conclusion: &'static str = match item.get("conclusion_kind").and_then(Value::as_str)
            {
                Some("contradiction") => "contradiction",
                Some("unresolved_branch") => "unresolved_branch",
                _ => "derived_relationship",
            };
            Ok((
                status.to_owned(),
                conclusion,
                strings(item.get("limitations")),
            ))
        }
        Some("artifact") => {
            if record.operation != "compare_artifacts" {
                return Err(invalid(
                    "Artifact selector requires artifact comparison Evidence",
                ));
            }
            let path = selector
                .get("logical_path")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| invalid("artifact selector logical_path is required"))?;
            let changes = record
                .normalized
                .get("changes")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("artifact comparison omitted changes"))?;
            let matches = changes
                .iter()
                .filter(|item| item.get("logical_path").and_then(Value::as_str) == Some(path))
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err(invalid(
                    "Artifact selector must resolve exactly one reported delta",
                ));
            }
            let item = matches[0];
            let status = item
                .get("classification")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("artifact change omitted classification"))?;
            ensure_status(status)?;
            let conclusion = match status {
                "contradiction" => "contradiction",
                "unknown" => "unresolved_branch",
                _ => "derived_relationship",
            };
            Ok((status.to_owned(), conclusion, Vec::new()))
        }
        _ => Err(invalid("mapping.static.selector.kind is invalid")),
    }
}

fn reject_unknown_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    label: &str,
) -> Result<(), Failure> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid(&format!("{label} contains unknown fields")));
    }
    Ok(())
}

fn observed_pattern(static_status: &str, runtime_status: &str) -> &'static str {
    if static_status == "truncated" || runtime_status == "truncated" {
        return "truncated";
    }
    if static_status == "unknown" || runtime_status == "unknown" {
        return "unknown";
    }
    let static_changed = static_status != "unchanged";
    let runtime_changed = runtime_status != "unchanged";
    match (static_changed, runtime_changed) {
        (true, true) => "cochanged",
        (true, false) => "static_only",
        (false, true) => "runtime_only",
        (false, false) => "both_unchanged",
    }
}

#[derive(Clone)]
struct Evidence {
    id: String,
    operation: String,
    normalized: Value,
    links: Vec<String>,
    limitations: Vec<String>,
}

fn parse_static(values: &[Value]) -> Result<Vec<Evidence>, Failure> {
    values
        .iter()
        .map(|value| parse_comparison(value, &["compare_artifacts", "compare_functions"], "static"))
        .collect()
}
fn parse_runtime(values: &[Value]) -> Result<Vec<Evidence>, Failure> {
    values
        .iter()
        .map(|value| parse_comparison(value, &["compare_process_captures"], "runtime"))
        .collect()
}
fn parse_comparison(value: &Value, operations: &[&str], side: &str) -> Result<Evidence, Failure> {
    let raw =
        serde_json::value::to_raw_value(value).map_err(|error| invalid(&error.to_string()))?;
    let record = EvidenceRecord::parse(&raw).map_err(|error| integrity(side, error))?;
    let operation: String = serde_json::from_str(record.operation().get())
        .map_err(|_| invalid("Evidence operation must be a string"))?;
    if !operations.contains(&operation.as_str()) {
        return Err(invalid(&format!(
            "{side} Evidence operation is not an allowed comparison"
        )));
    }
    let normalized: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| invalid(&error.to_string()))?;
    validate_result_shape(&normalized, &operation)?;
    let provider: Value = serde_json::from_str(record.provider_manifest().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let raw_object: Value =
        serde_json::from_str(record.raw().get()).map_err(|error| invalid(&error.to_string()))?;
    let links = strings(raw_object.get("evidence_links"));
    let limitations = strings(raw_object.get("limitations"));
    let confidence: Value = serde_json::from_str(record.confidence().get()).unwrap_or(Value::Null);
    let authority: Value = serde_json::from_str(record.authority().get()).unwrap_or(Value::Null);
    let subject: Value = serde_json::from_str(record.subject().get()).unwrap_or(Value::Null);
    if confidence.as_str() != Some("derived")
        || authority.as_str() != Some("analyst-inference")
        || !subject.is_null()
    {
        return Err(invalid(
            "Comparison Evidence operation, provider, or citations disagree",
        ));
    }
    validate_source_closure(&raw_object, &links, &operation)?;
    let predicate: String = serde_json::from_str(record.predicate_type().get())
        .map_err(|_| invalid("Evidence predicate_type must be a string"))?;
    let expected_predicate = match operation.as_str() {
        "compare_artifacts" => "rea.artifact-comparison",
        "compare_functions" => "rea.function-comparison",
        "compare_process_captures" => "rea.process-comparison",
        _ => "",
    };
    if predicate != expected_predicate {
        return Err(invalid(
            "Comparison Evidence predicate_type disagrees with operation",
        ));
    }
    validate_provider(&provider, &operation)?;
    if links.len() < 2 || links.iter().any(|link| link.is_empty()) {
        return Err(invalid(
            "Comparison Evidence must retain at least two source Evidence links",
        ));
    }
    Ok(Evidence {
        id: record.evidence_id().to_owned(),
        operation,
        normalized,
        links,
        limitations,
    })
}

fn validate_result_shape(result: &Value, operation: &str) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("comparison normalized_result must be an object"))?;
    match operation {
        "compare_functions" => {
            let overall_status = object
                .get("status")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("function comparison omitted status"))?;
            if !["unchanged", "changed", "unknown"].contains(&overall_status) {
                return Err(invalid("function comparison status is invalid"));
            }
            let function_match = object
                .get("function_match")
                .and_then(Value::as_object)
                .ok_or_else(|| invalid("function comparison omitted function_match"))?;
            let match_status = function_match
                .get("status")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("function comparison omitted function_match.status"))?;
            let match_method = function_match
                .get("method")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("function comparison omitted function_match.method"))?;
            if !["matched", "mismatched", "ambiguous"].contains(&match_status)
                || !["symbol", "explicit"].contains(&match_method)
            {
                return Err(invalid("function comparison match is invalid"));
            }
            if (match_status == "matched" && match_method != "symbol")
                || (match_status != "matched" && match_method != "explicit")
            {
                return Err(invalid(
                    "function comparison match method contradicts status",
                ));
            }
            if function_match
                .get("left_name")
                .and_then(Value::as_str)
                .is_none()
                || function_match
                    .get("right_name")
                    .and_then(Value::as_str)
                    .is_none()
            {
                return Err(invalid("function comparison match omitted names"));
            }
            let dimensions = object
                .get("dimensions")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("function comparison omitted dimensions"))?;
            if dimensions.len() != FUNCTION_DIMENSIONS.len() {
                return Err(invalid(
                    "function comparison must contain exactly eight dimensions",
                ));
            }
            let mut names = BTreeSet::new();
            let mut has_changed = false;
            let mut has_unknown = false;
            for item in dimensions {
                let item = item
                    .as_object()
                    .ok_or_else(|| invalid("function dimension must be an object"))?;
                let name = item
                    .get("dimension")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("function dimension omitted name"))?;
                if !FUNCTION_DIMENSIONS.contains(&name) || !names.insert(name) {
                    return Err(invalid(
                        "function comparison dimensions are not unique and complete",
                    ));
                }
                let status = item
                    .get("status")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("function dimension omitted status"))?;
                if !["unchanged", "changed", "unknown"].contains(&status) {
                    return Err(invalid("function dimension status is invalid"));
                }
                has_changed |= status == "changed";
                has_unknown |= status == "unknown";
                if item
                    .get("evidence_links")
                    .and_then(Value::as_array)
                    .is_none()
                {
                    return Err(invalid("function dimension omitted evidence_links"));
                }
                if item.get("limitations").and_then(Value::as_array).is_none() {
                    return Err(invalid("function dimension omitted limitations"));
                }
                match status {
                    "unknown" => {
                        if !item.get("left_digest").is_some_and(Value::is_null)
                            || !item.get("right_digest").is_some_and(Value::is_null)
                            || !item.get("text_delta").is_some_and(Value::is_null)
                        {
                            return Err(invalid(
                                "unknown function dimension must omit digests and text delta",
                            ));
                        }
                        if item.get("conclusion_kind").and_then(Value::as_str)
                            != Some("unresolved_branch")
                        {
                            return Err(invalid(
                                "unknown function dimension conclusion is invalid",
                            ));
                        }
                    }
                    "unchanged" => {
                        if item.get("conclusion_kind").and_then(Value::as_str)
                            != Some("derived_relationship")
                        {
                            return Err(invalid(
                                "unchanged function dimension conclusion is invalid",
                            ));
                        }
                    }
                    "changed" => {
                        if !["derived_relationship", "contradiction"].contains(
                            &item
                                .get("conclusion_kind")
                                .and_then(Value::as_str)
                                .unwrap_or_default(),
                        ) {
                            return Err(invalid(
                                "changed function dimension conclusion is invalid",
                            ));
                        }
                    }
                    _ => unreachable!(),
                }
            }
            let expected_status = if match_status == "mismatched" || has_changed {
                "changed"
            } else if match_status == "ambiguous" || has_unknown {
                "unknown"
            } else {
                "unchanged"
            };
            if overall_status != expected_status {
                return Err(invalid(
                    "function comparison status contradicts its dimensions or function match",
                ));
            }
        }
        "compare_artifacts" => {
            ensure_status(
                object
                    .get("status")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("artifact comparison omitted status"))?,
            )?;
            let changes = object
                .get("changes")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("artifact comparison omitted changes"))?;
            for item in changes {
                let item = item
                    .as_object()
                    .ok_or_else(|| invalid("artifact change must be an object"))?;
                if item
                    .get("logical_path")
                    .and_then(Value::as_str)
                    .filter(|path| !path.is_empty())
                    .is_none()
                    || item.get("classification").and_then(Value::as_str).is_none()
                {
                    return Err(invalid(
                        "artifact change omitted logical_path or classification",
                    ));
                }
                if !["added", "removed", "changed", "unknown", "contradiction"].contains(
                    &item
                        .get("classification")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                ) {
                    return Err(invalid("artifact change classification is invalid"));
                }
                if item
                    .get("dimensions")
                    .and_then(Value::as_array)
                    .map(|items| items.is_empty())
                    .unwrap_or(true)
                {
                    return Err(invalid("artifact change omitted dimensions"));
                }
                if item
                    .get("evidence_links")
                    .and_then(Value::as_array)
                    .is_none()
                {
                    return Err(invalid("artifact change omitted evidence_links"));
                }
            }
        }
        "compare_process_captures" => {
            let status = object
                .get("status")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("process comparison omitted status"))?;
            ensure_status(status)?;
            for dimension in RUNTIME_DIMENSIONS {
                ensure_status(
                    object
                        .get(dimension)
                        .and_then(Value::as_str)
                        .ok_or_else(|| invalid("process comparison omitted dimension"))?,
                )?;
            }
            if object
                .get("limitations")
                .and_then(Value::as_array)
                .is_none()
            {
                return Err(invalid("process comparison omitted limitations"));
            }
            let statuses = RUNTIME_DIMENSIONS
                .iter()
                .filter_map(|dimension| object.get(*dimension).and_then(Value::as_str))
                .collect::<Vec<_>>();
            let expected_status = if statuses.iter().any(|status| *status == "truncated") {
                "truncated"
            } else if statuses
                .iter()
                .any(|status| ["changed", "added", "removed"].contains(status))
            {
                "changed"
            } else if statuses.iter().any(|status| *status == "unknown") {
                "unknown"
            } else {
                "unchanged"
            };
            if status != expected_status {
                return Err(invalid(
                    "process comparison status contradicts its dimensions",
                ));
            }
        }
        _ => return Err(invalid("unsupported comparison operation")),
    }
    Ok(())
}

fn validate_provider(provider: &Value, operation: &str) -> Result<(), Failure> {
    let object = provider
        .as_object()
        .ok_or_else(|| invalid("Comparison Evidence provider must be an object"))?;
    let id = object.get("id").and_then(Value::as_str).unwrap_or_default();
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let version = object
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let valid = match operation {
        "compare_artifacts" => {
            id == "rea-artifact-comparison" && name == "REA artifact comparison" && version == "1"
        }
        "compare_functions" => {
            id == "rea-function-comparison" && name == "REA function comparison" && version == "1"
        }
        "compare_process_captures" => {
            id == "rea-process"
                && version == "3"
                && (name == "REA process capture" || name == "REA deterministic process harness")
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(invalid(
            "Comparison Evidence provider identity disagrees with operation",
        ))
    }
}

fn validate_source_closure(raw: &Value, links: &[String], operation: &str) -> Result<(), Failure> {
    let parameters = raw
        .get("parameters")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("Comparison Evidence omitted parameters"))?;
    let expected = match operation {
        "compare_process_captures" => ["left_evidence_id", "right_evidence_id"].as_slice(),
        "compare_functions" => ["left_evidence_id", "right_evidence_id"].as_slice(),
        "compare_artifacts" => ["left_evidence_ids", "right_evidence_ids"].as_slice(),
        _ => return Err(invalid("Unsupported comparison operation")),
    };
    let mut declared = Vec::new();
    for name in expected {
        let value = parameters
            .get(*name)
            .ok_or_else(|| invalid("Comparison Evidence parameters omitted source references"))?;
        if let Some(id) = value.as_str() {
            declared.push(id.to_owned());
        } else if let Some(ids) = value.as_array() {
            declared.extend(ids.iter().filter_map(Value::as_str).map(str::to_owned));
        } else {
            return Err(invalid(
                "Comparison Evidence source references must be strings or arrays",
            ));
        }
    }
    declared.sort();
    let mut actual = links.to_vec();
    actual.sort();
    declared.dedup();
    actual.dedup();
    if declared != actual {
        return Err(invalid(
            "Comparison Evidence closure disagrees with its source parameters",
        ));
    }
    Ok(())
}

fn ensure_status(value: &str) -> Result<(), Failure> {
    if [
        "unchanged",
        "changed",
        "unknown",
        "truncated",
        "added",
        "removed",
        "contradiction",
    ]
    .contains(&value)
    {
        Ok(())
    } else {
        Err(invalid("comparison status is invalid"))
    }
}
fn required_array<'a>(
    object: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a Vec<Value>, Failure> {
    object
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(&format!("{name} must be an array")))
}
fn string_field<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, Failure> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(&format!("{name} is required")))
}
fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
fn index(values: &[Evidence]) -> BTreeMap<String, Evidence> {
    values
        .iter()
        .cloned()
        .map(|item| (item.id.clone(), item))
        .collect()
}
fn reject_duplicate_ids(values: &[Evidence], label: &str) -> Result<(), Failure> {
    let mut ids = BTreeSet::new();
    if values.iter().any(|item| !ids.insert(item.id.as_str())) {
        Err(invalid(&format!(
            "Static/runtime correlation rejects duplicate {label}"
        )))
    } else {
        Ok(())
    }
}
fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide valid comparison Evidence and explicit mappings, then retry.".into(),
        BTreeMap::from([("operation".into(), Detail::Text(OPERATION.into()))]),
    )
}
fn integrity(side: &str, error: impl std::fmt::Display) -> Failure {
    Failure::new(
        "integrity_failure",
        "evidence_integrity",
        format!("{side} Evidence failed integrity validation: {error}"),
        true,
        "Retain the original Evidence and retry.".into(),
        BTreeMap::from([("operation".into(), Detail::Text(OPERATION.into()))]),
    )
}
