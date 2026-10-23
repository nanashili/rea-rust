//! Aggregate authenticated comparison Evidence into behavior findings.
//!
//! This projection deliberately keeps runtime observations separate from
//! static candidates.  Missing or incomplete comparison dimensions become
//! unresolved findings instead of being treated as unchanged behavior.

use rea_core::evidence::record::EvidenceRecord;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "find_changed_behavior";

const PROCESS_DIMENSIONS: [(&str, &str); 5] = [
    ("terminal", "runtime"),
    ("interaction", "runtime"),
    ("exit", "runtime"),
    ("filesystem", "resource"),
    ("process", "runtime"),
];

/// Aggregate caller-selected process, function, and artifact comparisons.
pub fn compare(input: &Value) -> Result<Value, Failure> {
    let input_object = input
        .as_object()
        .ok_or_else(|| invalid("changed-behavior input must be an object"))?;
    if input_object.keys().any(|key| key != "comparisons") {
        return Err(invalid("changed-behavior input contains an unknown field"));
    }
    let comparisons = input
        .get("comparisons")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| invalid("comparisons must be a non-empty array"))?;

    let mut parsed = Vec::with_capacity(comparisons.len());
    let mut comparison_ids = Vec::with_capacity(comparisons.len());
    for item in comparisons {
        let input_evidence = item
            .as_object()
            .ok_or_else(|| invalid("comparison Evidence must be an object"))?;

        let raw = serde_json::value::to_raw_value(item)
            .map_err(|error| invalid(&format!("comparison Evidence is not valid JSON: {error}")))?;
        let record = EvidenceRecord::parse(&raw).map_err(|error| {
            invalid(&format!(
                "comparison Evidence failed authentication: {error}"
            ))
        })?;
        let authenticated = serde_json::from_str::<Value>(record.raw().get()).map_err(|error| {
            invalid(&format!(
                "comparison Evidence could not be retained: {error}"
            ))
        })?;
        let evidence = authenticated
            .as_object()
            .ok_or_else(|| invalid("authenticated comparison Evidence must be an object"))?;

        let id = evidence_id(evidence)?;
        if comparison_ids.iter().any(|existing| existing == &id) {
            return Err(invalid(
                "Changed-behavior analysis rejects duplicate comparison Evidence",
            ));
        }
        let operation = serde_json::from_str::<String>(record.operation().get())
            .map_err(|_| invalid("comparison Evidence operation must be a string"))?;
        validate_comparison_record(&record, evidence, operation.as_str())?;

        if input_evidence.get("evidence_id") != evidence.get("evidence_id") {
            return Err(invalid(
                "comparison Evidence identity changed during authentication",
            ));
        }

        let operation = operation.to_owned();
        comparison_ids.push(id);
        parsed.push((operation, evidence.clone()));
    }

    let mut findings = Vec::new();
    let mut runtime_statuses = Vec::new();
    let mut limitations = Vec::new();
    for (operation, evidence) in parsed {
        let result = evidence
            .get("normalized_result")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("comparison Evidence must include normalized_result"))?;
        limitations.extend(string_values(evidence.get("limitations")));
        limitations.extend(string_values(result.get("limitations")));

        match operation.as_str() {
            "compare_process_captures" => {
                let status = result
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                runtime_statuses.push(status.to_owned());
                for (dimension, scope) in PROCESS_DIMENSIONS {
                    let dimension_status = result
                        .get(dimension)
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    if dimension_status != "unchanged" {
                        findings.push(
                            finding(scope, dimension, dimension_status, &evidence, &[], result)
                                .with_classification(
                                    if matches!(dimension_status, "added" | "removed" | "changed") {
                                        "observed_change"
                                    } else {
                                        "unresolved_branch"
                                    },
                                ),
                        );
                    }
                }
            }
            "compare_functions" => {
                let dimensions = result
                    .get("dimensions")
                    .and_then(Value::as_array)
                    .ok_or_else(|| invalid("function comparison dimensions are required"))?;
                for dimension in dimensions {
                    let status = dimension
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    if status == "unchanged" {
                        continue;
                    }
                    let classification = dimension
                        .get("conclusion_kind")
                        .and_then(Value::as_str)
                        .unwrap_or(if status == "unknown" {
                            "unresolved_branch"
                        } else {
                            "derived_relationship"
                        });
                    findings.push(
                        finding(
                            "static_candidate",
                            dimension
                                .get("dimension")
                                .and_then(Value::as_str)
                                .unwrap_or("unknown"),
                            status,
                            &evidence,
                            &string_values(dimension.get("evidence_links")),
                            result,
                        )
                        .with_classification(classification),
                    );
                }
            }
            "compare_artifacts" => {
                let changes = result
                    .get("changes")
                    .and_then(Value::as_array)
                    .ok_or_else(|| invalid("artifact comparison changes are required"))?;
                let mut has_unresolved = false;
                for change in changes {
                    let status = change
                        .get("classification")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    let classification = match status {
                        "contradiction" => "contradiction",
                        "unknown" => "unresolved_branch",
                        _ => "derived_relationship",
                    };
                    has_unresolved |= classification == "unresolved_branch";
                    findings.push(
                        finding(
                            "static_candidate",
                            &format!(
                                "artifact:{}",
                                change
                                    .get("logical_path")
                                    .and_then(Value::as_str)
                                    .unwrap_or("unknown")
                            ),
                            status,
                            &evidence,
                            &string_values(change.get("evidence_links")),
                            result,
                        )
                        .with_classification(classification),
                    );
                }
                let status = result
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                if matches!(status, "unknown" | "truncated") && !has_unresolved {
                    findings.push(
                        finding(
                            "static_candidate",
                            "artifact:coverage",
                            status,
                            &evidence,
                            &[],
                            result,
                        )
                        .with_classification("unresolved_branch"),
                    );
                }
            }
            _ => unreachable!(),
        }
    }

    findings.sort_by(|left, right| {
        ["scope", "dimension", "source_comparison_id"]
            .iter()
            .map(|key| left.get(*key).and_then(Value::as_str).unwrap_or(""))
            .cmp(
                ["scope", "dimension", "source_comparison_id"]
                    .iter()
                    .map(|key| right.get(*key).and_then(Value::as_str).unwrap_or("")),
            )
    });
    let behavior_status = runtime_behavior_status(&runtime_statuses);
    let summary = json!({
        "observed_changes": count_classification(&findings, "observed_change"),
        "static_candidates": count_classification(&findings, "derived_relationship"),
        "contradictions": count_classification(&findings, "contradiction"),
        "unresolved": count_classification(&findings, "unresolved_branch"),
    });
    if runtime_statuses.is_empty() {
        limitations.push("No process comparison Evidence was supplied.".into());
    }
    if findings
        .iter()
        .any(|finding| finding["scope"] == "static_candidate")
    {
        limitations
            .push("Static differences are behavior candidates, not runtime observations.".into());
    }
    let mut all_evidence_links = Vec::new();
    for item in comparisons {
        if let Some(evidence) = item.as_object() {
            if let Some(id) = evidence.get("evidence_id").and_then(Value::as_str) {
                all_evidence_links.push(id.to_owned());
            }
            all_evidence_links.extend(string_values(evidence.get("evidence_links")));
        }
    }
    let evidence_links = unique_strings(all_evidence_links.iter().map(String::as_str));
    if evidence_links.len() < 2 {
        return Err(invalid(
            "Changed-behavior output requires at least two Evidence links",
        ));
    }
    Ok(json!({
        "behavior_status": behavior_status,
        "summary": summary,
        "findings": { "items": findings },
        "evidence_links": evidence_links,
        "limitations": unique_strings(limitations.iter().map(String::as_str)),
    }))
}

fn finding(
    scope: &str,
    dimension: &str,
    status: &str,
    evidence: &Map<String, Value>,
    links: &[String],
    result: &Map<String, Value>,
) -> FindingBuilder {
    let mut evidence_links = vec![
        evidence
            .get("evidence_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
    ];
    evidence_links.extend(links.iter().cloned());
    if evidence_links.len() < 2 {
        evidence_links.extend(string_values(evidence.get("evidence_links")));
    }
    let mut finding_limitations = string_values(evidence.get("limitations"));
    finding_limitations.extend(string_values(result.get("limitations")));

    FindingBuilder {
        value: json!({
            "scope": scope,
            "dimension": dimension,
            "classification": "observed_change",
            "status": status,
            "source_comparison_id": evidence.get("evidence_id").cloned().unwrap_or(Value::Null),
            "evidence_links": unique_strings(evidence_links.iter().map(String::as_str)),
            "limitations": unique_strings(finding_limitations.iter().map(String::as_str)),
        }),
    }
}

struct FindingBuilder {
    value: Value,
}
type Finding = Value;

impl FindingBuilder {
    fn with_classification(mut self, classification: &str) -> Finding {
        self.value["classification"] = Value::String(classification.into());
        self.value
    }
}

fn evidence_id(evidence: &Map<String, Value>) -> Result<String, Failure> {
    let id = evidence
        .get("evidence_id")
        .and_then(Value::as_str)
        .filter(|id| {
            id.len() == 67
                && id.starts_with("ev_")
                && id[3..]
                    .chars()
                    .all(|character| character.is_ascii_hexdigit())
        })
        .ok_or_else(|| invalid("comparison Evidence must include a valid ev_ evidence_id"))?;
    Ok(id.to_owned())
}

fn require_source_links(evidence: &Map<String, Value>) -> Result<Vec<String>, Failure> {
    let parameters = evidence
        .get("parameters")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("Comparison Evidence source parameters are required"))?;

    let left_single = parameters.contains_key("left_evidence_id");
    let right_single = parameters.contains_key("right_evidence_id");
    let left_multiple = parameters.contains_key("left_evidence_ids");
    let right_multiple = parameters.contains_key("right_evidence_ids");
    if left_single != right_single || left_multiple != right_multiple {
        return Err(invalid(
            "Comparison Evidence source representation omitted one side",
        ));
    }

    let left = source_side(parameters, "left_evidence_id", "left_evidence_ids")?;
    let right = source_side(parameters, "right_evidence_id", "right_evidence_ids")?;
    let mut source_ids = left;
    source_ids.extend(right);
    source_ids.sort();
    source_ids.dedup();
    let links = string_values(evidence.get("evidence_links"));
    if source_ids
        .iter()
        .any(|id| !links.iter().any(|link| link == id))
    {
        return Err(invalid(
            "Comparison Evidence must cite both selected source observations",
        ));
    }
    Ok(source_ids)
}

fn source_side(
    parameters: &Map<String, Value>,
    singular_name: &str,
    plural_name: &str,
) -> Result<Vec<String>, Failure> {
    let singular = parameters.get(singular_name);
    let plural = parameters.get(plural_name);
    match (singular, plural) {
        (Some(single), Some(multiple)) => {
            let single = single
                .as_str()
                .filter(|value| is_evidence_id(value))
                .ok_or_else(|| invalid("Comparison Evidence source id is invalid"))?;
            let multiple = multiple
                .as_array()
                .ok_or_else(|| invalid("Comparison Evidence source ids must be an array"))?;
            if multiple.len() != 1 || multiple[0].as_str() != Some(single) {
                return Err(invalid(
                    "Comparison Evidence source representations disagree",
                ));
            }
            Ok(vec![single.to_owned()])
        }
        (Some(single), None) => {
            let single = single
                .as_str()
                .filter(|value| is_evidence_id(value))
                .ok_or_else(|| invalid("Comparison Evidence source id is invalid"))?;
            Ok(vec![single.to_owned()])
        }
        (None, Some(multiple)) => {
            let multiple = multiple
                .as_array()
                .ok_or_else(|| invalid("Comparison Evidence source ids must be an array"))?;
            if multiple.is_empty() {
                return Err(invalid("Comparison Evidence omitted its source parameters"));
            }
            let values = multiple
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .filter(|id| is_evidence_id(id))
                        .map(str::to_owned)
                        .ok_or_else(|| invalid("Comparison Evidence source id is invalid"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut unique = values.clone();
            unique.sort();
            unique.dedup();
            if unique.len() != values.len() {
                return Err(invalid(
                    "Comparison Evidence repeats a source within one side",
                ));
            }
            Ok(values)
        }
        (None, None) => Err(invalid("Comparison Evidence omitted its source parameters")),
    }
}

fn validate_comparison_record(
    record: &EvidenceRecord,
    evidence: &Map<String, Value>,
    operation: &str,
) -> Result<(), Failure> {
    let expected_predicate = match operation {
        "compare_process_captures" => "rea.process-comparison",
        "compare_functions" => "rea.function-comparison",
        "compare_artifacts" => "rea.artifact-comparison",
        _ => {
            return Err(invalid(
                "Changed-behavior analysis requires a supported comparison operation",
            ));
        }
    };
    let predicate = serde_json::from_str::<String>(record.predicate_type().get())
        .map_err(|_| invalid("comparison Evidence predicate_type must be a string"))?;
    if predicate != expected_predicate {
        return Err(invalid(
            "Comparison Evidence predicate does not match its operation",
        ));
    }

    let provider = serde_json::from_str::<Value>(record.provider_manifest().get())
        .map_err(|_| invalid("comparison Evidence provider must be an object"))?;
    let provider_id = provider.get("id").and_then(Value::as_str);
    let provider_name = provider.get("name").and_then(Value::as_str);
    let provider_version = provider.get("version").and_then(Value::as_str);
    let provider_matches = match operation {
        "compare_process_captures" => {
            provider_id == Some("rea-process")
                && provider_version == Some("3")
                && matches!(
                    provider_name,
                    Some("REA process capture" | "REA deterministic process harness")
                )
        }
        "compare_functions" => {
            provider_id == Some("rea-function-comparison")
                && provider_name == Some("REA function comparison")
                && provider_version == Some("1")
        }
        "compare_artifacts" => {
            provider_id == Some("rea-artifact-comparison")
                && provider_name == Some("REA artifact comparison")
                && provider_version == Some("1")
        }
        _ => false,
    };
    if !provider_matches {
        return Err(invalid(
            "Comparison Evidence provider does not match its operation",
        ));
    }

    let confidence = serde_json::from_str::<String>(record.confidence().get())
        .map_err(|_| invalid("comparison Evidence confidence must be a string"))?;
    let authority = serde_json::from_str::<String>(record.authority().get())
        .map_err(|_| invalid("comparison Evidence authority must be a string"))?;
    if confidence != "derived"
        || authority != "analyst-inference"
        || record.subject().get() != "null"
    {
        return Err(invalid(
            "Comparison Evidence must be derived analyst inference without a subject",
        ));
    }

    require_source_links(evidence)?;
    validate_result_shape(evidence, operation)
}

fn validate_result_shape(evidence: &Map<String, Value>, operation: &str) -> Result<(), Failure> {
    let result = evidence
        .get("normalized_result")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("comparison Evidence must include normalized_result"))?;

    match operation {
        "compare_process_captures" => {
            let dimensions = PROCESS_DIMENSIONS
                .iter()
                .map(|(dimension, _)| {
                    result
                        .get(*dimension)
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                })
                .collect::<Vec<_>>();
            for status in dimensions.iter().chain(std::iter::once(
                &result
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
            )) {
                if !is_comparison_status(status) {
                    return Err(invalid("process comparison contains an invalid status"));
                }
            }
            let expected = if dimensions.contains(&"truncated") {
                "truncated"
            } else if dimensions
                .iter()
                .any(|status| matches!(*status, "changed" | "added" | "removed"))
            {
                "changed"
            } else if dimensions.contains(&"unknown") {
                "unknown"
            } else {
                "unchanged"
            };
            if result.get("status").and_then(Value::as_str) != Some(expected) {
                return Err(invalid(
                    "process comparison status contradicts its dimensions",
                ));
            }
        }
        "compare_functions" => {
            let dimensions = result
                .get("dimensions")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("function comparison dimensions are required"))?;
            for dimension in dimensions {
                let nested_links = string_values(dimension.get("evidence_links"));
                validate_nested_links(evidence, &nested_links)?;
                if !dimension.is_object()
                    || !is_comparison_status(
                        dimension
                            .get("status")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown"),
                    )
                    || dimension.get("dimension").and_then(Value::as_str).is_none()
                {
                    return Err(invalid("function comparison contains an invalid dimension"));
                }
            }
        }
        "compare_artifacts" => {
            let changes = result
                .get("changes")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("artifact comparison changes are required"))?;
            for change in changes {
                let nested_links = string_values(change.get("evidence_links"));
                validate_nested_links(evidence, &nested_links)?;
                let classification = change
                    .get("classification")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                if !is_comparison_status(classification)
                    || change.get("logical_path").and_then(Value::as_str).is_none()
                {
                    return Err(invalid("artifact comparison contains an invalid change"));
                }
            }
            let status = result
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            if !is_comparison_status(status) {
                return Err(invalid("artifact comparison contains an invalid status"));
            }
        }
        _ => return Err(invalid("unsupported comparison operation")),
    }

    Ok(())
}

fn validate_nested_links(evidence: &Map<String, Value>, links: &[String]) -> Result<(), Failure> {
    let closure = string_values(evidence.get("evidence_links"));
    if links
        .iter()
        .any(|link| !closure.iter().any(|candidate| candidate == link))
    {
        return Err(invalid(
            "Comparison finding cites Evidence outside its top-level closure",
        ));
    }
    Ok(())
}

fn is_comparison_status(status: &str) -> bool {
    matches!(
        status,
        "unchanged" | "added" | "removed" | "changed" | "truncated" | "unknown" | "contradiction"
    )
}

fn is_evidence_id(value: &str) -> bool {
    value.len() == 67
        && value.starts_with("ev_")
        && value[3..]
            .chars()
            .all(|character| character.is_ascii_hexdigit())
}

fn runtime_behavior_status(statuses: &[String]) -> &'static str {
    if statuses.is_empty() {
        return "unknown";
    }
    if statuses.iter().any(|status| status == "truncated") {
        return "truncated";
    }
    if statuses.iter().any(|status| status == "unknown") {
        return "unknown";
    }
    if statuses
        .iter()
        .any(|status| matches!(status.as_str(), "changed" | "added" | "removed"))
    {
        return "observed_changed";
    }
    "observed_unchanged"
}

fn count_classification(findings: &[Finding], classification: &str) -> usize {
    findings
        .iter()
        .filter(|finding| finding["classification"] == classification)
        .count()
}

fn string_values(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn unique_strings<'a>(values: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut sorted = values
        .into_iter()
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    sorted.sort();
    sorted.dedup();
    sorted
}

fn invalid(reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_input",
        "input",
        reason.into(),
        false,
        "Provide comparison Evidence and retry.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
