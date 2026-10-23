//! `findChangedBehavior` (`src/domain/changedBehavior.ts`): aggregate existing
//! comparison Evidence into runtime observations and static change candidates.
//!
//! The public input schema stays available to clients; this internal admission
//! only checks the list shape because `parseEvidence` owns validation and
//! authentication of each retained Evidence item. The TypeScript source is the
//! oracle for parse order, ordering rules, messages and error kinds.
use super::schemas::{self, PROCESS_COMPARISON_DIMENSIONS, derive_process_comparison_status};
use super::static_runtime::{
    assert_comparison_finding_links, comparison_source_evidence_ids, is_process_provider,
};
use crate::derived::{invalid_value, parse_evidence};
use crate::js::{compare_code_points, composite_key, unique_sorted};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};
use std::collections::HashSet;

const OPERATION: &str = "find_changed_behavior";

/// A parsed, authenticated comparison Evidence record together with the
/// operation that produced it and its validated normalized result.
struct ParsedComparison {
    operation: String,
    evidence: Value,
    result: Value,
}

/// `findChangedBehavior` return value: the schema-shaped result plus the
/// authenticated comparison Evidence IDs the handler cites in parameters.
pub(crate) struct FoundChangedBehavior {
    pub(crate) result: Value,
    pub(crate) comparison_evidence_ids: Vec<String>,
}

fn field_str<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn string_array(value: Option<&Value>) -> Vec<String> {
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

/// `(evidence.operation in EXPECTED_PROVIDERS)` plus `z.enum([...]).parse`.
fn expected_provider(
    operation: &str,
) -> Option<(&'static [&'static str], &'static str, &'static str)> {
    match operation {
        "compare_process_captures" => Some((
            &["rea.process-comparison"],
            "rea-process",
            "REA process capture",
        )),
        "compare_artifacts" => Some((
            &["rea.artifact-comparison"],
            "rea-artifact-comparison",
            "REA artifact comparison",
        )),
        "compare_functions" => Some((
            &["rea.function-comparison"],
            "rea-function-comparison",
            "REA function comparison",
        )),
        _ => None,
    }
}

/// `parseComparisonEvidence(input)`.
fn parse_comparison_evidence(input: &Value) -> Result<ParsedComparison, AnalysisError> {
    let evidence =
        parse_evidence(input).map_err(|error| invalid_value(OPERATION, error.to_string()))?;
    let evidence = evidence.value().clone();
    let operation = field_str(&evidence, "operation").to_owned();
    let Some((predicates, provider_id, provider_name)) = expected_provider(&operation) else {
        return Err(invalid_value(
            OPERATION,
            "Changed-behavior analysis requires process, artifact, or function comparison Evidence",
        ));
    };
    let provider = evidence.get("provider").cloned().unwrap_or(Value::Null);
    let provider_ok = if operation == "compare_process_captures" {
        is_process_provider(&provider)
    } else {
        field_str(&provider, "id") == provider_id
            && field_str(&provider, "name") == provider_name
            && provider.get("version").and_then(Value::as_str) == Some("1")
    };
    let predicate = field_str(&evidence, "predicate_type");
    if !predicates.contains(&predicate)
        || !provider_ok
        || field_str(&evidence, "confidence") != "derived"
        || field_str(&evidence, "authority") != "analyst-inference"
        || !evidence.get("subject").map(Value::is_null).unwrap_or(true)
    {
        return Err(invalid_value(
            OPERATION,
            "Comparison Evidence operation, predicate, and provider disagree",
        ));
    }
    let source_ids = comparison_source_evidence_ids(&evidence, OPERATION)?;
    let closure: HashSet<&str> = evidence
        .get("evidence_links")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if source_ids.iter().any(|id| !closure.contains(id.as_str())) {
        return Err(invalid_value(
            OPERATION,
            "Comparison Evidence must cite both selected source observations",
        ));
    }
    parse_result(evidence, operation)
}

/// `parseResult(evidence, operation)`.
fn parse_result(evidence: Value, operation: String) -> Result<ParsedComparison, AnalysisError> {
    let normalized = evidence
        .get("normalized_result")
        .cloned()
        .unwrap_or(Value::Null);
    if operation == "compare_process_captures" {
        let result =
            schemas::parse_or_describe(&schemas::process_capture_comparison(), &normalized)
                .map_err(|message| invalid_value(OPERATION, message))?;
        let dimensions: Vec<&str> = PROCESS_COMPARISON_DIMENSIONS
            .iter()
            .map(|dimension| field_str(&result, dimension))
            .collect();
        let expected = derive_process_comparison_status(&dimensions);
        if field_str(&result, "status") != expected {
            return Err(invalid_value(
                OPERATION,
                "Process comparison status contradicts its dimensions",
            ));
        }
        return Ok(ParsedComparison {
            operation,
            evidence,
            result,
        });
    }
    if operation == "compare_functions" {
        let result =
            schemas::parse_or_describe(&schemas::function_comparison_result(), &normalized)
                .map_err(|message| invalid_value(OPERATION, message))?;
        let nested = flat_links(&result, "dimensions");
        assert_comparison_finding_links(&evidence, &nested, OPERATION)?;
        return Ok(ParsedComparison {
            operation,
            evidence,
            result,
        });
    }
    let result = schemas::parse_or_describe(&schemas::artifact_comparison_result(), &normalized)
        .map_err(|message| invalid_value(OPERATION, message))?;
    let nested = flat_links(&result, "changes");
    assert_comparison_finding_links(&evidence, &nested, OPERATION)?;
    Ok(ParsedComparison {
        operation,
        evidence,
        result,
    })
}

/// `result.<field>.flatMap(({ evidence_links }) => links)`.
fn flat_links(result: &Value, field: &str) -> Vec<String> {
    result
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("evidence_links").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// `makeFinding(input)` — builds and validates a single finding record.
fn make_finding(
    evidence: &Value,
    dimension: String,
    scope: &str,
    status: &str,
    classification: &str,
    limitations: Vec<String>,
    links: Option<Vec<String>>,
) -> Value {
    let evidence_id = field_str(evidence, "evidence_id").to_owned();
    let base_links = links.unwrap_or_else(|| string_array(evidence.get("evidence_links")));
    let mut all_links = vec![evidence_id.clone()];
    all_links.extend(base_links);
    let evidence_links = unique_sorted(all_links);
    let limitations = unique_sorted(limitations);
    json!({
        "scope": scope,
        "dimension": dimension,
        "classification": classification,
        "status": status,
        "source_comparison_id": evidence_id,
        "evidence_links": evidence_links,
        "limitations": limitations,
    })
}

/// `isChange(status)`.
fn is_change(status: &str) -> bool {
    matches!(status, "added" | "removed" | "changed")
}

/// `processFindings(comparison)`.
fn process_findings(comparison: &ParsedComparison) -> Vec<Value> {
    let result = &comparison.result;
    let dimensions: [(&str, &str, &str); 5] = [
        ("terminal", field_str(result, "terminal"), "runtime"),
        ("interaction", field_str(result, "interaction"), "runtime"),
        ("exit", field_str(result, "exit"), "runtime"),
        ("filesystem", field_str(result, "filesystem"), "resource"),
        ("process", field_str(result, "process"), "runtime"),
    ];
    let limitations = string_array(result.get("limitations"));
    let mut findings = Vec::new();
    for (dimension, status, scope) in dimensions {
        if status == "unchanged" {
            continue;
        }
        let classification = if is_change(status) {
            "observed_change"
        } else {
            "unresolved_branch"
        };
        findings.push(make_finding(
            &comparison.evidence,
            dimension.to_owned(),
            scope,
            status,
            classification,
            limitations.clone(),
            None,
        ));
    }
    findings
}

/// `functionFindings(comparison)`.
fn function_findings(comparison: &ParsedComparison) -> Vec<Value> {
    let mut findings = Vec::new();
    for dimension in comparison
        .result
        .get("dimensions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let status = field_str(dimension, "status");
        if status == "unchanged" {
            continue;
        }
        let classification = if status == "unknown" {
            "unresolved_branch".to_owned()
        } else {
            field_str(dimension, "conclusion_kind").to_owned()
        };
        findings.push(make_finding(
            &comparison.evidence,
            field_str(dimension, "dimension").to_owned(),
            "static_candidate",
            status,
            &classification,
            string_array(dimension.get("limitations")),
            Some(string_array(dimension.get("evidence_links"))),
        ));
    }
    findings
}

/// `artifactFindings(comparison)`.
fn artifact_findings(comparison: &ParsedComparison) -> Vec<Value> {
    let result = &comparison.result;
    let limitations = string_array(result.get("limitations"));
    let mut changes = Vec::new();
    for change in result
        .get("changes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let classification_in = field_str(change, "classification");
        let classification = match classification_in {
            "contradiction" => "contradiction",
            "unknown" => "unresolved_branch",
            _ => "derived_relationship",
        };
        changes.push(make_finding(
            &comparison.evidence,
            format!("artifact:{}", field_str(change, "logical_path")),
            "static_candidate",
            classification_in,
            classification,
            limitations.clone(),
            Some(string_array(change.get("evidence_links"))),
        ));
    }
    let result_status = field_str(result, "status");
    let has_unresolved = changes
        .iter()
        .any(|finding| field_str(finding, "classification") == "unresolved_branch");
    if (result_status == "unknown" || result_status == "truncated") && !has_unresolved {
        changes.push(make_finding(
            &comparison.evidence,
            "artifact:coverage".to_owned(),
            "static_candidate",
            result_status,
            "unresolved_branch",
            limitations.clone(),
            None,
        ));
    }
    changes
}

/// `findingsFor(comparison)`.
fn findings_for(comparison: &ParsedComparison) -> Vec<Value> {
    match comparison.operation.as_str() {
        "compare_process_captures" => process_findings(comparison),
        "compare_functions" => function_findings(comparison),
        _ => artifact_findings(comparison),
    }
}

/// `compareFindings(left, right)`.
fn compare_findings(left: &Value, right: &Value) -> std::cmp::Ordering {
    let key = |finding: &Value| {
        composite_key(&[
            field_str(finding, "scope"),
            field_str(finding, "dimension"),
            field_str(finding, "source_comparison_id"),
        ])
    };
    compare_code_points(&key(left), &key(right))
}

/// `behaviorStatus(statuses)`.
fn behavior_status(statuses: &[String]) -> &'static str {
    if statuses.is_empty() {
        return "unknown";
    }
    if statuses.iter().any(|status| status == "truncated") {
        return "truncated";
    }
    if statuses.iter().any(|status| status == "unknown") {
        return "unknown";
    }
    if statuses.iter().any(|status| is_change(status)) {
        "observed_changed"
    } else {
        "observed_unchanged"
    }
}

/// `count(findings, classification)`.
fn count(findings: &[Value], classification: &str) -> usize {
    findings
        .iter()
        .filter(|finding| field_str(finding, "classification") == classification)
        .count()
}

/// `assertUnique(values, label)`.
fn assert_unique(ids: &[String], label: &str) -> Result<(), AnalysisError> {
    if ids.iter().collect::<HashSet<_>>().len() != ids.len() {
        return Err(invalid_value(
            OPERATION,
            format!("Changed-behavior analysis rejects duplicate {label}"),
        ));
    }
    Ok(())
}

/// `findChangedBehavior(input)`.
pub(crate) fn find_changed_behavior(input: &Value) -> Result<FoundChangedBehavior, AnalysisError> {
    // z.strictObject({ comparisons: z.array(z.unknown()).min(1) }).parse(input).
    let comparisons = input
        .get("comparisons")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_value(OPERATION, "at comparisons: Invalid input: expected array"))?;
    if comparisons.is_empty() {
        return Err(invalid_value(
            OPERATION,
            "at comparisons: Too small: expected array to have more items",
        ));
    }
    let evidence: Vec<ParsedComparison> = comparisons
        .iter()
        .map(parse_comparison_evidence)
        .collect::<Result<_, _>>()?;
    let ids: Vec<String> = evidence
        .iter()
        .map(|comparison| field_str(&comparison.evidence, "evidence_id").to_owned())
        .collect();
    assert_unique(&ids, "comparison Evidence")?;
    let mut findings: Vec<Value> = evidence.iter().flat_map(findings_for).collect();
    findings.sort_by(compare_findings);
    let runtime_statuses: Vec<String> = evidence
        .iter()
        .filter(|comparison| comparison.operation == "compare_process_captures")
        .map(|comparison| field_str(&comparison.result, "status").to_owned())
        .collect();
    let links = unique_sorted(evidence.iter().flat_map(|comparison| {
        let mut all = vec![field_str(&comparison.evidence, "evidence_id").to_owned()];
        all.extend(string_array(comparison.evidence.get("evidence_links")));
        all
    }));
    let mut limitations: Vec<String> = evidence
        .iter()
        .flat_map(|comparison| string_array(comparison.evidence.get("limitations")))
        .collect();
    if evidence
        .iter()
        .any(|comparison| comparison.operation != "compare_process_captures")
    {
        limitations.push(
            "Static differences are behavior candidates, not runtime observations.".to_owned(),
        );
    }
    if runtime_statuses.is_empty() {
        limitations.push("No process comparison Evidence was supplied.".to_owned());
    }
    let limitations = unique_sorted(limitations);

    // changedBehaviorResultSchema.parse: build in the schema's object-literal
    // shape order (behavior_status, summary, findings, evidence_links,
    // limitations). The superRefine checks are structural invariants this
    // construction already satisfies.
    let mut result = Map::new();
    result.insert(
        "behavior_status".into(),
        json!(behavior_status(&runtime_statuses)),
    );
    result.insert(
        "summary".into(),
        json!({
            "observed_changes": count(&findings, "observed_change"),
            "static_candidates": count(&findings, "derived_relationship"),
            "contradictions": count(&findings, "contradiction"),
            "unresolved": count(&findings, "unresolved_branch"),
        }),
    );
    result.insert("findings".into(), json!({ "items": findings }));
    result.insert("evidence_links".into(), json!(links));
    result.insert("limitations".into(), json!(limitations));

    let comparison_evidence_ids = ids;
    Ok(FoundChangedBehavior {
        result: Value::Object(result),
        comparison_evidence_ids,
    })
}
