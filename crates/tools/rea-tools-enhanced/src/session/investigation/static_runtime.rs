//! `correlateStaticAndRuntime` (`src/domain/staticRuntimeCorrelation.ts`) and the
//! comparison-source helpers it shares with the other investigation tools
//! (`comparisonSourceEvidence.ts`).

use super::schemas;
use crate::derived::{invalid_value, parse_evidence};
use crate::js::compare_code_points;
use rea_core::analysis_error::AnalysisError;
use rea_core::canonical_json;
use serde_json::{Map, Value, json};
use std::collections::{BTreeSet, HashMap, HashSet};

const OPERATION: &str = "correlate_static_and_runtime";

/// `uniqueSorted` of strings.
fn unique_sorted(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut unique: Vec<String> = values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    unique.sort_by(|left, right| compare_code_points(left, right));
    unique
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

fn field_str<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// `comparisonSourceEvidenceSides(evidence)`.
pub(crate) fn comparison_source_evidence_sides(
    evidence: &Value,
    operation: &str,
) -> Result<(Vec<String>, Vec<String>), AnalysisError> {
    let parameters = evidence.get("parameters").cloned().unwrap_or(Value::Null);
    let single = |key: &str| -> Option<String> {
        parameters
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let multiple = |key: &str| -> Option<Vec<String>> {
        parameters.get(key).and_then(Value::as_array).map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
    };
    for key in ["left_evidence_id", "right_evidence_id"] {
        if let Some(value) = single(key)
            && !super::is_prefixed_digest(&value, "ev")
        {
            return Err(invalid_value(
                operation,
                "at parameters: Invalid string: must match pattern",
            ));
        }
    }
    for key in ["left_evidence_ids", "right_evidence_ids"] {
        if let Some(values) = multiple(key) {
            if values.is_empty() {
                return Err(invalid_value(
                    operation,
                    "at parameters: Too small: expected array to have more items",
                ));
            }
            if values
                .iter()
                .any(|value| !super::is_prefixed_digest(value, "ev"))
            {
                return Err(invalid_value(
                    operation,
                    "at parameters: Invalid string: must match pattern",
                ));
            }
        }
    }
    let left_single = single("left_evidence_id");
    let right_single = single("right_evidence_id");
    let left_multiple = multiple("left_evidence_ids");
    let right_multiple = multiple("right_evidence_ids");
    if (left_single.is_none() != right_single.is_none())
        || (left_multiple.is_none() != right_multiple.is_none())
    {
        return Err(invalid_value(
            operation,
            "Comparison Evidence source representation omitted one side",
        ));
    }
    let side = |single: Option<String>,
                multiple: Option<Vec<String>>|
     -> Result<Vec<String>, AnalysisError> {
        if let (Some(single), Some(multiple)) = (&single, &multiple)
            && (multiple.len() != 1 || multiple.first() != Some(single))
        {
            return Err(invalid_value(
                operation,
                "Comparison Evidence source representations disagree",
            ));
        }
        let selected = match single {
            None => multiple.unwrap_or_default(),
            Some(single) => vec![single],
        };
        if selected.is_empty() {
            return Err(invalid_value(
                operation,
                "Comparison Evidence omitted its source parameters",
            ));
        }
        if selected.iter().collect::<HashSet<_>>().len() != selected.len() {
            return Err(invalid_value(
                operation,
                "Comparison Evidence repeats a source within one side",
            ));
        }
        Ok(selected)
    };
    let left = side(left_single, left_multiple)?;
    let right = side(right_single, right_multiple)?;
    Ok((left, right))
}

/// `comparisonSourceEvidenceIds(evidence)`.
pub(crate) fn comparison_source_evidence_ids(
    evidence: &Value,
    operation: &str,
) -> Result<Vec<String>, AnalysisError> {
    let (left, right) = comparison_source_evidence_sides(evidence, operation)?;
    Ok(unique_sorted(left.into_iter().chain(right)))
}

/// `assertComparisonFindingLinks(evidence, nestedLinks)`.
pub(crate) fn assert_comparison_finding_links(
    evidence: &Value,
    nested_links: &[String],
    operation: &str,
) -> Result<(), AnalysisError> {
    let closure: HashSet<&str> = evidence
        .get("evidence_links")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if nested_links.iter().any(|id| !closure.contains(id.as_str())) {
        return Err(invalid_value(
            operation,
            "Comparison finding cites Evidence outside its top-level closure",
        ));
    }
    Ok(())
}

/// `isProcessEvidenceProvider(provider)`.
pub(crate) fn is_process_provider(provider: &Value) -> bool {
    field_str(provider, "id") == "rea-process"
        && provider.get("version").and_then(Value::as_str) == Some("3")
        && matches!(
            field_str(provider, "name"),
            "REA process capture" | "REA deterministic process harness"
        )
}

fn authenticate(input: &Value) -> Result<Value, AnalysisError> {
    let evidence =
        parse_evidence(input).map_err(|error| invalid_value(OPERATION, error.to_string()))?;
    Ok(evidence.value().clone())
}

fn describe(result: Result<Value, String>) -> Result<Value, AnalysisError> {
    result.map_err(|message| invalid_value(OPERATION, message))
}

/// `assertComparisonIdentity(evidence)`.
fn assert_comparison_identity(evidence: &Value) -> Result<(), AnalysisError> {
    let operation = field_str(evidence, "operation");
    let expected: Option<(Vec<&str>, &str, &str)> = match operation {
        "compare_artifacts" => Some((
            vec!["rea.artifact-comparison"],
            "rea-artifact-comparison",
            "REA artifact comparison",
        )),
        "compare_functions" => Some((
            vec!["rea.function-comparison"],
            "rea-function-comparison",
            "REA function comparison",
        )),
        "compare_process_captures" => Some((
            vec!["rea.process-comparison"],
            "rea-process",
            "REA process capture",
        )),
        _ => None,
    };
    let disagree = || {
        invalid_value(
            OPERATION,
            "Comparison Evidence operation, predicate, provider, or citations disagree",
        )
    };
    let Some((predicates, provider_id, provider_name)) = expected else {
        return Err(disagree());
    };
    let predicate = field_str(evidence, "predicate_type");
    let provider = evidence.get("provider").cloned().unwrap_or(Value::Null);
    let provider_ok = if operation == "compare_process_captures" {
        is_process_provider(&provider)
    } else {
        field_str(&provider, "id") == provider_id
            && field_str(&provider, "name") == provider_name
            && provider.get("version").and_then(Value::as_str) == Some("1")
    };
    if !predicates.contains(&predicate)
        || !provider_ok
        || field_str(evidence, "confidence") != "derived"
        || field_str(evidence, "authority") != "analyst-inference"
        || !evidence.get("subject").map(Value::is_null).unwrap_or(true)
    {
        return Err(disagree());
    }
    let expected_links = comparison_source_evidence_ids(evidence, OPERATION)?;
    let actual_links = unique_sorted(string_array(evidence.get("evidence_links")));
    if expected_links != actual_links {
        return Err(invalid_value(
            OPERATION,
            "Comparison Evidence closure disagrees with its source parameters",
        ));
    }
    Ok(())
}

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

/// `parseStatic(input)`.
fn parse_static(input: &Value) -> Result<Value, AnalysisError> {
    let evidence = authenticate(input)?;
    let operation = field_str(&evidence, "operation");
    if operation != "compare_artifacts" && operation != "compare_functions" {
        return Err(invalid_value(
            OPERATION,
            "Static/runtime correlation requires artifact or function comparison Evidence",
        ));
    }
    assert_comparison_identity(&evidence)?;
    let normalized = evidence
        .get("normalized_result")
        .cloned()
        .unwrap_or(Value::Null);
    if operation == "compare_artifacts" {
        let result = describe(schemas::parse_or_describe(
            &schemas::artifact_comparison_result(),
            &normalized,
        ))?;
        assert_comparison_finding_links(&evidence, &flat_links(&result, "changes"), OPERATION)?;
    } else {
        let result = describe(schemas::parse_or_describe(
            &schemas::function_comparison_result(),
            &normalized,
        ))?;
        assert_comparison_finding_links(&evidence, &flat_links(&result, "dimensions"), OPERATION)?;
    }
    Ok(evidence)
}

/// `parseRuntime(input)`.
fn parse_runtime(input: &Value) -> Result<Value, AnalysisError> {
    let evidence = authenticate(input)?;
    if field_str(&evidence, "operation") != "compare_process_captures" {
        return Err(invalid_value(
            OPERATION,
            "Static/runtime correlation requires process comparison Evidence",
        ));
    }
    assert_comparison_identity(&evidence)?;
    let normalized = evidence
        .get("normalized_result")
        .cloned()
        .unwrap_or(Value::Null);
    describe(schemas::parse_or_describe(
        &schemas::process_capture_comparison(),
        &normalized,
    ))?;
    Ok(evidence)
}

fn assert_unique(evidence: &[Value], label: &str) -> Result<(), AnalysisError> {
    let ids: Vec<&str> = evidence
        .iter()
        .map(|item| field_str(item, "evidence_id"))
        .collect();
    if ids.iter().collect::<HashSet<_>>().len() != ids.len() {
        return Err(invalid_value(
            OPERATION,
            format!("Static/runtime correlation rejects duplicate {label}"),
        ));
    }
    Ok(())
}

/// `observedPattern(staticStatus, runtimeStatus)`.
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

struct SelectedStatic {
    status: String,
    conclusion_kind: String,
    limitations: Vec<String>,
}

/// `selectStatic(evidence, selector)`.
fn select_static(evidence: &Value, selector: &Value) -> Result<SelectedStatic, AnalysisError> {
    let normalized = evidence
        .get("normalized_result")
        .cloned()
        .unwrap_or(Value::Null);
    let kind = field_str(selector, "kind");
    if kind == "function" {
        if field_str(evidence, "operation") != "compare_functions" {
            return Err(invalid_value(
                OPERATION,
                "Function selector requires function comparison Evidence",
            ));
        }
        let result = describe(schemas::parse_or_describe(
            &schemas::function_comparison_result(),
            &normalized,
        ))?;
        let dimension = field_str(selector, "dimension");
        let matches: Vec<&Value> = result
            .get("dimensions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|item| field_str(item, "dimension") == dimension)
            .collect();
        if matches.len() != 1 {
            return Err(invalid_value(
                OPERATION,
                "Function selector must resolve exactly once",
            ));
        }
        let matched = matches[0];
        return Ok(SelectedStatic {
            status: field_str(matched, "status").to_owned(),
            conclusion_kind: field_str(matched, "conclusion_kind").to_owned(),
            limitations: string_array(matched.get("limitations")),
        });
    }
    if field_str(evidence, "operation") != "compare_artifacts" {
        return Err(invalid_value(
            OPERATION,
            "Artifact selector requires artifact comparison Evidence",
        ));
    }
    let result = describe(schemas::parse_or_describe(
        &schemas::artifact_comparison_result(),
        &normalized,
    ))?;
    let logical_path = field_str(selector, "logical_path");
    let matches: Vec<&Value> = result
        .get("changes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| field_str(item, "logical_path") == logical_path)
        .collect();
    if matches.len() != 1 {
        return Err(invalid_value(
            OPERATION,
            "Artifact selector must resolve exactly one reported delta",
        ));
    }
    let status = field_str(matches[0], "classification").to_owned();
    let conclusion_kind = match status.as_str() {
        "contradiction" => "contradiction",
        "unknown" => "unresolved_branch",
        _ => "derived_relationship",
    }
    .to_owned();
    Ok(SelectedStatic {
        status,
        conclusion_kind,
        limitations: Vec::new(),
    })
}

/// `correlate(mapping, staticById, runtimeById)`.
fn correlate(
    mapping: &Value,
    static_by_id: &HashMap<String, Value>,
    runtime_by_id: &HashMap<String, Value>,
) -> Result<Value, AnalysisError> {
    let static_id = field_str(&mapping["static"], "comparison_evidence_id");
    let runtime_id = field_str(&mapping["runtime"], "comparison_evidence_id");
    let static_evidence = static_by_id.get(static_id).ok_or_else(|| {
        invalid_value(
            OPERATION,
            "Mapping references absent static comparison Evidence",
        )
    })?;
    let runtime_evidence = runtime_by_id.get(runtime_id).ok_or_else(|| {
        invalid_value(
            OPERATION,
            "Mapping references absent runtime comparison Evidence",
        )
    })?;
    let selected = select_static(static_evidence, &mapping["static"]["selector"])?;
    let process = describe(schemas::parse_or_describe(
        &schemas::process_capture_comparison(),
        &runtime_evidence
            .get("normalized_result")
            .cloned()
            .unwrap_or(Value::Null),
    ))?;
    let runtime_dimension = field_str(&mapping["runtime"], "dimension");
    let runtime_status = field_str(&process, runtime_dimension).to_owned();
    let pattern = observed_pattern(&selected.status, &runtime_status);
    let expected_pattern = field_str(&mapping["hypothesis"], "expected_pattern");
    let classification = if pattern == "unknown" || pattern == "truncated" {
        "unresolved_branch"
    } else if pattern == expected_pattern {
        "hypothesis"
    } else {
        "contradiction"
    };

    let projection = json!({
        "static": mapping.get("static").cloned().unwrap_or(Value::Null),
        "runtime": mapping.get("runtime").cloned().unwrap_or(Value::Null),
        "side_alignment": mapping.get("side_alignment").cloned().unwrap_or(Value::Null),
        "hypothesis": mapping.get("hypothesis").cloned().unwrap_or(Value::Null),
    });
    let digest = canonical_json::digest(&projection)
        .map_err(|error| invalid_value(OPERATION, error.to_string()))?;
    let correlation_id = format!("cor_{digest}");

    let mut static_out = Map::new();
    if let Some(object) = mapping.get("static").and_then(Value::as_object) {
        for (key, value) in object {
            static_out.insert(key.clone(), value.clone());
        }
    }
    static_out.insert("status".into(), json!(selected.status));
    static_out.insert("conclusion_kind".into(), json!(selected.conclusion_kind));

    let mut runtime_out = Map::new();
    if let Some(object) = mapping.get("runtime").and_then(Value::as_object) {
        for (key, value) in object {
            runtime_out.insert(key.clone(), value.clone());
        }
    }
    runtime_out.insert("status".into(), json!(runtime_status));

    let evidence_links = unique_sorted(
        vec![field_str(static_evidence, "evidence_id").to_owned()]
            .into_iter()
            .chain(string_array(static_evidence.get("evidence_links")))
            .chain(vec![field_str(runtime_evidence, "evidence_id").to_owned()])
            .chain(string_array(runtime_evidence.get("evidence_links"))),
    );

    let mut limitations = Vec::new();
    limitations.extend(string_array(static_evidence.get("limitations")));
    limitations.extend(selected.limitations.clone());
    limitations.extend(string_array(runtime_evidence.get("limitations")));
    limitations.extend(string_array(process.get("limitations")));
    limitations.push(
        "This correlation tests an explicit hypothesis and does not establish causality."
            .to_owned(),
    );
    limitations.push("Side alignment is caller-declared and was not independently validated against source subjects or environments.".to_owned());
    let limitations = unique_sorted(limitations);

    let mut item = Map::new();
    item.insert("correlation_id".into(), json!(correlation_id));
    item.insert("static".into(), Value::Object(static_out));
    item.insert("runtime".into(), Value::Object(runtime_out));
    item.insert(
        "side_alignment".into(),
        mapping
            .get("side_alignment")
            .cloned()
            .unwrap_or(Value::Null),
    );
    item.insert(
        "hypothesis".into(),
        mapping.get("hypothesis").cloned().unwrap_or(Value::Null),
    );
    item.insert("observed_pattern".into(), json!(pattern));
    item.insert("classification".into(), json!(classification));
    item.insert("evidence_links".into(), json!(evidence_links));
    item.insert("limitations".into(), json!(limitations));
    Ok(Value::Object(item))
}

fn by_id(evidence: &[Value]) -> HashMap<String, Value> {
    evidence
        .iter()
        .map(|item| (field_str(item, "evidence_id").to_owned(), item.clone()))
        .collect()
}

/// `correlateStaticAndRuntime(input)`.
pub(crate) fn correlate_static_and_runtime(input: &Value) -> Result<Value, AnalysisError> {
    let static_comparisons = input
        .get("static_comparisons")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let runtime_comparisons = input
        .get("runtime_comparisons")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mappings = input
        .get("mappings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let static_evidence: Vec<Value> = static_comparisons
        .iter()
        .map(parse_static)
        .collect::<Result<_, _>>()?;
    let runtime_evidence: Vec<Value> = runtime_comparisons
        .iter()
        .map(parse_runtime)
        .collect::<Result<_, _>>()?;
    assert_unique(&static_evidence, "static comparison Evidence")?;
    assert_unique(&runtime_evidence, "runtime comparison Evidence")?;

    let static_by_id = by_id(&static_evidence);
    let runtime_by_id = by_id(&runtime_evidence);

    let mut correlations: Vec<Value> = mappings
        .iter()
        .map(|mapping| correlate(mapping, &static_by_id, &runtime_by_id))
        .collect::<Result<_, _>>()?;
    correlations.sort_by(|left, right| {
        compare_code_points(
            field_str(left, "correlation_id"),
            field_str(right, "correlation_id"),
        )
    });

    let ids: Vec<&str> = correlations
        .iter()
        .map(|item| field_str(item, "correlation_id"))
        .collect();
    if ids.iter().collect::<HashSet<_>>().len() != ids.len() {
        return Err(invalid_value(
            OPERATION,
            "Static/runtime correlation rejects duplicate mappings",
        ));
    }

    let links = unique_sorted(
        correlations
            .iter()
            .flat_map(|item| string_array(item.get("evidence_links"))),
    );
    let unresolved = correlations
        .iter()
        .filter(|item| field_str(item, "classification") == "unresolved_branch")
        .count();
    let contradictions = correlations
        .iter()
        .filter(|item| field_str(item, "classification") == "contradiction")
        .count();
    let any_truncated = correlations
        .iter()
        .any(|item| field_str(item, "observed_pattern") == "truncated");

    let status = if any_truncated {
        "truncated"
    } else if unresolved > 0 {
        "unknown"
    } else if contradictions > 0 {
        "contradicted"
    } else {
        "correlated"
    };
    let hypotheses = correlations.len() - contradictions - unresolved;

    let mut result = Map::new();
    result.insert("status".into(), json!(status));
    result.insert(
        "summary".into(),
        json!({
            "hypotheses": hypotheses,
            "contradictions": contradictions,
            "unresolved": unresolved,
        }),
    );
    result.insert("correlations".into(), json!({ "items": correlations }));
    result.insert("evidence_links".into(), json!(links));
    result.insert(
        "limitations".into(),
        json!([
            "Mappings are caller-declared hypotheses; consistency does not establish causality.",
            "Only explicit mappings were evaluated; similar unmapped observations were not correlated.",
        ]),
    );
    Ok(Value::Object(result))
}

/// Parameters projection for the handler: `{ mapping_count }`.
pub(crate) fn handler_parameters(input: &Value) -> Value {
    let count = input
        .get("mappings")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    json!({ "mapping_count": count })
}

/// comparisonClosure seed records for the handler.
pub(crate) fn comparison_closure_seed(input: &Value) -> Vec<Value> {
    let mut seed = Vec::new();
    for key in ["static_comparisons", "runtime_comparisons"] {
        if let Some(items) = input.get(key).and_then(Value::as_array) {
            seed.extend(items.iter().cloned());
        }
    }
    seed
}
