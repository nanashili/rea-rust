//! Pure Evidence evaluation for verify_reconstruction.
//!
//! Providers and session storage own Evidence authentication. This module
//! consumes an already exported bundle and evaluates only the claims named by
//! the caller; it never infers global equivalence or accesses a target.

use rea_core::canonical_json;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub const OPERATION: &str = "verify_reconstruction";

const BEHAVIORAL_DIMENSIONS: &[&str] = &[
    "overall",
    "terminal",
    "interaction",
    "exit",
    "filesystem",
    "process",
];
const FUNCTION_DIMENSIONS: &[&str] = &[
    "overall",
    "identity",
    "pseudocode",
    "assembly",
    "comments",
    "calls",
    "references",
    "strings_names",
    "cfg",
];

/// Evaluate a specification against a retained Evidence bundle.
pub fn verify(specification: &Value, bundle: &Value) -> Result<Value, Failure> {
    validate_specification(specification)?;
    let records = records(bundle)?;
    let unknown_heads = unknown_heads(bundle)?;
    let claims = specification
        .get("claims")
        .and_then(Value::as_array)
        .expect("validate_specification established claims");

    let mut results = claims
        .iter()
        .map(|claim| evaluate_claim(claim, &records, &unknown_heads))
        .collect::<Result<Vec<_>, _>>()?;
    results.sort_by(|left, right| string(left, "claim_id").cmp(string(right, "claim_id")));

    let passed = count_status(&results, "pass");
    let failed = count_status(&results, "fail");
    let unknown = count_status(&results, "unknown");
    let evidence_links = sorted_unique(
        results
            .iter()
            .flat_map(|item| strings(item.get("evidence_links")))
            .collect(),
    );
    let probes = recommended_probes(&results, &unknown_heads);
    let specification_sha256 = canonical_json::digest(&canonical_specification(specification)?)
        .map_err(|error| invalid(&format!("Specification canonicalization failed: {error}")))?;

    Ok(json!({
        "status": if failed > 0 { "fail" } else if unknown > 0 { "unknown" } else { "pass" },
        "specification_sha256": specification_sha256,
        "summary": {
            "total": results.len(),
            "passed": passed,
            "failed": failed,
            "unknown": unknown,
            "behavioral": results.iter().filter(|item| string(item, "kind") == "behavioral").count(),
            "structural": results.iter().filter(|item| string(item, "kind") != "behavioral").count(),
        },
        "claims": { "items": results },
        "recommended_probes": probes,
        "evidence_links": evidence_links,
        "limitations": [
            "Pass means every declared claim passed; it does not establish global implementation equivalence."
        ],
    }))
}

/// Validate the session input shape before the session supplies its bundle.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("verify_reconstruction input must be an object"))?;
    if object.len() != 1 || !object.contains_key("specification") {
        return Err(invalid(
            "verify_reconstruction input must contain only specification",
        ));
    }
    validate_specification(
        object
            .get("specification")
            .ok_or_else(|| invalid("specification is required"))?,
    )
}

pub fn project(input: &Value, bundle: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    verify(
        input
            .get("specification")
            .expect("validate_input established specification"),
        bundle,
    )
}

fn validate_specification(value: &Value) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("specification must be an object"))?;
    non_empty_text(object.get("name"), "specification.name")?;
    let claims = object
        .get("claims")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("specification.claims must be an array"))?;
    if claims.is_empty() {
        return Err(invalid("specification.claims must not be empty"));
    }

    let mut ids = HashSet::new();
    let mut selectors = HashSet::new();
    for claim in claims {
        let claim = claim
            .as_object()
            .ok_or_else(|| invalid("reconstruction claim must be an object"))?;
        let id = non_empty_text(claim.get("claim_id"), "claim.claim_id")?;
        non_empty_text(claim.get("title"), "claim.title")?;
        let kind = non_empty_text(claim.get("kind"), "claim.kind")?;
        let dimension = non_empty_text(claim.get("dimension"), "claim.dimension")?;
        let comparison = non_empty_text(
            claim.get("comparison_evidence_id"),
            "claim.comparison_evidence_id",
        )?;
        if !ids.insert(id.to_owned()) {
            return Err(invalid("Claim IDs must be unique"));
        }
        if !selectors.insert(format!("{kind}:{comparison}:{dimension}")) {
            return Err(invalid("Claim comparison selectors must be unique"));
        }
        let dimensions = match kind {
            "behavioral" => BEHAVIORAL_DIMENSIONS,
            "structural-function" => FUNCTION_DIMENSIONS,
            "structural-artifact" => &["overall"],
            _ => return Err(invalid("claim.kind is unsupported")),
        };
        if !dimensions.contains(&dimension) {
            return Err(invalid("claim.dimension is unsupported for claim.kind"));
        }
    }
    Ok(())
}

fn records(bundle: &Value) -> Result<HashMap<String, Value>, Failure> {
    let records = bundle
        .get("records")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("Evidence bundle records are required"))?;
    let mut output = HashMap::new();
    for record in records {
        let object = record
            .as_object()
            .ok_or_else(|| invalid("Evidence record must be an object"))?;
        let id = non_empty_text(object.get("evidence_id"), "evidence_id")?;
        if output.insert(id.to_owned(), record.clone()).is_some() {
            return Err(invalid("Evidence bundle contains duplicate record IDs"));
        }
    }
    Ok(output)
}

fn unknown_heads(bundle: &Value) -> Result<HashMap<String, Value>, Failure> {
    let unknowns = bundle
        .get("unknowns")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("Evidence bundle unknowns are required"))?;
    let mut heads = HashMap::new();
    for unknown in unknowns {
        let object = unknown
            .as_object()
            .ok_or_else(|| invalid("Residual unknown must be an object"))?;
        let id = non_empty_text(object.get("unknown_id"), "unknown_id")?;
        let revision = object.get("revision").and_then(Value::as_u64).unwrap_or(0);
        let replace = heads
            .get(id)
            .and_then(Value::as_object)
            .and_then(|current| current.get("revision"))
            .and_then(Value::as_u64)
            .is_none_or(|current| revision > current);
        if replace {
            heads.insert(id.to_owned(), unknown.clone());
        }
    }
    Ok(heads)
}

fn evaluate_claim(
    claim: &Value,
    records: &HashMap<String, Value>,
    heads: &HashMap<String, Value>,
) -> Result<Value, Failure> {
    let claim_object = claim
        .as_object()
        .ok_or_else(|| invalid("reconstruction claim must be an object"))?;
    let claim_id = non_empty_text(claim_object.get("claim_id"), "claim.claim_id")?;
    let kind = non_empty_text(claim_object.get("kind"), "claim.kind")?;
    let dimension = non_empty_text(claim_object.get("dimension"), "claim.dimension")?;
    let comparison_id = non_empty_text(
        claim_object.get("comparison_evidence_id"),
        "claim.comparison_evidence_id",
    )?;
    let comparison = records
        .get(comparison_id)
        .ok_or_else(|| invalid(&format!("Missing comparison Evidence {comparison_id}")))?;
    validate_comparison_identity(comparison, kind)?;
    let sides = comparison_sides(comparison)?;
    let all_source_ids = sorted_unique([sides.0.clone(), sides.1.clone()].concat());
    if !same_set(&strings(comparison.get("evidence_links")), &all_source_ids) {
        return Err(invalid(
            "Comparison Evidence closure disagrees with its parameters",
        ));
    }
    let sources = all_source_ids
        .iter()
        .map(|id| {
            records
                .get(id)
                .ok_or_else(|| invalid(&format!("Missing source Evidence {id}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_sources(kind, &sources)?;

    let (observed, mut limitations, independent_function_change) =
        comparison_observation(comparison, kind, dimension)?;
    limitations.extend(strings(comparison.get("limitations")));
    limitations.extend(authority_limitations(kind, &sources, &sides));
    if kind == "structural-function"
        && (dimension == "calls" || (dimension == "overall" && !independent_function_change))
    {
        for source in &sources {
            if let Some(coverage) = source
                .get("relationship_coverage")
                .and_then(Value::as_object)
            {
                if coverage.get("status").and_then(Value::as_str) != Some("complete") {
                    limitations.push(format!(
                        "Source {}: Function call coverage is incomplete.",
                        string(source, "evidence_id")
                    ));
                }
            } else {
                limitations.push(format!(
                    "Source {}: Function relationship coverage is unavailable.",
                    string(source, "evidence_id")
                ));
            }
            if let Some(unresolved_calls) = source
                .get("normalized_result")
                .and_then(|result| result.get("unresolved_calls"))
            {
                for call in unresolved_calls.as_array().into_iter().flatten() {
                    if let (Some(address), Some(reason)) = (
                        call.get("address").and_then(Value::as_str),
                        call.get("reason").and_then(Value::as_str),
                    ) {
                        limitations.push(format!(
                            "Source {}: Unresolved call at {address}: {reason}",
                            string(source, "evidence_id")
                        ));
                    }
                }
            }
        }
    }

    let related = relevant_unknowns(heads, comparison_id, &all_source_ids, dimension);
    let status = classify(&observed, &limitations, &related);
    let mut claim_limitations = limitations;
    claim_limitations.extend(
        related
            .iter()
            .filter_map(|id| heads.get(id))
            .filter_map(|unknown| unknown.get("question").and_then(Value::as_str))
            .map(|question| format!("Residual unknown: {question}")),
    );

    Ok(json!({
        "claim_id": claim_id,
        "kind": kind,
        "dimension": dimension,
        "status": status,
        "observed_status": observed,
        "comparison_evidence_id": comparison_id,
        "left_evidence_ids": sides.0,
        "right_evidence_ids": sides.1,
        "evidence_links": sorted_unique(
            std::iter::once(comparison_id.to_owned())
                .chain(all_source_ids.iter().cloned())
                .collect(),
        ),
        "unknown_ids": related,
        "limitations": sorted_unique(claim_limitations),
    }))
}

fn validate_comparison_identity(comparison: &Value, kind: &str) -> Result<(), Failure> {
    let object = comparison
        .as_object()
        .ok_or_else(|| invalid("Comparison Evidence must be an object"))?;
    let expected = match kind {
        "behavioral" => ("compare_process_captures", "rea.process-comparison"),
        "structural-function" => ("compare_functions", "rea.function-comparison"),
        "structural-artifact" => ("compare_artifacts", "rea.artifact-comparison"),
        _ => return Err(invalid("claim.kind is unsupported")),
    };
    if object.get("operation").and_then(Value::as_str) != Some(expected.0)
        || object.get("predicate_type").and_then(Value::as_str) != Some(expected.1)
        || object.get("confidence").and_then(Value::as_str) != Some("derived")
        || object.get("authority").and_then(Value::as_str) != Some("analyst-inference")
        || !object.get("subject").is_some_and(Value::is_null)
    {
        return Err(invalid(
            "Comparison Evidence identity or authority disagrees",
        ));
    }
    let provider = object
        .get("provider")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("Comparison Evidence provider is required"))?;
    let provider_matches = match kind {
        "behavioral" => {
            provider.get("id").and_then(Value::as_str) == Some("rea-process")
                && provider.get("version").and_then(Value::as_str) == Some("3")
                && matches!(
                    provider.get("name").and_then(Value::as_str),
                    Some("REA process capture") | Some("REA deterministic process harness")
                )
        }
        "structural-function" => {
            provider.get("id").and_then(Value::as_str) == Some("rea-function-comparison")
                && provider.get("name").and_then(Value::as_str) == Some("REA function comparison")
                && provider.get("version").and_then(Value::as_str) == Some("1")
        }
        "structural-artifact" => {
            provider.get("id").and_then(Value::as_str) == Some("rea-artifact-comparison")
                && provider.get("name").and_then(Value::as_str) == Some("REA artifact comparison")
                && provider.get("version").and_then(Value::as_str) == Some("1")
        }
        _ => false,
    };
    if !provider_matches {
        return Err(invalid("Comparison Evidence provider identity disagrees"));
    }
    Ok(())
}

fn comparison_sides(comparison: &Value) -> Result<(Vec<String>, Vec<String>), Failure> {
    let parameters = comparison
        .get("parameters")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("Comparison Evidence parameters are required"))?;
    let left = side(parameters, "left")?;
    let right = side(parameters, "right")?;
    Ok((left, right))
}

fn side(parameters: &Map<String, Value>, prefix: &str) -> Result<Vec<String>, Failure> {
    let single = parameters
        .get(&format!("{prefix}_evidence_id"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let multiple = parameters
        .get(&format!("{prefix}_evidence_ids"))
        .and_then(Value::as_array)
        .map(|items| strings(Some(&Value::Array(items.clone()))));
    let selected = match (single, multiple) {
        (Some(single), Some(multiple)) => {
            if multiple.len() != 1 || multiple[0] != single {
                return Err(invalid(
                    "Comparison Evidence source representations disagree",
                ));
            }
            vec![single]
        }
        (Some(single), None) => vec![single],
        (None, Some(multiple)) => multiple,
        (None, None) => return Err(invalid("Comparison Evidence omitted its source parameters")),
    };
    if selected.is_empty() || selected.iter().collect::<HashSet<_>>().len() != selected.len() {
        return Err(invalid(
            "Comparison Evidence repeats a source within one side",
        ));
    }
    Ok(selected)
}

fn validate_sources(kind: &str, sources: &[&Value]) -> Result<(), Failure> {
    let expected = match kind {
        "behavioral" => ("capture_process_scenario", "rea.process-capture"),
        "structural-function" => ("analyze_function", "rea.analysis"),
        "structural-artifact" => ("", "rea.analysis"),
        _ => return Err(invalid("claim.kind is unsupported")),
    };
    for source in sources {
        let operation = source
            .get("operation")
            .and_then(Value::as_str)
            .unwrap_or("");
        let predicate = source
            .get("predicate_type")
            .and_then(Value::as_str)
            .unwrap_or("");
        let valid = if kind == "structural-artifact" {
            (operation == "inventory_artifact" || operation == "inspect_artifact")
                && predicate == expected.1
        } else if kind == "structural-artifact" {
            predicate == expected.1
        } else {
            operation == expected.0 && predicate == expected.1
        };
        if !valid {
            return Err(invalid(
                "Comparison source Evidence has an unexpected observation type",
            ));
        }
    }
    Ok(())
}

fn comparison_observation(
    comparison: &Value,
    kind: &str,
    dimension: &str,
) -> Result<(String, Vec<String>, bool), Failure> {
    let result = comparison
        .get("normalized_result")
        .or_else(|| comparison.get("result"))
        .ok_or_else(|| invalid("Comparison Evidence result is required"))?;
    if kind == "behavioral" {
        let observed = if dimension == "overall"
            && result.get("status").and_then(Value::as_str) == Some("unchanged")
            && result
                .pointer("/first_divergence/status")
                .and_then(Value::as_str)
                == Some("unknown")
        {
            "unknown".to_owned()
        } else {
            result
                .get(dimension)
                .or_else(|| result.get("status"))
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("Process comparison dimension is missing"))?
                .to_owned()
        };
        let limitations = if dimension == "overall" && observed == "unknown" {
            vec![
                result
                    .pointer("/first_divergence/reason")
                    .and_then(Value::as_str)
                    .unwrap_or("Process comparison is unknown.")
                    .to_owned(),
            ]
        } else {
            Vec::new()
        };
        return Ok((observed, limitations, false));
    }
    if kind == "structural-artifact" {
        return Ok((
            result
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned(),
            Vec::new(),
            false,
        ));
    }
    let dimensions = result
        .get("dimensions")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("Function comparison dimensions are missing"))?;
    let function_status = result
        .get("function_match")
        .and_then(|item| item.get("status"))
        .and_then(Value::as_str);
    let independent = function_status == Some("mismatched")
        || function_status == Some("matched")
            && dimensions.iter().any(|item| {
                item.get("dimension").and_then(Value::as_str) != Some("calls")
                    && item.get("status").and_then(Value::as_str) == Some("changed")
            });
    if dimension == "overall" {
        return Ok((
            result
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned(),
            dimensions
                .iter()
                .flat_map(|item| strings(item.get("limitations")))
                .collect(),
            independent,
        ));
    }
    let item = dimensions
        .iter()
        .find(|item| item.get("dimension").and_then(Value::as_str) == Some(dimension))
        .ok_or_else(|| invalid("Function comparison dimension missing"))?;
    Ok((
        item.get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned(),
        strings(item.get("limitations")),
        independent,
    ))
}

fn authority_limitations(
    kind: &str,
    sources: &[&Value],
    sides: &(Vec<String>, Vec<String>),
) -> Vec<String> {
    let mut limitations = Vec::new();
    if sides.0.iter().any(|id| sides.1.contains(id)) {
        limitations.push("A source observation appears on both comparison sides; independent original and reconstruction observations are unavailable.".into());
    }
    let required = if kind == "behavioral" {
        "controlled-replay"
    } else {
        "shipped-artifact"
    };
    if sources.iter().any(|source| {
        source.get("authority").and_then(Value::as_str) != Some(required)
            || (kind == "structural-function"
                && source.get("confidence").and_then(Value::as_str) == Some("inferred"))
            || (kind != "behavioral"
                && source.get("confidence").and_then(Value::as_str) != Some("observed"))
    }) {
        limitations.push(format!(
            "Source Evidence lacks qualifying {required} authority."
        ));
    }
    if kind != "behavioral"
        && sources
            .iter()
            .any(|source| source.get("subject").is_some_and(Value::is_null))
    {
        limitations.push("Structural source artifact identity is unavailable.".into());
    }
    if kind == "behavioral" {
        let environment = sources.first().and_then(|source| source.get("environment"));
        if environment.is_none()
            || environment.is_some_and(Value::is_null)
            || sources
                .iter()
                .any(|source| source.get("environment") != environment)
        {
            limitations
                .push("Controlled replay environments are unavailable or incompatible.".into());
        }
    }
    limitations
}

fn relevant_unknowns(
    heads: &HashMap<String, Value>,
    comparison_id: &str,
    source_ids: &[String],
    dimension: &str,
) -> Vec<String> {
    let evidence_ids: HashSet<&str> = std::iter::once(comparison_id)
        .chain(source_ids.iter().map(String::as_str))
        .collect();
    let mut relevant = BTreeSet::new();
    for (id, unknown) in heads {
        if unknown.get("status").and_then(Value::as_str) == Some("resolved") {
            continue;
        }
        if let Some(scope) = unknown.get("comparison_conclusion_scope") {
            if scope.get("comparison_evidence_id").and_then(Value::as_str) != Some(comparison_id)
                || !scope
                    .get("dimensions")
                    .is_some_and(|items| strings(Some(items)).iter().any(|item| item == dimension))
            {
                continue;
            }
        }
        let referenced = strings(unknown.get("supporting_evidence_ids"))
            .into_iter()
            .chain(strings(unknown.get("contradicting_evidence_ids")))
            .any(|evidence_id| evidence_ids.contains(evidence_id.as_str()));
        if referenced {
            relevant.insert(id.clone());
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for (id, unknown) in heads {
            if relevant.contains(id)
                || unknown.get("status").and_then(Value::as_str) == Some("resolved")
            {
                continue;
            }
            let depends = unknown
                .get("relationships")
                .and_then(Value::as_array)
                .is_some_and(|relations| {
                    relations.iter().any(|relation| {
                        relation.get("type").and_then(Value::as_str) != Some("related-to")
                            && relation
                                .get("unknown_id")
                                .and_then(Value::as_str)
                                .is_some_and(|dependency| relevant.contains(dependency))
                    })
                });
            if depends {
                relevant.insert(id.clone());
                changed = true;
            }
        }
    }
    relevant.into_iter().collect()
}

fn classify(observed: &str, limitations: &[String], unknowns: &[String]) -> &'static str {
    if !limitations.is_empty() {
        return "unknown";
    }
    if ["changed", "added", "removed", "contradiction"].contains(&observed) {
        return "fail";
    }
    if ["unknown", "truncated"].contains(&observed) || !unknowns.is_empty() {
        return "unknown";
    }
    "pass"
}

fn recommended_probes(results: &[Value], heads: &HashMap<String, Value>) -> Vec<Value> {
    let mut probes: BTreeMap<String, (String, String, BTreeSet<String>, BTreeSet<String>)> =
        BTreeMap::new();
    for result in results
        .iter()
        .filter(|result| string(result, "status") == "unknown")
    {
        let kind = string(result, "kind");
        let default = match kind {
            "behavioral" => (
                "capture_process_scenario",
                "Repeat both scenarios under one controlled environment.",
            ),
            "structural-function" => (
                "analyze_function",
                "Capture complete function dossiers under equal limits.",
            ),
            _ => (
                "inspect_artifact",
                "Capture complete artifact inventories under equal limits.",
            ),
        };
        let unknown_ids = strings(result.get("unknown_ids"));
        let candidates: Vec<(String, String)> = unknown_ids
            .iter()
            .flat_map(|id| heads.get(id).into_iter())
            .flat_map(|unknown| {
                unknown
                    .get("recommended_probes")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
            })
            .filter_map(|probe| {
                Some((
                    probe.get("operation")?.as_str()?.to_owned(),
                    probe.get("rationale")?.as_str()?.to_owned(),
                ))
            })
            .collect();
        let candidates = if candidates.is_empty() {
            vec![(default.0.into(), default.1.into())]
        } else {
            candidates
        };
        for (operation, rationale) in candidates {
            let key = format!("{operation}\u{0}{rationale}");
            let entry = probes.entry(key).or_insert_with(|| {
                (
                    operation.clone(),
                    rationale.clone(),
                    BTreeSet::new(),
                    BTreeSet::new(),
                )
            });
            entry.2.insert(string(result, "claim_id").to_owned());
            entry.3.extend(unknown_ids.iter().cloned());
        }
    }
    probes
        .into_values()
        .map(|(operation, rationale, claim_ids, unknown_ids)| {
            json!({
                "operation": operation,
                "rationale": rationale,
                "claim_ids": claim_ids.into_iter().collect::<Vec<_>>(),
                "unknown_ids": unknown_ids.into_iter().collect::<Vec<_>>(),
            })
        })
        .collect()
}

fn canonical_specification(specification: &Value) -> Result<Value, Failure> {
    let object = specification
        .as_object()
        .ok_or_else(|| invalid("specification must be an object"))?;
    let mut normalized = object.clone();
    if let Some(claims) = object.get("claims").and_then(Value::as_array) {
        let mut sorted = claims.clone();
        sorted.sort_by(|left, right| string(left, "claim_id").cmp(string(right, "claim_id")));
        normalized.insert("claims".into(), Value::Array(sorted));
    }
    Ok(Value::Object(normalized))
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn same_set(left: &[String], right: &[String]) -> bool {
    sorted_unique(left.to_vec()) == sorted_unique(right.to_vec())
}

fn count_status(results: &[Value], status: &str) -> usize {
    results
        .iter()
        .filter(|item| string(item, "status") == status)
        .count()
}

fn string<'a>(value: &'a Value, field: &str) -> &'a str {
    value.get(field).and_then(Value::as_str).unwrap_or("")
}

fn non_empty_text<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a str, Failure> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty string")))
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a typed reconstruction specification and retained Evidence bundle.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
