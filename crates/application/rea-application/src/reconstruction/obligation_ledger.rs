//! Contract boundary for deterministic reconstruction obligation ledgers.

use rea_core::canonical_json;
use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "build_reconstruction_obligation_ledger";

/// Compose the reviewed obligations and explicit manifest into a deterministic
/// ledger. Facts that cannot be established remain diagnostics or limitations.
pub fn build_ledger(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;
    let evidence_bundle = object_field(object, "evidence_bundle")?;
    let records = array_field(evidence_bundle, "records")?;
    let reviewed = array_field_in_object(object, "reviewed_obligations")?;
    let manifest = object_field(object, "manifest")?;
    let bindings = array_field(manifest, "bindings")?;
    let evidence_ids = evidence_ids(evidence_bundle)?;
    let evidence_id_order = evidence_id_order(records)?;
    for obligation in reviewed {
        for evidence_id in string_array(obligation, "review_evidence_ids")?
            .iter()
            .filter_map(Value::as_str)
        {
            if !evidence_ids.contains(evidence_id) {
                return Err(invalid("reviewed obligation references absent Evidence"));
            }
        }
    }

    let mut obligations = reviewed
        .iter()
        .map(|review| compose_obligation(review, bindings, records, &evidence_ids, manifest))
        .collect::<Result<Vec<_>, _>>()?;
    obligations.sort_by_key(|obligation| {
        obligation["obligation_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    });
    apply_dependency_diagnostics(&mut obligations);

    let evidence_links = evidence_links(&obligations, manifest);
    let limitations = if obligations.is_empty() {
        vec!["No reconstruction obligations were derived; closure cannot be claimed.".to_owned()]
    } else {
        Vec::new()
    };
    let status = ledger_status(&obligations, &limitations);
    let coverage = json!({"status": if limitations.is_empty() { "complete" } else { "partial" }});
    let summary = summarize(&obligations);
    let reports = reports(&obligations);
    let ownership_graph = ownership_graph(&obligations);
    let dependency_graph = dependency_graph(&obligations);
    let closure = json!({
        "status": status,
        "coverage": coverage,
        "summary": summary,
        "reports": reports,
        "ownership_graph": ownership_graph,
        "dependency_graph": dependency_graph,
        "obligations": obligations,
        "evidence_links": evidence_links,
        "limitations": limitations,
    });
    let closure_digest = canonical_json::digest(&json!({
        "schema": "ReconstructionObligationClosure",
        "status": closure["status"],
        "coverage": closure["coverage"],
        "summary": closure["summary"],
        "reports": closure["reports"],
        "ownership_graph": closure["ownership_graph"],
        "dependency_graph": closure["dependency_graph"],
        "obligations": closure["obligations"],
        "evidence_links": closure["evidence_links"],
        "limitations": closure["limitations"],
    }))
    .map_err(|_| invalid("ledger facts are not canonical JSON"))?;
    let obligation_ids = closure["obligations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|obligation| obligation["obligation_id"].as_str())
        .collect::<Vec<_>>();
    let ledger_id = canonical_json::digest(&json!({
        "schema": "ReconstructionObligationLedger",
        "evidence_ids": evidence_id_order,
        "obligation_ids": obligation_ids,
        "closure_digest": closure_digest,
    }))
    .map_err(|_| invalid("ledger identity is not canonical JSON"))?;
    let mut ledger = closure
        .as_object()
        .cloned()
        .ok_or_else(|| invalid("ledger facts must be an object"))?;
    ledger.insert("schema".to_owned(), json!("ReconstructionObligationLedger"));
    ledger.insert("ledger_id".to_owned(), json!(format!("rol_{ledger_id}")));
    ledger.insert("closure_digest".to_owned(), json!(closure_digest));
    Ok(Value::Object(ledger))
}

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("reconstruction ledger input must be an object"))?;

    let evidence_bundle = object_field(object, "evidence_bundle")?;
    for field in [
        "artifacts",
        "providers",
        "environments",
        "scenarios",
        "captures",
        "unknowns",
        "records",
    ] {
        array_field(evidence_bundle, field)?;
    }

    let reviewed = array_field_in_object(object, "reviewed_obligations")?;
    validate_unique_ids(reviewed, "reviewed_obligations")?;

    let manifest = object_field(object, "manifest")?;
    let bindings = array_field(manifest, "bindings")?;
    validate_unique_ids(bindings, "manifest.bindings")?;

    let contradictions = array_field(manifest, "contradictions")?;
    for contradiction in contradictions {
        let contradiction = contradiction
            .as_object()
            .ok_or_else(|| invalid("manifest.contradictions entries must be objects"))?;
        let ids = contradiction
            .get("evidence_ids")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("manifest.contradictions entries need evidence_ids"))?;
        if ids.len() < 2 {
            return Err(invalid(
                "manifest.contradictions entries need at least two evidence_ids",
            ));
        }
    }

    Ok(())
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("reconstruction ledger result must be an object"));
    }
    Ok(result)
}

fn object_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a Value, Failure> {
    object
        .get(field)
        .filter(|value| value.is_object())
        .ok_or_else(|| invalid(&format!("{field} must be an object")))
}

fn evidence_ids(value: &Value) -> Result<BTreeSet<String>, Failure> {
    let records = array_field(value, "records")?;
    let mut ids = BTreeSet::new();
    for record in records {
        let id = record
            .get("evidence_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| invalid("evidence_bundle.records entries need evidence_id"))?;
        if !ids.insert(id.to_owned()) {
            return Err(invalid(
                "evidence_bundle.records evidence_id values must be unique",
            ));
        }
    }
    Ok(ids)
}

fn evidence_id_order(records: &[Value]) -> Result<Vec<String>, Failure> {
    records
        .iter()
        .map(|record| {
            record
                .get("evidence_id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| invalid("evidence_bundle.records entries need evidence_id"))
        })
        .collect()
}

fn string_array<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>, Failure> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(&format!("{field} must be an array")))
}

fn compose_obligation(
    review: &Value,
    bindings: &[Value],
    records: &[Value],
    evidence_ids: &BTreeSet<String>,
    manifest: &Value,
) -> Result<Value, Failure> {
    let object = review
        .as_object()
        .ok_or_else(|| invalid("reviewed_obligations entries must be objects"))?;
    let obligation_id = object
        .get("obligation_id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("reviewed obligation needs obligation_id"))?;
    let review_ids = string_array(review, "review_evidence_ids")?;
    let authority_references = review_ids
        .iter()
        .filter_map(Value::as_str)
        .map(|id| {
            let evidence = records.iter().find(|record| {
                record.get("evidence_id").and_then(Value::as_str) == Some(id)
            });
            json!({
                "evidence_id": id,
                "authority": evidence.and_then(|record| record.get("authority")).cloned().unwrap_or_else(|| json!("analyst-inference")),
                "state": evidence.map(reviewed_evidence_state).unwrap_or("reviewed"),
                "location": format!("/evidence/{id}"),
            })
        })
        .collect::<Vec<_>>();
    let matching_bindings = bindings
        .iter()
        .filter(|binding| {
            binding.get("obligation_id").and_then(Value::as_str) == Some(obligation_id)
        })
        .collect::<Vec<_>>();
    let binding = (matching_bindings.len() == 1).then(|| matching_bindings[0]);
    let mut diagnostics = Vec::new();
    if matching_bindings.is_empty() {
        diagnostics.push(json!({
            "code": "missing-owner",
            "detail": "No reconstruction manifest binding owns this obligation."
        }));
    }
    if matching_bindings.len() > 1 {
        diagnostics.push(json!({
            "code": "ambiguous-owner",
            "detail": "Multiple reconstruction manifest bindings claim this obligation."
        }));
    }
    let binding_value = binding.cloned().unwrap_or(Value::Null);
    if binding_value.is_null() || binding_value.get("verifier").is_some_and(Value::is_null) {
        diagnostics.push(json!({
            "code": "missing-verifier",
            "detail": "No verifier claim is bound to this obligation."
        }));
    }
    if let Some(binding) = binding {
        if object.get("requires_parser_type") == Some(&Value::Bool(true))
            && binding.get("parser_type").is_some_and(Value::is_null)
        {
            diagnostics.push(json!({
                "code": "missing-parser-type",
                "detail": "This boundary requires an explicit parser, schema, and domain type."
            }));
        }
        let required_cases = string_array(review, "required_case_kinds")?;
        let original_cases = binding
            .get("original_cases")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("manifest binding original_cases must be an array"))?;
        for case_kind in required_cases.iter().filter_map(Value::as_str) {
            let matching_cases = original_cases
                .iter()
                .filter(|case| case.get("kind").and_then(Value::as_str) == Some(case_kind))
                .collect::<Vec<_>>();
            if matching_cases.is_empty() {
                diagnostics.push(json!({
                    "code": "missing-original-case",
                    "detail": format!("Original {case_kind} behavior has not been observed.")
                }));
            } else if !matching_cases.iter().any(|case| {
                case.get("evidence_id")
                    .and_then(Value::as_str)
                    .and_then(|id| {
                        records.iter().find(|record| {
                            record.get("evidence_id").and_then(Value::as_str) == Some(id)
                        })
                    })
                    .is_some_and(|record| original_authority_supports(record, object))
            }) {
                diagnostics.push(json!({
                    "code": "weak-original-case-authority",
                    "detail": format!("Original {case_kind} case lacks authenticated authority."),
                }));
            }
            let fixtures = binding
                .get("fixtures")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|fixture| {
                    fixture.get("case_kind").and_then(Value::as_str) == Some(case_kind)
                })
                .collect::<Vec<_>>();
            if fixtures.is_empty() {
                diagnostics.push(json!({
                    "code": "missing-case",
                    "detail": format!("Required {case_kind} fixture is missing.")
                }));
            }
            for fixture in fixtures {
                let fixture_authority = fixture
                    .get("authority")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                for evidence_id in fixture
                    .get("evidence_ids")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                {
                    if !evidence_ids.contains(evidence_id) {
                        diagnostics.push(json!({
                            "code": "missing-case",
                            "detail": format!("{case_kind} fixture references Evidence {evidence_id}, which is absent from the bundle.")
                        }));
                    }
                }
                let fixture_has_authenticated_evidence = fixture
                    .get("evidence_ids")
                    .and_then(Value::as_array)
                    .is_some_and(|ids| {
                        ids.iter().filter_map(Value::as_str).any(|id| {
                            records.iter().any(|record| {
                                record.get("evidence_id").and_then(Value::as_str) == Some(id)
                                    && record.get("confidence").and_then(Value::as_str)
                                        == Some("observed")
                            })
                        })
                    });
                if !fixture_has_authenticated_evidence || fixture_authority == "unknown" {
                    diagnostics.push(json!({
                        "code": "weak-fixture-authority",
                        "detail": format!("{case_kind} fixture lacks authenticated Evidence authority."),
                    }));
                }
            }
        }
        if let Some(verifier) = binding.get("verifier").filter(|value| !value.is_null()) {
            let enumerates = verifier
                .get("enumerated_obligation_ids")
                .and_then(Value::as_array)
                .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(obligation_id)));
            if !enumerates {
                diagnostics.push(json!({
                    "code": "verifier-does-not-enumerate",
                    "detail": "The verifier claim does not enumerate this obligation ID."
                }));
            }
            if verifier
                .get("result_evidence_id")
                .and_then(Value::as_str)
                .is_none_or(|id| !evidence_ids.contains(id))
            {
                diagnostics.push(json!({
                    "code": "missing-verifier-result",
                    "detail": "The latest verifier result Evidence is absent from the bundle."
                }));
            }
            if verifier.get("status").and_then(Value::as_str) != Some("pass") {
                diagnostics.push(json!({
                    "code": "verifier-failed",
                    "detail": format!("Latest verifier status is {}.", verifier.get("status").and_then(Value::as_str).unwrap_or("unknown"))
                }));
            }
        }
    }
    evaluate_original_authority(object, &authority_references, records, diagnostics.as_mut());
    if let Some(contradiction) = manifest
        .get("contradictions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|item| item.get("obligation_id").and_then(Value::as_str) == Some(obligation_id))
    {
        let missing = contradiction
            .get("evidence_ids")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|id| !evidence_ids.contains(*id))
            .collect::<Vec<_>>();
        diagnostics.push(if missing.is_empty() {
            json!({"code": "contradiction", "detail": "Authenticated contradictory Evidence reopens this obligation."})
        } else {
            json!({"code": "contradiction-evidence-missing", "detail": format!("Contradiction references missing Evidence: {}.", missing.join(", "))})
        });
    }
    for evidence_id in review_ids.iter().filter_map(Value::as_str) {
        if !evidence_ids.contains(evidence_id) {
            diagnostics.push(json!({
                "code": "residual-unknown",
                "detail": format!("Review Evidence remains unresolved: {evidence_id}.")
            }));
        }
    }
    for dependency in string_array(review, "dependency_obligation_ids")?
        .iter()
        .filter_map(Value::as_str)
    {
        if !bindings
            .iter()
            .any(|item| item.get("obligation_id").and_then(Value::as_str) == Some(dependency))
        {
            diagnostics.push(json!({
                "code": "dependency-missing",
                "detail": format!("Dependency obligation is missing: {dependency}.")
            }));
        }
    }
    let status = if object.get("disposition").and_then(Value::as_str) == Some("out-of-scope") {
        "out-of-scope"
    } else if object.get("disposition").and_then(Value::as_str) == Some("blocked") {
        "blocked"
    } else if diagnostics
        .iter()
        .any(|item| item["code"] == "contradiction")
    {
        "contradicted"
    } else if diagnostics.iter().any(|item| {
        matches!(
            item["code"].as_str(),
            Some("blocked" | "dependency-missing" | "dependency-open")
        )
    }) {
        "blocked"
    } else if diagnostics
        .iter()
        .any(|item| item["code"] == "dependency-missing")
    {
        "blocked"
    } else if binding.is_none() {
        "unowned"
    } else if diagnostics.iter().any(|item| {
        matches!(
            item["code"].as_str(),
            Some("residual-unknown" | "unavailable-authority")
        )
    }) {
        "unknown"
    } else if diagnostics.is_empty() {
        "verified"
    } else {
        "implemented"
    };
    let mut result = object.clone();
    result.remove("disposition");
    result.remove("review_evidence_ids");
    result.insert("origin".to_owned(), json!("reviewed"));
    result.insert(
        "authority_references".to_owned(),
        json!(authority_references),
    );
    result.insert("source_state".to_owned(), json!("reviewed"));
    result.insert(
        "observed_cases".to_owned(),
        binding_value
            .get("original_cases")
            .cloned()
            .unwrap_or_else(|| json!([])),
    );
    result.insert("binding".to_owned(), binding_value);
    result.insert("status".to_owned(), json!(status));
    result.insert("diagnostics".to_owned(), json!(diagnostics));
    Ok(Value::Object(result))
}

fn evaluate_original_authority(
    obligation: &serde_json::Map<String, Value>,
    references: &[Value],
    records: &[Value],
    diagnostics: &mut Vec<Value>,
) {
    let required = obligation
        .get("required_original_authority")
        .and_then(Value::as_str);
    let Some(required) = required else {
        return;
    };

    let satisfied = references.iter().any(|reference| {
        let id = reference.get("evidence_id").and_then(Value::as_str);
        let state = reference.get("state").and_then(Value::as_str);
        let Some(record) = id.and_then(|id| {
            records
                .iter()
                .find(|record| record.get("evidence_id").and_then(Value::as_str) == Some(id))
        }) else {
            return false;
        };
        original_authority_supports(record, obligation)
            && (required == "static" || state == Some("observed"))
    });

    if !satisfied {
        diagnostics.push(json!({
            "code": "static-only",
            "detail": format!("No {required} authority characterizes the original finite behavior."),
        }));
    }
}

fn original_authority_supports(
    record: &Value,
    obligation: &serde_json::Map<String, Value>,
) -> bool {
    let Some(required) = obligation
        .get("required_original_authority")
        .and_then(Value::as_str)
    else {
        return false;
    };
    let observed = record.get("confidence").and_then(Value::as_str) == Some("observed");
    let authority = record.get("authority").and_then(Value::as_str);
    match required {
        "static" => observed && authority == Some("shipped-artifact"),
        "runtime" => {
            observed && matches!(authority, Some("controlled-replay" | "external-service"))
        }
        "process" => {
            observed
                && record.get("operation").and_then(Value::as_str)
                    == Some("capture_process_scenario")
                && record.get("predicate_type").and_then(Value::as_str)
                    == Some("rea.process-capture")
        }
        _ => observed && authority == Some("external-service"),
    }
}

fn reviewed_evidence_state(record: &Value) -> &'static str {
    if record.get("confidence").and_then(Value::as_str) == Some("observed")
        && (record.get("operation").and_then(Value::as_str) == Some("capture_process_scenario")
            && record.get("predicate_type").and_then(Value::as_str) == Some("rea.process-capture"))
    {
        return "observed";
    }
    if record.get("confidence").and_then(Value::as_str) == Some("observed")
        && record.get("authority").and_then(Value::as_str) == Some("external-service")
    {
        return "observed";
    }
    if record.get("authority").and_then(Value::as_str) == Some("shipped-artifact") {
        return "candidate";
    }
    "reviewed"
}

fn apply_dependency_diagnostics(obligations: &mut [Value]) {
    let ids = obligations
        .iter()
        .filter_map(|value| {
            value
                .get("obligation_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect::<BTreeSet<_>>();
    let statuses = obligations
        .iter()
        .filter_map(|value| {
            Some((
                value.get("obligation_id")?.as_str()?.to_owned(),
                value.get("status")?.as_str()?.to_owned(),
            ))
        })
        .collect::<BTreeMap<_, _>>();
    for obligation in obligations.iter_mut() {
        let dependencies = obligation
            .get("dependency_obligation_ids")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut additions = Vec::new();
        for dependency in dependencies.iter().filter_map(Value::as_str) {
            if !ids.contains(dependency) {
                additions.push(json!({
                    "code": "dependency-missing",
                    "detail": format!("Dependency obligation is missing: {dependency}.")
                }));
            } else if statuses
                .get(dependency)
                .is_none_or(|status| status != "verified")
            {
                additions.push(json!({
                    "code": "dependency-open",
                    "detail": format!("Dependency obligation is not verified: {dependency}.")
                }));
            }
        }
        if additions.is_empty() {
            continue;
        }
        if let Some(diagnostics) = obligation
            .get_mut("diagnostics")
            .and_then(Value::as_array_mut)
        {
            diagnostics.extend(additions);
        }
        if !matches!(
            obligation.get("status").and_then(Value::as_str),
            Some("contradicted" | "out-of-scope")
        ) {
            obligation["status"] = json!("blocked");
        }
    }
}

fn evidence_links(obligations: &[Value], manifest: &Value) -> Vec<Value> {
    let mut links = BTreeSet::new();
    for obligation in obligations {
        for field in ["authority_references", "observed_cases"] {
            if let Some(values) = obligation.get(field).and_then(Value::as_array) {
                for value in values {
                    if let Some(id) = value.get("evidence_id").and_then(Value::as_str) {
                        links.insert(id.to_owned());
                    }
                }
            }
        }
    }
    if let Some(bindings) = manifest.get("bindings").and_then(Value::as_array) {
        for binding in bindings {
            if let Some(cases) = binding.get("original_cases").and_then(Value::as_array) {
                for case_value in cases {
                    if let Some(id) = case_value.get("evidence_id").and_then(Value::as_str) {
                        links.insert(id.to_owned());
                    }
                }
            }
            if let Some(fixtures) = binding.get("fixtures").and_then(Value::as_array) {
                for fixture in fixtures {
                    if let Some(ids) = fixture.get("evidence_ids").and_then(Value::as_array) {
                        links.extend(ids.iter().filter_map(Value::as_str).map(str::to_owned));
                    }
                }
            }
            if let Some(verifier) = binding.get("verifier").filter(|value| !value.is_null()) {
                if let Some(id) = verifier.get("result_evidence_id").and_then(Value::as_str) {
                    links.insert(id.to_owned());
                }
            }
        }
    }
    if let Some(contradictions) = manifest.get("contradictions").and_then(Value::as_array) {
        for contradiction in contradictions {
            if let Some(ids) = contradiction.get("evidence_ids").and_then(Value::as_array) {
                links.extend(ids.iter().filter_map(Value::as_str).map(str::to_owned));
            }
        }
    }
    links.into_iter().map(Value::String).collect()
}

fn summarize(obligations: &[Value]) -> Value {
    let count = |predicate: &dyn Fn(&Value) -> bool| {
        obligations.iter().filter(|value| predicate(value)).count()
    };
    let statuses = [
        "unowned",
        "characterized",
        "implemented",
        "verified",
        "contradicted",
        "blocked",
        "out-of-scope",
        "unknown",
    ];
    let layers = [
        "cli",
        "protocol",
        "electron",
        "persistence",
        "process",
        "runtime",
        "packaging",
        "native-abi",
        "application",
        "other",
    ];
    let authorities = ["candidate", "observed", "reviewed", "unknown"];
    json!({
        "total": obligations.len(),
        "required": count(&|value| value["required"] == true),
        "verified": count(&|value| value["status"] == "verified"),
        "required_open": count(&|value| value["required"] == true && value["status"] != "verified"),
        "by_status": statuses.iter().map(|key| json!({"key": key, "count": count(&|value| value["status"] == *key)})).collect::<Vec<_>>(),
        "by_application_layer": layers.iter().map(|key| json!({"key": key, "count": count(&|value| value["application_layer"] == *key)})).collect::<Vec<_>>(),
        "by_evidence_authority": authorities.iter().map(|key| json!({"key": key, "count": count(&|value| value["source_state"] == *key)})).collect::<Vec<_>>(),
    })
}

fn reports(obligations: &[Value]) -> Value {
    let ids_for = |code: &str| {
        let mut ids = obligations
            .iter()
            .filter(|value| {
                value["diagnostics"]
                    .as_array()
                    .is_some_and(|items| items.iter().any(|item| item["code"] == code))
            })
            .filter_map(|value| value["obligation_id"].as_str())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        ids.sort();
        ids
    };
    let mut residual = obligations
        .iter()
        .flat_map(|value| {
            value["residual_unknown_ids"]
                .as_array()
                .into_iter()
                .flatten()
        })
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    residual.sort();
    residual.dedup();
    json!({
        "missing_owner_obligation_ids": ids_for("missing-owner"),
        "missing_verifier_obligation_ids": ids_for("missing-verifier"),
        "contradicted_obligation_ids": ids_for("contradiction"),
        "residual_unknown_ids": residual,
    })
}

fn ownership_graph(obligations: &[Value]) -> Vec<Value> {
    let mut graph = obligations
        .iter()
        .filter_map(|value| {
            let binding = value["binding"].as_object()?;
            let owner = binding.get("owner")?.as_object()?;
            Some(json!({
                "obligation_id": value["obligation_id"],
                "module_path": owner["module_path"],
                "symbol": owner["symbol"],
            }))
        })
        .collect::<Vec<_>>();
    graph.sort_by_key(|value| {
        value["obligation_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    });
    graph
}

fn dependency_graph(obligations: &[Value]) -> Vec<Value> {
    let mut graph = obligations
        .iter()
        .flat_map(|value| {
            let id = value["obligation_id"].clone();
            value["dependency_obligation_ids"]
                .as_array()
                .into_iter()
                .flatten()
                .map(move |dependency| {
                    json!({
                        "obligation_id": id,
                        "depends_on_obligation_id": dependency,
                    })
                })
        })
        .collect::<Vec<_>>();
    graph.sort_by_key(|value| {
        (
            value["obligation_id"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            value["depends_on_obligation_id"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        )
    });
    graph
}

fn ledger_status(obligations: &[Value], limitations: &[String]) -> &'static str {
    if obligations.is_empty() {
        return "unknown";
    }
    let required_open = obligations
        .iter()
        .any(|value| value["required"] == true && value["status"] != "verified");
    if obligations.iter().any(|value| {
        value["required"] == true
            && (value["status"] == "contradicted"
                || value["diagnostics"].as_array().is_some_and(|items| {
                    items.iter().any(|item| item["code"] == "verifier-failed")
                }))
    }) {
        return "failed";
    }
    if !limitations.is_empty() {
        return "unknown";
    }
    if obligations
        .iter()
        .any(|value| value["required"] == true && value["status"] == "unknown")
    {
        return "unknown";
    }
    if required_open { "open" } else { "ready" }
}

fn array_field<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>, Failure> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(&format!("{field} must be an array")))
}

fn array_field_in_object<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a Vec<Value>, Failure> {
    object
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(&format!("{field} must be an array")))
}

fn validate_unique_ids(values: &[Value], field: &str) -> Result<(), Failure> {
    let mut ids = BTreeSet::new();
    for value in values {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(&format!("{field} entries must be objects")))?;
        let id = object
            .get("obligation_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| invalid(&format!("{field} entries need obligation_id")))?;
        if !ids.insert(id) {
            return Err(invalid(&format!(
                "{field} obligation_id values must be unique"
            )));
        }
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide an authenticated Evidence bundle, reviewed obligations, and a deterministic reconstruction manifest.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Value {
        serde_json::json!({
            "evidence_bundle": {
                "artifacts": [],
                "providers": [],
                "environments": [],
                "scenarios": [],
                "captures": [],
                "unknowns": [],
                "records": []
            },
            "reviewed_obligations": [],
            "manifest": {"bindings": [], "contradictions": []}
        })
    }

    #[test]
    fn accepts_empty_authenticated_bundle_shape() {
        validate_input(&input()).expect("valid reconstruction ledger input");
        assert!(retain_result(&input(), serde_json::json!({"status": "ready"})).is_ok());
    }

    #[test]
    fn composes_reviewed_obligations_with_stable_evidence_links() {
        let mut value = input();
        value["evidence_bundle"]["records"] = serde_json::json!([
            {"evidence_id": "ev_review"}
        ]);
        value["reviewed_obligations"] = serde_json::json!([{
            "obligation_id": "obligation_one",
            "review_evidence_ids": ["ev_review"],
            "dependency_obligation_ids": [],
            "residual_unknown_ids": [],
            "required": true,
            "source_state": "reviewed"
        }]);

        let ledger = build_ledger(&value).expect("ledger is composed");
        assert_eq!(ledger["obligations"][0]["origin"], "reviewed");
        assert_eq!(ledger["evidence_links"], serde_json::json!(["ev_review"]));
        assert_eq!(ledger["status"], "open");
    }

    #[test]
    fn rejects_reviewed_obligations_with_absent_evidence_references() {
        let mut value = input();
        value["reviewed_obligations"] = serde_json::json!([{
            "obligation_id": "obligation_one",
            "review_evidence_ids": ["ev_missing"],
            "dependency_obligation_ids": []
        }]);
        assert!(build_ledger(&value).is_err());
    }

    #[test]
    fn rejects_missing_bundle_sections() {
        let mut invalid_input = input();
        invalid_input["evidence_bundle"] = serde_json::json!({});
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_duplicate_reviewed_obligation_ids() {
        let mut invalid_input = input();
        invalid_input["reviewed_obligations"] = serde_json::json!([
            {"obligation_id": "obligation_one"},
            {"obligation_id": "obligation_one"}
        ]);
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_contradictions_without_two_evidence_records() {
        let mut invalid_input = input();
        invalid_input["manifest"]["contradictions"] = serde_json::json!([
            {"obligation_id": "obligation_one", "evidence_ids": ["ev_one"]}
        ]);
        assert!(validate_input(&invalid_input).is_err());
    }
}
