//! Conservative reconstruction-obligation generation and closure.
//!
//! Compatibility owners: `src/server/registerApplicationTools/obligationLedger.ts`,
//! `src/application/ReconstructionObligationLedgerService.ts`,
//! `ReconstructionObligationCandidates.ts`, `ReconstructionObligationPolicies.ts`,
//! `ReconstructionObligationAuthority.ts`, `ReconstructionObligationOriginalCases.ts`,
//! `ReconstructionObligationLedgerDiagnostics.ts`,
//! `ReconstructionObligationLedgerProjection.ts`,
//! `ReconstructionObligationLedgerEvaluation.ts` and
//! `src/domain/reconstructionObligationLedger{Schemas,Integrity}.ts`.
use crate::bundle;
use crate::ledger_sources::{self, ApplicationSource};
use crate::rejection::Rejection;
use crate::sdk_input::{Trimmer, extend};
use crate::support;
use rea_core::analysis_error::AnalysisError;
use rea_core::canonical_json;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation};
use rea_mcp::{Registry, ToolOutput};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub const OPERATION: &str = "build_reconstruction_obligation_ledger";
const CONTEXT: &str = "Reconstruction obligation ledger";

pub fn register(registry: &mut Registry) {
    registry.handle(OPERATION, |context, mut input| {
        if let Some(failure) = trim_request(&mut input).failure(context.contract) {
            return ToolOutput::Raw(failure);
        }
        let evidence = build_ledger_evidence(&input);
        let sources = input["evidence_bundle"]["records"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        support::deliver(context.session, &sources, evidence)
    });
}

/// Apply the request schema's trimmed text fields in Zod traversal order.
fn trim_request(input: &mut Value) -> Trimmer {
    let mut trimmer = Trimmer::default();
    if let Some(items) = input["reviewed_obligations"].as_array_mut() {
        for (index, item) in items.iter_mut().enumerate() {
            let base = vec!["reviewed_obligations".to_owned(), index.to_string()];
            trimmer.field(&mut item["title"], &extend(&base, &["title"]));
            trimmer.field(&mut item["family"], &extend(&base, &["family"]));
            trimmer.field(
                &mut item["target"]["location"],
                &extend(&base, &["target", "location"]),
            );
            trimmer.each(
                &mut item["unavailable_authority"],
                &extend(&base, &["unavailable_authority"]),
            );
            trimmer.each(
                &mut item["required_next_evidence"],
                &extend(&base, &["required_next_evidence"]),
            );
        }
    }
    if let Some(items) = input["manifest"]["bindings"].as_array_mut() {
        for (index, item) in items.iter_mut().enumerate() {
            let base = vec![
                "manifest".to_owned(),
                "bindings".to_owned(),
                index.to_string(),
            ];
            trimmer.field(
                &mut item["owner"]["module_path"],
                &extend(&base, &["owner", "module_path"]),
            );
            trimmer.field(
                &mut item["owner"]["symbol"],
                &extend(&base, &["owner", "symbol"]),
            );
            if item["parser_type"].is_object() {
                for field in ["parser", "schema", "domain_type"] {
                    trimmer.field(
                        &mut item["parser_type"][field],
                        &extend(&base, &["parser_type", field]),
                    );
                }
            }
            if let Some(cases) = item["original_cases"].as_array_mut() {
                for (case_index, case) in cases.iter_mut().enumerate() {
                    trimmer.field(
                        &mut case["location"],
                        &extend(
                            &base,
                            &["original_cases", &case_index.to_string(), "location"],
                        ),
                    );
                }
            }
            if item["verifier"].is_object() {
                trimmer.field(
                    &mut item["verifier"]["command"],
                    &extend(&base, &["verifier", "command"]),
                );
                trimmer.field(
                    &mut item["verifier"]["nondeterminism"]["specification"],
                    &extend(&base, &["verifier", "nondeterminism", "specification"]),
                );
            }
        }
    }
    trimmer
}

/// `buildReconstructionObligationLedgerEvidenceValidated`.
fn build_ledger_evidence(input: &Value) -> Result<Evidence, AnalysisError> {
    let ledger = build_ledger(input).map_err(|rejection| {
        if rejection.unclassified {
            AnalysisError::protocol("Reconstruction obligation ledger generation failed")
        } else {
            rejection.into_input_error(OPERATION)
        }
    })?;
    let limitations: Vec<String> = strings(&ledger, "limitations")
        .into_iter()
        .map(str::to_owned)
        .collect();
    let links: Vec<String> = strings(&ledger, "evidence_links")
        .into_iter()
        .map(str::to_owned)
        .collect();
    let provider = EvidenceProvider::new(
        "rea-javascript-application-workflows",
        "REA JavaScript application workflows",
        Some("1".into()),
    );
    let parameters = json!({
        "ledger_id": ledger["ledger_id"],
        "closure_digest": ledger["closure_digest"],
    });
    let observation = Observation::new(OPERATION, parameters, ledger)
        .predicate("rea.reconstruction-obligation-ledger")
        .raw(Value::Null)
        .confidence("inferred")
        .authority("analyst-inference")
        .limitations(limitations)
        .links(links);
    Evidence::create(None, &provider, observation)
        .map_err(|_| AnalysisError::protocol("Reconstruction obligation ledger generation failed"))
}

/// One generated or reviewed obligation before manifest closure evaluation.
#[derive(Clone)]
struct Candidate {
    /// Every definition field in the obligation schema's order, excluding
    /// `binding`, `status` and `diagnostics`.
    fields: Map<String, Value>,
    definition_count: usize,
    disposition: String,
}

impl Candidate {
    fn id(&self) -> &str {
        text(&self.fields["obligation_id"])
    }
    fn get(&self, key: &str) -> &Value {
        self.fields.get(key).unwrap_or(&Value::Null)
    }
    fn strings(&self, key: &str) -> Vec<&str> {
        strings(self.get(key), "")
    }
    fn origin(&self) -> &str {
        text(self.get("origin"))
    }
}

/// `buildReconstructionObligationLedger`: candidates, then closure.
fn build_ledger(input: &Value) -> Result<Value, Rejection> {
    let bundle_value = &input["evidence_bundle"];
    let authenticated = bundle::authenticate(bundle_value)?;
    let (candidates, generation_limitations) = derive_candidates(
        &authenticated.records,
        &authenticated.by_id,
        input["reviewed_obligations"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default(),
    )?;
    evaluate_ledger(
        candidates,
        &authenticated.records,
        &input["manifest"],
        generation_limitations,
    )
}

/// `deriveReconstructionObligationCandidates`.
fn derive_candidates(
    records: &[Value],
    by_id: &HashMap<String, Value>,
    reviewed: &[Value],
) -> Result<(Vec<Candidate>, Vec<String>), Rejection> {
    let mut candidates: BTreeMap<String, Candidate> = BTreeMap::new();
    let mut limitations = BTreeSet::new();
    for evidence in records {
        derive_application_candidates(evidence, by_id, &mut candidates, &mut limitations)?;
        derive_process_candidate(evidence, &mut candidates, &mut limitations)?;
    }
    for obligation in reviewed {
        add_candidate(&mut candidates, reviewed_candidate(obligation, by_id)?);
    }
    Ok((
        candidates.into_values().collect(),
        limitations.into_iter().collect(),
    ))
}

fn derive_application_candidates(
    evidence: &Value,
    records: &HashMap<String, Value>,
    candidates: &mut BTreeMap<String, Candidate>,
    limitations: &mut BTreeSet<String>,
) -> Result<(), Rejection> {
    let operation = text(&evidence["operation"]);
    if !matches!(
        operation,
        "analyze_javascript_application"
            | "reconcile_javascript_runtime"
            | "project_managed_application_graph"
    ) {
        return Ok(());
    }
    let evidence_id = text(&evidence["evidence_id"]);
    let Some(source) = ledger_sources::parse_application_graph_evidence(evidence) else {
        limitations.insert(format!(
            "Application Evidence {evidence_id} could not generate candidates because it failed graph validation."
        ));
        return Ok(());
    };
    if let Err(message) =
        application_candidates(evidence, records, &source, candidates, limitations)
    {
        limitations.insert(format!(
            "Application Evidence {evidence_id} could not generate candidates: {message}"
        ));
    }
    Ok(())
}

/// The `try` body of `deriveApplicationCandidates`. Like the original, it
/// adds candidates and limitations as it goes, so a later failure keeps the
/// earlier additions.
fn application_candidates(
    evidence: &Value,
    records: &HashMap<String, Value>,
    source: &ApplicationSource<'_>,
    candidates: &mut BTreeMap<String, Candidate>,
    limitations: &mut BTreeSet<String>,
) -> Result<(), String> {
    let graph = source.graph;
    let graph_id = text(&graph["graph_id"]);
    for node in items(graph, "nodes") {
        let kind = text(&node["kind"]);
        let node_id = text(&node["node_id"]);
        let Some(policy) = application_policy(kind) else {
            if kind == "unknown" {
                limitations.insert(format!(
                    "Application graph {graph_id} contains unresolved node {node_id}; reconstruction obligations remain unknown."
                ));
            }
            continue;
        };
        let references = items(node, "observations")
            .iter()
            .map(|observation| {
                graph_reference(
                    evidence,
                    records,
                    &observation["evidence"],
                    format!(
                        "{graph_id}/node/{node_id}/observation/{}",
                        text(&observation["observation_id"])
                    ),
                )
            })
            .collect::<Vec<_>>();
        let title = items(node, "observations")
            .first()
            .and_then(|observation| observation["label"].as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{kind} boundary"));
        add_generated(
            candidates,
            GeneratedInput {
                key: format!("application:{node_id}:{}", policy.family),
                title,
                policy: &policy,
                artifact_sha256: source.root_artifact_sha256.to_owned(),
                application_node_id: Value::String(node_id.to_owned()),
                semantic_node_id: Value::Null,
                location: format!("application-graph:{graph_id}/nodes/{node_id}"),
                authority_references: references,
            },
        )?;
    }
    if let Some(semantic) = source.semantic_graph {
        let semantic_graph_id = text(&semantic["graph_id"]);
        let contexts: HashMap<&str, &Value> = items(semantic, "evidence_contexts")
            .iter()
            .map(|context| (text(&context["context_id"]), context))
            .collect();
        for node in items(semantic, "nodes") {
            let kind = text(&node["kind"]);
            let Some(policy) = semantic_policy(kind) else {
                continue;
            };
            let node_id = text(&node["node_id"]);
            let Some(context) = contexts.get(text(&node["evidence"]["context_id"])) else {
                return Err("Semantic evidence reference names an absent context".into());
            };
            add_generated(
                candidates,
                GeneratedInput {
                    key: format!("semantic:{node_id}:{}", policy.family),
                    title: node["label"]
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| format!("{kind} semantic boundary")),
                    policy: &policy,
                    artifact_sha256: text(&node["identity"]["artifact_sha256"]).to_owned(),
                    application_node_id: items(node, "application_node_ids")
                        .first()
                        .cloned()
                        .unwrap_or(Value::Null),
                    semantic_node_id: Value::String(node_id.to_owned()),
                    location: format!("semantic-graph:{semantic_graph_id}/nodes/{node_id}"),
                    authority_references: vec![graph_reference(
                        evidence,
                        records,
                        context,
                        format!("{semantic_graph_id}/node/{node_id}"),
                    )],
                },
            )?;
        }
    }
    let status = text(&graph["coverage"]["status"]);
    if status != "complete" {
        limitations.insert(format!(
            "Application graph {graph_id} coverage is {status}; omitted candidates remain unknown."
        ));
    }
    Ok(())
}

fn add_generated(
    candidates: &mut BTreeMap<String, Candidate>,
    input: GeneratedInput<'_>,
) -> Result<(), String> {
    add_candidate(candidates, generated_candidate(input)?);
    Ok(())
}

fn derive_process_candidate(
    evidence: &Value,
    candidates: &mut BTreeMap<String, Candidate>,
    limitations: &mut BTreeSet<String>,
) -> Result<(), Rejection> {
    if evidence["operation"] != "capture_process_scenario"
        || evidence["predicate_type"] != "rea.process-capture"
    {
        return Ok(());
    }
    let evidence_id = text(&evidence["evidence_id"]);
    let capture = match ledger_sources::parse_process_capture(&evidence["normalized_result"]) {
        Ok(capture) => capture,
        Err(message) => {
            limitations.insert(format!(
                "Process Evidence {evidence_id} could not generate candidates: {message}"
            ));
            return Ok(());
        }
    };
    let mut observed_cases = vec![
        json!({
            "kind": if capture.exit_code == Some(0.0) { "positive" } else { "negative" },
            "evidence_id": evidence_id,
            "location": "/normalized_result/exit",
        }),
        json!({
            "kind": "teardown",
            "evidence_id": evidence_id,
            "location": "/normalized_result/settlement",
        }),
    ];
    if capture.exit_signal_present || capture.exit_reason != "exited" {
        observed_cases.push(json!({
            "kind": "cancellation",
            "evidence_id": evidence_id,
            "location": "/normalized_result/exit",
        }));
    }
    let Some(executable_sha256) = capture.executable_sha256 else {
        limitations.insert(format!(
            "Process capture {evidence_id} has no validated executable artifact identity; packaged-process lifecycle obligation was not bound to an artifact."
        ));
        return Ok(());
    };
    let obligation_id = obligation_id(&format!(
        "process:{executable_sha256}:{}",
        capture.full_scenario_sha256
    ))?;
    let mut fields = Map::new();
    fields.insert("obligation_id".into(), json!(obligation_id));
    fields.insert("obligation_version".into(), json!(1));
    fields.insert("title".into(), json!("Captured packaged-process lifecycle"));
    fields.insert("origin".into(), json!("generated"));
    fields.insert("application_layer".into(), json!("process"));
    fields.insert("family".into(), json!("packaged-process-lifecycle"));
    fields.insert(
        "target".into(),
        json!({
            "artifact_sha256": executable_sha256,
            "application_node_id": null,
            "semantic_node_id": null,
            "location": format!("/evidence/{evidence_id}/normalized_result"),
        }),
    );
    fields.insert(
        "authority_references".into(),
        json!([{
            "evidence_id": evidence_id,
            "authority": evidence["authority"],
            "state": "observed",
            "location": "/normalized_result",
        }]),
    );
    fields.insert("source_state".into(), json!("observed"));
    fields.insert("observed_cases".into(), Value::Array(observed_cases));
    fields.insert("required".into(), json!(true));
    fields.insert(
        "required_case_kinds".into(),
        json!(["positive", "negative", "cancellation", "teardown"]),
    );
    fields.insert("required_original_authority".into(), json!("process"));
    fields.insert(
        "required_fixture_authority".into(),
        json!("packaged-process"),
    );
    fields.insert(
        "required_verifier_authority".into(),
        json!("packaged-process"),
    );
    fields.insert("requires_parser_type".into(), json!(false));
    fields.insert("dependency_obligation_ids".into(), json!([]));
    fields.insert("residual_unknown_ids".into(), json!([]));
    fields.insert(
        "unavailable_authority".into(),
        json!(
            capture
                .residual_unknowns
                .iter()
                .map(|(scope, reason)| format!("{scope}: {reason}"))
                .collect::<Vec<_>>()
        ),
    );
    fields.insert(
        "required_next_evidence".into(),
        if capture.truncated {
            json!(["Repeat the packaged-process capture without truncation."])
        } else {
            json!([])
        },
    );
    add_candidate(
        candidates,
        Candidate {
            fields,
            definition_count: 1,
            disposition: "active".into(),
        },
    );
    if capture.truncated {
        limitations.insert(format!(
            "Process Evidence {evidence_id} is truncated; absence and upper bounds remain unknown."
        ));
    }
    Ok(())
}

/// `ReconstructionObligationCandidatePolicy`.
struct Policy {
    application_layer: &'static str,
    family: &'static str,
    fixture_authority: &'static str,
    verifier_authority: &'static str,
    original_authority: &'static str,
    cases: &'static [&'static str],
    requires_parser_type: bool,
}

const fn policy(
    layer: &'static str,
    family: &'static str,
    authority: &'static str,
    cases: &'static [&'static str],
) -> Policy {
    Policy {
        application_layer: layer,
        family,
        fixture_authority: authority,
        verifier_authority: authority,
        original_authority: "runtime",
        cases,
        requires_parser_type: false,
    }
}

const fn parser_policy(
    layer: &'static str,
    family: &'static str,
    authority: &'static str,
) -> Policy {
    let mut policy = policy(
        layer,
        family,
        authority,
        &["positive", "negative", "malformed"],
    );
    policy.requires_parser_type = true;
    policy
}

const fn native_policy(family: &'static str) -> Policy {
    Policy {
        application_layer: "native-abi",
        family,
        fixture_authority: "native-abi",
        verifier_authority: "native-abi",
        original_authority: "static",
        cases: &["positive", "negative"],
        requires_parser_type: false,
    }
}

/// `applicationObligationPolicy`.
fn application_policy(kind: &str) -> Option<Policy> {
    Some(match kind {
        "package" => policy(
            "packaging",
            "package-lifecycle",
            "packaged-process",
            &["positive", "negative", "teardown"],
        ),
        "installer" => policy(
            "packaging",
            "installer",
            "packaged-process",
            &["positive", "negative", "teardown"],
        ),
        "context-bridge-api" => policy(
            "electron",
            "context-bridge",
            "renderer",
            &["positive", "negative", "malformed"],
        ),
        "ipc-channel" | "ipc-handler" => policy(
            "electron",
            "ipc",
            "renderer",
            &["positive", "negative", "malformed"],
        ),
        "endpoint" => policy(
            "protocol",
            "endpoint",
            "protocol",
            &["positive", "negative", "malformed"],
        ),
        "storage" => policy(
            "persistence",
            "persistence",
            "integration",
            &["positive", "negative", "malformed"],
        ),
        "worker" | "service-worker" => policy(
            "process",
            "worker-lifecycle",
            "packaged-process",
            &["positive", "cancellation", "teardown"],
        ),
        "native-addon" => native_policy("native-addon"),
        "native-export" => native_policy("native-export"),
        "managed-pinvoke-import" => native_policy("managed-pinvoke"),
        "managed-native-implementation" => native_policy("managed-native"),
        _ => return None,
    })
}

/// `semanticObligationPolicy`.
fn semantic_policy(kind: &str) -> Option<Policy> {
    Some(match kind {
        "child-process" => policy(
            "process",
            "child-process",
            "packaged-process",
            &["positive", "negative", "cancellation", "teardown"],
        ),
        "stdio" => policy(
            "process",
            "stdio",
            "packaged-process",
            &["positive", "negative", "teardown"],
        ),
        "signal" => policy(
            "process",
            "signal",
            "packaged-process",
            &["positive", "cancellation", "teardown"],
        ),
        "config-source" => parser_policy("cli", "configuration", "integration"),
        "request" => parser_policy("protocol", "request", "protocol"),
        "response" => parser_policy("protocol", "response", "protocol"),
        "boundary" => parser_policy("application", "parser-boundary", "integration"),
        "resource" => policy(
            "persistence",
            "resource-lifecycle",
            "integration",
            &["positive", "negative", "teardown"],
        ),
        "event" => policy(
            "runtime",
            "event",
            "packaged-process",
            &["positive", "negative", "cancellation"],
        ),
        "timer" => policy(
            "runtime",
            "timer",
            "packaged-process",
            &["positive", "cancellation", "teardown"],
        ),
        "promise" => policy(
            "runtime",
            "promise-ownership",
            "packaged-process",
            &["positive", "negative", "cancellation"],
        ),
        "task" => policy(
            "runtime",
            "task-lifecycle",
            "packaged-process",
            &["positive", "cancellation", "teardown"],
        ),
        _ => return None,
    })
}

struct GeneratedInput<'a> {
    key: String,
    title: String,
    policy: &'a Policy,
    artifact_sha256: String,
    application_node_id: Value,
    semantic_node_id: Value,
    location: String,
    authority_references: Vec<Value>,
}

/// `generatedCandidate`.
fn generated_candidate(input: GeneratedInput<'_>) -> Result<Candidate, String> {
    let policy = input.policy;
    let source_state = source_state(&input.authority_references);
    let obligation_id =
        obligation_id(&input.key).map_err(|rejection| rejection.messages.join("; "))?;
    let mut fields = Map::new();
    fields.insert("obligation_id".into(), json!(obligation_id));
    fields.insert("obligation_version".into(), json!(1));
    fields.insert("title".into(), json!(input.title));
    fields.insert("origin".into(), json!("generated"));
    fields.insert("application_layer".into(), json!(policy.application_layer));
    fields.insert("family".into(), json!(policy.family));
    fields.insert(
        "target".into(),
        json!({
            "artifact_sha256": input.artifact_sha256,
            "application_node_id": input.application_node_id,
            "semantic_node_id": input.semantic_node_id,
            "location": input.location,
        }),
    );
    fields.insert(
        "authority_references".into(),
        Value::Array(input.authority_references),
    );
    fields.insert("source_state".into(), json!(source_state));
    fields.insert("observed_cases".into(), json!([]));
    fields.insert("required".into(), json!(true));
    fields.insert("required_case_kinds".into(), json!(policy.cases));
    fields.insert(
        "required_original_authority".into(),
        json!(policy.original_authority),
    );
    fields.insert(
        "required_fixture_authority".into(),
        json!(policy.fixture_authority),
    );
    fields.insert(
        "required_verifier_authority".into(),
        json!(policy.verifier_authority),
    );
    fields.insert(
        "requires_parser_type".into(),
        json!(policy.requires_parser_type),
    );
    fields.insert("dependency_obligation_ids".into(), json!([]));
    fields.insert("residual_unknown_ids".into(), json!([]));
    fields.insert("unavailable_authority".into(), json!([]));
    fields.insert(
        "required_next_evidence".into(),
        json!([format!(
            "Obtain {} authority for this finite {} claim.",
            policy.original_authority, policy.family
        )]),
    );
    Ok(Candidate {
        fields,
        definition_count: 1,
        disposition: "active".into(),
    })
}

/// `reviewedCandidate`.
fn reviewed_candidate(
    obligation: &Value,
    records: &HashMap<String, Value>,
) -> Result<Candidate, Rejection> {
    let mut references = Vec::new();
    for evidence_id in strings(obligation, "review_evidence_ids") {
        let Some(evidence) = records.get(evidence_id) else {
            return Err(Rejection::type_error(format!(
                "Reviewed obligation Evidence is missing: {evidence_id}"
            )));
        };
        references.push(json!({
            "evidence_id": evidence_id,
            "authority": evidence["authority"],
            "state": reviewed_evidence_state(evidence),
            "location": format!("/evidence/{evidence_id}"),
        }));
    }
    let mut fields = Map::new();
    for key in [
        "obligation_id",
        "obligation_version",
        "title",
        "origin",
        "application_layer",
        "family",
        "target",
        "authority_references",
        "source_state",
        "observed_cases",
        "required",
        "required_case_kinds",
        "required_original_authority",
        "required_fixture_authority",
        "required_verifier_authority",
        "requires_parser_type",
        "dependency_obligation_ids",
        "residual_unknown_ids",
        "unavailable_authority",
        "required_next_evidence",
    ] {
        let value = match key {
            "origin" => json!("reviewed"),
            "authority_references" => Value::Array(references.clone()),
            "source_state" => json!("reviewed"),
            "observed_cases" => json!([]),
            _ => obligation[key].clone(),
        };
        fields.insert(key.into(), value);
    }
    Ok(Candidate {
        fields,
        definition_count: 1,
        disposition: text(&obligation["disposition"]).to_owned(),
    })
}

/// `graphReference`.
fn graph_reference(
    envelope: &Value,
    records: &HashMap<String, Value>,
    graph_evidence: &Value,
    location: String,
) -> Value {
    let linked_id = strings(graph_evidence, "evidence_ids")
        .into_iter()
        .find(|id| records.contains_key(*id))
        .unwrap_or_else(|| text(&envelope["evidence_id"]));
    let linked = records.get(linked_id).unwrap_or(envelope);
    let authority = text(&graph_evidence["authority"]);
    let state = text(&graph_evidence["state"]);
    let runtime = matches!(authority, "passive-cdp-runtime" | "controlled-replay");
    let reference_state = if runtime && state == "observed" {
        "observed"
    } else if state == "unknown" || state == "unavailable" {
        "unknown"
    } else {
        "candidate"
    };
    json!({
        "evidence_id": linked["evidence_id"],
        "authority": linked["authority"],
        "state": reference_state,
        "location": location,
    })
}

/// `reviewedEvidenceState`.
fn reviewed_evidence_state(evidence: &Value) -> &'static str {
    if evidence["operation"] == "capture_process_scenario"
        && evidence["predicate_type"] == "rea.process-capture"
        && evidence["confidence"] == "observed"
    {
        return "observed";
    }
    if evidence["authority"] == "external-service" && evidence["confidence"] == "observed" {
        return "observed";
    }
    if evidence["authority"] == "shipped-artifact" {
        return "candidate";
    }
    "reviewed"
}

/// `addCandidate`: merge one claim seen by several records.
fn add_candidate(candidates: &mut BTreeMap<String, Candidate>, candidate: Candidate) {
    let id = candidate.id().to_owned();
    let Some(current) = candidates.get_mut(&id) else {
        candidates.insert(id, candidate);
        return;
    };
    let references: Vec<Value> = values(current.get("authority_references"))
        .iter()
        .chain(values(candidate.get("authority_references")))
        .cloned()
        .collect();
    let merged_references = unique_by(references.clone(), |reference| {
        format!(
            "{}:{}:{}",
            text(&reference["evidence_id"]),
            text(&reference["state"]),
            text(&reference["location"])
        )
    });
    let cases = unique_by(
        values(current.get("observed_cases"))
            .iter()
            .chain(values(candidate.get("observed_cases")))
            .cloned()
            .collect(),
        |item| {
            format!(
                "{}:{}:{}",
                text(&item["kind"]),
                text(&item["evidence_id"]),
                text(&item["location"])
            )
        },
    );
    let unavailable = unique_by(
        values(current.get("unavailable_authority"))
            .iter()
            .chain(values(candidate.get("unavailable_authority")))
            .cloned()
            .collect(),
        |item| text(item).to_owned(),
    );
    let next = unique_by(
        values(current.get("required_next_evidence"))
            .iter()
            .chain(values(candidate.get("required_next_evidence")))
            .cloned()
            .collect(),
        |item| text(item).to_owned(),
    );
    let both_generated = current.origin() == "generated" && candidate.origin() == "generated";
    current.fields.insert(
        "authority_references".into(),
        Value::Array(merged_references),
    );
    current
        .fields
        .insert("observed_cases".into(), Value::Array(cases));
    current
        .fields
        .insert("source_state".into(), json!(source_state(&references)));
    current
        .fields
        .insert("unavailable_authority".into(), Value::Array(unavailable));
    current
        .fields
        .insert("required_next_evidence".into(), Value::Array(next));
    if !both_generated {
        current.definition_count += candidate.definition_count;
    }
}

/// `sourceState`.
fn source_state(references: &[Value]) -> &'static str {
    let has = |state: &str| {
        references
            .iter()
            .any(|reference| reference["state"] == state)
    };
    if has("observed") {
        "observed"
    } else if has("candidate") {
        "candidate"
    } else if has("reviewed") {
        "reviewed"
    } else {
        "unknown"
    }
}

/// `uniqueBy`: last value per key, ordered by key.
fn unique_by(values: Vec<Value>, key: impl Fn(&Value) -> String) -> Vec<Value> {
    let mut unique: BTreeMap<String, Value> = BTreeMap::new();
    for value in values {
        unique.insert(key(&value), value);
    }
    unique.into_values().collect()
}

/// `obligationId(key)`.
fn obligation_id(key: &str) -> Result<String, Rejection> {
    canonical_json::digest(&json!({ "schema": "ReconstructionObligation", "key": key }))
        .map(|digest| format!("obl_{digest}"))
        .map_err(|_| Rejection::unclassified("Reconstruction obligation key is not canonical JSON"))
}

/// Read-only evaluation lookups (`EvaluationContext`).
struct EvaluationContext<'a> {
    candidate_ids: HashSet<String>,
    evidence: HashMap<&'a str, &'a Value>,
    bindings: HashMap<&'a str, Vec<&'a Value>>,
    contradictions: HashMap<&'a str, Vec<&'a str>>,
}

/// `evaluateReconstructionObligationLedger`.
fn evaluate_ledger(
    candidates: Vec<Candidate>,
    records: &[Value],
    manifest: &Value,
    generation_limitations: Vec<String>,
) -> Result<Value, Rejection> {
    let candidate_ids: HashSet<String> = candidates
        .iter()
        .map(|candidate| candidate.id().to_owned())
        .collect();
    let orphans: BTreeSet<&str> = items(manifest, "bindings")
        .iter()
        .chain(items(manifest, "contradictions"))
        .map(|entry| text(&entry["obligation_id"]))
        .filter(|id| !candidate_ids.contains(*id))
        .collect();
    let mut bindings: HashMap<&str, Vec<&Value>> = HashMap::new();
    for binding in items(manifest, "bindings") {
        bindings
            .entry(text(&binding["obligation_id"]))
            .or_default()
            .push(binding);
    }
    let mut contradictions: HashMap<&str, Vec<&str>> = HashMap::new();
    for contradiction in items(manifest, "contradictions") {
        contradictions
            .entry(text(&contradiction["obligation_id"]))
            .or_default()
            .extend(strings(contradiction, "evidence_ids"));
    }
    let context = EvaluationContext {
        candidate_ids,
        evidence: records
            .iter()
            .map(|record| (text(&record["evidence_id"]), record))
            .collect(),
        bindings,
        contradictions,
    };
    let evaluated: Vec<Map<String, Value>> = candidates
        .iter()
        .map(|candidate| evaluate_obligation(candidate, &context))
        .collect();
    let obligations = apply_dependency_diagnostics(evaluated, &context);
    let ownership_graph = ownership_graph(&obligations)?;
    let dependency_graph = dependency_graph(&obligations)?;
    let evidence_links = ledger_evidence_links(&obligations, manifest);
    let mut limitations: BTreeSet<String> = generation_limitations.into_iter().collect();
    if candidates.is_empty() {
        limitations.insert(
            "No reconstruction obligations were derived; closure cannot be claimed.".into(),
        );
    }
    if !orphans.is_empty() {
        limitations.insert(format!(
            "Manifest entries reference unknown obligations: {}.",
            orphans.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    let limitations: Vec<String> = limitations.into_iter().collect();
    let obligations: Vec<Value> = obligations.into_iter().map(Value::Object).collect();
    let coverage = json!({ "status": if limitations.is_empty() { "complete" } else { "partial" } });
    let summary = summarize(&obligations);
    let reports = reports(&obligations);
    let status = ledger_status(&obligations, &limitations);
    let closure_digest = digest(&json!({
        "schema": "ReconstructionObligationClosure",
        "status": status,
        "coverage": coverage,
        "summary": summary,
        "reports": reports,
        "ownership_graph": ownership_graph,
        "dependency_graph": dependency_graph,
        "obligations": obligations,
        "evidence_links": evidence_links,
        "limitations": limitations,
    }))?;
    let ledger_id = digest(&json!({
        "schema": "ReconstructionObligationLedger",
        "evidence_ids": records.iter().map(|record| record["evidence_id"].clone()).collect::<Vec<_>>(),
        "obligation_ids": obligations.iter().map(|obligation| obligation["obligation_id"].clone()).collect::<Vec<_>>(),
        "closure_digest": closure_digest,
    }))?;
    Ok(json!({
        "schema": "ReconstructionObligationLedger",
        "ledger_id": format!("rol_{ledger_id}"),
        "closure_digest": closure_digest,
        "status": status,
        "coverage": coverage,
        "summary": summary,
        "reports": reports,
        "ownership_graph": ownership_graph,
        "dependency_graph": dependency_graph,
        "obligations": obligations,
        "evidence_links": evidence_links,
        "limitations": limitations,
    }))
}

fn diagnostic(diagnostics: &mut Vec<Value>, code: &str, detail: impl Into<String>) {
    diagnostics.push(json!({ "code": code, "detail": detail.into() }));
}

/// `evaluateObligation`.
fn evaluate_obligation(
    candidate: &Candidate,
    context: &EvaluationContext<'_>,
) -> Map<String, Value> {
    let bindings = context
        .bindings
        .get(candidate.id())
        .cloned()
        .unwrap_or_default();
    let binding = (bindings.len() == 1).then(|| bindings[0]);
    let mut diagnostics = Vec::new();
    if candidate.definition_count > 1 {
        diagnostic(
            &mut diagnostics,
            "duplicate-definition",
            "Multiple candidate definitions share this obligation ID.",
        );
    }
    if bindings.is_empty() {
        diagnostic(
            &mut diagnostics,
            "missing-owner",
            "No reconstruction manifest binding owns this obligation.",
        );
    }
    if bindings.len() > 1 {
        diagnostic(
            &mut diagnostics,
            "ambiguous-owner",
            "Multiple reconstruction manifest bindings claim this obligation.",
        );
    }
    if let Some(binding) = binding {
        evaluate_binding(candidate, binding, context, &mut diagnostics);
    }
    let original_cases = original_cases_for(candidate, binding);
    original_case_diagnostics(candidate, &original_cases, context, &mut diagnostics);
    evaluate_authority(candidate, &original_cases, context, &mut diagnostics);
    match candidate.disposition.as_str() {
        "blocked" => diagnostic(
            &mut diagnostics,
            "blocked",
            "Reviewed disposition marks this obligation blocked.",
        ),
        "out-of-scope" => diagnostic(
            &mut diagnostics,
            "out-of-scope",
            "Reviewed disposition marks this obligation out of scope; it remains visible.",
        ),
        _ => {}
    }
    let contradiction_ids = context
        .contradictions
        .get(candidate.id())
        .cloned()
        .unwrap_or_default();
    if !contradiction_ids.is_empty() {
        let missing: Vec<&str> = contradiction_ids
            .iter()
            .copied()
            .filter(|id| !context.evidence.contains_key(id))
            .collect();
        if missing.is_empty() {
            diagnostic(
                &mut diagnostics,
                "contradiction",
                "Authenticated contradictory Evidence reopens this obligation.",
            );
        } else {
            diagnostic(
                &mut diagnostics,
                "contradiction-evidence-missing",
                format!(
                    "Contradiction references missing Evidence: {}.",
                    missing.join(", ")
                ),
            );
        }
    }
    for unknown_id in candidate.strings("residual_unknown_ids") {
        diagnostic(
            &mut diagnostics,
            "residual-unknown",
            format!("Residual unknown remains visible: {unknown_id}."),
        );
    }
    for unavailable in candidate.strings("unavailable_authority") {
        diagnostic(&mut diagnostics, "unavailable-authority", unavailable);
    }
    let status = obligation_status(binding.is_some(), &diagnostics);
    let mut obligation = Map::new();
    for (key, value) in &candidate.fields {
        let value = if key == "observed_cases" {
            Value::Array(original_cases.clone())
        } else {
            value.clone()
        };
        obligation.insert(key.clone(), value);
    }
    obligation.insert("binding".into(), binding.cloned().unwrap_or(Value::Null));
    obligation.insert("status".into(), json!(status));
    obligation.insert(
        "diagnostics".into(),
        Value::Array(unique_diagnostics(diagnostics)),
    );
    obligation
}

fn evaluate_binding(
    candidate: &Candidate,
    binding: &Value,
    context: &EvaluationContext<'_>,
    diagnostics: &mut Vec<Value>,
) {
    let required_fixture = text(candidate.get("required_fixture_authority"));
    if candidate.get("requires_parser_type") == &Value::Bool(true)
        && binding["parser_type"].is_null()
    {
        diagnostic(
            diagnostics,
            "missing-parser-type",
            "This boundary requires an explicit parser, schema, and domain type.",
        );
    }
    for case_kind in candidate.strings("required_case_kinds") {
        let fixtures: Vec<&Value> = items(binding, "fixtures")
            .iter()
            .filter(|fixture| fixture["case_kind"] == case_kind)
            .collect();
        if fixtures.is_empty() {
            diagnostic(
                diagnostics,
                "missing-case",
                format!("Required {case_kind} fixture is missing."),
            );
            continue;
        }
        for fixture in &fixtures {
            for evidence_id in strings(fixture, "evidence_ids") {
                if !context.evidence.contains_key(evidence_id) {
                    diagnostic(
                        diagnostics,
                        "missing-case",
                        format!(
                            "{case_kind} fixture {} references Evidence {evidence_id}, which is absent from the bundle.",
                            text(&fixture["fixture_id"])
                        ),
                    );
                }
            }
        }
        let satisfied = fixtures.iter().any(|fixture| {
            let authority = text(&fixture["authority"]);
            proof_authority_satisfies(authority, required_fixture)
                && strings(fixture, "evidence_ids").iter().all(|id| {
                    context.evidence.get(id).is_some_and(|evidence| {
                        evidence_supports_proof(
                            evidence,
                            authority,
                            &[
                                ("obligation_ids", Some(candidate.id())),
                                ("fixture_ids", fixture["fixture_id"].as_str()),
                                ("case_kinds", fixture["case_kind"].as_str()),
                                ("verifier_ids", None),
                                ("claim_ids", None),
                            ],
                        )
                    })
                })
        });
        if !satisfied {
            diagnostic(
                diagnostics,
                "weak-fixture-authority",
                format!(
                    "{case_kind} fixture lacks {required_fixture} authority or authenticated Evidence."
                ),
            );
        }
    }
    let verifier = &binding["verifier"];
    if verifier.is_null() {
        diagnostic(
            diagnostics,
            "missing-verifier",
            "No verifier claim is bound to this obligation.",
        );
        return;
    }
    if !strings(verifier, "enumerated_obligation_ids").contains(&candidate.id()) {
        diagnostic(
            diagnostics,
            "verifier-does-not-enumerate",
            "The verifier claim does not enumerate this obligation ID.",
        );
    }
    let result = context.evidence.get(text(&verifier["result_evidence_id"]));
    if result.is_none() {
        diagnostic(
            diagnostics,
            "missing-verifier-result",
            "The latest verifier result Evidence is absent from the bundle.",
        );
    }
    let required_verifier = text(candidate.get("required_verifier_authority"));
    let authority = text(&verifier["authority"]);
    if !proof_authority_satisfies(authority, required_verifier)
        || result.is_some_and(|evidence| {
            !evidence_supports_proof(
                evidence,
                authority,
                &[
                    ("obligation_ids", Some(candidate.id())),
                    ("fixture_ids", None),
                    ("case_kinds", None),
                    ("verifier_ids", verifier["verifier_id"].as_str()),
                    ("claim_ids", verifier["claim_id"].as_str()),
                ],
            )
        })
    {
        diagnostic(
            diagnostics,
            "weak-verifier-authority",
            format!("Verifier authority does not satisfy {required_verifier}."),
        );
    }
    let status = text(&verifier["status"]);
    if status != "pass" {
        diagnostic(
            diagnostics,
            "verifier-failed",
            format!("Latest verifier status is {status}."),
        );
    }
}

/// `originalCasesFor`: generated and manifest-supplied observations, by key.
fn original_cases_for(candidate: &Candidate, binding: Option<&Value>) -> Vec<Value> {
    let cases: Vec<Value> = values(candidate.get("observed_cases"))
        .iter()
        .chain(
            binding
                .map(|binding| items(binding, "original_cases"))
                .unwrap_or_default(),
        )
        .cloned()
        .collect();
    unique_by(cases, |case| {
        format!(
            "{}:{}:{}",
            text(&case["kind"]),
            text(&case["evidence_id"]),
            text(&case["location"])
        )
    })
}

/// `originalCaseDiagnostics`.
fn original_case_diagnostics(
    candidate: &Candidate,
    original_cases: &[Value],
    context: &EvaluationContext<'_>,
    diagnostics: &mut Vec<Value>,
) {
    let required = text(candidate.get("required_original_authority"));
    for case_kind in candidate.strings("required_case_kinds") {
        let cases: Vec<&Value> = original_cases
            .iter()
            .filter(|case| case["kind"] == case_kind)
            .collect();
        if cases.is_empty() {
            diagnostic(
                diagnostics,
                "missing-original-case",
                format!("Original {case_kind} behavior has not been observed."),
            );
            continue;
        }
        for case in &cases {
            let evidence_id = text(&case["evidence_id"]);
            if !context.evidence.contains_key(evidence_id) {
                diagnostic(
                    diagnostics,
                    "missing-original-case",
                    format!(
                        "Original {case_kind} case references Evidence {evidence_id}, which is absent from the bundle."
                    ),
                );
            }
        }
        if !cases.iter().any(|case| {
            context
                .evidence
                .get(text(&case["evidence_id"]))
                .is_some_and(|evidence| evidence_supports_original(evidence, required))
        }) {
            diagnostic(
                diagnostics,
                "weak-original-case-authority",
                format!("Original {case_kind} behavior lacks {required} Evidence."),
            );
        }
    }
}

/// `evaluateAuthority`.
fn evaluate_authority(
    candidate: &Candidate,
    original_cases: &[Value],
    context: &EvaluationContext<'_>,
    diagnostics: &mut Vec<Value>,
) {
    let required = text(candidate.get("required_original_authority"));
    let reference_satisfied =
        values(candidate.get("authority_references"))
            .iter()
            .any(|reference| {
                let state = text(&reference["state"]);
                context
                    .evidence
                    .get(text(&reference["evidence_id"]))
                    .is_some_and(|evidence| {
                        (if required == "static" {
                            matches!(state, "candidate" | "observed")
                        } else {
                            state == "observed"
                        }) && evidence_supports_original(evidence, required)
                    })
            });
    let case_satisfied = original_cases.iter().any(|case| {
        context
            .evidence
            .get(text(&case["evidence_id"]))
            .is_some_and(|evidence| evidence_supports_original(evidence, required))
    });
    if !(reference_satisfied || case_satisfied) {
        diagnostic(
            diagnostics,
            "static-only",
            format!("No {required} authority characterizes the original finite behavior."),
        );
    }
}

/// `proofAuthoritySatisfies(actual, required)`.
fn proof_authority_satisfies(actual: &str, required: &str) -> bool {
    let accepted: &[&str] = match required {
        "unit" => &[
            "unit",
            "integration",
            "protocol",
            "renderer",
            "packaged-process",
            "native-abi",
            "live-observation",
            "external",
        ],
        "integration" => &[
            "integration",
            "protocol",
            "renderer",
            "packaged-process",
            "native-abi",
            "live-observation",
        ],
        "protocol" => &["protocol", "packaged-process", "live-observation"],
        "renderer" => &["renderer", "packaged-process", "live-observation"],
        "packaged-process" => &["packaged-process", "live-observation"],
        "native-abi" => &["native-abi"],
        "live-observation" => &["live-observation"],
        "external" => &["external"],
        _ => &[],
    };
    accepted.contains(&actual)
}

/// `evidenceAuthoritySupportsProof`.
fn evidence_supports_proof(
    evidence: &Value,
    authority: &str,
    expected: &[(&str, Option<&str>)],
) -> bool {
    let accepted: &[&str] = match authority {
        "unit" | "native-abi" => &["shipped-artifact", "controlled-replay"],
        "integration" | "packaged-process" => &["controlled-replay"],
        "protocol" | "renderer" | "live-observation" => &["controlled-replay", "external-service"],
        "external" => &["external-service"],
        _ => &[],
    };
    if evidence["confidence"] != "observed"
        || !accepted.contains(&text(&evidence["authority"]))
        || evidence["predicate_type"] != "rea.reconstruction-proof"
        || evidence["operation"] != "verify_reconstruction_obligations"
    {
        return false;
    }
    let result = &evidence["normalized_result"];
    if !result.is_object() {
        return false;
    }
    result["passed"] == Value::Bool(true)
        && expected.iter().all(|(key, value)| match value {
            None => true,
            Some(value) => result[*key]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(value))),
        })
}

/// `evidenceSupportsOriginalAuthority`.
fn evidence_supports_original(evidence: &Value, authority: &str) -> bool {
    if evidence["confidence"] != "observed" {
        return false;
    }
    let evidence_authority = text(&evidence["authority"]);
    match authority {
        "static" => evidence_authority == "shipped-artifact",
        "runtime" => matches!(evidence_authority, "controlled-replay" | "external-service"),
        "process" => {
            evidence["operation"] == "capture_process_scenario"
                && evidence["predicate_type"] == "rea.process-capture"
        }
        _ => evidence_authority == "external-service",
    }
}

/// `uniqueObligationDiagnostics`: last per `code:detail`, ordered by key.
fn unique_diagnostics(diagnostics: Vec<Value>) -> Vec<Value> {
    unique_by(diagnostics, |item| {
        format!("{}:{}", text(&item["code"]), text(&item["detail"]))
    })
}

fn has_diagnostic(diagnostics: &[Value], code: &str) -> bool {
    diagnostics.iter().any(|item| item["code"] == code)
}

/// `obligationStatus`.
fn obligation_status(bound: bool, diagnostics: &[Value]) -> &'static str {
    if has_diagnostic(diagnostics, "out-of-scope") {
        "out-of-scope"
    } else if has_diagnostic(diagnostics, "blocked") {
        "blocked"
    } else if has_diagnostic(diagnostics, "contradiction") {
        "contradicted"
    } else if has_diagnostic(diagnostics, "duplicate-definition")
        || has_diagnostic(diagnostics, "residual-unknown")
        || has_diagnostic(diagnostics, "unavailable-authority")
    {
        "unknown"
    } else if !bound {
        "unowned"
    } else if diagnostics.is_empty() {
        "verified"
    } else {
        "implemented"
    }
}

/// `applyDependencyDiagnostics`: propagate open dependencies to a fixpoint.
fn apply_dependency_diagnostics(
    obligations: Vec<Map<String, Value>>,
    context: &EvaluationContext<'_>,
) -> Vec<Map<String, Value>> {
    let passes = obligations.len();
    let mut evaluated = obligations;
    for _ in 0..passes {
        let statuses: HashMap<String, String> = evaluated
            .iter()
            .map(|obligation| {
                (
                    text(&obligation["obligation_id"]).to_owned(),
                    text(&obligation["status"]).to_owned(),
                )
            })
            .collect();
        let mut changed = false;
        for obligation in &mut evaluated {
            let mut diagnostics = values(&obligation["diagnostics"]).to_vec();
            for dependency in strings(&obligation["dependency_obligation_ids"], "") {
                let missing = !context.candidate_ids.contains(dependency);
                if missing || statuses.get(dependency).map(String::as_str) != Some("verified") {
                    diagnostic(
                        &mut diagnostics,
                        if missing {
                            "dependency-missing"
                        } else {
                            "dependency-open"
                        },
                        format!(
                            "Dependency obligation is {}: {dependency}.",
                            if missing { "missing" } else { "not verified" }
                        ),
                    );
                }
            }
            let normalized = unique_diagnostics(diagnostics);
            let status = text(&obligation["status"]).to_owned();
            let next = if (has_diagnostic(&normalized, "dependency-missing")
                || has_diagnostic(&normalized, "dependency-open"))
                && !matches!(status.as_str(), "contradicted" | "out-of-scope")
            {
                "blocked".to_owned()
            } else {
                status.clone()
            };
            changed |= next != status;
            obligation.insert("status".into(), json!(next));
            obligation.insert("diagnostics".into(), Value::Array(normalized));
        }
        if !changed {
            break;
        }
    }
    evaluated
}

/// `obligationEdgeOrder`: code-point order of canonical JSON.
fn edge_order(edges: &mut [Value]) -> Result<(), Rejection> {
    let mut keyed = Vec::with_capacity(edges.len());
    for edge in edges.iter() {
        keyed.push((canonical(edge)?, edge.clone()));
    }
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    for (slot, (_, edge)) in edges.iter_mut().zip(keyed) {
        *slot = edge;
    }
    Ok(())
}

/// `reconstructionObligationOwnershipGraph`.
fn ownership_graph(obligations: &[Map<String, Value>]) -> Result<Vec<Value>, Rejection> {
    let mut edges: Vec<Value> = obligations
        .iter()
        .filter(|obligation| !obligation["binding"].is_null())
        .map(|obligation| {
            json!({
                "obligation_id": obligation["obligation_id"],
                "module_path": obligation["binding"]["owner"]["module_path"],
                "symbol": obligation["binding"]["owner"]["symbol"],
            })
        })
        .collect();
    edge_order(&mut edges)?;
    Ok(edges)
}

/// `reconstructionObligationDependencyGraph`.
fn dependency_graph(obligations: &[Map<String, Value>]) -> Result<Vec<Value>, Rejection> {
    let mut edges: Vec<Value> = obligations
        .iter()
        .flat_map(|obligation| {
            strings(&obligation["dependency_obligation_ids"], "")
                .into_iter()
                .map(|dependency| {
                    json!({
                        "obligation_id": obligation["obligation_id"],
                        "depends_on_obligation_id": dependency,
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect();
    edge_order(&mut edges)?;
    Ok(edges)
}

/// `reconstructionObligationEvidenceIds` (unsorted, with duplicates).
fn obligation_evidence_ids(obligation: &Map<String, Value>) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    let mut push = |value: &Value| ids.push(text(value).to_owned());
    for reference in values(&obligation["authority_references"]) {
        push(&reference["evidence_id"]);
    }
    for case in values(&obligation["observed_cases"]) {
        push(&case["evidence_id"]);
    }
    let binding = &obligation["binding"];
    if !binding.is_null() {
        binding_evidence_ids(binding, &mut push);
    }
    ids
}

fn binding_evidence_ids(binding: &Value, push: &mut impl FnMut(&Value)) {
    for case in items(binding, "original_cases") {
        push(&case["evidence_id"]);
    }
    for fixture in items(binding, "fixtures") {
        for id in items(fixture, "evidence_ids") {
            push(id);
        }
    }
    if !binding["verifier"].is_null() {
        push(&binding["verifier"]["result_evidence_id"]);
    }
}

/// `obligationLedgerEvidenceLinks`.
fn ledger_evidence_links(obligations: &[Map<String, Value>], manifest: &Value) -> Vec<String> {
    let mut links: BTreeSet<String> = obligations
        .iter()
        .flat_map(obligation_evidence_ids)
        .collect();
    let mut push = |value: &Value| {
        links.insert(text(value).to_owned());
    };
    for binding in items(manifest, "bindings") {
        binding_evidence_ids(binding, &mut push);
    }
    for contradiction in items(manifest, "contradictions") {
        for id in items(contradiction, "evidence_ids") {
            push(id);
        }
    }
    links.into_iter().collect()
}

/// `summarizeReconstructionObligations`.
fn summarize(obligations: &[Value]) -> Value {
    let count_by = |field: &str, keys: &[&str]| -> Vec<Value> {
        keys.iter()
            .map(|key| {
                json!({
                    "key": key,
                    "count": obligations.iter().filter(|obligation| obligation[field] == *key).count(),
                })
            })
            .collect()
    };
    json!({
        "total": obligations.len(),
        "required": obligations.iter().filter(|obligation| obligation["required"] == true).count(),
        "verified": obligations.iter().filter(|obligation| obligation["status"] == "verified").count(),
        "required_open": obligations
            .iter()
            .filter(|obligation| obligation["required"] == true && obligation["status"] != "verified")
            .count(),
        "by_status": count_by(
            "status",
            &["unowned", "characterized", "implemented", "verified", "contradicted", "blocked", "out-of-scope", "unknown"],
        ),
        "by_application_layer": count_by(
            "application_layer",
            &["cli", "protocol", "electron", "persistence", "process", "runtime", "packaging", "native-abi", "application", "other"],
        ),
        "by_evidence_authority": count_by("source_state", &["candidate", "observed", "reviewed", "unknown"]),
    })
}

/// `reconstructionObligationReports`.
fn reports(obligations: &[Value]) -> Value {
    let with = |code: &str| -> Vec<String> {
        let mut ids: Vec<String> = obligations
            .iter()
            .filter(|obligation| has_diagnostic(values(&obligation["diagnostics"]), code))
            .map(|obligation| text(&obligation["obligation_id"]).to_owned())
            .collect();
        ids.sort();
        ids
    };
    let unknowns: BTreeSet<String> = obligations
        .iter()
        .flat_map(|obligation| strings(&obligation["residual_unknown_ids"], ""))
        .map(str::to_owned)
        .collect();
    json!({
        "missing_owner_obligation_ids": with("missing-owner"),
        "missing_verifier_obligation_ids": with("missing-verifier"),
        "contradicted_obligation_ids": with("contradiction"),
        "residual_unknown_ids": unknowns.into_iter().collect::<Vec<_>>(),
    })
}

/// `reconstructionObligationLedgerStatus`.
fn ledger_status(obligations: &[Value], limitations: &[String]) -> &'static str {
    if obligations.is_empty() {
        return "unknown";
    }
    let open: Vec<&Value> = obligations
        .iter()
        .filter(|obligation| obligation["required"] == true && obligation["status"] != "verified")
        .collect();
    if open.iter().any(|obligation| {
        obligation["status"] == "contradicted"
            || has_diagnostic(values(&obligation["diagnostics"]), "verifier-failed")
    }) {
        return "failed";
    }
    if !limitations.is_empty() {
        return "unknown";
    }
    if open
        .iter()
        .any(|obligation| obligation["status"] == "unknown")
    {
        return "unknown";
    }
    if open.is_empty() { "ready" } else { "open" }
}

fn canonical(value: &Value) -> Result<String, Rejection> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| Rejection::unclassified(error.to_string()))?;
    let mut bytes = Vec::new();
    canonical_json::write(&raw, &mut bytes)
        .map_err(|_| Rejection::unclassified(format!("{CONTEXT} could not canonicalize data")))?;
    Ok(String::from_utf8(bytes).unwrap_or_default())
}

fn digest(value: &Value) -> Result<String, Rejection> {
    canonical_json::digest(value)
        .map_err(|_| Rejection::unclassified(format!("{CONTEXT} could not canonicalize data")))
}

fn values(value: &Value) -> &[Value] {
    value.as_array().map(Vec::as_slice).unwrap_or_default()
}

fn items<'a>(value: &'a Value, field: &str) -> &'a [Value] {
    values(&value[field])
}

/// String items of `value[field]`, or of `value` itself when `field` is empty.
fn strings<'a>(value: &'a Value, field: &str) -> Vec<&'a str> {
    let target = if field.is_empty() {
        value
    } else {
        &value[field]
    };
    values(target).iter().filter_map(Value::as_str).collect()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or_default()
}
