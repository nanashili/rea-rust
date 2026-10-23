//! `project_managed_application_graph`.
//!
//! Compatibility owners:
//! `src/server/registerManagedWorkflowTools/projectManagedApplicationGraph.ts`,
//! `src/application/managed/ManagedApplicationGraphService.ts`,
//! `src/domain/managed/managedApplicationGraph.ts`,
//! `managedApplicationGraphNodes.ts`, `managedApplicationGraphCoverage.ts` and
//! `managedInspectionEvidence.ts`.
use super::error::{DomainError, classify};
use super::graph_builder::{self, BuiltNode, EdgeInput, GraphInput, NodeInput, ObservationInput};
use super::inspection::{self, InspectionKind};
use crate::common::json;
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::evidence::envelope::{Observation, SubjectTarget};
use serde_json::{Map, Value, json};
use std::collections::HashMap;

use rea_mcp::{ToolContext, ToolOutput};

const OPERATION: &str = "project_managed_application_graph";

pub fn handle(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    // `managedApplicationGraphReferenceInputSchema.superRefine` duplicate-ID
    // check, which the advertised JSON Schema cannot express (the frozen
    // schema itself rejects an input with no source).
    let ids: Vec<&Value> = [
        "managed_artifact",
        "managed_members",
        "managed_native_boundaries",
    ]
    .into_iter()
    .filter_map(|key| input.get(key)?.get("evidence_id"))
    .collect();
    if ids
        .iter()
        .enumerate()
        .any(|(index, id)| ids[..index].contains(id))
    {
        return crate::common::refinement_failure(
            OPERATION,
            vec![crate::common::Refinement::new(
                Vec::new(),
                "Managed application graph Evidence IDs must be unique",
            )],
        );
    }
    // Resolve each optional input, authenticating its operation.
    let managed_artifact =
        match resolve_optional(&input, "managed_artifact", "inspect_managed_artifact") {
            Ok(record) => record,
            Err(error) => return ToolOutput::Failure(error),
        };
    let managed_members =
        match resolve_optional(&input, "managed_members", "inspect_managed_members") {
            Ok(record) => record,
            Err(error) => return ToolOutput::Failure(error),
        };
    let managed_boundaries = match resolve_optional(
        &input,
        "managed_native_boundaries",
        "inspect_managed_native_boundaries",
    ) {
        Ok(record) => record,
        Err(error) => return ToolOutput::Failure(error),
    };
    // `projectManagedApplicationGraphEvidence(parsed)`.
    let derived = match project(
        managed_artifact.as_ref(),
        managed_members.as_ref(),
        managed_boundaries.as_ref(),
    ) {
        Ok(derived) => derived,
        Err(error) => return ToolOutput::Failure(classify(OPERATION, error)),
    };
    // `recordSessionEvidenceSources(sourceEvidence(parsed))`: artifact,
    // members, boundaries in that order, skipping absent inputs.
    let sources: Vec<&Value> = [
        managed_artifact.as_ref(),
        managed_members.as_ref(),
        managed_boundaries.as_ref(),
    ]
    .into_iter()
    .flatten()
    .collect();
    if let Err(error) = super::record_sources(context.session, &sources) {
        return ToolOutput::Failure(error);
    }
    match crate::common::create_evidence(
        OPERATION,
        derived.subject.as_ref(),
        &crate::common::managed_workflow_provider(),
        derived.observation,
    ) {
        Ok(evidence) => super::deliver(context.session, evidence, None),
        Err(error) => ToolOutput::Failure(error),
    }
}

/// `resolveManaged*Evidence(input.X)` when the optional field is present.
fn resolve_optional(
    input: &Value,
    key: &str,
    operation: &str,
) -> Result<Option<Value>, AnalysisError> {
    match input.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => super::resolve_expected(value, Some(operation)).map(Some),
    }
}

struct DerivedEvidence {
    subject: Option<SubjectTarget>,
    observation: Observation,
}

/// One parsed managed inspection input: its evidence record and result.
struct ParsedInput {
    evidence: Value,
    parsed: inspection::ParsedInspection,
}

impl ParsedInput {
    fn evidence_id(&self) -> &str {
        &self.parsed.evidence_id
    }
    fn result(&self) -> &Value {
        &self.parsed.result
    }
    fn operation(&self) -> &str {
        self.evidence
            .get("operation")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }
}

struct ParsedManagedGraphInput {
    artifact: Option<ParsedInput>,
    members: Option<ParsedInput>,
    boundaries: Option<ParsedInput>,
}

/// Graph building state (`GraphBuildState`).
struct GraphBuildState {
    nodes: Vec<Value>,
    edges: Vec<Value>,
    artifact_sha256: String,
    artifact_path: String,
    evidence_links: Vec<String>,
    type_nodes: HashMap<String, String>,
    method_nodes: HashMap<String, String>,
    field_nodes: HashMap<String, String>,
}

/// `projectManagedApplicationGraphEvidence` + `projectManagedApplicationGraph`
/// + `createManagedApplicationGraphEvidence`.
fn project(
    artifact: Option<&Value>,
    members: Option<&Value>,
    boundaries: Option<&Value>,
) -> Result<DerivedEvidence, DomainError> {
    // `projectManagedApplicationGraphInputSchema.superRefine`: at least one
    // record is required. The frozen inputSchema does not require this, so the
    // domain enforces it as a request input error with an empty path.
    if artifact.is_none() && members.is_none() && boundaries.is_none() {
        return Err(DomainError::from(AnalysisError::input(
            OPERATION,
            vec![InputIssue {
                path: Vec::new(),
                reason: "invalid_value",
                message: Some(
                    "At least one managed artifact, member, or native-boundary Evidence record is required"
                        .to_owned(),
                ),
                expected: None,
                minimum: None,
                maximum: None,
            }],
        )));
    }
    let parsed = parse_managed_inputs(artifact, members, boundaries)?;
    let artifact_identity = choose_artifact(&parsed)?;
    assert_same_artifact(&parsed, &artifact_identity.0)?;
    assert_consistent_module_identity(&parsed)?;
    let evidence_links: Vec<String> = [
        parsed
            .artifact
            .as_ref()
            .map(|input| input.evidence_id().to_owned()),
        parsed
            .members
            .as_ref()
            .map(|input| input.evidence_id().to_owned()),
        parsed
            .boundaries
            .as_ref()
            .map(|input| input.evidence_id().to_owned()),
    ]
    .into_iter()
    .flatten()
    .collect();
    let mut state = GraphBuildState {
        nodes: Vec::new(),
        edges: Vec::new(),
        artifact_sha256: artifact_identity.0.clone(),
        artifact_path: artifact_identity.1.clone(),
        evidence_links,
        type_nodes: HashMap::new(),
        method_nodes: HashMap::new(),
        field_nodes: HashMap::new(),
    };
    let artifact_node = add_artifact_node(&mut state)?;
    add_artifact_identity_nodes(&mut state, &artifact_node, &parsed)?;
    add_member_nodes(&mut state, &artifact_node, &parsed)?;
    add_boundary_nodes(&mut state, &artifact_node, &parsed)?;
    let omissions = assess_managed_graph_omissions(&parsed);
    let limitations = projection_limitations(&parsed, &omissions);
    let graph = graph_builder::create_graph(GraphInput {
        root_node_ids: vec![artifact_node.node_id.clone()],
        nodes: state.nodes.clone(),
        edges: state.edges.clone(),
        coverage: managed_graph_evidence_coverage(&omissions),
        limitations: limitations.clone(),
    })?;
    let graph_nodes = graph
        .get("nodes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let graph_edges = graph
        .get("edges")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let count = |kind: &str| {
        graph_nodes
            .iter()
            .filter(|node| node.get("kind").and_then(Value::as_str) == Some(kind))
            .count()
    };
    // `withoutId` in its literal key order.
    let without_id = json!({
        "root_artifact_sha256": state.artifact_sha256,
        "source_evidence": {
            "managed_artifact_evidence_id": optional_id(&parsed.artifact),
            "managed_members_evidence_id": optional_id(&parsed.members),
            "managed_native_boundaries_evidence_id": optional_id(&parsed.boundaries),
        },
        "summary": {
            "graph_nodes": graph_nodes.len(),
            "graph_edges": graph_edges.len(),
            "assemblies": count("managed-assembly"),
            "modules": count("managed-module"),
            "types": count("managed-type"),
            "methods": count("managed-method"),
            "fields": count("managed-field"),
            "pinvoke_imports": count("managed-pinvoke-import"),
            "native_implementations": count("managed-native-implementation"),
        },
        "graph": graph,
        "coverage": managed_graph_result_coverage(&omissions),
        "evidence_links": Value::Array(state.evidence_links.iter().map(|id| json!(id)).collect()),
        "limitations": Value::Array(limitations.iter().map(|limit| json!(limit)).collect()),
    });
    let projection_id = format!("magp_{}", canonical_digest(&without_id)?);
    // `{ ...withoutId, projection_id }` parsed by the result schema, which
    // lists `projection_id` first; emit it first to match the schema order.
    let mut ordered = Map::new();
    ordered.insert("projection_id".into(), json!(projection_id));
    if let Some(object) = without_id.as_object() {
        for (key, value) in object {
            ordered.insert(key.clone(), value.clone());
        }
    }
    let result = Value::Object(ordered);
    Ok(build_evidence(&parsed, result))
}

fn optional_id(input: &Option<ParsedInput>) -> Value {
    input
        .as_ref()
        .map(|input| json!(input.evidence_id()))
        .unwrap_or(Value::Null)
}

/// `sha256(canonicalize(value))`.
fn canonical_digest(value: &Value) -> Result<String, DomainError> {
    rea_core::canonical_json::digest(value)
        .map_err(|_| DomainError::type_error("Managed application graph canonicalization failed"))
}

/// `parseManagedInputs`.
fn parse_managed_inputs(
    artifact: Option<&Value>,
    members: Option<&Value>,
    boundaries: Option<&Value>,
) -> Result<ParsedManagedGraphInput, DomainError> {
    let parse = |value: Option<&Value>, operation: &str, kind: InspectionKind| {
        value
            .map(|value| {
                inspection::parse(value, operation, kind).map(|parsed| ParsedInput {
                    evidence: value.clone(),
                    parsed,
                })
            })
            .transpose()
    };
    Ok(ParsedManagedGraphInput {
        artifact: parse(
            artifact,
            "inspect_managed_artifact",
            InspectionKind::Artifact,
        )?,
        members: parse(members, "inspect_managed_members", InspectionKind::Members)?,
        boundaries: parse(
            boundaries,
            "inspect_managed_native_boundaries",
            InspectionKind::Boundary,
        )?,
    })
}

/// `chooseArtifact`: first available artifact identity.
fn choose_artifact(parsed: &ParsedManagedGraphInput) -> Result<(String, String), DomainError> {
    let result = parsed
        .artifact
        .as_ref()
        .or(parsed.members.as_ref())
        .or(parsed.boundaries.as_ref())
        .map(ParsedInput::result)
        .ok_or_else(|| {
            DomainError::type_error("Managed graph projection requires managed Evidence")
        })?;
    Ok((
        result
            .get("artifact")
            .and_then(|artifact| artifact.get("sha256"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        result
            .get("artifact")
            .and_then(|artifact| artifact.get("path"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    ))
}

/// `assertSameArtifact`.
fn assert_same_artifact(
    parsed: &ParsedManagedGraphInput,
    sha256_value: &str,
) -> Result<(), DomainError> {
    for input in [&parsed.artifact, &parsed.members, &parsed.boundaries] {
        if let Some(input) = input {
            let sha256 = input
                .result()
                .get("artifact")
                .and_then(|artifact| artifact.get("sha256"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if sha256 != sha256_value {
                return Err(DomainError::type_error(
                    "Managed graph projection inputs must describe the same artifact SHA-256",
                ));
            }
        }
    }
    Ok(())
}

fn module_of(input: &Option<ParsedInput>) -> Option<&Value> {
    input
        .as_ref()
        .and_then(|input| input.result().get("module"))
        .filter(|module| !module.is_null())
}

fn module_field<'a>(module: &'a Value, field: &str) -> Option<&'a str> {
    module.get(field).and_then(Value::as_str)
}

/// `assertConsistentModuleIdentity`.
fn assert_consistent_module_identity(parsed: &ParsedManagedGraphInput) -> Result<(), DomainError> {
    // MVID and token-scope claims collapse to lowercase.
    let mut mvid_claims: Vec<String> = Vec::new();
    let mut push_mvid = |value: Option<&str>| {
        if let Some(value) = value {
            mvid_claims.push(value.to_lowercase());
        }
    };
    push_mvid(module_of(&parsed.artifact).and_then(|module| module_field(module, "mvid")));
    push_mvid(module_of(&parsed.members).and_then(|module| module_field(module, "mvid")));
    push_mvid(
        parsed
            .members
            .as_ref()
            .and_then(|input| input.result().get("identity_scope"))
            .and_then(|scope| scope.get("requires_mvid"))
            .and_then(Value::as_str),
    );
    push_mvid(module_of(&parsed.boundaries).and_then(|module| module_field(module, "mvid")));
    push_mvid(
        parsed
            .boundaries
            .as_ref()
            .and_then(|input| input.result().get("identity_scope"))
            .and_then(|scope| scope.get("requires_mvid"))
            .and_then(Value::as_str),
    );
    if unique_count(&mvid_claims) > 1 {
        return Err(DomainError::type_error(
            "Managed graph inputs report conflicting known module MVIDs or token scopes",
        ));
    }
    let modules: Vec<&Value> = [
        module_of(&parsed.artifact),
        module_of(&parsed.members),
        module_of(&parsed.boundaries),
    ]
    .into_iter()
    .flatten()
    .collect();
    for field in ["name", "generation", "token", "row_offset"] {
        let values: Vec<String> = modules
            .iter()
            .map(|module| canonical_scalar(module.get(field).unwrap_or(&Value::Null)))
            .collect();
        if unique_count(&values) > 1 {
            return Err(DomainError::type_error(format!(
                "Managed graph inputs report conflicting module {field} values"
            )));
        }
    }
    for field in ["enc_id", "enc_base_id"] {
        let values: Vec<String> = modules
            .iter()
            .filter_map(|module| module_field(module, field))
            .map(str::to_lowercase)
            .collect();
        if unique_count(&values) > 1 {
            return Err(DomainError::type_error(format!(
                "Managed graph inputs report conflicting module {field} values"
            )));
        }
    }
    Ok(())
}

/// Stable string key for a scalar module value, so `new Set(...)` dedup works.
fn canonical_scalar(value: &Value) -> String {
    match value {
        Value::Null => "\u{0}null".to_owned(),
        other => other.to_string(),
    }
}

fn unique_count(values: &[String]) -> usize {
    let mut unique: Vec<&String> = Vec::new();
    for value in values {
        if !unique.iter().any(|existing| *existing == value) {
            unique.push(value);
        }
    }
    unique.len()
}

// ---------------------------------------------------------------------------
// Node construction (`managedApplicationGraphNodes.ts`).
// ---------------------------------------------------------------------------

/// `metadataLabel`: empty names have no label.
fn metadata_label(name: &str) -> Value {
    if name.is_empty() {
        Value::Null
    } else {
        json!(name)
    }
}

/// `basename`.
fn basename(value: &str) -> &str {
    let after_slash = value.rsplit('/').next().unwrap_or(value);
    after_slash.rsplit('\\').next().unwrap_or(after_slash)
}

/// `addArtifactNode`.
fn add_artifact_node(state: &mut GraphBuildState) -> Result<BuiltNode, DomainError> {
    let identity = json!({
        "strategy": "content-digest",
        "stability": "global-exact",
        "sha256": state.artifact_sha256,
    });
    let observation = ObservationInput {
        label: json!(basename(&state.artifact_path)),
        properties: json!({ "format": "pe", "source": "managed-application-graph" }),
        evidence: projected_managed_evidence(state, "project-managed-artifact", None),
    };
    let node = graph_builder::create_node(NodeInput {
        kind: "artifact".to_owned(),
        identity,
        observations: vec![observation],
    })?;
    state.nodes.push(node.value.clone());
    Ok(node)
}

/// `addArtifactIdentityNodes`.
fn add_artifact_identity_nodes(
    state: &mut GraphBuildState,
    artifact_node: &BuiltNode,
    parsed: &ParsedManagedGraphInput,
) -> Result<(), DomainError> {
    if let Some(artifact_input) = &parsed.artifact {
        let assembly = artifact_input.result().get("assembly");
        if let Some(assembly) = assembly.filter(|assembly| !assembly.is_null()) {
            let coverage_state = coverage_state_of(artifact_input.result());
            let artifact_evidence = source_managed_evidence(
                state,
                artifact_input.operation(),
                &coverage_state,
                &[artifact_input.evidence_id().to_owned()],
            );
            let node = graph_builder::create_node(NodeInput {
                kind: "managed-assembly".to_owned(),
                identity: artifact_local_identity(
                    &state.artifact_sha256,
                    "managed-assembly",
                    assembly
                        .get("token")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                ),
                observations: vec![ObservationInput {
                    label: metadata_label(
                        assembly
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                    ),
                    properties: json!({
                        "name": assembly.get("name").cloned().unwrap_or(Value::Null),
                        "version": assembly.get("version").cloned().unwrap_or(Value::Null),
                        "culture": assembly.get("culture").cloned().unwrap_or(Value::Null),
                        "public_key_kind": assembly
                            .get("public_key")
                            .and_then(|key| key.get("kind"))
                            .cloned()
                            .unwrap_or(Value::Null),
                    }),
                    evidence: artifact_evidence.clone(),
                }],
            })?;
            state.nodes.push(node.value.clone());
            let coverage = coverage_from_evidence(&artifact_evidence);
            add_contains_edge(
                state,
                artifact_node,
                &node,
                "declares-managed-assembly",
                coverage,
            )?;
        }
    }
    if let Some(module_source) = select_module_source(parsed) {
        let module = module_source.module;
        let module_evidence = source_managed_evidence(
            state,
            module_source.operation,
            &module_source.coverage_state,
            &[module_source.evidence_id.clone()],
        );
        let key = module
            .get("mvid")
            .and_then(Value::as_str)
            .map(str::to_lowercase)
            .unwrap_or_else(|| {
                module
                    .get("token")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            });
        let node = graph_builder::create_node(NodeInput {
            kind: "managed-module".to_owned(),
            identity: artifact_local_identity(&state.artifact_sha256, "managed-module", &key),
            observations: vec![ObservationInput {
                label: metadata_label(
                    module
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                ),
                properties: json!({
                    "name": module.get("name").cloned().unwrap_or(Value::Null),
                    "mvid": module.get("mvid").cloned().unwrap_or(Value::Null),
                    "generation": module.get("generation").cloned().unwrap_or(Value::Null),
                    "token": module.get("token").cloned().unwrap_or(Value::Null),
                }),
                evidence: module_evidence.clone(),
            }],
        })?;
        state.nodes.push(node.value.clone());
        let coverage = coverage_from_evidence(&module_evidence);
        add_contains_edge(
            state,
            artifact_node,
            &node,
            "declares-managed-module",
            coverage,
        )?;
    }
    Ok(())
}

struct ModuleSource<'a> {
    module: &'a Value,
    operation: &'a str,
    evidence_id: String,
    coverage_state: String,
}

/// `selectModuleSource`: prefer a known MVID, else the first module.
fn select_module_source(parsed: &ParsedManagedGraphInput) -> Option<ModuleSource<'_>> {
    let mut sources: Vec<ModuleSource<'_>> = Vec::new();
    for input in [&parsed.artifact, &parsed.members, &parsed.boundaries] {
        if let Some(input) = input
            && let Some(module) = input
                .result()
                .get("module")
                .filter(|module| !module.is_null())
        {
            sources.push(ModuleSource {
                module,
                operation: input.operation(),
                evidence_id: input.evidence_id().to_owned(),
                coverage_state: coverage_state_of(input.result()),
            });
        }
    }
    if let Some(index) = sources.iter().position(|source| {
        !source
            .module
            .get("mvid")
            .map(Value::is_null)
            .unwrap_or(true)
    }) {
        return Some(sources.swap_remove(index));
    }
    if sources.is_empty() {
        None
    } else {
        Some(sources.swap_remove(0))
    }
}

/// `addMemberNodes`.
fn add_member_nodes(
    state: &mut GraphBuildState,
    artifact_node: &BuiltNode,
    parsed: &ParsedManagedGraphInput,
) -> Result<(), DomainError> {
    let Some(member_input) = &parsed.members else {
        return Ok(());
    };
    let members = member_input.result().clone();
    let coverage_state = coverage_state_of(&members);
    let type_coverage = managed_source_coverage(&coverage_state);
    let method_coverage = managed_source_coverage(&coverage_state);
    let field_coverage = managed_source_coverage(&coverage_state);
    let source_evidence = source_managed_evidence(
        state,
        member_input.operation(),
        &coverage_state,
        &[member_input.evidence_id().to_owned()],
    );
    for type_row in json::array_at(&members, "types").to_vec() {
        let node = type_node(state, &type_row, &source_evidence)?;
        let token = type_row
            .get("token")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        state.nodes.push(node.value.clone());
        state.type_nodes.insert(token, node.node_id.clone());
        add_contains_edge(
            state,
            artifact_node,
            &node,
            "declares-managed-type",
            type_coverage.clone(),
        )?;
    }
    for method in json::array_at(&members, "methods").to_vec() {
        let node = method_node(state, &method, &source_evidence)?;
        let token = method
            .get("token")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        state.nodes.push(node.value.clone());
        state.method_nodes.insert(token, node.node_id.clone());
        let owner = owner_node(state, artifact_node, method.get("declaring_type_token"));
        add_contains_edge(
            state,
            &owner,
            &node,
            "declares-managed-method",
            method_coverage.clone(),
        )?;
    }
    for field in json::array_at(&members, "fields").to_vec() {
        let node = field_node(state, &field, &source_evidence)?;
        let token = field
            .get("token")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        state.nodes.push(node.value.clone());
        state.field_nodes.insert(token, node.node_id.clone());
        let owner = owner_node(state, artifact_node, field.get("declaring_type_token"));
        add_contains_edge(
            state,
            &owner,
            &node,
            "declares-managed-field",
            field_coverage.clone(),
        )?;
    }
    Ok(())
}

/// Resolve the declaring type owner node, defaulting to the artifact.
fn owner_node(
    state: &GraphBuildState,
    artifact_node: &BuiltNode,
    declaring_type_token: Option<&Value>,
) -> BuiltNode {
    let token = declaring_type_token.and_then(Value::as_str);
    match token {
        None => node_handle(artifact_node),
        Some(token) => state
            .type_nodes
            .get(token)
            .map(|node_id| BuiltNode {
                node_id: node_id.clone(),
                value: Value::Null,
            })
            .unwrap_or_else(|| node_handle(artifact_node)),
    }
}

fn node_handle(node: &BuiltNode) -> BuiltNode {
    BuiltNode {
        node_id: node.node_id.clone(),
        value: Value::Null,
    }
}

/// `typeNode`.
fn type_node(
    state: &GraphBuildState,
    type_row: &Value,
    evidence: &Value,
) -> Result<BuiltNode, DomainError> {
    graph_builder::create_node(NodeInput {
        kind: "managed-type".to_owned(),
        identity: artifact_local_identity(
            &state.artifact_sha256,
            "managed-type-token",
            type_row
                .get("token")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ),
        observations: vec![ObservationInput {
            label: metadata_label(
                type_row
                    .get("full_name")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            ),
            properties: json!({
                "token": type_row.get("token").cloned().unwrap_or(Value::Null),
                "namespace": type_row.get("namespace").cloned().unwrap_or(Value::Null),
                "name": type_row.get("name").cloned().unwrap_or(Value::Null),
                "full_name": type_row.get("full_name").cloned().unwrap_or(Value::Null),
                "flags": type_row.get("flags").cloned().unwrap_or(Value::Null),
                "extends_token": type_row.get("extends_token").cloned().unwrap_or(Value::Null),
            }),
            evidence: evidence.clone(),
        }],
    })
}

/// `methodNode`.
fn method_node(
    state: &GraphBuildState,
    method: &Value,
    evidence: &Value,
) -> Result<BuiltNode, DomainError> {
    let declaring_type = method.get("declaring_type").and_then(Value::as_str);
    let name = method
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let label = match declaring_type {
        None => name.to_owned(),
        Some(declaring_type) => format!("{declaring_type}.{name}"),
    };
    let signature = method.get("signature");
    let body = method.get("body");
    graph_builder::create_node(NodeInput {
        kind: "managed-method".to_owned(),
        identity: artifact_local_identity(
            &state.artifact_sha256,
            "managed-method-token",
            method
                .get("token")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ),
        observations: vec![ObservationInput {
            label: metadata_label(&label),
            properties: json!({
                "token": method.get("token").cloned().unwrap_or(Value::Null),
                "declaring_type_token": method.get("declaring_type_token").cloned().unwrap_or(Value::Null),
                "declaring_type": method.get("declaring_type").cloned().unwrap_or(Value::Null),
                "name": method.get("name").cloned().unwrap_or(Value::Null),
                "rva": method.get("rva").cloned().unwrap_or(Value::Null),
                "signature_sha256": signature.and_then(|s| s.get("raw_sha256")).cloned().unwrap_or(Value::Null),
                "signature_status": signature.and_then(|s| s.get("parse_status")).cloned().unwrap_or(Value::Null),
                "body_status": body.and_then(|b| b.get("status")).cloned().unwrap_or(Value::Null),
                "normalized_il_sha256": body.and_then(|b| b.get("normalized_il_sha256")).cloned().unwrap_or(Value::Null),
                "il_size": body.and_then(|b| b.get("il_size")).cloned().unwrap_or(Value::Null),
            }),
            evidence: evidence.clone(),
        }],
    })
}

/// `fieldNode`.
fn field_node(
    state: &GraphBuildState,
    field: &Value,
    evidence: &Value,
) -> Result<BuiltNode, DomainError> {
    let declaring_type = field.get("declaring_type").and_then(Value::as_str);
    let name = field
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let label = match declaring_type {
        None => name.to_owned(),
        Some(declaring_type) => format!("{declaring_type}.{name}"),
    };
    let signature = field.get("signature");
    graph_builder::create_node(NodeInput {
        kind: "managed-field".to_owned(),
        identity: artifact_local_identity(
            &state.artifact_sha256,
            "managed-field-token",
            field
                .get("token")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ),
        observations: vec![ObservationInput {
            label: metadata_label(&label),
            properties: json!({
                "token": field.get("token").cloned().unwrap_or(Value::Null),
                "declaring_type_token": field.get("declaring_type_token").cloned().unwrap_or(Value::Null),
                "declaring_type": field.get("declaring_type").cloned().unwrap_or(Value::Null),
                "name": field.get("name").cloned().unwrap_or(Value::Null),
                "flags": field.get("flags").cloned().unwrap_or(Value::Null),
                "signature_sha256": signature.and_then(|s| s.get("raw_sha256")).cloned().unwrap_or(Value::Null),
                "signature_status": signature.and_then(|s| s.get("parse_status")).cloned().unwrap_or(Value::Null),
            }),
            evidence: evidence.clone(),
        }],
    })
}

/// `addBoundaryNodes`.
fn add_boundary_nodes(
    state: &mut GraphBuildState,
    artifact_node: &BuiltNode,
    parsed: &ParsedManagedGraphInput,
) -> Result<(), DomainError> {
    let Some(boundary_input) = &parsed.boundaries else {
        return Ok(());
    };
    let boundaries = boundary_input.result().clone();
    let coverage_state = coverage_state_of(&boundaries);
    let pinvoke_coverage = managed_source_coverage(&coverage_state);
    let implementation_coverage = managed_source_coverage(&coverage_state);
    let source_evidence = source_managed_evidence(
        state,
        boundary_input.operation(),
        &coverage_state,
        &[boundary_input.evidence_id().to_owned()],
    );
    let can_join_member_tokens = parsed.members.is_some()
        && token_scopes_match(
            parsed
                .members
                .as_ref()
                .and_then(|input| input.result().get("identity_scope"))
                .and_then(|scope| scope.get("requires_mvid"))
                .and_then(Value::as_str),
            boundaries
                .get("identity_scope")
                .and_then(|scope| scope.get("requires_mvid"))
                .and_then(Value::as_str),
        );
    let boundary_evidence_id = boundary_input.evidence_id().to_owned();
    let boundary_operation = boundary_input.operation().to_owned();
    let member_evidence_id = parsed
        .members
        .as_ref()
        .map(|input| input.evidence_id().to_owned());
    for pinvoke in json::array_at(&boundaries, "pinvoke_imports").to_vec() {
        let node = pinvoke_node(state, &pinvoke, &source_evidence)?;
        state.nodes.push(node.value.clone());
        let member_token = pinvoke.get("member_token").and_then(Value::as_str);
        let method_node_id = match (member_token, can_join_member_tokens) {
            (Some(token), true) => state.method_nodes.get(token).cloned(),
            _ => None,
        };
        let owner_id = method_node_id
            .clone()
            .unwrap_or_else(|| artifact_node.node_id.clone());
        let member_link = match (&method_node_id, &member_evidence_id) {
            (Some(_), Some(member_id)) => Some(member_id.clone()),
            _ => None,
        };
        let evidence = pinvoke_association_evidence(
            state,
            &boundary_operation,
            &boundary_evidence_id,
            &pinvoke_coverage,
            member_link.as_deref(),
        );
        let edge = graph_builder::create_edge(EdgeInput {
            source_node_id: owner_id,
            target_node_id: node.node_id.clone(),
            relation: "imports".to_owned(),
            properties: json!({
                "kind": "managed-pinvoke",
                "import_name": pinvoke.get("import_name").cloned().unwrap_or(Value::Null),
                "import_scope_name": pinvoke.get("import_scope_name").cloned().unwrap_or(Value::Null),
            }),
            evidence,
        })?;
        state.edges.push(edge);
    }
    for implementation in json::array_at(&boundaries, "native_implementations").to_vec() {
        let node = native_implementation_node(state, &implementation, &source_evidence)?;
        state.nodes.push(node.value.clone());
        let token = implementation.get("token").and_then(Value::as_str);
        let owner_id = match (token, can_join_member_tokens) {
            (Some(token), true) => state.method_nodes.get(token).cloned(),
            _ => None,
        }
        .unwrap_or_else(|| artifact_node.node_id.clone());
        let owner = BuiltNode {
            node_id: owner_id,
            value: Value::Null,
        };
        add_contains_edge(
            state,
            &owner,
            &node,
            "declares-managed-native-implementation",
            implementation_coverage.clone(),
        )?;
    }
    Ok(())
}

/// `pinvokeNode`.
fn pinvoke_node(
    state: &GraphBuildState,
    pinvoke: &Value,
    evidence: &Value,
) -> Result<BuiltNode, DomainError> {
    graph_builder::create_node(NodeInput {
        kind: "managed-pinvoke-import".to_owned(),
        identity: artifact_local_identity(
            &state.artifact_sha256,
            "managed-pinvoke-token",
            pinvoke
                .get("token")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ),
        observations: vec![ObservationInput {
            label: metadata_label(
                pinvoke
                    .get("import_name")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            ),
            properties: json!({
                "token": pinvoke.get("token").cloned().unwrap_or(Value::Null),
                "member_token": pinvoke.get("member_token").cloned().unwrap_or(Value::Null),
                "member_name": pinvoke.get("member_name").cloned().unwrap_or(Value::Null),
                "import_name": pinvoke.get("import_name").cloned().unwrap_or(Value::Null),
                "import_scope_name": pinvoke.get("import_scope_name").cloned().unwrap_or(Value::Null),
                "char_set": pinvoke.get("char_set").cloned().unwrap_or(Value::Null),
                "call_convention": pinvoke.get("call_convention").cloned().unwrap_or(Value::Null),
                "verification": pinvoke.get("verification").cloned().unwrap_or(Value::Null),
            }),
            evidence: evidence.clone(),
        }],
    })
}

/// `nativeImplementationNode`.
fn native_implementation_node(
    state: &GraphBuildState,
    implementation: &Value,
    evidence: &Value,
) -> Result<BuiltNode, DomainError> {
    graph_builder::create_node(NodeInput {
        kind: "managed-native-implementation".to_owned(),
        identity: artifact_local_identity(
            &state.artifact_sha256,
            "managed-native-implementation-token",
            implementation
                .get("token")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ),
        observations: vec![ObservationInput {
            label: metadata_label(
                implementation
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            ),
            properties: json!({
                "token": implementation.get("token").cloned().unwrap_or(Value::Null),
                "name": implementation.get("name").cloned().unwrap_or(Value::Null),
                "rva": implementation.get("rva").cloned().unwrap_or(Value::Null),
                "code_type": implementation.get("code_type").cloned().unwrap_or(Value::Null),
                "managed_kind": implementation.get("managed_kind").cloned().unwrap_or(Value::Null),
                "pinvoke_declared": implementation.get("pinvoke_declared").cloned().unwrap_or(Value::Null),
                "boundary_kind": implementation.get("boundary_kind").cloned().unwrap_or(Value::Null),
                "body_interpretation": implementation.get("body_interpretation").cloned().unwrap_or(Value::Null),
            }),
            evidence: evidence.clone(),
        }],
    })
}

/// `addContainsEdge`.
fn add_contains_edge(
    state: &mut GraphBuildState,
    source: &BuiltNode,
    target: &BuiltNode,
    kind: &str,
    coverage: Value,
) -> Result<(), DomainError> {
    let evidence = projected_managed_evidence(state, "project-managed-contains", Some(coverage));
    let edge = graph_builder::create_edge(EdgeInput {
        source_node_id: source.node_id.clone(),
        target_node_id: target.node_id.clone(),
        relation: "contains".to_owned(),
        properties: json!({ "kind": kind }),
        evidence,
    })?;
    state.edges.push(edge);
    Ok(())
}

/// `artifactLocalIdentity`.
fn artifact_local_identity(artifact_sha256: &str, namespace: &str, key: &str) -> Value {
    json!({
        "strategy": "artifact-local-key",
        "stability": "artifact-version",
        "artifact_sha256": artifact_sha256,
        "namespace": namespace,
        "key": key,
    })
}

// ---------------------------------------------------------------------------
// Graph evidence (`createManagedEvidence` and friends).
// ---------------------------------------------------------------------------

fn coverage_state_of(result: &Value) -> String {
    result
        .get("coverage")
        .and_then(|coverage| coverage.get("state"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// `sourceManagedEvidence`.
fn source_managed_evidence(
    state: &GraphBuildState,
    operation: &str,
    coverage_state: &str,
    evidence_ids: &[String],
) -> Value {
    create_managed_evidence(
        state,
        operation,
        managed_source_coverage(coverage_state),
        evidence_ids,
    )
}

/// `projectedManagedEvidence`: defaults to complete coverage and the graph's
/// shared evidence links.
fn projected_managed_evidence(
    state: &GraphBuildState,
    operation: &str,
    coverage: Option<Value>,
) -> Value {
    let coverage = coverage.unwrap_or_else(|| managed_source_coverage("complete"));
    let links = state.evidence_links.clone();
    create_managed_evidence(state, operation, coverage, &links)
}

/// `pinvokeAssociationEvidence`.
fn pinvoke_association_evidence(
    state: &GraphBuildState,
    operation: &str,
    boundary_evidence_id: &str,
    coverage: &Value,
    member_evidence_id: Option<&str>,
) -> Value {
    let mut ids = vec![boundary_evidence_id.to_owned()];
    if let Some(member) = member_evidence_id {
        ids.push(member.to_owned());
    }
    create_managed_evidence(state, operation, coverage.clone(), &ids)
}

/// `createManagedEvidence`.
fn create_managed_evidence(
    state: &GraphBuildState,
    operation: &str,
    coverage: Value,
    evidence_ids: &[String],
) -> Value {
    let status = coverage
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let limitations: Vec<Value> = if status == "complete" {
        Vec::new()
    } else {
        vec![json!(
            "The source managed Evidence slice is incomplete; unreturned or unavailable items remain unobserved."
        )]
    };
    json!({
        "authority": "managed-static-analysis",
        "state": "observed",
        "confidence": "exact",
        "artifact": {
            "available": true,
            "artifact_id": format!("art_{}", state.artifact_sha256),
            "sha256": state.artifact_sha256,
        },
        "location": {
            "available": true,
            "value": {
                "kind": "artifact-path",
                "path": graph_artifact_path(&state.artifact_path),
            },
        },
        "extractor": {
            "name": "rea-dotnet-static",
            "version": "1",
            "operation": operation,
            "executable_sha256": Value::Null,
        },
        "coverage": coverage,
        "limitations": Value::Array(limitations),
        "evidence_ids": Value::Array(evidence_ids.iter().map(|id| json!(id)).collect()),
    })
}

/// Extract the `coverage` object from a built evidence value.
fn coverage_from_evidence(evidence: &Value) -> Value {
    evidence.get("coverage").cloned().unwrap_or(Value::Null)
}

/// `graphArtifactPath`.
fn graph_artifact_path(path: &str) -> String {
    let name: String = basename(path)
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .collect();
    format!(
        "managed/{}",
        if name.is_empty() {
            "artifact.pe"
        } else {
            &name
        }
    )
}

// ---------------------------------------------------------------------------
// Coverage (`managedApplicationGraphCoverage.ts`).
// ---------------------------------------------------------------------------

/// `managedTokenScopesMatch`.
fn token_scopes_match(left: Option<&str>, right: Option<&str>) -> bool {
    inspection::token_scopes_match(left, right)
}

/// `managedSourceCoverage`.
fn managed_source_coverage(state: &str) -> Value {
    if state == "complete" {
        complete_coverage()
    } else {
        json!({
            "status": state,
            "truncated": false,
            "omitted_count": Value::Null,
            "limits": [],
        })
    }
}

fn complete_coverage() -> Value {
    json!({
        "status": "complete",
        "truncated": false,
        "omitted_count": 0,
        "limits": [],
    })
}

struct Omissions {
    partial_input: bool,
    unscoped_token_relationships: bool,
    selected_types: Option<Vec<String>>,
}

fn omits_any(omissions: &Omissions) -> bool {
    omissions.partial_input
        || omissions.unscoped_token_relationships
        || omissions.selected_types.is_some()
}

/// `assessManagedGraphOmissions`.
fn assess_managed_graph_omissions(parsed: &ParsedManagedGraphInput) -> Omissions {
    let members = parsed.members.as_ref().map(ParsedInput::result);
    let boundaries = parsed.boundaries.as_ref().map(ParsedInput::result);
    let unscoped_token_relationships = match (members, boundaries) {
        (Some(members), Some(boundaries)) => {
            let has_member_token =
                json::array_at(boundaries, "pinvoke_imports")
                    .iter()
                    .any(|item| {
                        item.get("member_token")
                            .map(|token| !token.is_null())
                            .unwrap_or(false)
                    });
            let has_implementations =
                !json::array_at(boundaries, "native_implementations").is_empty();
            (has_member_token || has_implementations)
                && !token_scopes_match(
                    members
                        .get("identity_scope")
                        .and_then(|scope| scope.get("requires_mvid"))
                        .and_then(Value::as_str),
                    boundaries
                        .get("identity_scope")
                        .and_then(|scope| scope.get("requires_mvid"))
                        .and_then(Value::as_str),
                )
        }
        _ => false,
    };
    let partial_input = [
        parsed
            .members
            .as_ref()
            .map(|input| coverage_state_of(input.result())),
        parsed
            .boundaries
            .as_ref()
            .map(|input| coverage_state_of(input.result())),
        parsed
            .artifact
            .as_ref()
            .map(|input| coverage_state_of(input.result())),
    ]
    .into_iter()
    .flatten()
    .any(|state| state != "complete");
    let selected_types = parsed.members.as_ref().and_then(|input| {
        input
            .result()
            .get("selection")
            .filter(|selection| !selection.is_null())
            .and_then(|selection| selection.get("type_names"))
            .and_then(Value::as_array)
            .map(|names| {
                names
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
    });
    Omissions {
        partial_input,
        unscoped_token_relationships,
        selected_types,
    }
}

/// `managedGraphEvidenceCoverage`.
fn managed_graph_evidence_coverage(omissions: &Omissions) -> Value {
    if omits_any(omissions) {
        json!({
            "status": "partial",
            "truncated": false,
            "omitted_count": Value::Null,
            "limits": [],
        })
    } else {
        complete_coverage()
    }
}

/// `managedGraphResultCoverage`.
fn managed_graph_result_coverage(omissions: &Omissions) -> Value {
    json!({
        "status": if omits_any(omissions) { "partial" } else { "complete-within-inputs" },
    })
}

/// `projectionLimitations`.
fn projection_limitations(parsed: &ParsedManagedGraphInput, omissions: &Omissions) -> Vec<String> {
    let mut limitations: Vec<String> = vec![
        "Managed graph projection preserves static metadata observations only; it does not execute managed code, load assemblies, or map managed tokens to native addresses.".to_owned(),
    ];
    if parsed.members.is_none() {
        limitations.push(
            "Managed member Evidence was not supplied; type, method, and field nodes are absent."
                .to_owned(),
        );
    }
    if parsed.artifact.is_none() {
        limitations.push(
            "Managed artifact Evidence was not supplied; assembly identity observations are absent."
                .to_owned(),
        );
    }
    if parsed.boundaries.is_none() {
        limitations.push(
            "Managed native-boundary Evidence was not supplied; P/Invoke and native-implementation nodes are absent."
                .to_owned(),
        );
    }
    if omissions.partial_input {
        limitations
            .push("At least one supplied managed Evidence record has partial coverage.".to_owned());
    }
    if let Some(selected) = &omissions.selected_types {
        limitations.push(format!(
            "Managed member Evidence selected only these declaring types: {}; type, method, and field nodes of other types are omitted, not absent.",
            selected.join(", ")
        ));
    }
    if omissions.unscoped_token_relationships {
        limitations.push(
            "Managed boundary tokens were not linked to member nodes because matching module MVID scope was not established."
                .to_owned(),
        );
    }
    limitations
}

// ---------------------------------------------------------------------------
// Evidence (`createManagedApplicationGraphEvidence`).
// ---------------------------------------------------------------------------

/// `createManagedApplicationGraphEvidence`.
fn build_evidence(parsed: &ParsedManagedGraphInput, result: Value) -> DerivedEvidence {
    let subject = subject_target(parsed);
    let parameters = json!({
        "managed_artifact_evidence_id": optional_id(&parsed.artifact),
        "managed_members_evidence_id": optional_id(&parsed.members),
        "managed_native_boundaries_evidence_id": optional_id(&parsed.boundaries),
    });
    let limitations = json::strings(result.get("limitations").unwrap_or(&Value::Null));
    let evidence_links = json::strings(result.get("evidence_links").unwrap_or(&Value::Null));
    let observation = Observation::new(OPERATION, parameters, result)
        .predicate("rea.managed-application-graph")
        .confidence("inferred")
        .authority("analyst-inference")
        .environment(Value::Null)
        .limitations(limitations)
        .links(evidence_links);
    DerivedEvidence {
        subject,
        observation,
    }
}

/// `subjectTarget`: the first PE subject among the inputs, else none.
fn subject_target(parsed: &ParsedManagedGraphInput) -> Option<SubjectTarget> {
    let subject = [
        parsed.artifact.as_ref(),
        parsed.members.as_ref(),
        parsed.boundaries.as_ref(),
    ]
    .into_iter()
    .flatten()
    .find_map(|input| {
        input
            .evidence
            .get("subject")
            .filter(|subject| !subject.is_null())
            .cloned()
    })?;
    if subject.get("format").and_then(Value::as_str) != Some("pe") {
        return None;
    }
    Some(SubjectTarget {
        path: subject
            .get("local_path")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        sha256: subject
            .get("digest")
            .and_then(|digest| digest.get("sha256"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        format: "pe".to_owned(),
        architecture: subject
            .get("architecture")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}
