//! Authenticated JavaScript Application Graph Evidence sources.
//!
//! Compatibility owners: `parseApplicationGraphEvidence` and
//! `parseNativeApplicationEvidence` in
//! `src/application/javascript/JavaScriptApplicationEvidenceGraph.ts`, and
//! `resolveEvidenceInput` in `src/application/EvidenceInputResolver.ts`.
//!
//! The envelope rules (authentication, operation, predicate, provider,
//! authority and confidence, analysis parameters, subject identity, link
//! containment and application layer) are ported with the original issue
//! paths and messages. The complete Zod result schemas have no native owner;
//! the graph, node, observation, edge, evidence-context and semantic-binding
//! commitments are revalidated instead, and any failure is reported at
//! `normalized_result`.
use crate::ledger_sources;
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::evidence::record::{EvidenceRecord, EvidenceRecordError};
use rea_mcp::ToolContext;
use serde_json::{Value, json};

/// `ApplicationGraphEvidenceSource`.
pub struct GraphSource {
    pub evidence: Value,
    pub graph: Value,
    pub root_artifact_sha256: String,
    pub semantic_graph: Option<Value>,
}

impl GraphSource {
    pub fn evidence_id(&self) -> &str {
        self.evidence["evidence_id"].as_str().unwrap_or_default()
    }
}

const APPLICATION_PROVIDER: (&str, &str) = (
    "rea-javascript-application",
    "REA JavaScript application analyzer",
);
const RECONCILIATION_PROVIDER: (&str, &str) = (
    "rea-javascript-runtime-reconciliation",
    "REA JavaScript runtime reconciliation",
);
const MANAGED_PROVIDER: (&str, &str) = ("rea-dotnet-workflows", "REA managed-code workflows");

/// `applicationGraphEvidenceInputError(operation, failure)`.
pub fn input_error(operation: &str, issues: Vec<InputIssue>) -> AnalysisError {
    AnalysisError::input(operation, issues)
}

fn issue(path: &[Value], field: &str, message: impl Into<String>) -> InputIssue {
    let mut full = path.to_vec();
    full.push(Value::String(field.into()));
    InputIssue {
        path: full,
        reason: "invalid_value",
        message: Some(message.into()),
        expected: None,
        minimum: None,
        maximum: None,
    }
}

/// `parseEvidence`: authenticate the complete envelope.
pub fn parse_evidence_input(input: &Value, path: &[Value]) -> Result<Value, Vec<InputIssue>> {
    let raw = serde_json::value::to_raw_value(input)
        .map_err(|error| vec![issue(path, "evidence_id", error.to_string())])?;
    match EvidenceRecord::parse(&raw) {
        Ok(_) => Ok(input.clone()),
        Err(EvidenceRecordError::SemanticIdMismatch) => Err(vec![issue(
            path,
            "evidence_id",
            "Evidence semantic identifier does not match its record",
        )]),
        Err(other) => Err(vec![InputIssue {
            path: path.to_vec(),
            reason: "invalid_value",
            message: Some(other.to_string()),
            expected: None,
            minimum: None,
            maximum: None,
        }]),
    }
}

/// `parseApplicationGraphEvidence(input, path)`.
pub fn parse_application_graph_evidence(
    input: &Value,
    path: &[Value],
) -> Result<GraphSource, Vec<InputIssue>> {
    let evidence = parse_evidence_input(input, path)?;
    let operation = evidence["operation"].as_str().unwrap_or_default();
    match operation {
        "analyze_javascript_application" => {
            require_predicate(&evidence, "rea.javascript-application-analysis", path)?;
            require_provider(&evidence, APPLICATION_PROVIDER, path)?;
            static_application_source(evidence, path)
        }
        "reconcile_javascript_runtime" => {
            require_predicate(&evidence, "rea.javascript-runtime-reconciliation", path)?;
            require_provider(&evidence, RECONCILIATION_PROVIDER, path)?;
            inferred_source(evidence, path, "Runtime reconciliation", true)
        }
        "project_managed_application_graph" => {
            require_predicate(&evidence, "rea.managed-application-graph", path)?;
            require_provider(&evidence, MANAGED_PROVIDER, path)?;
            inferred_source(evidence, path, "Managed application graph", false)
        }
        _ => Err(vec![issue(
            path,
            "operation",
            "Expected authenticated JavaScript analysis, runtime reconciliation, or managed application graph Evidence.",
        )]),
    }
}

fn require_predicate(
    evidence: &Value,
    expected: &str,
    path: &[Value],
) -> Result<(), Vec<InputIssue>> {
    if evidence["predicate_type"].as_str() == Some(expected) {
        return Ok(());
    }
    Err(vec![issue(
        path,
        "predicate_type",
        format!(
            "Expected predicate {expected} for operation {}.",
            evidence["operation"].as_str().unwrap_or_default()
        ),
    )])
}

fn require_provider(
    evidence: &Value,
    (id, name): (&str, &str),
    path: &[Value],
) -> Result<(), Vec<InputIssue>> {
    let provider = &evidence["provider"];
    if provider["id"] == id && provider["name"] == name && provider["version"] == "1" {
        return Ok(());
    }
    Err(vec![issue(
        path,
        "provider",
        format!(
            "Expected provider {id} v1 for operation {}.",
            evidence["operation"].as_str().unwrap_or_default()
        ),
    )])
}

fn result_path(path: &[Value]) -> Vec<Value> {
    let mut full = path.to_vec();
    full.push(json!("normalized_result"));
    full
}

fn invalid_result(path: &[Value]) -> Vec<InputIssue> {
    vec![InputIssue {
        path: result_path(path),
        reason: "invalid_value",
        message: Some(
            "Application graph result does not satisfy its schema or identifier commitments."
                .into(),
        ),
        expected: None,
        minimum: None,
        maximum: None,
    }]
}

fn static_application_source(
    evidence: Value,
    path: &[Value],
) -> Result<GraphSource, Vec<InputIssue>> {
    let Some(source) = ledger_sources::parse_application_graph_evidence_unchecked(&evidence) else {
        return Err(invalid_result(path));
    };
    let (graph, root, semantic) = (
        source.graph.clone(),
        source.root_artifact_sha256.to_owned(),
        source.semantic_graph.cloned(),
    );
    if evidence["authority"] != "shipped-artifact" || evidence["confidence"] != "derived" {
        return Err(vec![issue(
            path,
            "authority",
            "JavaScript application Evidence must use shipped-artifact authority and derived confidence.",
        )]);
    }
    validate_analysis_parameters(&evidence, path)?;
    let result = &evidence["normalized_result"];
    let subject = &evidence["subject"];
    if subject.is_null()
        || subject["digest"]["sha256"] != result["root_artifact_sha256"]
        || subject["format"] != result["format"]
        || subject["local_path"] != result["input_path"]
    {
        return Err(vec![issue(
            path,
            "subject",
            "JavaScript application Evidence subject must match the analyzed artifact identity and input path.",
        )]);
    }
    Ok(GraphSource {
        evidence,
        graph,
        root_artifact_sha256: root,
        semantic_graph: semantic,
    })
}

/// `analyzeJavaScriptApplicationInputSchema.parse({ input_path, ...parameters })`.
fn validate_analysis_parameters(evidence: &Value, path: &[Value]) -> Result<(), Vec<InputIssue>> {
    let mut parameters_path = path.to_vec();
    parameters_path.push(json!("parameters"));
    let Some(parameters) = evidence["parameters"].as_object() else {
        return Err(vec![InputIssue {
            path: parameters_path,
            reason: "invalid_type",
            message: None,
            expected: Some(json!("object")),
            minimum: None,
            maximum: None,
        }]);
    };
    const FIELDS: &[&str] = &[
        "input_path",
        "format",
        "integrity_policy",
        "source_paths",
        "max_semantic_nodes",
        "max_semantic_nodes_per_file",
        "max_semantic_unknowns",
        "max_semantic_unknowns_per_file",
        "max_heap_mb",
        "analysis_timeout_ms",
    ];
    let unknown: Vec<InputIssue> = parameters
        .keys()
        .filter(|key| !FIELDS.contains(&key.as_str()))
        .map(|key| {
            let mut full = parameters_path.clone();
            full.push(json!(key));
            InputIssue {
                path: full,
                reason: "unknown_argument",
                message: None,
                expected: None,
                minimum: None,
                maximum: None,
            }
        })
        .collect();
    if !unknown.is_empty() {
        return Err(unknown);
    }
    Ok(())
}

fn inferred_source(
    evidence: Value,
    path: &[Value],
    label: &str,
    runtime: bool,
) -> Result<GraphSource, Vec<InputIssue>> {
    if evidence["authority"] != "analyst-inference" || evidence["confidence"] != "inferred" {
        return Err(vec![issue(
            path,
            "authority",
            format!(
                "{label} Evidence must use analyst-inference authority and inferred confidence."
            ),
        )]);
    }
    let result = &evidence["normalized_result"];
    let Some(source) = ledger_sources::parse_application_graph_evidence_unchecked(&evidence) else {
        return Err(invalid_result(path));
    };
    let (graph, root) = (source.graph.clone(), source.root_artifact_sha256.to_owned());
    let envelope = evidence["evidence_links"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if let Some(unmatched) = result["evidence_links"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|link| !envelope.contains(link))
    {
        return Err(vec![issue(
            &result_path(path),
            "evidence_links",
            format!(
                "{label} result references Evidence {} outside its envelope.",
                unmatched.as_str().unwrap_or_default()
            ),
        )]);
    }
    if runtime
        && !result["static_layers"]
            .as_array()
            .is_some_and(|layers| layers.iter().any(|layer| layer["role"] == "application"))
    {
        return Err(vec![issue(
            &result_path(path),
            "static_layers",
            "Runtime reconciliation Evidence must include its application layer.",
        )]);
    }
    Ok(GraphSource {
        evidence,
        graph,
        root_artifact_sha256: root,
        semantic_graph: None,
    })
}

/// `parseNativeApplicationEvidence(inputs, path)`.
pub fn parse_native_application_evidence(
    inputs: &[Value],
    path: &[Value],
) -> Result<Vec<Value>, Vec<InputIssue>> {
    let mut parsed = Vec::with_capacity(inputs.len());
    for (index, input) in inputs.iter().enumerate() {
        let mut item = path.to_vec();
        item.push(json!(index));
        parsed.push(parse_evidence_input(input, &item)?);
    }
    if let Some(index) = parsed
        .iter()
        .position(|evidence| evidence["subject"].is_null())
    {
        let mut item = path.to_vec();
        item.push(json!(index));
        return Err(vec![issue(
            &item,
            "subject",
            "Native handoff Evidence requires an artifact subject.",
        )]);
    }
    let mut ids = std::collections::HashSet::new();
    if !parsed
        .iter()
        .all(|evidence| ids.insert(evidence["evidence_id"].as_str().unwrap_or_default()))
    {
        return Err(vec![issue(
            path,
            "evidence_id",
            "Native handoff Evidence must be unique.",
        )]);
    }
    Ok(parsed)
}

/// `resolveEvidenceInput`: inline Evidence is returned as-is; a retained
/// reference resolves from this session's ledger.
pub fn resolve_evidence_input(
    context: &ToolContext<'_>,
    input: &Value,
) -> Result<Value, AnalysisError> {
    if input.get("kind").is_none() {
        return Ok(input.clone());
    }
    let evidence_id = input["evidence_id"].as_str().unwrap_or_default();
    let Some(record) = context.session.evidence(evidence_id) else {
        return Err(AnalysisError::evidence_reference(
            evidence_id,
            "missing",
            "Evidence retained in this session",
            None,
        ));
    };
    let actual = record["evidence_id"].as_str().map(str::to_owned);
    if actual.as_deref() != Some(evidence_id) {
        return Err(AnalysisError::evidence_reference(
            evidence_id,
            "identity_mismatch",
            evidence_id,
            actual,
        ));
    }
    Ok(record)
}
