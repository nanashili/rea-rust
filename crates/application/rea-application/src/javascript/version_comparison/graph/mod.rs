//! Authenticated application Evidence and graph facts used by version comparison.

mod source_validation;
mod validation;

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, value::RawValue};
use std::collections::{BTreeMap, BTreeSet};

const OPERATION: &str = "compare_application_versions";

#[derive(Clone, Debug)]
pub(super) struct ApplicationEvidence {
    pub evidence_id: String,
    pub subject_digest: String,
}

#[derive(Clone, Debug)]
pub(super) struct VersionSource {
    pub evidence_id: String,
    pub root_artifact_sha256: String,
    pub graph: ApplicationGraph,
}

#[derive(Clone, Debug)]
pub(super) struct ApplicationGraph {
    pub raw: Value,
    pub graph_id: String,
    pub root_node_ids: Vec<String>,
    pub nodes: Vec<ApplicationNode>,
    pub edges: Vec<ApplicationEdge>,
    pub coverage: GraphCoverage,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug)]
pub(super) struct ApplicationNode {
    pub raw: Value,
    pub node_id: String,
    pub kind: String,
    pub identity: Value,
    pub observations: Vec<NodeObservation>,
}

#[derive(Clone, Debug)]
pub(super) struct NodeObservation {
    pub raw: Value,
    pub observation_id: String,
    pub label: Option<String>,
    pub properties: Map<String, Value>,
    pub source_map_reference: Value,
    pub evidence: Value,
}

#[derive(Clone, Debug)]
pub(super) struct ApplicationEdge {
    pub raw: Value,
    pub edge_id: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub relation: String,
}

#[derive(Clone, Debug)]
pub(super) struct GraphCoverage {
    pub raw: Value,
    pub status: String,
    pub truncated: bool,
    pub omitted_count: Option<u64>,
    pub limits: Vec<Value>,
}

#[derive(Debug)]
struct ParsedSource {
    evidence_id: String,
    root_artifact_sha256: String,
    graph: ApplicationGraph,
}

pub(super) fn parse_application_source(
    raw: Box<RawValue>,
    side: &str,
) -> Result<VersionSource, Failure> {
    let record = EvidenceRecord::parse(&raw).map_err(|error| integrity_error(side, 0, error))?;
    let source = parse_supported_source(&record, side)?;
    Ok(VersionSource {
        evidence_id: source.evidence_id,
        root_artifact_sha256: source.root_artifact_sha256,
        graph: source.graph,
    })
}

fn parse_supported_source(record: &EvidenceRecord, side: &str) -> Result<ParsedSource, Failure> {
    let evidence: Value = serde_json::from_str(record.raw().get()).map_err(|error| {
        invalid(
            side,
            &format!("Evidence envelope is not representable: {error}"),
        )
    })?;
    let result: Value =
        serde_json::from_str(record.normalized_result().get()).map_err(|error| {
            invalid(
                side,
                &format!("Evidence result is not representable: {error}"),
            )
        })?;

    let operation = string_field(&evidence, "operation", side)?;
    match operation {
        "analyze_javascript_application" => {
            require_source_envelope(
                &evidence,
                "rea.javascript-application-analysis",
                "rea-javascript-application",
                "REA JavaScript application analyzer",
                "shipped-artifact",
                "derived",
                side,
            )?;
            parse_static_source(record, &evidence, &result, side)
        }
        "reconcile_javascript_runtime" => {
            require_source_envelope(
                &evidence,
                "rea.javascript-runtime-reconciliation",
                "rea-javascript-runtime-reconciliation",
                "REA JavaScript runtime reconciliation",
                "analyst-inference",
                "inferred",
                side,
            )?;
            parse_reconciliation_source(record, &evidence, &result, side)
        }
        "project_managed_application_graph" => {
            require_source_envelope(
                &evidence,
                "rea.managed-application-graph",
                "rea-dotnet-workflows",
                "REA managed-code workflows",
                "analyst-inference",
                "inferred",
                side,
            )?;
            parse_managed_source(record, &evidence, &result, side)
        }
        _ => Err(invalid(
            side,
            "Expected authenticated JavaScript analysis, runtime reconciliation, or managed application graph Evidence",
        )),
    }
}

fn require_source_envelope(
    evidence: &Value,
    expected_predicate: &str,
    expected_provider_id: &str,
    expected_provider_name: &str,
    expected_authority: &str,
    expected_confidence: &str,
    side: &str,
) -> Result<(), Failure> {
    if string_field(evidence, "predicate_type", side)? != expected_predicate {
        return Err(invalid(
            side,
            "Evidence predicate does not match its supported application graph operation",
        ));
    }
    if string_field(evidence, "authority", side)? != expected_authority
        || string_field(evidence, "confidence", side)? != expected_confidence
    {
        return Err(invalid(
            side,
            "Application graph Evidence authority or confidence is not supported",
        ));
    }

    let provider = evidence
        .get("provider")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(side, "Evidence provider must be an object"))?;
    if provider.get("id").and_then(Value::as_str) != Some(expected_provider_id)
        || provider.get("name").and_then(Value::as_str) != Some(expected_provider_name)
        || provider.get("version").and_then(Value::as_str) != Some("1")
    {
        return Err(invalid(
            side,
            "Evidence provider does not match its supported application graph operation",
        ));
    }

    Ok(())
}

fn parse_static_source(
    record: &EvidenceRecord,
    evidence: &Value,
    result: &Value,
    side: &str,
) -> Result<ParsedSource, Failure> {
    source_validation::static_result(result, side)?;

    let input_path = string_field(result, "input_path", side)?;
    let format = string_field(result, "format", side)?;
    if !matches!(format, "asar" | "directory") {
        return Err(invalid(
            side,
            "JavaScript application format is unsupported",
        ));
    }
    let root_artifact_sha256 = sha256_field(result, "root_artifact_sha256", side)?;
    let subject = evidence
        .get("subject")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(side, "JavaScript application Evidence requires a subject"))?;
    let subject_digest = subject
        .get("digest")
        .and_then(Value::as_object)
        .and_then(|digest| digest.get("sha256"))
        .and_then(Value::as_str);
    if subject_digest != Some(root_artifact_sha256.as_str())
        || subject.get("format").and_then(Value::as_str) != Some(format)
        || subject.get("local_path").and_then(Value::as_str) != Some(input_path)
    {
        return Err(invalid(
            side,
            "JavaScript application Evidence subject must match the artifact digest, format, and input path",
        ));
    }

    parse_graph_source(record, result, root_artifact_sha256, side)
}

fn parse_reconciliation_source(
    record: &EvidenceRecord,
    evidence: &Value,
    result: &Value,
    side: &str,
) -> Result<ParsedSource, Failure> {
    source_validation::runtime_result(result, side)?;

    require_result_links_within_envelope(evidence, result, side, 2)?;

    let application_layer = result
        .get("static_layers")
        .and_then(Value::as_array)
        .and_then(|layers| {
            layers
                .iter()
                .find(|layer| layer.get("role").and_then(Value::as_str) == Some("application"))
        })
        .ok_or_else(|| {
            invalid(
                side,
                "Runtime reconciliation must include its application layer",
            )
        })?;
    let root_artifact_sha256 = sha256_field(application_layer, "root_artifact_sha256", side)?;

    parse_graph_source(record, result, root_artifact_sha256, side)
}

fn parse_managed_source(
    record: &EvidenceRecord,
    evidence: &Value,
    result: &Value,
    side: &str,
) -> Result<ParsedSource, Failure> {
    source_validation::managed_result(result, side)?;

    require_result_links_within_envelope(evidence, result, side, 1)?;
    let root_artifact_sha256 = sha256_field(result, "root_artifact_sha256", side)?;

    parse_graph_source(record, result, root_artifact_sha256, side)
}

fn parse_graph_source(
    record: &EvidenceRecord,
    result: &Value,
    root_artifact_sha256: String,
    side: &str,
) -> Result<ParsedSource, Failure> {
    let graph_value = result
        .get("graph")
        .ok_or_else(|| invalid(side, "Application Evidence result has no graph"))?;
    let graph = validation::parse_graph(graph_value, side)?;

    Ok(ParsedSource {
        evidence_id: record.evidence_id().to_owned(),
        root_artifact_sha256,
        graph,
    })
}

fn require_result_links_within_envelope(
    evidence: &Value,
    result: &Value,
    side: &str,
    minimum_links: usize,
) -> Result<(), Failure> {
    let envelope_links = evidence
        .get("evidence_links")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(side, "Evidence envelope must contain evidence_links"))?;
    let result_links = result
        .get("evidence_links")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(side, "Application result must contain evidence_links"))?;
    if result_links.len() < minimum_links {
        return Err(invalid(
            side,
            "Application result contains too few Evidence links",
        ));
    }
    let envelope_ids = parse_evidence_link_ids(envelope_links, side, "evidence_links")?;
    let result_ids =
        parse_evidence_link_ids(result_links, side, "normalized_result.evidence_links")?;

    for evidence_id in result_ids {
        if !envelope_ids.contains(evidence_id) {
            return Err(invalid(
                side,
                "Application result references Evidence outside its envelope",
            ));
        }
    }

    Ok(())
}

fn parse_evidence_link_ids<'a>(
    links: &'a [Value],
    side: &str,
    field: &str,
) -> Result<BTreeSet<&'a str>, Failure> {
    links
        .iter()
        .map(|link| {
            link.as_str().ok_or_else(|| {
                invalid(
                    side,
                    &format!("{field} must contain only Evidence identifiers"),
                )
            })
        })
        .collect()
}

fn string_field<'a>(value: &'a Value, field: &str, path: &str) -> Result<&'a str, Failure> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(path, &format!("{field} must be a string")))
}

fn sha256_field(value: &Value, field: &str, path: &str) -> Result<String, Failure> {
    let digest = string_field(value, field, path)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(
            path,
            &format!("{field} must be a lowercase SHA-256 digest"),
        ));
    }
    Ok(digest.to_owned())
}

pub(super) fn invalid(path: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Application version comparison input is invalid. Check the arguments and retry.".into(),
        false,
        "Provide authenticated application graph Evidence records with valid graph commitments."
            .into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("path", Detail::Text(path.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}

pub(super) fn canonical_string(value: &Value, path: &str, field: &str) -> Result<String, Failure> {
    validation::canonical_string(value, path, field)
}

pub(super) fn validate_graph(value: &Value, path: &str) -> Result<(), Failure> {
    validation::parse_graph(value, path).map(|_| ())
}

pub(super) fn integrity_error(side: &str, index: usize, error: impl std::fmt::Display) -> Failure {
    Failure::new(
        "evidence_integrity_mismatch",
        "integrity_mismatch",
        "Evidence is invalid or has changed. Recreate or re-import it, then try again.".into(),
        false,
        "Recreate or re-import the Evidence, then retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("side", Detail::Text(side.into())),
            ("index", Detail::Count(index as u64)),
            ("reason", Detail::Text(error.to_string())),
        ]),
    )
}
