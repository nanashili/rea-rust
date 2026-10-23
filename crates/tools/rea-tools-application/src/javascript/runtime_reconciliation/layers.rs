//! `parseStaticLayers` (`javascriptRuntimeReconciliationParsing.ts`).
//!
//! The complete `javascriptApplicationAnalysisResultSchema` has no native
//! owner; the shared application-graph revalidation
//! (`ledger_sources::parse_application_graph_evidence_unchecked`) checks the
//! graph and semantic commitments, and a failure is reported once at
//! `normalized_result` instead of the original's per-field Zod issues.
use super::{custom, digest, join, str_of};
use crate::javascript::graph_evidence;
use crate::ledger_sources;
use rea_core::analysis_error::InputIssue;
use serde_json::{Value, json};

pub struct Layer {
    pub layer_id: String,
    pub role: String,
    pub evidence: Value,
    pub runtime_mappings: Vec<Value>,
}

impl Layer {
    pub fn result(&self) -> &Value {
        &self.evidence["normalized_result"]
    }
    pub fn graph(&self) -> &Value {
        &self.evidence["normalized_result"]["graph"]
    }
    pub fn evidence_id(&self) -> &str {
        str_of(&self.evidence["evidence_id"])
    }
    pub fn nodes(&self) -> &[Value] {
        self.graph()["nodes"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
    }
    pub fn edges(&self) -> &[Value] {
        self.graph()["edges"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
    }
}

pub fn parse_static_layers(layers: &Value) -> Result<Vec<Layer>, Vec<InputIssue>> {
    let mut parsed = Vec::new();
    for (index, layer) in layers.as_array().into_iter().flatten().enumerate() {
        let path = [json!("static_layers"), json!(index), json!("analysis")];
        parsed.push(parse_static_layer(layer, &path)?);
    }
    parsed.sort_by(|left, right| left.layer_id.cmp(&right.layer_id));
    Ok(parsed)
}

/// `assertEvidenceIdentity` for the static analysis contract.
fn identity_matches(evidence: &Value) -> bool {
    let provider = &evidence["provider"];
    evidence["operation"] == "analyze_javascript_application"
        && evidence["predicate_type"] == "rea.javascript-application-analysis"
        && provider["id"] == "rea-javascript-application"
        && provider["name"] == "REA JavaScript application analyzer"
        && provider["version"] == "1"
        && evidence["authority"] == "shipped-artifact"
        && evidence["confidence"] == "derived"
}

fn parse_static_layer(layer: &Value, path: &[Value]) -> Result<Layer, Vec<InputIssue>> {
    let evidence = graph_evidence::parse_evidence_input(&layer["analysis"], path)?;
    let result = &evidence["normalized_result"];
    let result_valid = ledger_sources::parse_application_graph_evidence_unchecked(&evidence)
        .is_some()
        && matches!(result["format"].as_str(), Some("asar" | "directory"))
        && result["input_path"]
            .as_str()
            .is_some_and(|value| !value.is_empty());
    if !result_valid {
        return Err(vec![custom(
            &join(path, &[json!("normalized_result")]),
            "JavaScript application analysis result does not satisfy its schema or identifier commitments.",
        )]);
    }
    if !identity_matches(&evidence) {
        return Err(vec![custom(
            path,
            "Evidence does not match the supported analyze_javascript_application contract",
        )]);
    }
    let subject = &evidence["subject"];
    if subject.is_null()
        || subject["digest"]["sha256"] != result["root_artifact_sha256"]
        || subject["format"] != result["format"]
        || subject["local_path"] != result["input_path"]
    {
        return Err(vec![custom(
            &join(path, &[json!("subject")]),
            "JavaScript application Evidence subject disagrees with its result",
        )]);
    }
    let role = str_of(&layer["role"]).to_owned();
    let runtime_mappings = layer["runtime_mappings"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let layer_id = digest(&json!({
        "role": role,
        "evidence_id": evidence["evidence_id"],
        "runtime_mappings": runtime_mappings,
    }))
    .map(|digest| format!("jrl_{digest}"))
    .map_err(|_| {
        vec![custom(
            path,
            "Runtime reconciliation could not canonicalize data",
        )]
    })?;
    Ok(Layer {
        layer_id,
        role,
        evidence,
        runtime_mappings,
    })
}
