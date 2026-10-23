//! Session tool `compare_artifacts`: Evidence-backed deterministic comparison
//! of two artifact inventories.
//!
//! Compatibility owner: `src/server/registerArtifactComparisonTool.ts`
//! (handler flow), `src/domain/artifactComparison.ts` and its imports
//! (comparison semantics) and
//! `src/application/artifacts/ArtifactComparisonEvidence.ts` (summary
//! resolution). Returned Evidence satisfies the frozen `compare_artifacts`
//! `outputSchema`.

mod canonical;
mod compare;
mod identity;
mod inventory;
mod resolve;

// Reusable comparison surface for the investigation tools; the parent agent
// may consolidate these. Not every entry is used by this handler yet.
#[allow(unused_imports)]
pub(crate) use compare::{ArtifactComparison, compare_artifacts as compare_inventories};
#[allow(unused_imports)]
pub(crate) use inventory::{InventorySet, ParsedInventorySet, parse_artifact_inventory_evidence};

use crate::derived::{deliver, parse_evidence, run_derived_operation, with_session_admission};
use crate::workflow::record_derived_evidence;
use rea_analysis::ProviderIdentity;
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, Observation};
use rea_mcp::{Session, ToolContext, ToolOutput};
use serde_json::{Map, Value, json};
use std::sync::Arc;

/// `ARTIFACT_COMPARISON_PROVIDER`.
pub(crate) fn provider() -> ProviderIdentity {
    ProviderIdentity::new(
        "rea-artifact-comparison",
        "REA artifact comparison",
        Some("1".to_owned()),
    )
}

/// Handler for `compare_artifacts`.
pub fn compare_artifacts(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    with_session_admission(context, || run(context, &input))
}

struct Computed {
    left: Evidence,
    right: Evidence,
    comparison: ArtifactComparison,
}

fn run(context: &ToolContext<'_>, input: &Value) -> ToolOutput {
    let name = context.name();
    let session = context.session;

    // runDerivedOperation: parse, resolve and compare inside the guarded block.
    let computed = run_derived_operation(context, name, || compute(session, input));
    let Computed {
        left,
        right,
        comparison,
    } = match computed {
        Ok(value) => value,
        Err(error) => return ToolOutput::Failure(error),
    };

    // Record both sources in order; a rejection stops delivery.
    for source in [&left, &right] {
        if let Err(error) = session.record(source) {
            return ToolOutput::Failure(error);
        }
    }

    let left_evidence_ids = vec![left.id().to_owned()];
    let right_evidence_ids = vec![right.id().to_owned()];

    let limitations: Vec<String> = comparison.value["limitations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();

    let observation = Observation::new(
        name,
        json!({
            "left_evidence_ids": left_evidence_ids,
            "right_evidence_ids": right_evidence_ids,
        }),
        comparison.value.clone(),
    )
    .predicate("rea.artifact-comparison")
    .confidence("derived")
    .authority("analyst-inference")
    .limitations(limitations)
    .links([left_evidence_ids.clone(), right_evidence_ids.clone()].concat());

    let evidence = match Evidence::create(None, &provider().evidence_provider(), observation) {
        Ok(evidence) => evidence,
        Err(error) => return ToolOutput::Failure(AnalysisError::output(name, error.to_string())),
    };

    let unknown = artifact_unknown_input(&left, &right, &comparison.status, evidence.id());
    let recorded = record_derived_evidence(session, &evidence, unknown);
    deliver(evidence, recorded)
}

fn compute(session: &Arc<Session>, input: &Value) -> Result<Computed, AnalysisError> {
    let supplied_left = parse_evidence(&input["left"]).map_err(|error| {
        AnalysisError::evidence_integrity(crate::derived::evidence_failure_message(&error))
    })?;
    let supplied_right = parse_evidence(&input["right"]).map_err(|error| {
        AnalysisError::evidence_integrity(crate::derived::evidence_failure_message(&error))
    })?;
    let left = resolve::resolve(session, supplied_left)?;
    let right = resolve::resolve(session, supplied_right)?;

    let left_parsed: ParsedInventorySet =
        parse_artifact_inventory_evidence(std::slice::from_ref(&left))?;
    let right_parsed: ParsedInventorySet =
        parse_artifact_inventory_evidence(std::slice::from_ref(&right))?;

    let comparison = compare_inventories(
        &left_parsed.inventory,
        &right_parsed.inventory,
        &left_parsed.evidence_ids,
        &right_parsed.evidence_ids,
    )?;

    Ok(Computed {
        left,
        right,
        comparison,
    })
}

/// `artifactUnknownInput`: the residual question for a non-`unchanged`
/// comparison, or `None`.
fn artifact_unknown_input(
    left: &Evidence,
    right: &Evidence,
    status: &str,
    comparison_evidence_id: &str,
) -> Option<Value> {
    if status == "unchanged" {
        return None;
    }
    let left_id = left.id().to_owned();
    let right_id = right.id().to_owned();
    let contradictory = (status == "changed" || status == "contradiction") && left_id != right_id;

    let supporting: Vec<String> = if contradictory {
        vec![left_id.clone()]
    } else if left_id == right_id {
        // [...new Set([left_id, right_id])]
        vec![left_id.clone()]
    } else {
        vec![left_id.clone(), right_id.clone()]
    };
    let contradicting: Vec<String> = if contradictory {
        vec![right_id.clone()]
    } else {
        Vec::new()
    };

    let severity = if status == "unknown" || status == "truncated" {
        "high"
    } else {
        "medium"
    };

    let mut object = Map::new();
    object.insert(
        "question".into(),
        json!(format!(
            "Artifact comparison is {status} (comparison {comparison_evidence_id})"
        )),
    );
    object.insert("severity".into(), json!(severity));
    object.insert("domain".into(), json!("artifact-comparison"));
    object.insert("supporting_evidence_ids".into(), json!(supporting));
    object.insert("contradicting_evidence_ids".into(), json!(contradicting));
    object.insert("required_authority".into(), json!("shipped-artifact"));
    object.insert("required_confidence".into(), json!("observed"));
    object.insert("required_environment".into(), Value::Null);
    object.insert(
        "recommended_probes".into(),
        json!([{
            "operation": "inspect_artifact",
            "rationale": "Inspect both artifacts and compare their complete graphs.",
        }]),
    );
    object.insert("relationships".into(), json!([]));
    Some(Value::Object(object))
}
