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

use crate::derived::{run_derived_operation, with_session_admission};
use rea_analysis::ProviderIdentity;
use rea_application::javascript::graph::json::{self, Json, Obj};
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::record::EvidenceRecord;
use rea_mcp::{Session, ToolContext, ToolOutput};
use serde_json::{Value, value::RawValue};
use std::sync::Arc;

/// `ARTIFACT_COMPARISON_PROVIDER`.
pub(crate) fn provider() -> ProviderIdentity {
    ProviderIdentity::new(
        "rea-artifact-comparison",
        "REA artifact comparison",
        Some("1".to_owned()),
    )
}

const SUBJECT_UNAVAILABLE: &str = "Artifact identity is unavailable for this observation.";

/// Handler for `compare_artifacts`.
pub fn compare_artifacts(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let raw = match serde_json::value::to_raw_value(&input) {
        Ok(raw) => raw,
        Err(error) => {
            return ToolOutput::Failure(AnalysisError::evidence_integrity(error.to_string()));
        }
    };
    compare_artifacts_raw(context, &raw)
}

struct Computed {
    left: EvidenceRecord,
    right: EvidenceRecord,
    comparison: ArtifactComparison,
}

/// Raw MCP handler preserving exact Evidence strings through authentication,
/// summary resolution, comparison and delivery.
pub fn compare_artifacts_raw(context: &ToolContext<'_>, input: &RawValue) -> ToolOutput {
    with_session_admission(context, || run_raw(context, input))
}

fn run_raw(context: &ToolContext<'_>, input: &RawValue) -> ToolOutput {
    let name = context.name();
    let session = context.session;

    let arguments = match validate_arguments(context, input) {
        Ok(arguments) => arguments,
        Err(error) => return ToolOutput::Failure(error),
    };

    let computed = run_derived_operation(context, name, || compute(session, &arguments));
    let Computed {
        left,
        right,
        comparison,
    } = match computed {
        Ok(value) => value,
        Err(error) => return ToolOutput::Failure(error),
    };

    if let Err(error) = record_sources(session, [&left, &right]) {
        return ToolOutput::Failure(error);
    }

    let evidence = match create_comparison_evidence(name, &left, &right, &comparison) {
        Ok(evidence) => evidence,
        Err(error) => return ToolOutput::Failure(error),
    };

    match record_comparison_evidence(session, &left, &right, &comparison.status, evidence) {
        Ok(evidence) => ToolOutput::RawEvidence(evidence),
        Err(error) => ToolOutput::Failure(error),
    }
}

fn validate_arguments(context: &ToolContext<'_>, input: &RawValue) -> Result<Json, AnalysisError> {
    let arguments = json::parse(input.get()).map_err(|error| {
        AnalysisError::input_message(context.name(), error.to_string(), Vec::new())
    })?;
    rea_application::javascript::application_view_validation::parse_input_for_operation(
        context.name(),
        &arguments,
        context.contract.input_schema(),
    )
}

fn record_sources<const N: usize>(
    session: &Session,
    sources: [&EvidenceRecord; N],
) -> Result<(), AnalysisError> {
    for source in sources {
        session.record_raw(source.raw())?;
    }
    Ok(())
}

fn create_comparison_evidence(
    operation: &str,
    left: &EvidenceRecord,
    right: &EvidenceRecord,
    comparison: &ArtifactComparison,
) -> Result<EvidenceRecord, AnalysisError> {
    let left_id = left.evidence_id().to_owned();
    let right_id = right.evidence_id().to_owned();
    let links = vec![left_id.clone(), right_id.clone()];
    let provider = provider().evidence_provider();
    let limitations = Json::array(
        std::iter::once(Json::from(SUBJECT_UNAVAILABLE))
            .chain(comparison.value.at("limitations").arr().iter().cloned())
            .collect(),
    );
    let unsigned: Json = Obj::new()
        .with("subject", Json::Null)
        .with(
            "provider",
            Obj::new()
                .with("id", provider.id)
                .with("name", provider.name)
                .with("version", provider.version),
        )
        .with("analysis_profile", Json::Null)
        .with("predicate_type", "rea.artifact-comparison")
        .with("operation", operation)
        .with(
            "parameters",
            Obj::new()
                .with("left_evidence_ids", json::strings([left_id]))
                .with("right_evidence_ids", json::strings([right_id])),
        )
        .with("raw_result", Json::Null)
        .with("normalized_result", comparison.value.clone())
        .with("confidence", "derived")
        .with("authority", "analyst-inference")
        .with("environment", Json::Null)
        .with("limitations", limitations)
        .with("relationship_coverage", Json::Null)
        .with("locations", Vec::<Json>::new())
        .with("evidence_links", json::strings(links))
        .into();
    let unsigned_raw = RawValue::from_string(unsigned.stringify())
        .map_err(|error| AnalysisError::output(operation, error.to_string()))?;
    EvidenceRecord::create_unsigned(&unsigned_raw)
        .map_err(|error| AnalysisError::output(operation, error.to_string()))
}

fn record_comparison_evidence(
    session: &Session,
    left: &EvidenceRecord,
    right: &EvidenceRecord,
    status: &str,
    evidence: EvidenceRecord,
) -> Result<EvidenceRecord, AnalysisError> {
    let unknown = artifact_unknown_input(left, right, status, evidence.evidence_id());
    match unknown {
        None => session.record_raw(evidence.raw())?,
        Some(unknown) => {
            let unknown_raw = RawValue::from_string(unknown.stringify())
                .map_err(|error| AnalysisError::output("compare_artifacts", error.to_string()))?;
            session
                .records()
                .record_evidence_with_unknown(evidence.raw(), &unknown_raw)
                .map_err(rea_mcp::session::record_error)?;
        }
    }
    Ok(evidence)
}

fn compute(session: &Arc<Session>, input: &Json) -> Result<Computed, AnalysisError> {
    let supplied_left = authenticate_input_evidence(input.at("left"))?;
    let supplied_right = authenticate_input_evidence(input.at("right"))?;
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
fn authenticate_input_evidence(input: &Json) -> Result<EvidenceRecord, AnalysisError> {
    let raw = RawValue::from_string(input.stringify())
        .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))?;
    EvidenceRecord::parse(&raw).map_err(|error| {
        AnalysisError::evidence_integrity(crate::derived::evidence_failure_message(&error))
    })
}

fn artifact_unknown_input(
    left: &EvidenceRecord,
    right: &EvidenceRecord,
    status: &str,
    comparison_evidence_id: &str,
) -> Option<Json> {
    if status == "unchanged" {
        return None;
    }
    let left_id = left.evidence_id().to_owned();
    let right_id = right.evidence_id().to_owned();
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

    Some(
        Obj::new()
            .with(
                "question",
                format!("Artifact comparison is {status} (comparison {comparison_evidence_id})"),
            )
            .with("severity", severity)
            .with("domain", "artifact-comparison")
            .with("supporting_evidence_ids", json::strings(supporting))
            .with("contradicting_evidence_ids", json::strings(contradicting))
            .with("required_authority", "shipped-artifact")
            .with("required_confidence", "observed")
            .with("required_environment", Json::Null)
            .with(
                "recommended_probes",
                vec![
                    Obj::new()
                        .with("operation", "inspect_artifact")
                        .with(
                            "rationale",
                            "Inspect both artifacts and compare their complete graphs.",
                        )
                        .into(),
                ],
            )
            .with("relationships", Vec::<Json>::new())
            .into(),
    )
}
