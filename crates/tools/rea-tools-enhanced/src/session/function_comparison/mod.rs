//! Session tool `compare_functions`: explicit Evidence-backed comparison of
//! two `analyze_function` observations.
//!
//! Compatibility owner: `src/server/registerFunctionComparisonTool.ts`
//! (handler flow) and `src/domain/functionComparison.ts` and its imports
//! (comparison semantics). Returned Evidence satisfies the frozen
//! `compare_functions` `outputSchema`.

mod canonical;
mod compare;
mod dimensions;
mod line_diff;
mod native_address;
mod normalization;
mod reference_comparison;
mod reference_compatibility;
mod results;
mod snapshot;

// Reusable comparison surface for the investigation tools; the parent agent
// may consolidate these. Not every entry is used by this handler yet.
#[allow(unused_imports)]
pub(crate) use compare::{
    FunctionComparison, compare_functions as compare_function_evidence, compare_snapshots,
};
#[allow(unused_imports)]
pub(crate) use snapshot::{FunctionSnapshot, parse_function_evidence, snapshot_from_evidence};

use crate::derived::{
    deliver, parse_evidence, record_sources, run_derived_operation, with_session_admission,
};
use crate::js::unique_sorted;
use crate::workflow::record_derived_evidence;
use rea_analysis::ProviderIdentity;
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, Observation};
use rea_mcp::{ToolContext, ToolOutput};
use serde_json::{Map, Value, json};

/// `FUNCTION_COMPARISON_PROVIDER`.
pub(crate) fn provider() -> ProviderIdentity {
    ProviderIdentity::new(
        "rea-function-comparison",
        "REA function comparison",
        Some("1".to_owned()),
    )
}

/// Handler for `compare_functions`.
pub fn compare_functions(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    with_session_admission(context, || run(context, &input))
}

fn run(context: &ToolContext<'_>, input: &Value) -> ToolOutput {
    let name = context.name();
    // parseEvidence both inputs; a failure becomes an EvidenceIntegrityError
    // with the original parser's message (toCallToolResult of err(...)).
    let left_evidence = match parse_evidence(&input["left"]) {
        Ok(evidence) => evidence,
        Err(error) => {
            return ToolOutput::Failure(AnalysisError::evidence_integrity(
                crate::derived::evidence_failure_message(&error),
            ));
        }
    };
    let right_evidence = match parse_evidence(&input["right"]) {
        Ok(evidence) => evidence,
        Err(error) => {
            return ToolOutput::Failure(AnalysisError::evidence_integrity(
                crate::derived::evidence_failure_message(&error),
            ));
        }
    };

    // Operation/predicate gate before any derivation.
    let left = left_evidence.value();
    let right = right_evidence.value();
    if left["operation"].as_str() != Some("analyze_function")
        || right["operation"].as_str() != Some("analyze_function")
        || left["predicate_type"].as_str() != Some("rea.analysis")
        || right["predicate_type"].as_str() != Some("rea.analysis")
    {
        return ToolOutput::Failure(AnalysisError::evidence_integrity(
            "Expected analyze_function Evidence",
        ));
    }

    let left_ids = vec![left_evidence.id().to_owned()];
    let right_ids = vec![right_evidence.id().to_owned()];

    // runDerivedOperation(compareFunctions(...)).
    let left_id = left_evidence.id().to_owned();
    let right_id = right_evidence.id().to_owned();
    let computed = run_derived_operation(context, name, || {
        let left_snapshot = snapshot_from_evidence(left_evidence.clone())?;
        let right_snapshot = snapshot_from_evidence(right_evidence.clone())?;
        compare_snapshots(left_snapshot, right_snapshot)
    });
    let comparison = match computed {
        Ok(comparison) => comparison,
        Err(error) => return ToolOutput::Failure(error),
    };

    // recordSessionEvidenceSources([left, right]).
    if let Err(error) = record_sources(context.session, &[&left_evidence, &right_evidence]) {
        return ToolOutput::Failure(error);
    }

    // createEvidence(undefined, FUNCTION_COMPARISON_PROVIDER, {...}).
    let observation = Observation::new(
        name,
        json!({
            "left_evidence_id": left_id,
            "right_evidence_id": right_id,
        }),
        comparison.value.clone(),
    )
    .predicate("rea.function-comparison")
    .confidence("derived")
    .authority("analyst-inference")
    .limitations(comparison.limitations.clone())
    .links([left_ids.clone(), right_ids.clone()].concat());

    let evidence = match Evidence::create(None, &provider().evidence_provider(), observation) {
        Ok(evidence) => evidence,
        Err(error) => return ToolOutput::Failure(AnalysisError::output(name, error.to_string())),
    };

    let unknown = comparison_unknown_input(&comparison, &left_ids, &right_ids, evidence.id());
    let recorded = record_derived_evidence(context.session, &evidence, unknown);
    deliver(evidence, recorded)
}

/// `comparisonUnknownInput`/`functionUnknownInput`: the residual question for a
/// non-`unchanged` comparison, or `None`.
fn comparison_unknown_input(
    comparison: &FunctionComparison,
    left_ids: &[String],
    right_ids: &[String],
    comparison_evidence_id: &str,
) -> Option<Value> {
    let status = comparison.status.as_str();
    if status == "unchanged" {
        return None;
    }

    let contradictory = status == "changed";

    let supporting: Vec<String> = if contradictory {
        let mut ids = left_ids.to_vec();
        ids.push(comparison_evidence_id.to_owned());
        ids
    } else {
        let mut seen = std::collections::HashSet::new();
        let mut ids = Vec::new();
        for id in left_ids
            .iter()
            .chain(right_ids.iter())
            .cloned()
            .chain(std::iter::once(comparison_evidence_id.to_owned()))
        {
            if seen.insert(id.clone()) {
                ids.push(id);
            }
        }
        ids
    };

    let contradicting: Vec<String> = if contradictory {
        right_ids
            .iter()
            .filter(|id| !left_ids.contains(id))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };

    let mut dimension_inputs: Vec<String> = Vec::new();
    if status == "unknown" || comparison.reported_dimensions.is_empty() {
        dimension_inputs.push("overall".to_owned());
    }
    dimension_inputs.extend(comparison.reported_dimensions.iter().cloned());
    let dimensions = unique_sorted(dimension_inputs);

    let severity = if status == "changed" {
        "medium"
    } else {
        "high"
    };

    let mut object = Map::new();
    object.insert(
        "question".into(),
        json!(format!(
            "Function comparison is {status} (comparison {comparison_evidence_id})"
        )),
    );
    object.insert("severity".into(), json!(severity));
    object.insert("domain".into(), json!("function-comparison"));
    object.insert(
        "comparison_conclusion_scope".into(),
        json!({
            "comparison_evidence_id": comparison_evidence_id,
            "dimensions": dimensions,
        }),
    );
    object.insert("supporting_evidence_ids".into(), json!(supporting));
    object.insert("contradicting_evidence_ids".into(), json!(contradicting));
    object.insert("required_authority".into(), json!("shipped-artifact"));
    object.insert("required_confidence".into(), json!("observed"));
    object.insert("required_environment".into(), Value::Null);
    object.insert(
        "recommended_probes".into(),
        json!([{
            "operation": "analyze_function",
            "rationale": "Capture complete dossiers for both functions under the same target context.",
        }]),
    );
    object.insert("relationships".into(), json!([]));
    Some(Value::Object(object))
}
