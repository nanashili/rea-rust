//! `compare_managed_members`.
//!
//! Compatibility owners:
//! `src/server/registerManagedWorkflowTools/compareManagedMembers.ts`,
//! `src/application/managed/ManagedMemberComparisonService.ts`
//! (`compareManagedMembersEvidenceValidated` + `createManagedMemberComparisonEvidence`),
//! and `src/domain/managed/managedMemberComparison.ts` plus its helpers
//! (`managedMemberComparisonMatch.ts`, `managedMemberComparisonItems.ts`,
//! `managedMemberComparisonCoverage.ts`, `managedMemberSignatureIdentity.ts`).
//!
//! The registration layer accepts two inline Evidence records (`left`, `right`),
//! each the full `evidenceSchema`. It authenticates both as
//! `inspect_managed_members` observations, records them as sources in order,
//! then records one derived `rea.managed-member-comparison` Evidence. When the
//! comparison summary leaves any member unknown, an automatic residual question
//! is attached atomically with the derived record.
mod coverage;
mod items;
mod matching;
mod signature;

use super::error::{DomainError, classify};
use super::inspection::{self, InspectionKind};
use super::unknown::{Probe, WorkflowUnknown, workflow_unknown_input};
use crate::common::create_evidence;
use items::ItemContext;
use rea_core::evidence::envelope::Observation;
use rea_mcp::{ToolContext, ToolOutput};
use serde_json::{Map, Value, json};
use std::collections::HashSet;

const OPERATION: &str = "compare_managed_members";

pub fn handle(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    // `resolveManagedEvidence(input.left)` / `(input.right)`: authenticate each
    // record at the registration boundary and require `inspect_managed_members`.
    let left_value = input.get("left").cloned().unwrap_or(Value::Null);
    let right_value = input.get("right").cloned().unwrap_or(Value::Null);

    // `compareManagedMembersReferenceInputSchema.superRefine`: the frozen JSON
    // Schema cannot express cross-field distinctness, so the SDK
    // input-validation failure is reproduced before any Evidence resolution.
    if left_value.get("evidence_id") == right_value.get("evidence_id") {
        return crate::common::refinement_failure(
            OPERATION,
            vec![crate::common::Refinement::new(
                vec![json!("right")],
                "Managed member Evidence must be distinct",
            )],
        );
    }

    let left_record = match super::resolve_expected(&left_value, Some("inspect_managed_members")) {
        Ok(record) => record,
        Err(error) => return ToolOutput::Failure(error),
    };
    let right_record = match super::resolve_expected(&right_value, Some("inspect_managed_members"))
    {
        Ok(record) => record,
        Err(error) => return ToolOutput::Failure(error),
    };

    // `compareManagedMembersEvidenceValidated(parsed)`.
    let derived = match compare_members(&left_record, &right_record) {
        Ok(derived) => derived,
        Err(error) => return ToolOutput::Failure(classify(OPERATION, error)),
    };

    // `recordSessionEvidenceSources(recordEvidence, [parsed.left, parsed.right])`.
    if let Err(error) = super::record_sources(context.session, &[&left_record, &right_record]) {
        return ToolOutput::Failure(error);
    }

    // Build the automatic residual question when any member is unknown.
    let unknown_count = derived
        .result
        .get("summary")
        .and_then(|summary| summary.get("unknown"))
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let evidence = match create_evidence(
        OPERATION,
        None,
        &crate::common::managed_workflow_provider(),
        derived.observation,
    ) {
        Ok(evidence) => evidence,
        Err(error) => return ToolOutput::Failure(error),
    };

    let unknown = if unknown_count > 0 {
        match workflow_unknown_input(evidence.id(), member_comparison_unknown()) {
            Ok(value) => Some(value),
            Err(error) => return ToolOutput::Failure(error),
        }
    } else {
        None
    };

    super::deliver(context.session, evidence, unknown)
}

/// The automatic residual question `compareManagedMembers.ts` builds.
fn member_comparison_unknown() -> WorkflowUnknown {
    WorkflowUnknown {
        question: "Which managed members remain unmatched or ambiguous across these versions?",
        severity: "medium",
        domain: "managed-member-comparison",
        required_authority: "shipped-artifact",
        required_confidence: "observed",
        recommended_probes: vec![Probe {
            operation: "inspect_managed_members",
            rationale: "Review the inspection Evidence coverage and limit diagnostics; this operation has no page override, so unresolved members must remain unknown.",
        }],
    }
}

struct DerivedComparison {
    result: Value,
    observation: Observation,
}

/// `compareManagedMembersEvidenceValidated` + `compareManagedMembers` +
/// `createManagedMemberComparisonEvidence`.
fn compare_members(
    left_record: &Value,
    right_record: &Value,
) -> Result<DerivedComparison, DomainError> {
    // `parseManagedMemberEvidence`: re-authenticate and normalize each side.
    let left = inspection::parse(
        left_record,
        "inspect_managed_members",
        InspectionKind::Members,
    )?;
    let right = inspection::parse(
        right_record,
        "inspect_managed_members",
        InspectionKind::Members,
    )?;

    let result = compare(
        &left.evidence_id,
        &left.result,
        &right.evidence_id,
        &right.result,
    )?;

    // `createManagedMemberComparisonEvidence(input, result)` with no source paths.
    let parameters = json!({
        "left_evidence_id": left.evidence_id,
        "right_evidence_id": right.evidence_id,
    });
    let limitations = string_vec(result.get("limitations"));
    let evidence_links = string_vec(result.get("evidence_links"));
    let observation = Observation::new(OPERATION, parameters, result.clone())
        .predicate("rea.managed-member-comparison")
        .confidence("inferred")
        .authority("analyst-inference")
        .environment(Value::Null)
        .limitations(limitations)
        .locations(Vec::new())
        .links(evidence_links);

    Ok(DerivedComparison {
        result,
        observation,
    })
}

/// `selectedTypes(result)`: declaring-type selection as a set, or `None`.
fn selected_types(result: &Value) -> Option<HashSet<String>> {
    let selection = result.get("selection")?;
    if selection.is_null() {
        return None;
    }
    Some(
        selection
            .get("type_names")
            .and_then(Value::as_array)
            .map(|names| {
                names
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
    )
}

fn metadata_complete(result: &Value) -> bool {
    result
        .get("metadata")
        .and_then(|metadata| metadata.get("status"))
        .and_then(Value::as_str)
        == Some("complete")
}

/// `compareManagedMembers(left, right)`.
fn compare(
    left_id: &str,
    left_result: &Value,
    right_id: &str,
    right_result: &Value,
) -> Result<Value, DomainError> {
    let member_matches = matching::key_members(left_result, right_result)?;

    let signature_resolution_examined = signature::has_signature_resolution(left_result)
        && signature::has_signature_resolution(right_result);
    let context = ItemContext {
        left_evidence_id: left_id.to_owned(),
        right_evidence_id: right_id.to_owned(),
        left_complete: metadata_complete(left_result),
        right_complete: metadata_complete(right_result),
        left_selection: selected_types(left_result),
        right_selection: selected_types(right_result),
        signature_resolution_examined,
    };

    let method_items = items::build_method_items(&member_matches.method_matches, &context)?;
    let field_items = items::build_field_items(&member_matches.field_matches, &context)?;
    let mut all_items: Vec<Value> = Vec::with_capacity(method_items.len() + field_items.len());
    all_items.extend(method_items.iter().cloned());
    all_items.extend(field_items.iter().cloned());

    let summary = coverage::build_summary(&all_items);
    let matching_tally = coverage::build_matching(&method_items, &field_items);
    let comparison_coverage = coverage::build_coverage(left_result, right_result);
    let limitations = coverage::comparison_limitations(left_result, right_result);

    let comparison_id = format!(
        "mmc_{}",
        matching::sha256(&json!({
            "left": left_id,
            "right": right_id,
            "methods": method_items,
            "fields": field_items,
        }))?
    );

    // Build the result object in the exact TS literal key order.
    let mut result = Map::new();
    result.insert("comparison_id".into(), json!(comparison_id));
    result.insert(
        "algorithm".into(),
        json!({
            "name": "rea-managed-member-comparison",
            "token_identity": "build-local",
            "name_matching": "exact-signature-fallback",
        }),
    );
    result.insert("left".into(), coverage::side_manifest(left_id, left_result));
    result.insert(
        "right".into(),
        coverage::side_manifest(right_id, right_result),
    );
    result.insert("summary".into(), summary);
    result.insert("matching".into(), matching_tally);
    result.insert("methods".into(), Value::Array(method_items));
    result.insert("fields".into(), Value::Array(field_items));
    result.insert("coverage".into(), comparison_coverage);
    result.insert("evidence_links".into(), json!([left_id, right_id]));
    result.insert(
        "limitations".into(),
        Value::Array(limitations.into_iter().map(Value::String).collect()),
    );
    Ok(Value::Object(result))
}

/// Strings of an array value, matching `result.limitations`/`evidence_links`.
fn string_vec(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
