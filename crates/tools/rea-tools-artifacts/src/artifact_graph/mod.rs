//! Artifact-graph provider tools: `inspect_artifact` and `extract_artifact`.
//!
//! Compatibility owners: `src/server/registerArtifactTools.ts`,
//! `src/artifacts/ArtifactProvider.ts` (the `ArtifactClient.execute` arms for
//! `inspect_artifact`, `extract_artifact` and the internal `inventory_artifact`
//! primitive), `src/contracts/artifactToolContracts.ts` and
//! `src/application/artifacts/ArtifactExtractionDestination.ts`.
//!
//! Scope and fail-closed boundary: the directory, ZIP-package and ASAR child
//! readers are ported in full. The macOS-only universal Mach-O (`lipo`) and
//! DMG (`hdiutil`) child readers are not ported; for those roots the provider
//! records the root hash and the exact TS unavailability limitation
//! (`inventoryCoverage`) instead of inventing child coverage, and extraction of
//! a Mach-O slice fails closed with an unavailable reader failure. This mirrors
//! the TS reader factory returning `undefined` when a reader is unavailable.
mod asar;
mod classify;
mod directory_reader;
mod extraction;
mod graph;
mod inspection;
mod scan;
mod zip_reader;

/// The shared reader contract (also implemented by the macOS readers).
use crate::artifact_reader as reader;

use crate::common::{
    self, ArtifactCause, Execution, ProviderCall, ProviderOutcome,
    ReaderFailure as CommonReaderFailure, artifact_graph_provider, source_or_path,
    translate_artifact_failure, without_detail,
};
use graph::ArtifactInventoryResult;
use rea_analysis::BinaryTarget;
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, Observation, SubjectTarget};
use rea_mcp::{Registry, ToolContext, ToolOutput};
use reader::ReaderFailure;
use serde_json::{Map, Value};

pub(crate) fn register(registry: &mut Registry) {
    registry.handle("inspect_artifact", inspect_artifact);
    registry.handle("extract_artifact", extract_artifact);
}

/// Translate a local reader failure into the common `ArtifactCause` so the
/// shared `translate_artifact_failure` projects the exact `ArtifactOperationError`.
fn to_cause(failure: ReaderFailure) -> ArtifactCause {
    ArtifactCause::Reader(CommonReaderFailure {
        reason: failure.reason,
        message: failure.message,
        details: failure.details,
        cleanup: failure.cleanup,
        partial_observation: None,
    })
}

/// `subjectFor(path, manifest)`.
fn subject_for(path: &str, inventory: &ArtifactInventoryResult) -> SubjectTarget {
    SubjectTarget {
        path: path.to_owned(),
        sha256: inventory.manifest.root_sha256.clone(),
        format: inventory.manifest.root_format.clone(),
        architecture: None,
    }
}

fn integrity_fail(parameters: &Map<String, Value>) -> bool {
    // Zod default is "fail"; the frozen inputSchema applies it before dispatch.
    parameters
        .get("integrity_policy")
        .and_then(Value::as_str)
        .map(|value| value == "fail")
        .unwrap_or(true)
}

/// `inspect_artifact`. Execution parameters drop the delivery-only `detail`;
/// Evidence parameters keep it. Delivery is a summary view when `detail` is
/// `"summary"`.
fn inspect_artifact(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let detail = input
        .get("detail")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let summary = detail.as_deref() == Some("summary");
    let execution_parameters = without_detail(&input);
    // Evidence identity keeps the explicit detail (inspect_artifact retains it).
    let evidence_parameters = input.clone();

    let call = ProviderCall {
        execution_parameters,
        evidence_parameters,
        summary,
        unavailable: None,
    };

    common::run_provider_tool(context, call, |target, parameters| {
        inspect_execute(context, target, parameters)
    })
}

fn inspect_execute(
    context: &ToolContext<'_>,
    target: &BinaryTarget,
    parameters: &Map<String, Value>,
) -> Result<ProviderOutcome, AnalysisError> {
    let fail = integrity_fail(parameters);
    let source_path = source_or_path(target).to_owned();

    context
        .progress
        .report("inspect_artifact.inventory", "inventory substep started");

    // inventory_artifact primitive (internal).
    let inventory = scan::inventory_artifact(&source_path, fail, &context.cancellation)
        .map_err(|failure| translate_artifact_failure("inspect_artifact", to_cause(failure)))?;

    let subject = subject_for(&source_path, &inventory);
    let inventory_value = common::to_value("inventory_artifact", &inventory)?;

    // Nested inventory_artifact Evidence (createEvidence, locations []).
    let inventory_parameters = Value::Object({
        let mut map = Map::new();
        map.insert(
            "integrity_policy".into(),
            parameters
                .get("integrity_policy")
                .cloned()
                .unwrap_or_else(|| Value::String("fail".into())),
        );
        map
    });
    let inventory_observation =
        Observation::new("inventory_artifact", inventory_parameters, inventory_value)
            .limitations(inventory.limitations.clone());
    let inventory_evidence = Evidence::create(
        Some(&subject),
        &artifact_graph_provider(),
        inventory_observation,
    )
    .map_err(|error| AnalysisError::output("inventory_artifact", error.to_string()))?;

    context
        .progress
        .report("inspect_artifact.inventory", "inventory substep completed");

    // createArtifactInspection over the inventory Evidence.
    let inspection = inspection::create_artifact_inspection(&inventory_evidence, &inventory);
    let limitations = inspection
        .get("limitations")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let mut execution = Execution::new(inspection, artifact_graph_provider());
    execution.limitations = limitations;
    execution.subject = Some(subject);

    // sourceEvidence = result.substeps[].evidence (the inventory Evidence).
    Ok(ProviderOutcome {
        execution,
        sources: vec![inventory_evidence],
    })
}

/// `extract_artifact`. Execution parameters add the REA-chosen `output_root`.
fn extract_artifact(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let mut execution_parameters = input.as_object().cloned().unwrap_or_default();
    let output_root = extraction::create_extraction_destination();
    execution_parameters.insert("output_root".into(), Value::String(output_root));
    let evidence_parameters = input.clone();

    let call = ProviderCall {
        execution_parameters,
        evidence_parameters,
        summary: false,
        unavailable: None,
    };

    common::run_provider_tool(context, call, |target, parameters| {
        extract_execute(context, target, parameters)
    })
}

fn extract_execute(
    context: &ToolContext<'_>,
    target: &BinaryTarget,
    parameters: &Map<String, Value>,
) -> Result<ProviderOutcome, AnalysisError> {
    let fail = integrity_fail(parameters);
    let output_root = parameters
        .get("output_root")
        .and_then(Value::as_str)
        .ok_or_else(|| AnalysisError::artifact_operation("extract_artifact", "io"))?
        .to_owned();
    let source_path = source_or_path(target).to_owned();
    let input_format = target.format.clone();

    let result = extraction::extract_artifact(
        &source_path,
        &input_format,
        &output_root,
        fail,
        &context.cancellation,
    )
    .map_err(|failure| {
        // A non-extractable format is a caller-selection (unsupported target)
        // failure, not an I/O fault; preserve the TS AnalysisUnsupportedTargetError.
        if failure.reason == "format"
            && failure
                .message
                .starts_with("Artifact format has no extraction reader")
        {
            return AnalysisError::unsupported_target(
                "extract_artifact",
                &source_path,
                failure.message.clone(),
            );
        }
        if failure.reason == "format" && failure.message.contains("is encrypted") {
            return AnalysisError::unsupported_target(
                "extract_artifact",
                &source_path,
                failure.message.clone(),
            );
        }
        translate_artifact_failure("extract_artifact", to_cause(failure))
    })?;

    // subject = subjectFor(sourcePath, result.manifest).
    let manifest = result.get("manifest").cloned().unwrap_or(Value::Null);
    let subject = SubjectTarget {
        path: source_path.clone(),
        sha256: manifest
            .get("root_sha256")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        format: manifest
            .get("root_format")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        architecture: None,
    };
    let limitations = result
        .get("limitations")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let mut execution = Execution::new(result, artifact_graph_provider());
    // rawResult: null (default), locations: [] (default).
    execution.limitations = limitations;
    execution.subject = Some(subject);
    Ok(ProviderOutcome::from(execution))
}
