//! Public JavaScript reconstruction boundary and artifact-reader lifecycle.

use rea_application::javascript::{
    application::OPERATION,
    graph::{SemanticLimits, json::parse},
    semantic::value_types::JsString,
    workflow::{WorkflowInterruption, WorkflowResult, reconstruct},
};
use rea_core::analysis_error::{AnalysisError, CapturedOutput, cleanup::with_cleanup_failure};
use rea_mcp::{Registry, ToolContext, ToolOutput};
use rea_tools_artifacts::{
    JavaScriptArtifactReaderHandle, ReaderFailure, inventory_for_javascript,
    open_javascript_artifact_reader_for_analysis, translate_javascript_reader_failure,
};
use serde_json::Value;

use super::reconstruction_evidence::{self, ReconstructionEvidenceInput};

pub(crate) fn register(registry: &mut Registry) {
    registry.handle(OPERATION, analyze);
}

fn analyze(context: &ToolContext<'_>, mut input: Value) -> ToolOutput {
    apply_defaults(&mut input);

    let completed = match reconstruct_application(context, &input) {
        Ok(completed) => completed,
        Err(error) => return ToolOutput::Failure(error),
    };

    let parameters = match parse(&input.to_string()) {
        Ok(parameters) => parameters,
        Err(error) => {
            return ToolOutput::Failure(AnalysisError::output(OPERATION, error.to_string()));
        }
    };
    let result = &completed.result;
    let path = parameters.at("input_path").text();
    let format = parameters.at("format").str();
    let root_sha256 = result.at("root_artifact_sha256").str();
    let interruption = completed
        .interrupted
        .map(analysis_interruption)
        .or_else(|| context.cancellation.reason().map(|_| cancelled()));

    reconstruction_evidence::deliver(
        context,
        ReconstructionEvidenceInput {
            parameters: &parameters,
            result,
            input_path: path,
            format,
            root_artifact_sha256: root_sha256,
        },
        input.get("detail").and_then(Value::as_str),
        interruption,
    )
}

fn apply_defaults(input: &mut Value) {
    if let Some(input) = input.as_object_mut() {
        input.entry("format").or_insert_with(|| Value::from("auto"));
        input
            .entry("integrity_policy")
            .or_insert_with(|| Value::from("fail"));
    }
}

fn reconstruct_application(
    context: &ToolContext<'_>,
    input: &Value,
) -> Result<WorkflowResult, AnalysisError> {
    if context.cancellation.reason().is_some() {
        return Err(cancelled());
    }

    let input_path = input["input_path"]
        .as_str()
        .ok_or_else(|| AnalysisError::output(OPERATION, "validated input has no input_path"))?;
    let requested_format = input["format"].as_str().unwrap_or("auto");
    let mut reader =
        open_javascript_artifact_reader_for_analysis(context, input_path, requested_format)?;

    // Closing after either outcome is deliberate. Acquisition may fail before
    // transferring its files, and inventory may fail before acquisition starts.
    let outcome = reconstruct_from_reader(context, input, &mut reader);
    let cleanup = reader
        .close()
        .map_err(|failure| translate_javascript_reader_failure(context, failure));
    match (outcome, cleanup) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(with_cleanup_failure(primary, cleanup, OPERATION)),
    }
}

fn reconstruct_from_reader(
    context: &ToolContext<'_>,
    input: &Value,
    reader: &mut JavaScriptArtifactReaderHandle,
) -> Result<WorkflowResult, AnalysisError> {
    let path = reader.path().to_owned();
    let format = reader.format();
    let fail_integrity = input["integrity_policy"].as_str() != Some("record-and-continue");

    context
        .progress
        .report(OPERATION, "Inventorying and parsing application artifacts");
    let snapshot = inventory_for_javascript(&path, fail_integrity, &context.cancellation)
        .map_err(|failure| translate_javascript_reader_failure(context, failure))?;
    if snapshot.manifest.root_format != format {
        return Err(translate_javascript_reader_failure(
            context,
            ReaderFailure::new(
                "format",
                format!(
                    "Artifact inventory classified {path} as {}, not {format}",
                    snapshot.manifest.root_format
                ),
            ),
        ));
    }

    let source_paths = selected_paths(input);
    context.progress.report(
        "read_javascript_artifacts",
        "Reading inventoried JavaScript application sources",
    );
    let files = reader
        .acquire(&snapshot, &context.cancellation, source_paths.as_deref())
        .map_err(|failure| translate_javascript_reader_failure(context, failure))?;

    // Source facts are now independent of the provider. Release the reader
    // before the expensive source analysis, retaining its owner on any failure.
    reader.close().map_err(|mut failure| {
        failure.partial_observation = Some(serde_json::json!({
            "kind": "artifact-inventory",
            "inventory": snapshot,
        }));
        translate_javascript_reader_failure(context, failure)
    })?;

    context.progress.report(
        "parse_javascript_sources",
        "Processing selected application files",
    );
    reconstruct(
        input,
        JsString::from(path),
        format,
        &snapshot,
        &files,
        semantic_limits(input),
        &context.cancellation,
    )
    .map_err(AnalysisError::from)
}

fn selected_paths(input: &Value) -> Option<Vec<String>> {
    input
        .get("source_paths")
        .and_then(Value::as_array)
        .map(|paths| {
            paths
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
}

fn semantic_limits(input: &Value) -> SemanticLimits {
    let defaults = SemanticLimits::default();
    let count = |field: &str, fallback: usize| {
        input
            .get(field)
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(fallback)
    };

    SemanticLimits {
        total_nodes: count("max_semantic_nodes", defaults.total_nodes),
        file_nodes: count("max_semantic_nodes_per_file", defaults.file_nodes),
        total_unknowns: count("max_semantic_unknowns", defaults.total_unknowns),
        file_unknowns: count("max_semantic_unknowns_per_file", defaults.file_unknowns),
    }
}

fn cancelled() -> AnalysisError {
    AnalysisError::artifact_operation(OPERATION, "cancelled")
        .with_user_message("JavaScript artifact reconstruction cancelled")
}

fn analysis_interruption(interruption: WorkflowInterruption) -> AnalysisError {
    match interruption {
        WorkflowInterruption::Cancelled(_) => cancelled(),
        WorkflowInterruption::Timeout { timeout_ms, .. } => {
            AnalysisError::timeout(OPERATION, timeout_ms.min(u64::MAX as u128) as u64)
                .with_captured_output(CapturedOutput {
                    stderr_bytes: Some(0),
                    exit_code: Some(None),
                    signal: Some(None),
                    ..CapturedOutput::default()
                })
        }
        WorkflowInterruption::ResourceConstraint { limits, message } => {
            let reported_limits = match serde_json::from_str(&limits.stringify()) {
                Ok(limits) => limits,
                Err(error) => {
                    return AnalysisError::output(
                        OPERATION,
                        format!(
                            "Could not represent JavaScript resource limits: {error}; original failure: {message}"
                        ),
                    );
                }
            };
            AnalysisError::resource_constraint(
                OPERATION,
                "javascript-source-analysis",
                message,
                Some(reported_limits),
            )
        }
        WorkflowInterruption::Failure(message) => {
            AnalysisError::provider_adapter("rea-javascript-application", OPERATION)
                .with_user_message(message)
        }
    }
}
