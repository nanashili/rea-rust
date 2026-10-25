//! Internal orchestration for JavaScript application reconstruction.
//!
//! The tool boundary owns admission and provider lifecycle.  This module owns
//! the ordered, provider-independent stages after acquisition: aggregate
//! analysis, graph construction, semantic projection, Electron summarisation,
//! and the canonical reconstruction envelope.

use std::collections::HashSet;
use std::ops::ControlFlow;

use rea_core::{
    artifact_inventory::ArtifactInventoryResult,
    cancellation::Cancellation,
    failure::{Detail, Failure},
};
use serde_json::Value;

use super::graph::json::{Json, Obj, parse};
use super::{
    acquisition::{JavaScriptArtifactFileSet, canonical_file_set_json},
    analysis::{JavaScriptAnalysisOptions, JavaScriptArtifactAnalysis, analyze_artifact_files},
    electron_summary::summarize_electron_boundaries,
    graph::{SemanticGraphProjection, SemanticLimits, build_application_graph},
    reconstruction::{CompletedReconstruction, assemble_result},
    resolution::graph_adapter::JavaScriptGraphResolver,
    semantic::value_types::JsString,
};

pub use super::analysis::AnalysisInterruption as WorkflowInterruption;

/// The result of reconstruction, including an interruption observed after
/// enough owned facts existed to assemble a valid partial envelope.
#[derive(Debug)]
pub struct WorkflowResult {
    pub result: Json,
    pub interrupted: Option<WorkflowInterruption>,
}

/// Run the post-acquisition JavaScript reconstruction stages.
pub fn reconstruct<'inventory>(
    input: &Value,
    resolved_input_path: JsString,
    resolved_format: &str,
    snapshot: &'inventory ArtifactInventoryResult,
    file_set: &'inventory JavaScriptArtifactFileSet<'inventory>,
    semantic_limits: SemanticLimits,
    cancellation: &Cancellation,
) -> Result<WorkflowResult, Failure> {
    let snapshot_json = serialize_snapshot(snapshot)?;
    let file_set_json = canonical_file_set_json(file_set);
    let mut interrupted = cancellation
        .reason()
        .map(|reason| WorkflowInterruption::Cancelled(reason.to_owned()));

    let analysis_options = JavaScriptAnalysisOptions::from_input(input);
    let mut analysis =
        analyze_artifact_files(file_set, &analysis_options, || checkpoint(cancellation));
    if analysis.interrupted {
        interrupted.get_or_insert_with(|| {
            analysis
                .interruption
                .as_ref()
                .cloned()
                .unwrap_or_else(|| WorkflowInterruption::Failure("analysis interrupted".to_owned()))
        });
    }
    retain_unvisited_files(
        &mut analysis.value,
        &file_set_json,
        interrupted.as_ref().map(WorkflowInterruption::message),
    );

    let resolver = JavaScriptGraphResolver::new(snapshot, file_set);
    let graph = build_application_graph(&snapshot_json, &file_set_json, &analysis.value, &resolver)
        .map_err(|error| {
            invalid_workflow(&format!("failed to build JavaScript graph: {error:?}"))
        })?;

    let semantic_graph = build_semantic_graph(
        snapshot,
        &analysis,
        &graph,
        semantic_limits,
        cancellation,
        &mut interrupted,
    )?;
    let directory_paths = directory_paths(snapshot);
    let electron_summary = summarize_electron_boundaries(&analysis.value, &directory_paths);

    let result = assemble_result(CompletedReconstruction {
        resolved_input_path,
        resolved_format,
        snapshot,
        file_set,
        analysis: &analysis.value,
        graph,
        semantic_graph,
        electron_summary,
    })?;

    Ok(WorkflowResult {
        result,
        interrupted,
    })
}

fn retain_unvisited_files(analysis: &mut Json, file_set: &Json, reason: Option<&str>) {
    let Some(reason) = reason else {
        return;
    };
    let visited = analysis
        .at("files")
        .arr()
        .iter()
        .map(|entry| entry.at("file").at("path").text().clone())
        .collect::<HashSet<_>>();
    let mut files = analysis.at("files").arr().to_vec();
    for file in file_set.at("files").arr() {
        if visited.contains(file.at("path").text()) {
            continue;
        }
        files.push(
            Obj::new()
                .with("file", file.clone())
                .with("javascript", Json::Null)
                .with("semantic", Json::Null)
                .with(
                    "analysis_failure",
                    Obj::new()
                        .with("scope", "analyze-javascript-source")
                        .with("status", "not-started")
                        .with("reason", reason)
                        .with("error", Json::Null)
                        .with("limits", Json::Null),
                )
                .into(),
        );
    }
    if let Json::Object(object) = analysis {
        object.set("files", Json::Array(files));
    }
}

fn checkpoint(cancellation: &Cancellation) -> ControlFlow<String> {
    match cancellation.reason() {
        Some(reason) => ControlFlow::Break(reason.to_owned()),
        None => ControlFlow::Continue(()),
    }
}

fn build_semantic_graph(
    snapshot: &ArtifactInventoryResult,
    analysis: &JavaScriptArtifactAnalysis,
    application_graph: &Json,
    limits: SemanticLimits,
    cancellation: &Cancellation,
    interrupted: &mut Option<WorkflowInterruption>,
) -> Result<Json, Failure> {
    if let Some(reason) = cancellation.reason() {
        interrupted.get_or_insert_with(|| WorkflowInterruption::Cancelled(reason.to_owned()));
    }
    let mut projection = match SemanticGraphProjection::new(limits) {
        Ok(projection) => projection,
        Err(error) => {
            return Err(invalid_workflow(&format!(
                "failed to initialize semantic projection: {error:?}"
            )));
        }
    };

    for file in analysis.value.at("files").arr() {
        let semantic = file.at("semantic");
        if semantic.is_null() {
            // Match the TypeScript graph builder's ownership boundary: a
            // semantic file is unavailable only when the caller excluded its
            // source from analysis. Parse/worker failures remain represented by
            // the application analysis result and must not manufacture a
            // semantic unknown frontier here.
            let source_file = file.at("file");
            let text = source_file.at("text");
            if text.at("included").as_bool() != Some(false)
                || text.at("reason").str() != "outside-analysis-scope"
            {
                continue;
            }
            projection.record_unavailable_file(
                source_file,
                "Source was not analyzed because it is outside the caller-selected source_paths.",
                &Json::Null,
                "incomplete-module",
            );
            continue;
        }
        if !semantic.at("projection").is_null() {
            match projection.adopt_file_projection(&semantic.at("projection")) {
                Ok(()) => continue,
                Err(error) => {
                    return Err(invalid_workflow(&format!(
                        "failed to adopt worker semantic projection: {error:?}"
                    )));
                }
            }
        }
        let ir = semantic.at("ir");
        let (nodes, unknowns) = projection.remaining_file_capacity();
        let paths = file
            .at("javascript")
            .at("electron")
            .at("call_paths")
            .arr()
            .to_vec();
        match super::graph::project_file(file.at("file"), ir, nodes, unknowns, &paths) {
            Ok(file_projection) => {
                projection
                    .adopt_file_projection(&file_projection)
                    .map_err(|error| {
                        invalid_workflow(&format!(
                            "failed to retain semantic projection for {}: {error:?}",
                            file_path_for_error(file)
                        ))
                    })?
            }
            Err(error) => {
                return Err(invalid_workflow(&format!(
                    "failed to project semantic IR for {}: {error:?}",
                    file_path_for_error(file)
                )));
            }
        }
    }

    let nodes = application_graph.at("nodes").arr();
    let graph_id = application_graph.at("graph_id").str();
    Ok(projection.finish(&snapshot.manifest.root_sha256, graph_id, nodes))
}

fn file_path_for_error(file: &Json) -> String {
    let path = file.at("file").at("path");
    path.text()
        .try_to_string()
        .unwrap_or_else(|_| path.stringify())
}

fn serialize_snapshot(snapshot: &ArtifactInventoryResult) -> Result<Json, Failure> {
    let text = serde_json::to_string(snapshot)
        .map_err(|error| invalid_workflow(&format!("failed to serialize inventory: {error}")))?;
    parse(&text).map_err(|error| invalid_workflow(&format!("invalid inventory JSON: {error}")))
}

fn directory_paths(snapshot: &ArtifactInventoryResult) -> HashSet<JsString> {
    snapshot
        .occurrences
        .iter()
        .filter(|occurrence| occurrence.entry_kind == "directory")
        .map(|occurrence| occurrence.logical_path.clone())
        .collect()
}

fn invalid_workflow(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide an authenticated JavaScript artifact and retry.".into(),
        [(
            "operation".into(),
            Detail::Text("analyze_javascript_application".into()),
        )]
        .into_iter()
        .collect(),
    )
}
