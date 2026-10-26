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
    acquisition::{JavaScriptArtifactFileSet, canonical_file_json, canonical_file_set_json},
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
        file_set,
        interrupted.as_ref().map(WorkflowInterruption::message),
    );

    let resolver = JavaScriptGraphResolver::new(snapshot, file_set);
    let graph = build_application_graph(&snapshot_json, &file_set_json, &analysis.value, &resolver)
        .map_err(|error| {
            invalid_workflow(&format!("failed to build JavaScript graph: {error:?}"))
        })?;
    drop(file_set_json);
    drop(snapshot_json);

    let semantic_graph = build_semantic_graph(
        snapshot,
        &mut analysis,
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

fn retain_unvisited_files(
    analysis: &mut Json,
    file_set: &JavaScriptArtifactFileSet<'_>,
    reason: Option<&str>,
) {
    let Some(reason) = reason else {
        return;
    };
    let visited = analysis
        .at("files")
        .arr()
        .iter()
        .map(|entry| entry.at("file").at("path").text().clone())
        .collect::<HashSet<_>>();
    let Json::Object(root) = analysis else {
        return;
    };
    let Some(files) = root.get_mut("files").and_then(Json::array_mut) else {
        return;
    };

    for file in &file_set.files {
        if visited.contains(&JsString::from(file.path.as_str())) {
            continue;
        }
        files.push(
            Obj::new()
                .with("file", canonical_file_json(file))
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
}

fn checkpoint(cancellation: &Cancellation) -> ControlFlow<String> {
    match cancellation.reason() {
        Some(reason) => ControlFlow::Break(reason.to_owned()),
        None => ControlFlow::Continue(()),
    }
}

fn build_semantic_graph(
    snapshot: &ArtifactInventoryResult,
    analysis: &mut JavaScriptArtifactAnalysis,
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

    let file_count = analysis.value.at("files").arr().len();
    for file_index in 0..file_count {
        let file = &analysis.value.at("files").arr()[file_index];
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
        if semantic.at("projection").is_null() {
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
        } else {
            projection
                .adopt_file_projection(&semantic.at("projection"))
                .map_err(|error| {
                    invalid_workflow(&format!(
                        "failed to adopt worker semantic projection: {error:?}"
                    ))
                })?;
        }

        release_semantic_ir(&mut analysis.value, file_index);
    }

    let nodes = application_graph.at("nodes").arr();
    let graph_id = application_graph.at("graph_id").str();
    Ok(projection.finish(&snapshot.manifest.root_sha256, graph_id, nodes))
}

/// The semantic graph owns the projected facts after each file is processed.
/// Drop the much larger worker IR as soon as its projection is adopted; the
/// final application envelope only needs static facts and aggregate counts.
fn release_semantic_ir(analysis: &mut Json, file_index: usize) {
    let Json::Object(root) = analysis else {
        return;
    };
    let Some(files) = root.get_mut("files").and_then(Json::array_mut) else {
        return;
    };
    let Some(Json::Object(file)) = files.get_mut(file_index) else {
        return;
    };
    let _ = file.remove("semantic");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn releases_projected_semantic_ir_but_keeps_file_facts() {
        let file = Obj::new()
            .with(
                "file",
                Obj::new()
                    .with("path", "src/main.js")
                    .with("kind", "javascript"),
            )
            .with(
                "javascript",
                Obj::new()
                    .with("findings", Json::array(vec![Json::from("require")]))
                    .with(
                        "electron",
                        Obj::new().with(
                            "call_paths",
                            Json::array(vec![Json::from("ipcRenderer.send")]),
                        ),
                    ),
            )
            .with(
                "semantic",
                Obj::new()
                    .with(
                        "ir",
                        Obj::new()
                            .with(
                                "moduleLinks",
                                Json::array(vec![
                                    Obj::new()
                                        .with("source", "./preload")
                                        .with("target", "./main")
                                        .into(),
                                ]),
                            )
                            .with(
                                "bindings",
                                Json::array(vec![
                                    Obj::new()
                                        .with("name", "ipc")
                                        .with("kind", "require")
                                        .into(),
                                ]),
                            ),
                    )
                    .with(
                        "projection",
                        Obj::new()
                            .with("nodes", Json::array(vec![]))
                            .with("relations", Json::array(vec![])),
                    ),
            );
        let retained_file_facts = file.get("file").expect("file facts").clone();
        let retained_static_facts = file.get("javascript").expect("static facts").clone();
        let mut analysis = Obj::new()
            .with("files", Json::array(vec![file.into()]))
            .into();

        release_semantic_ir(&mut analysis, 0);

        let retained_file = &analysis.at("files").arr()[0];
        assert_eq!(retained_file.at("file"), &retained_file_facts);
        assert_eq!(retained_file.at("javascript"), &retained_static_facts);
        assert!(retained_file.get("semantic").is_none());
    }
}
