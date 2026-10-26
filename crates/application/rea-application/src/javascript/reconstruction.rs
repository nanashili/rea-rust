//! Canonical application reconstruction result assembly.
//!
//! The producer stages own their facts: inventory is typed, acquisition is
//! typed, and analysis and graph values use the JavaScript-preserving `Json`
//! representation. This module only assembles those facts in the same order
//! as the TypeScript reconstruction envelope.

use rea_core::{
    artifact_inventory::ArtifactInventoryResult,
    failure::{Detail, Failure},
};
use serde::Serialize;
use std::collections::BTreeMap;

use super::acquisition::JavaScriptArtifactFileSet;
use super::{
    graph::json::{Json, Obj, parse},
    semantic::value_types::JsString,
};

const OPERATION: &str = "analyze_javascript_application";

/// Completed facts owned by the reconstruction stages.
pub struct CompletedReconstruction<'facts, 'inventory> {
    pub resolved_input_path: JsString,
    pub resolved_format: &'facts str,
    pub snapshot: &'facts ArtifactInventoryResult,
    pub file_set: &'facts JavaScriptArtifactFileSet<'inventory>,
    pub analysis: &'facts Json,
    pub graph: Json,
    pub semantic_graph: Json,
    pub electron_summary: Json,
}

/// Assemble one completed reconstruction from already-owned producer facts.
pub fn assemble_result(facts: CompletedReconstruction<'_, '_>) -> Result<Json, Failure> {
    validate_resolved_input(&facts.resolved_input_path, facts.resolved_format)?;

    let integrity_contradictions = serialize_json(&facts.snapshot.integrity_contradictions)?;
    let mut result = Obj::new()
        .with("input_path", facts.resolved_input_path)
        .with("format", facts.resolved_format)
        .with(
            "root_artifact_sha256",
            facts.snapshot.manifest.root_sha256.clone(),
        )
        .with(
            "inventory_manifest_id",
            facts.snapshot.manifest.manifest_id.clone(),
        )
        .with(
            "inventory_graph_sha256",
            facts.snapshot.manifest.graph_sha256.clone(),
        )
        .with("integrity_contradictions", integrity_contradictions);

    if let Some(selection) = &facts.file_set.source_selection {
        result.set(
            "source_selection",
            Obj::new()
                .with(
                    "requested_paths",
                    strings(selection.requested_paths.clone()),
                )
                .with("unselected_files", selection.unselected_files),
        );
    }

    result.set("graph", facts.graph);
    result.set("semantic_graph", facts.semantic_graph);
    result.set("electron_summary", facts.electron_summary);
    result.set("statistics", statistics(facts.file_set, facts.analysis)?);
    result.set(
        "limitations",
        required_array(facts.analysis, "limitations")?.clone(),
    );

    Ok(result.into())
}

fn validate_resolved_input(path: &JsString, format: &str) -> Result<(), Failure> {
    if path.is_empty() {
        return Err(invalid(
            "resolved JavaScript application path must be non-empty",
        ));
    }
    if !matches!(format, "asar" | "directory") {
        return Err(invalid(
            "resolved JavaScript application format is unsupported",
        ));
    }
    Ok(())
}

fn statistics(file_set: &JavaScriptArtifactFileSet<'_>, analysis: &Json) -> Result<Json, Failure> {
    let (parsed, skipped) = analysis_file_counts(analysis)?;
    Ok(Obj::new()
        .with(
            "relevant_files",
            file_set
                .files
                .len()
                .saturating_add(file_set.unavailable_relevant_files.len()),
        )
        .with("nested_asar_containers", file_set.containers.len())
        .with("text_bytes_read", json_u64(file_set.text_bytes_read))
        .with("invalid_utf8_files", json_u64(file_set.invalid_utf8_files))
        .with("parsed_javascript_files", parsed as f64)
        .with("skipped_javascript_files", skipped as f64)
        .with(
            "visited_ast_nodes",
            required_count(analysis, "visited_ast_nodes")?,
        )
        .with("findings", required_count(analysis, "findings")?)
        .with("modules", required_count(analysis, "modules")?)
        .with(
            "parse_failures",
            required_count(analysis, "parse_failures")?,
        )
        .into())
}

fn analysis_file_counts(analysis: &Json) -> Result<(usize, usize), Failure> {
    let files = match analysis.get("files") {
        Some(Json::Array(files)) => files,
        Some(_) => return Err(invalid("JavaScript analysis files must be an array")),
        None => return Err(invalid("JavaScript analysis has no files array")),
    };

    for entry in files.iter() {
        if entry.get("javascript").is_none() {
            return Err(invalid(
                "JavaScript analysis file is missing its javascript result",
            ));
        }
    }

    let parsed = files
        .iter()
        .filter(|entry| !entry.at("javascript").is_null())
        .count();
    let skipped = files
        .iter()
        .filter(|entry| {
            let file = entry.at("file");
            file.at("kind").str() == "javascript"
                && file.at("text").at("included").as_bool() == Some(true)
                && entry.at("javascript").is_null()
                && entry.get("analysis_failure").is_some()
        })
        .count();
    Ok((parsed, skipped))
}

fn required_count(analysis: &Json, field: &str) -> Result<f64, Failure> {
    let value = analysis.get(field).and_then(Json::as_f64).ok_or_else(|| {
        invalid(&format!(
            "JavaScript analysis field {field} must be numeric"
        ))
    })?;
    if value < 0.0 || value.fract() != 0.0 || value > u64::MAX as f64 {
        return Err(invalid(&format!(
            "JavaScript analysis field {field} must be a non-negative integer"
        )));
    }
    Ok(value)
}

fn required_array<'a>(analysis: &'a Json, field: &str) -> Result<&'a Json, Failure> {
    match analysis.get(field) {
        Some(value @ Json::Array(_)) => Ok(value),
        Some(_) => Err(invalid(&format!(
            "JavaScript analysis field {field} must be an array"
        ))),
        None => Err(invalid(&format!(
            "JavaScript analysis field {field} must be present"
        ))),
    }
}

fn json_u64(value: u64) -> Json {
    #[allow(clippy::cast_precision_loss)]
    Json::Number(value as f64)
}

fn strings(values: impl IntoIterator<Item = String>) -> Json {
    Json::array(values.into_iter().map(Json::from).collect())
}

fn serialize_json<T: Serialize>(value: &T) -> Result<Json, Failure> {
    let encoded = serde_json::to_string(value)
        .map_err(|error| invalid(&format!("failed to serialize inventory facts: {error}")))?;
    parse(&encoded)
        .map_err(|error| invalid(&format!("failed to preserve inventory facts: {error}")))
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a completed JavaScript application reconstruction.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::javascript::acquisition::JavaScriptSourceSelection;
    use crate::javascript::artifact_files::{
        InventoryLookup, JavaScriptArtifactContainer, JavaScriptArtifactFile,
        JavaScriptArtifactFileKind, JavaScriptText, JavaScriptUnanalyzedArtifactFile,
    };
    use rea_core::artifact_inventory::{
        ArtifactCommand, ArtifactGraphManifest, ArtifactInventoryCoverage, IntegrityContradiction,
    };

    fn snapshot() -> ArtifactInventoryResult {
        ArtifactInventoryResult {
            manifest: ArtifactGraphManifest {
                manifest_id: "manifest".into(),
                root_artifact_id: "root-id".into(),
                root_sha256: "root".into(),
                root_format: "directory".into(),
                graph_sha256: "graph".into(),
                node_count: 0,
                occurrence_count: 0,
                edge_count: 0,
            },
            nodes: Vec::new(),
            occurrences: Vec::new(),
            edges: Vec::new(),
            provenance: Vec::<ArtifactCommand>::new(),
            integrity_contradictions: vec![IntegrityContradiction {
                contradiction_id: "contradiction".into(),
                occurrence_id: "occurrence".into(),
                parent_artifact_id: "root-id".into(),
                logical_path: "nested/app.js".into(),
                declared_sha256: "declared".into(),
                observed_sha256: "observed".into(),
                entry_kind: "file".into(),
                unpacked: true,
                trust: "conflicted".into(),
                provenance: "inventory".into(),
                limitations: vec!["contradiction limitation".into()],
            }],
            coverage: ArtifactInventoryCoverage {
                scope: "artifact".into(),
                status: "complete".into(),
            },
            limitations: Vec::new(),
        }
    }

    #[test]
    fn reconstructs_strict_nonempty_envelope_and_omits_unselected_source_selection() {
        let surrogate = JsString::from_utf16(vec![0xd800]);
        let analysis: Json = Obj::new()
            .with(
                "files",
                Json::array(vec![
                    Obj::new()
                        .with(
                            "file",
                            Obj::new()
                                .with("kind", "javascript")
                                .with("path", "main.js")
                                .with("text", Obj::new().with("included", true)),
                        )
                        .with("javascript", Obj::new().with("facts", "parsed"))
                        .into(),
                    Obj::new()
                        .with(
                            "file",
                            Obj::new()
                                .with("kind", "javascript")
                                .with("path", "nested/skipped.js")
                                .with("text", Obj::new().with("included", true)),
                        )
                        .with("javascript", Json::Null)
                        .with("analysis_failure", Json::Null)
                        .into(),
                ]),
            )
            .with("visited_ast_nodes", 7usize)
            .with("findings", 2usize)
            .with("modules", 3usize)
            .with("parse_failures", 1usize)
            .with(
                "limitations",
                Json::array(vec![
                    Json::String(surrogate.clone()),
                    Json::from("analysis limitation"),
                ]),
            )
            .into();
        let graph: Json = Obj::new()
            .with("path", surrogate.clone())
            .with(
                "nested",
                Obj::new()
                    .with("value", surrogate.clone())
                    .with(surrogate.clone(), surrogate.clone()),
            )
            .into();
        let inventory = snapshot();
        let containers = vec![JavaScriptArtifactContainer {
            path: "nested/app.asar".into(),
            sha256: "container".into(),
            bytes: 11,
            inventory_artifact_id: "container-id".into(),
        }];
        let mut file_set = JavaScriptArtifactFileSet {
            files: vec![JavaScriptArtifactFile {
                path: "main.js".into(),
                container_sha256: "root".into(),
                sha256: "main-hash".into(),
                bytes: 8,
                inventory_artifact_id: "main-id".into(),
                kind: JavaScriptArtifactFileKind::JavaScript,
                unpacked: true,
                text: JavaScriptText::Included(JsString::from("source()")),
            }],
            unanalyzed_files: InventoryLookup::new(&inventory, &containers),
            unavailable_relevant_files: vec![JavaScriptUnanalyzedArtifactFile {
                path: "unavailable.js".into(),
                container_sha256: "root".into(),
                sha256: None,
                bytes: None,
                inventory_artifact_id: None,
                inventory_occurrence_id: "unavailable-occurrence".into(),
                kind: Some(JavaScriptArtifactFileKind::JavaScript),
                artifact_kind: "file".into(),
                hash_status: "unavailable".into(),
                limitations: vec!["unavailable source".into()],
            }],
            containers,
            text_bytes_read: 8,
            invalid_utf8_files: 1,
            source_selection: None,
        };

        let result = assemble_result(CompletedReconstruction {
            resolved_input_path: JsString::from("/tmp/app"),
            resolved_format: "directory",
            snapshot: &inventory,
            file_set: &file_set,
            analysis: &analysis,
            graph: graph.clone(),
            semantic_graph: graph.clone(),
            electron_summary: graph.clone(),
        })
        .expect("completed facts should assemble");
        assert_eq!(
            result.at("input_path").as_js_string().unwrap().units(),
            JsString::from("/tmp/app").units()
        );
        assert_eq!(result.at("format").str(), "directory");
        assert_eq!(result.at("root_artifact_sha256").str(), "root");
        assert_eq!(result.at("inventory_manifest_id").str(), "manifest");
        assert_eq!(result.at("inventory_graph_sha256").str(), "graph");
        let Json::Array(contradictions) = result.at("integrity_contradictions") else {
            panic!("contradictions should be an array");
        };
        assert_eq!(contradictions.len(), 1);
        assert_eq!(contradictions[0].at("logical_path").str(), "nested/app.js");
        assert_eq!(result.at("semantic_graph"), result.at("graph"));
        assert_eq!(result.at("electron_summary"), result.at("graph"));
        assert_eq!(result.at("statistics").at("relevant_files").num(), 2.0);
        assert_eq!(
            result.at("statistics").at("nested_asar_containers").num(),
            1.0
        );
        assert_eq!(result.at("statistics").at("text_bytes_read").num(), 8.0);
        assert_eq!(result.at("statistics").at("invalid_utf8_files").num(), 1.0);
        assert_eq!(
            result.at("statistics").at("parsed_javascript_files").num(),
            1.0
        );
        assert_eq!(
            result.at("statistics").at("skipped_javascript_files").num(),
            1.0
        );
        assert_eq!(result.at("statistics").at("visited_ast_nodes").num(), 7.0);
        assert_eq!(result.at("statistics").at("findings").num(), 2.0);
        assert_eq!(result.at("statistics").at("modules").num(), 3.0);
        assert_eq!(result.at("statistics").at("parse_failures").num(), 1.0);
        let Json::Array(limitations) = result.at("limitations") else {
            panic!("limitations should be an array");
        };
        assert_eq!(limitations[1].str(), "analysis limitation");
        assert_eq!(
            limitations[0].as_js_string().unwrap().units(),
            surrogate.units()
        );
        let nested = result.at("graph").at("nested");
        assert_eq!(
            nested
                .get_js_string(&surrogate)
                .unwrap()
                .as_js_string()
                .unwrap()
                .units(),
            surrogate.units()
        );
        assert!(result.get("source_selection").is_none());

        file_set.source_selection = Some(JavaScriptSourceSelection {
            requested_paths: vec!["main.js".into()],
            unselected_files: 1,
        });
        let selected_result = assemble_result(CompletedReconstruction {
            resolved_input_path: JsString::from("/tmp/app"),
            resolved_format: "directory",
            snapshot: &inventory,
            file_set: &file_set,
            analysis: &analysis,
            graph: graph.clone(),
            semantic_graph: graph.clone(),
            electron_summary: graph,
        })
        .expect("selected completed facts should assemble");
        let Json::Object(selection) = selected_result.at("source_selection") else {
            panic!("source selection should be present when requested");
        };
        let Json::Array(requested_paths) = selection.get("requested_paths").unwrap() else {
            panic!("requested paths should be an array");
        };
        assert_eq!(requested_paths[0].str(), "main.js");
        assert_eq!(selection.get("unselected_files").unwrap().num(), 1.0);
    }

    #[test]
    fn rejects_analysis_entry_without_explicit_javascript_result() {
        let analysis: Json = Obj::new()
            .with("files", Json::array(vec![Obj::new().into()]))
            .with("visited_ast_nodes", 0usize)
            .with("findings", 0usize)
            .with("modules", 0usize)
            .with("parse_failures", 0usize)
            .with("limitations", Json::array(Vec::new()))
            .into();
        let inventory = snapshot();
        let file_set = JavaScriptArtifactFileSet {
            files: Vec::new(),
            unanalyzed_files: InventoryLookup::new(&inventory, &[]),
            unavailable_relevant_files: Vec::new(),
            containers: Vec::new(),
            text_bytes_read: 0,
            invalid_utf8_files: 0,
            source_selection: None,
        };
        let facts = CompletedReconstruction {
            resolved_input_path: JsString::from("/tmp/app"),
            resolved_format: "directory",
            snapshot: &inventory,
            file_set: &file_set,
            analysis: &analysis,
            graph: Json::Object(Obj::new()),
            semantic_graph: Json::Object(Obj::new()),
            electron_summary: Json::Object(Obj::new()),
        };
        let failure = assemble_result(facts).expect_err("missing javascript must be invalid");
        assert_eq!(failure.code(), "invalid_request");
    }
}
