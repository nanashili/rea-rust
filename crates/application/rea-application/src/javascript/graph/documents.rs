//! `JavaScriptArtifactGraphDocuments`: HTML renderer roles and source-map originals.

use super::super::semantic::value_types::JsString;
use super::application_graph::{EdgeInput, NodeInput, ObservationInput};
use super::context::{
    GraphContext, InferenceEdge, RoleNode, add_artifact_contains_edge, add_static_inference_edge,
    artifact_local_identity, create_electron_role_node, link_electron_role_to_asset,
};
use super::evidence::{EvidenceInput, artifact_observation, complete_coverage, static_inference};
use super::json::{Json, Obj, js_int};
use super::resolution::{ResolveRequest, limitations};

/// `addJavaScriptHtmlRoles`.
pub fn add_html_roles(context: &mut GraphContext<'_>) {
    let mut by_html: Vec<(JsString, Vec<Json>)> = Vec::new();
    for script in context.analysis.at("html_scripts").arr() {
        let html = script.at("html_path").text().clone();
        if let Some(entry) = by_html.iter_mut().find(|(path, _)| path == &html) {
            entry.1.push(script.clone());
        } else {
            by_html.push((html, vec![script.clone()]));
        }
    }
    for (html_path, scripts) in by_html {
        let Some(html) = context.files_by_path.get(&html_path).cloned() else {
            continue;
        };
        let path_js = html.at("path").text().clone();
        let role_resolution: Json = Obj::new()
            .with_static("declared_path", Json::String(path_js.clone()))
            .with_static("resolution_context", "html-reference")
            .with_static("resolved_path", Json::String(path_js.clone()))
            .with_static("resolution_status", "resolved")
            .with_static("limitations", Json::array(Vec::new()))
            .into();
        let role = create_electron_role_node(
            context,
            RoleNode {
                kind: "electron-renderer",
                anchor: &html,
                resolution: &role_resolution,
                mechanism: "html-script-entrypoint",
                range: None,
                coverage: None,
            },
        );
        let root = context.root.clone();
        add_artifact_contains_edge(context, &root, &role, &html, "discover-html-renderer");
        link_electron_role_to_asset(context, &role, &html, &role_resolution, None, None);
        for script in &scripts {
            let script_path_js = script.at("script_path").text().clone();
            let mut request = ResolveRequest::new_exact(
                &script_path_js,
                &path_js,
                &JsString::from("html-reference"),
            );
            request.html_base_href = script.get("base_href").cloned();
            let resolution = context.resolve(&request);
            let resolved_path_js = resolution.at("resolved_path").text().clone();
            if resolution.at("resolution_status").str() != "resolved" {
                let mut properties = Obj::new()
                    .with_static("mechanism", "html-script-reference")
                    .with_static("script_path", Json::String(script_path_js.clone()))
                    .with_static("base_href", script.at("base_href").clone());
                if let Some(object) = resolution.as_obj() {
                    properties.extend_from(object);
                }
                let evidence = static_inference(
                    &EvidenceInput::new(
                        html.at("sha256").str(),
                        &path_js,
                        "resolve-html-script-reference",
                        complete_coverage(),
                    )
                    .range(script.at("location"))
                    .limitations(limitations(&resolution)),
                    None,
                );
                context.accumulator.add_node(NodeInput {
                    kind: role.kind.clone(),
                    identity: role.identity.clone(),
                    observations: vec![ObservationInput::new_js(
                        Some(script_path_js.clone()),
                        properties,
                        evidence,
                    )],
                });
                continue;
            }
            let Some(resolved) = context.file_nodes.get(&resolved_path_js).cloned() else {
                continue;
            };
            let properties = Obj::new()
                .with_static("script_path", Json::String(script_path_js.clone()))
                .with_static("base_href", script.at("base_href").clone())
                .with_static(
                    "resolution_context",
                    resolution.at("resolution_context").clone(),
                )
                .with_static("resolved_path", Json::String(resolved_path_js))
                .with_static(
                    "resolution_status",
                    resolution.at("resolution_status").clone(),
                )
                .with_static("limitations", resolution.at("limitations").clone());
            let coverage = complete_coverage();
            add_static_inference_edge(
                context,
                InferenceEdge {
                    source: &role,
                    target: &resolved,
                    file: &html,
                    range: script.at("location"),
                    coverage: &coverage,
                    relation: "loads",
                    properties,
                    confidence: None,
                    limitations: None,
                },
            );
        }
    }
}

/// `addJavaScriptSourceMapOriginals`.
pub fn add_source_map_originals(context: &mut GraphContext<'_>) {
    let source_maps = context.analysis.at("source_maps").clone();
    for source_map in source_maps.arr() {
        let map_path = source_map.at("path").text().clone();
        let (Some(map_file), Some(map_node)) = (
            context.files_by_path.get(&map_path).cloned(),
            context.file_nodes.get(&map_path).cloned(),
        ) else {
            continue;
        };
        let sha = map_file.at("sha256").str();
        let limitation = source_map.at("limitation").as_js_string().cloned();
        for original in source_map.at("sources").arr() {
            let reference = original.at("reference");
            let identity = if reference.is_null() {
                artifact_local_identity(
                    sha,
                    "source-map-unnamed-declaration",
                    &js_int(original.at("declaration_index").num()),
                )
            } else {
                Obj::new()
                    .with_static("strategy", "source-map-original")
                    .with_static("stability", "source-map-exact")
                    .with_static("source_map_sha256", sha)
                    .with_static("original_source", reference.at("source_name").clone())
                    .with_static("source_root", reference.at("source_root").clone())
                    .with_static("source_sha256", original.at("content_sha256").clone())
                    .into()
            };
            let label = reference
                .at("source_name")
                .as_js_string()
                .filter(|name| !name.is_empty())
                .cloned();
            let properties = Obj::new()
                .with_static("source_index", original.at("source_index").clone())
                .with_static(
                    "declaration_index",
                    original.at("declaration_index").clone(),
                )
                .with_static("source_name_available", !reference.is_null())
                .with_static("content_available", !original.at("content").is_null())
                .with_static("content_sha256", original.at("content_sha256").clone());
            let map_file_path = map_file.at("path").text().clone();
            let evidence = || {
                let mut evidence = artifact_observation(&EvidenceInput::new(
                    sha,
                    &map_file_path,
                    "parse-local-source-map",
                    complete_coverage(),
                ));
                if let Some(limitation) = &limitation {
                    let mut object = evidence.obj();
                    object.set(
                        "limitations",
                        Json::array(vec![Json::String(limitation.clone())]),
                    );
                    evidence = object.into();
                }
                evidence
            };
            let mut observation = ObservationInput::new_js(label, properties, evidence());
            observation.source_map_reference = reference.clone();
            let node = context.accumulator.add_node(NodeInput {
                kind: if reference.is_null() {
                    "unknown"
                } else {
                    "source-module"
                }
                .into(),
                identity,
                observations: vec![observation],
            });
            let source_name = if reference.is_null() {
                Json::Null
            } else {
                reference.at("source_name").clone()
            };
            let source_root = if reference.is_null() {
                Json::Null
            } else {
                reference.at("source_root").clone()
            };
            context.accumulator.add_edge(EdgeInput {
                source: map_node.node_id.clone(),
                target: node.node_id,
                relation: "contains".into(),
                properties: Obj::new()
                    .with_static("source_index", original.at("source_index").clone())
                    .with_static(
                        "declaration_index",
                        original.at("declaration_index").clone(),
                    )
                    .with_static("original_source", source_name)
                    .with_static("source_root", source_root),
                evidence: evidence(),
            });
        }
    }
}
