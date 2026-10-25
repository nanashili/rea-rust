//! `JavaScriptArtifactGraphStructure`: root, containers, files, ASAR entries,
//! unavailable scopes and package roles.

use std::collections::HashMap;

use super::super::semantic::value_types::JsString;
use super::application_graph::{Accumulator, AppNode, EdgeInput, NodeInput, ObservationInput};
use super::context::{
    GraphContext, RoleNode, UnavailableParse, add_artifact_contains_edge,
    add_unavailable_static_parse_scope, artifact_file_node_kind, artifact_local_identity,
    canonical_path_identity, content_identity, create_electron_role_node,
    html_inline_script_limitation, html_inline_script_location_limit, javascript_analysis_coverage,
    link_electron_role_to_asset, omitted_html_inline_script_locations, string_list_js,
};
use super::evidence::{
    EvidenceInput, artifact_observation, ast_observation, complete_coverage, partial_coverage,
    static_inference,
};
use super::json::{Json, Obj};
use super::leaves::analysis_coverage_limits;
use super::resolution::{ResolveRequest, limitations, resolution_properties};

/// `javascriptArtifactAnalysisScopes[kind]` as `(operation, authority)`.
pub fn analysis_scope(kind: &str) -> Option<(&'static str, &'static str)> {
    match kind {
        "javascript" => Some(("analyze-javascript-source", "ast-static-analysis")),
        "package-json" => Some(("parse-package-json", "artifact-bytes")),
        "json" => Some(("parse-json-module", "artifact-bytes")),
        "html" => Some(("parse-html-script-references", "artifact-bytes")),
        "source-map" => Some(("parse-local-source-map", "artifact-bytes")),
        _ => None,
    }
}

/// `isSkippedJavaScriptAnalysis`.
pub fn is_skipped(entry: &Json) -> bool {
    let file = entry.at("file");
    file.at("kind").str() == "javascript"
        && file.at("text").at("included").as_bool() == Some(true)
        && entry.at("javascript").is_null()
        && entry.get("analysis_failure").is_some()
}

/// `createJavaScriptArtifactRootNode`.
pub fn create_root_node(accumulator: &mut Accumulator, snapshot: &Json) -> Option<AppNode> {
    let manifest = snapshot.at("manifest");
    let root = snapshot
        .at("nodes")
        .arr()
        .iter()
        .find(|node| node.at("artifact_id") == manifest.at("root_artifact_id"))?;
    let sha = root.at("sha256").str();
    let properties = Obj::new()
        .with("format", manifest.at("root_format").clone())
        .with("bytes", root.at("size").clone())
        .with("inventory_manifest_id", manifest.at("manifest_id").clone())
        .with(
            "inventory_graph_sha256",
            manifest.at("graph_sha256").clone(),
        )
        .with("inventory_artifact_id", root.at("artifact_id").clone());
    let evidence = artifact_observation(
        &EvidenceInput::new(sha, "artifact-root", "inventory-root", complete_coverage()).limitations(vec![
            "artifact-root is a path-independent alias; the application result retains the canonical local input path."
                .to_owned(),
        ]),
    );
    Some(accumulator.add_node(NodeInput {
        kind: "artifact".into(),
        identity: content_identity(sha),
        observations: vec![ObservationInput::new(
            Some(JsString::from("artifact root")),
            properties,
            evidence,
        )],
    }))
}

/// `addJavaScriptArtifactContainers`.
pub fn add_containers(context: &mut GraphContext<'_>) {
    for container in context.file_set.at("containers").arr() {
        let sha = container.at("sha256").str();
        let path_key = container.at("path").text();
        let properties = Obj::new()
            .with("path", Json::String(path_key.clone()))
            .with("format", "asar")
            .with("bytes", container.at("bytes").clone())
            .with(
                "inventory_artifact_id",
                container.at("inventory_artifact_id").clone(),
            );
        let evidence = artifact_observation(&EvidenceInput::new(
            sha,
            path_key,
            "inventory-nested-asar",
            complete_coverage(),
        ));
        let node = context.accumulator.add_node(NodeInput {
            kind: "artifact".into(),
            identity: content_identity(sha),
            observations: vec![ObservationInput::new_js(
                Some(container.at("path").text().clone()),
                properties,
                evidence,
            )],
        });
        context.container_nodes.insert(sha.to_owned(), node.clone());
        let evidence = artifact_observation(&EvidenceInput::new(
            context.root_sha256(),
            path_key,
            "inventory-nested-asar",
            complete_coverage(),
        ));
        context.accumulator.add_edge(EdgeInput {
            source: context.root.node_id.clone(),
            target: node.node_id,
            relation: "contains".into(),
            properties: Obj::new()
                .with("path", Json::String(path_key.clone()))
                .with("format", "asar"),
            evidence,
        });
    }
}

fn index_first_by_path(values: &Json) -> HashMap<JsString, &Json> {
    let mut index = HashMap::new();
    for value in values.arr() {
        index
            .entry(value.at("path").text().clone())
            .or_insert(value);
    }
    index
}

fn is_asar_container(context: &GraphContext<'_>, container_sha256: &str) -> bool {
    context.snapshot.at("manifest").at("root_format").str() == "asar"
        || container_sha256 != context.root_sha256()
}

/// `sourceFileRange`: whole-text range in UTF-16 columns.
fn source_file_range(file: &Json) -> Json {
    let text = file.at("text").at("value").text();
    let mut line = 1.0;
    let mut column = 0.0;
    let mut units = text.encode_utf16().peekable();

    while let Some(unit) = units.next() {
        let terminator = match unit {
            0x000d => {
                if units.peek() == Some(&0x000a) {
                    units.next();
                }
                true
            }
            0x000a | 0x2028 | 0x2029 => true,
            _ => false,
        };
        if terminator {
            line += 1.0;
            column = 0.0;
        } else {
            column += 1.0;
        }
    }

    Obj::new()
        .with("start", Obj::new().with("line", 1.0).with("column", 0.0))
        .with("end", Obj::new().with("line", line).with("column", column))
        .into()
}

/// `addJavaScriptArtifactFiles`.
pub fn add_files(context: &mut GraphContext<'_>) {
    let raw = context.raw_analysis;
    let packages = index_first_by_path(raw.at("packages"));
    let json_modules = index_first_by_path(raw.at("json_modules"));
    let source_maps = index_first_by_path(raw.at("source_maps"));
    let inline_scripts = index_first_by_path(raw.at("html_inline_scripts"));
    for analyzed in raw.at("files").arr() {
        let file = analyzed.at("file");
        let path_key = file.at("path").text().clone();
        let json_value = json_modules.get(&path_key).copied();
        let javascript = analyzed.at("javascript");
        let target =
            create_file_target(context, file, javascript, json_value, is_skipped(analyzed));
        if let (Some(failure), false) = (
            analyzed.get("application_projection_failure"),
            javascript.is_null(),
        ) {
            let semantic = analyzed.at("semantic");
            let properties = Obj::new()
                .with("static_analysis", javascript.clone())
                .with(
                    "semantic_module_analysis",
                    if semantic.is_null() {
                        Json::Null
                    } else {
                        let compact = semantic.at("metadata").at("moduleIr");
                        if compact.is_null() {
                            semantic.at("ir").clone()
                        } else {
                            compact.clone()
                        }
                    },
                )
                .with(
                    "application_projection_failure",
                    failure.at("error").clone(),
                );
            let range = source_file_range(file);
            let evidence = ast_observation(
                &EvidenceInput::new(
                    file.at("sha256").str(),
                    &path_key,
                    "retain-unexpanded-static-findings",
                    javascript_analysis_coverage(javascript),
                )
                .range(&range)
                .limitations(vec![failure.at("reason").str().to_owned()]),
            );
            context.accumulator.add_node(NodeInput {
                kind: target.kind.clone(),
                identity: target.identity.clone(),
                observations: vec![ObservationInput::new_js(
                    Some(path_key.clone()),
                    properties,
                    evidence,
                )],
            });
        }
        context.file_nodes.insert(path_key.clone(), target.clone());
        if file.at("kind").str() == "javascript" {
            context.asset_nodes.insert(path_key.clone(), target.clone());
        }
        let entry = create_asar_entry(context, file);
        let parent = context
            .container_nodes
            .get(file.at("container_sha256").str())
            .cloned()
            .unwrap_or_else(|| context.root.clone());
        match entry {
            None => add_artifact_contains_edge(context, &parent, &target, file, "inventory-file"),
            Some(entry) => {
                add_artifact_contains_edge(context, &parent, &entry, file, "inventory-entry");
                let evidence = artifact_observation(&EvidenceInput::new(
                    file.at("container_sha256").str(),
                    &path_key,
                    "map-entry-content",
                    complete_coverage(),
                ));
                context.accumulator.add_edge(EdgeInput {
                    source: entry.node_id,
                    target: target.node_id.clone(),
                    relation: "maps_to".into(),
                    properties: Obj::new().with("sha256", file.at("sha256").clone()),
                    evidence,
                });
            }
        }
        let kind = file.at("kind").str();
        let scope = analysis_scope(kind);
        let text = file.at("text");
        let outside = text.at("included").as_bool() != Some(true)
            && text.at("reason").str() == "outside-analysis-scope";
        if let (true, Some((_, authority))) = (outside, scope) {
            add_unavailable_static_parse_scope(
                context,
                UnavailableParse::new(
                    file,
                    &target,
                    "select-javascript-sources",
                    authority,
                    "Source is outside the caller-selected source_paths; it was inventoried but not analyzed.",
                ),
            );
        } else if let Some(failure) = analyzed.get("analysis_failure") {
            let scope = failure.at("scope");
            let mut input = UnavailableParse::new(
                file,
                &target,
                scope.at("operation").str(),
                scope.at("authority").str(),
                failure.at("reason").str().to_owned(),
            );
            input.failure = Some(failure.at("error").clone());
            input.limits = Some(analysis_coverage_limits(failure.at("limits")));
            input.details = Some(Obj::new().with("analysis_status", failure.at("status").clone()));
            add_unavailable_static_parse_scope(context, input);
        } else if kind == "javascript"
            && (javascript.is_null() || javascript.at("parse_status").str() == "failed")
        {
            let limitation = if text.at("included").as_bool() == Some(true) {
                "JavaScript syntax could not be parsed.".to_owned()
            } else {
                format!(
                    "JavaScript text was unavailable: {}.",
                    text.at("reason").str()
                )
            };
            add_unavailable_static_parse_scope(
                context,
                UnavailableParse::new(
                    file,
                    &target,
                    "parse-javascript",
                    "ast-static-analysis",
                    limitation,
                ),
            );
        }
        if let Some(failure) = analyzed.get("application_projection_failure") {
            let mut input = UnavailableParse::new(
                file,
                &target,
                "project-javascript-application",
                "ast-static-analysis",
                failure.at("reason").str().to_owned(),
            );
            input.failure = Some(failure.at("error").clone());
            input.limits = Some(analysis_coverage_limits(failure.at("limits")));
            add_unavailable_static_parse_scope(context, input);
        }
        if let Some(package) = packages.get(&path_key)
            && package.at("status").str() != "included"
        {
            add_unavailable_static_parse_scope(
                context,
                UnavailableParse::new(
                    file,
                    &target,
                    "parse-package-json",
                    "artifact-bytes",
                    package.at("limitation").str().to_owned(),
                ),
            );
        }
        if let Some(json) = json_value
            && json.at("status").str() != "included"
        {
            add_unavailable_static_parse_scope(
                context,
                UnavailableParse::new(
                    file,
                    &target,
                    "parse-json-module",
                    "artifact-bytes",
                    json.at("limitation").str().to_owned(),
                ),
            );
        }
        if let Some(map) = source_maps.get(&path_key)
            && map.at("status").str() == "invalid"
        {
            add_unavailable_static_parse_scope(
                context,
                UnavailableParse::new(
                    file,
                    &target,
                    "parse-local-source-map",
                    "artifact-bytes",
                    map.at("limitation").str().to_owned(),
                ),
            );
        }
        if let Some(inline) = inline_scripts.get(&path_key) {
            let scripts = inline.at("scripts").arr();
            #[allow(clippy::cast_precision_loss)]
            let truncated = inline.at("script_count").num() > scripts.len() as f64;
            let mut input = UnavailableParse::new(
                file,
                &target,
                "parse-html-inline-scripts",
                "ast-static-analysis",
                html_inline_script_limitation(inline),
            );
            input.limits = Some(if truncated {
                vec![html_inline_script_location_limit()]
            } else {
                Vec::new()
            });
            input.omitted_count = Some(omitted_html_inline_script_locations([*inline]));
            input.details = Some(
                Obj::new()
                    .with("inline_script_count", inline.at("script_count").clone())
                    .with(
                        "inline_scripts",
                        Json::Array(
                            scripts
                                .iter()
                                .map(|script| {
                                    let location = script.at("location");
                                    Obj::new()
                                        .with("script_type", script.at("script_type").clone())
                                        .with(
                                            "location",
                                            Obj::new()
                                                .with("start", location.at("start").clone())
                                                .with("end", location.at("end").clone()),
                                        )
                                        .into()
                                })
                                .collect(),
                        ),
                    ),
            );
            add_unavailable_static_parse_scope(context, input);
        }
    }
    add_unavailable_asar_entries(context);
}

fn add_unavailable_asar_entries(context: &mut GraphContext<'_>) {
    let file_set = context.file_set;
    for file in file_set.at("unavailable_relevant_files").arr() {
        let container = file.at("container_sha256").str();
        if !is_asar_container(context, container) {
            continue;
        }
        let path_key = file.at("path").text().clone();
        let kind = file.get("kind");
        let mut limitations = string_list_js(file.at("limitations"));
        limitations.push(JsString::from(format!(
            "The inventoried {} entry has unavailable bytes; no content artifact identity can be established.",
            kind.map_or("relevant", Json::str)
        )));
        let mut properties = Obj::new()
            .with("entry_sha256", file.at("sha256").clone())
            .with("bytes", file.at("bytes").clone())
            .with(
                "inventory_artifact_id",
                file.at("inventory_artifact_id").clone(),
            );
        if let Some(occurrence) = file.get("inventory_occurrence_id") {
            properties.set("inventory_occurrence_id", occurrence.clone());
        }
        if let Some(status) = file.get("hash_status") {
            properties.set("hash_status", status.clone());
        }
        if let Some(artifact) = file.get("artifact_kind") {
            properties.set("artifact_kind", artifact.clone());
        }
        if let Some(kind) = kind {
            properties.set("kind", kind.clone());
        }
        properties.set("content_available", false);
        let evidence_for = |operation: &str| {
            artifact_observation(
                &EvidenceInput::new(
                    container,
                    &path_key,
                    operation,
                    partial_coverage(Vec::new(), None),
                )
                .limitations(limitations.clone()),
            )
        };
        let entry = context.accumulator.add_node(NodeInput {
            kind: "asar-entry".into(),
            identity: canonical_path_identity(container, path_key.clone()),
            observations: vec![ObservationInput::new_js(
                Some(file.at("path").text().clone()),
                properties,
                evidence_for("inventory-asar-unavailable-entry"),
            )],
        });
        let parent = context
            .container_nodes
            .get(container)
            .cloned()
            .unwrap_or_else(|| context.root.clone());
        let mut edge_properties = Obj::new()
            .with("path", Json::String(path_key.clone()))
            .with("content_available", false);
        if let Some(status) = file.get("hash_status") {
            edge_properties.set("hash_status", status.clone());
        }
        context.accumulator.add_edge(EdgeInput {
            source: parent.node_id,
            target: entry.node_id.clone(),
            relation: "contains".into(),
            properties: edge_properties,
            evidence: evidence_for("inventory-asar-unavailable-entry"),
        });
        if kind.map(Json::str) == Some("native-addon")
            || file.at("artifact_kind").str() == "native-addon"
        {
            let mut addon_properties = Obj::new().with("availability", "unavailable");
            if let Some(status) = file.get("hash_status") {
                addon_properties.set("hash_status", status.clone());
            }
            if let Some(artifact) = file.get("artifact_kind") {
                addon_properties.set("artifact_kind", artifact.clone());
            }
            addon_properties.set("bytes", file.at("bytes").clone());
            addon_properties.set(
                "inventory_artifact_id",
                file.at("inventory_artifact_id").clone(),
            );
            if let Some(occurrence) = file.get("inventory_occurrence_id") {
                addon_properties.set("inventory_occurrence_id", occurrence.clone());
            }
            let addon = context.accumulator.add_node(NodeInput {
                kind: "native-addon".into(),
                identity: canonical_path_identity(container, path_key.clone()),
                observations: vec![ObservationInput::new_js(
                    Some(file.at("path").text().clone()),
                    addon_properties,
                    evidence_for("classify-unavailable-native-addon"),
                )],
            });
            context.accumulator.add_edge(EdgeInput {
                source: entry.node_id,
                target: addon.node_id,
                relation: "contains".into(),
                properties: Obj::new()
                    .with("classification", "native-addon")
                    .with("content_available", false),
                evidence: evidence_for("classify-unavailable-native-addon"),
            });
        }
    }
}

fn create_file_target(
    context: &mut GraphContext<'_>,
    file: &Json,
    javascript: &Json,
    json: Option<&Json>,
    skipped: bool,
) -> AppNode {
    let kind = artifact_file_node_kind(file.at("kind").str());
    let path_key = file.at("path").text().clone();
    let text = file.at("text");
    let parse_status = if javascript.is_null() {
        if skipped {
            Json::from("skipped")
        } else {
            Json::Null
        }
    } else {
        javascript.at("parse_status").clone()
    };
    let properties = Obj::new()
        .with("path", Json::String(path_key.clone()))
        .with("bytes", file.at("bytes").clone())
        .with(
            "inventory_artifact_id",
            file.at("inventory_artifact_id").clone(),
        )
        .with("unpacked", file.at("unpacked").clone())
        .with("file_kind", file.at("kind").clone())
        .with(
            "text_status",
            if text.at("included").as_bool() == Some(true) {
                Json::from("included")
            } else {
                text.at("reason").clone()
            },
        )
        .with("parse_status", parse_status)
        .with(
            "json_parse_status",
            json.map_or(Json::Null, |json| json.at("status").clone()),
        )
        .with(
            "json_top_level_keys",
            json.map_or(Json::Array(Vec::new()), |json| {
                json.at("top_level_keys").clone()
            }),
        )
        .with(
            "omitted_json_top_level_keys",
            json.map_or(Json::Number(0.0), |json| {
                json.at("omitted_top_level_keys").clone()
            }),
        )
        .with(
            "vendor_markers",
            if javascript.is_null() {
                Json::Array(Vec::new())
            } else {
                javascript.at("vendors").clone()
            },
        );
    let sha = file.at("sha256").str();
    let evidence = artifact_observation(&EvidenceInput::new(
        sha,
        file.at("path").text(),
        "inventory-relevant-file",
        complete_coverage(),
    ));
    context.accumulator.add_node(NodeInput {
        kind: kind.into(),
        identity: content_identity(sha),
        observations: vec![ObservationInput::new_js(
            Some(file.at("path").text().clone()),
            properties,
            evidence,
        )],
    })
}

fn create_asar_entry(context: &mut GraphContext<'_>, file: &Json) -> Option<AppNode> {
    let container = file.at("container_sha256").str();
    if !is_asar_container(context, container) {
        return None;
    }
    let path_key = file.at("path").text().clone();
    let properties = Obj::new()
        .with("entry_sha256", file.at("sha256").clone())
        .with("bytes", file.at("bytes").clone())
        .with("unpacked", file.at("unpacked").clone())
        .with(
            "inventory_artifact_id",
            file.at("inventory_artifact_id").clone(),
        );
    let evidence = artifact_observation(&EvidenceInput::new(
        container,
        file.at("path").text(),
        "inventory-asar-entry",
        complete_coverage(),
    ));
    Some(context.accumulator.add_node(NodeInput {
        kind: "asar-entry".into(),
        identity: canonical_path_identity(container, path_key),
        observations: vec![ObservationInput::new_js(
            Some(file.at("path").text().clone()),
            properties,
            evidence,
        )],
    }))
}

fn dependency_manifest(path: &JsString) -> bool {
    let node_modules = JsString::from("node_modules");
    let mut segment_start = 0;
    let units = path.units();
    for (index, unit) in units.iter().enumerate() {
        if *unit != u16::from(b'/') {
            continue;
        }
        if JsString::from_utf16(units[segment_start..index].to_vec()) == node_modules {
            return index + 1 < units.len();
        }
        segment_start = index + 1;
    }
    false
}

fn application_manifest_path(context: &GraphContext<'_>) -> Option<JsString> {
    let mut paths: Vec<JsString> = context
        .analysis
        .at("packages")
        .arr()
        .iter()
        .map(|package| package.at("path").text().clone())
        .filter(|path| context.files_by_path.contains_key(path) && !dependency_manifest(path))
        .collect();
    paths.sort_by(|left, right| {
        left.units()
            .iter()
            .filter(|unit| **unit == u16::from(b'/'))
            .count()
            .cmp(
                &right
                    .units()
                    .iter()
                    .filter(|unit| **unit == u16::from(b'/'))
                    .count(),
            )
            .then_with(|| left.cmp(right))
    });
    paths.into_iter().next()
}

/// `addJavaScriptPackageNodes`.
pub fn add_package_nodes(context: &mut GraphContext<'_>) -> Vec<AppNode> {
    let mut roots = Vec::new();
    let root_path = application_manifest_path(context);
    let packages = context.analysis.at("packages").arr().to_vec();
    for package in &packages {
        let package_path = package.at("path").text();
        let Some(file) = context.files_by_path.get(package_path).cloned() else {
            continue;
        };
        let path_key = file.at("path").text().clone();
        let sha = file.at("sha256").str();
        let properties = Obj::new()
            .with("path", Json::String(path_key.clone()))
            .with("name", package.at("name").clone())
            .with("version", package.at("version").clone())
            .with("main", package.at("main").clone())
            .with("renderer", package.at("renderer").clone())
            .with("parse_status", package.at("status").clone());
        let limitations = package
            .at("limitation")
            .as_str()
            .map(|text| vec![text.to_owned()])
            .unwrap_or_default();
        let evidence = artifact_observation(
            &EvidenceInput::new(sha, &path_key, "parse-package-json", complete_coverage())
                .limitations(limitations),
        );
        let label = package
            .at("name")
            .as_js_string()
            .cloned()
            .unwrap_or_else(|| path_key.clone());
        let node = context.accumulator.add_node(NodeInput {
            kind: "package".into(),
            identity: artifact_local_identity(sha, "package-json", path_key.clone()),
            observations: vec![ObservationInput::new_js(Some(label), properties, evidence)],
        });
        if root_path.as_ref() == Some(&path_key) {
            roots.push(node.clone());
            let evidence = static_inference(
                &EvidenceInput::new(
                    sha,
                    &path_key,
                    "associate-package-artifact",
                    complete_coverage(),
                ),
                None,
            );
            context.accumulator.add_edge(EdgeInput {
                source: node.node_id.clone(),
                target: context.root.node_id.clone(),
                relation: "contains".into(),
                properties: Obj::new().with("basis", "package-metadata-within-artifact"),
                evidence,
            });
        } else {
            let root = context.root.clone();
            add_artifact_contains_edge(context, &root, &node, &file, "inventory-package");
        }
        if dependency_manifest(&path_key) {
            continue;
        }
        add_package_role(context, &node, &file, "electron-main", package.at("main"));
        add_package_role(
            context,
            &node,
            &file,
            "electron-renderer",
            package.at("renderer"),
        );
    }
    roots
}

fn add_package_role(
    context: &mut GraphContext<'_>,
    package_node: &AppNode,
    package_file: &Json,
    kind: &str,
    declared: &Json,
) {
    let Some(declared) = declared.as_js_string() else {
        return;
    };
    let path_key = package_file.at("path").text();
    let context_key = JsString::from("package-entrypoint");
    let resolution = context.resolve(&ResolveRequest::new_exact(declared, path_key, &context_key));
    let role = create_electron_role_node(
        context,
        RoleNode {
            kind,
            anchor: package_file,
            resolution: &resolution,
            mechanism: if kind == "electron-main" {
                "package.json:main"
            } else {
                "package.json:renderer"
            },
            range: None,
            coverage: None,
        },
    );
    let mut properties = Obj::new()
        .with("declared_path", declared)
        .with(
            "resolution_context",
            resolution.at("resolution_context").clone(),
        )
        .with("resolved_path", resolution.at("resolved_path").clone())
        .with(
            "resolution_status",
            resolution.at("resolution_status").clone(),
        );
    properties.extend_from(&resolution_properties(Some(&resolution)));
    properties.set("limitations", resolution.at("limitations").clone());
    let evidence = static_inference(
        &EvidenceInput::new(
            package_file.at("sha256").str(),
            package_file.at("path").text(),
            "discover-package-entrypoint",
            complete_coverage(),
        )
        .limitations(limitations(&resolution)),
        None,
    );
    context.accumulator.add_edge(EdgeInput {
        source: package_node.node_id.clone(),
        target: role.node_id.clone(),
        relation: "loads".into(),
        properties,
        evidence,
    });
    link_electron_role_to_asset(context, &role, package_file, &resolution, None, None);
}

#[cfg(test)]
mod tests {
    use super::{JsString, Json, Obj, source_file_range};

    fn file_with_text(value: JsString) -> Json {
        Obj::new()
            .with("text", Obj::new().with("value", Json::String(value)))
            .into()
    }

    #[test]
    fn source_range_distinguishes_surrogate_from_literal_escape_text() {
        let actual_surrogate = source_file_range(&file_with_text(JsString::from_utf16([0xd800])));
        let literal_escape = source_file_range(&file_with_text(JsString::from("\\uD800")));

        assert_eq!(actual_surrogate.at("end").at("column").num(), 1.0);
        assert_eq!(literal_escape.at("end").at("column").num(), 6.0);
    }

    #[test]
    fn source_range_counts_line_terminators_and_utf16_columns() {
        let range = source_file_range(&file_with_text(JsString::from(
            "a\r\nb\rc\nd\u{2028}e\u{2029}😀x",
        )));

        assert_eq!(range.at("end").at("line").num(), 6.0);
        assert_eq!(range.at("end").at("column").num(), 3.0);
    }
}
