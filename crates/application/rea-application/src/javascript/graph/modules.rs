//! `JavaScriptModuleRelationships`: source modules and semantic import/export edges.

use super::super::semantic::value_types::JsString;
use super::application_graph::{AppNode, EdgeInput, NodeInput, ObservationInput};
use super::context::{
    GraphContext, add_ast_contains_edge, artifact_local_identity, string_list_js,
};
use super::evidence::{
    EvidenceInput, ast_observation, complete_coverage, partial_coverage, static_inference,
};
use super::json::{Json, Obj, composite_key};
use super::leaves::{
    export_return_shapes, semantic_resource_limit_coverage, semantic_resource_limit_reason,
    semantic_resource_limits,
};
use super::resolution::{
    ResolveRequest, limitations, resolution_mode_properties, resolution_properties,
};

fn semantic_coverage(ir: &Json) -> Json {
    let limits = semantic_resource_limits(ir.at("coverage"));
    if ir.at("coverage").at("status").str() == "complete" && limits.is_empty() {
        return complete_coverage();
    }
    partial_coverage(
        semantic_resource_limit_coverage(&limits),
        ir.at("coverage").at("omittedCount").as_f64(),
    )
}

fn program_scope(ir: &Json) -> Option<&Json> {
    ir.at("scopes")
        .arr()
        .iter()
        .find(|scope| scope.at("kind").str() == "program")
}

fn has_ascii_suffix(path: &JsString, suffix: &[u8]) -> bool {
    path.units().len() >= suffix.len()
        && path.units()[path.units().len() - suffix.len()..]
            .iter()
            .zip(suffix)
            .all(|(unit, expected)| {
                let unit = if (b'A' as u16..=b'Z' as u16).contains(unit) {
                    unit + (b'a' - b'A') as u16
                } else {
                    *unit
                };
                unit == u16::from(*expected)
            })
}

fn module_format(path: &JsString, ir: &Json) -> &'static str {
    let file_name_start = path
        .units()
        .iter()
        .rposition(|unit| *unit == u16::from(b'/'))
        .map_or(0, |index| index + 1);
    let file_name = JsString::from_utf16(path.units()[file_name_start..].to_vec());
    if has_ascii_suffix(&file_name, b".mjs") || has_ascii_suffix(&file_name, b".mts") {
        return "esm";
    }
    if has_ascii_suffix(&file_name, b".cjs") || has_ascii_suffix(&file_name, b".cts") {
        return "commonjs";
    }
    if has_ascii_suffix(&file_name, b".ts") || has_ascii_suffix(&file_name, b".tsx") {
        return "unknown";
    }
    let links = ir.at("moduleLinks").arr();
    let esm = links
        .iter()
        .any(|link| matches!(link.at("kind").str(), "import" | "export" | "re-export"));
    let common = links
        .iter()
        .any(|link| matches!(link.at("kind").str(), "require" | "commonjs-export"));
    match (esm, common) {
        (true, true) => "mixed",
        (true, false) => "esm",
        (false, true) => "commonjs",
        (false, false) => "unknown",
    }
}

/// `addJavaScriptSourceModules`.
pub fn add_source_modules(context: &mut GraphContext<'_>) {
    let files = context.files().to_vec();
    for analyzed in &files {
        let file = analyzed.at("file");
        let path_js = file.at("path").text().clone();
        let semantic = analyzed.at("semantic");
        let Some(asset) = context.asset_nodes.get(&path_js).cloned() else {
            continue;
        };
        if semantic.is_null() {
            continue;
        }
        let ir = semantic.at("ir");
        let Some(program) = program_scope(ir) else {
            continue;
        };
        let links = ir.at("moduleLinks").arr();
        let names = |types: bool| {
            let mut names: Vec<JsString> = links
                .iter()
                .filter(|link| {
                    !link.at("exportedName").is_null()
                        && (link.at("kind").str() == "type-import") == types
                })
                .map(|link| link.at("exportedName").text().clone())
                .collect();
            names.sort_by(|left, right| left.compare_code_points(right));
            names
        };
        let exports = names(false);
        let type_exports = names(true);
        let dedup = |values: &[JsString]| {
            let mut seen: Vec<JsString> = Vec::new();
            for value in values {
                if !seen.contains(value) {
                    seen.push(value.clone());
                }
            }
            seen
        };
        let coverage = semantic_coverage(ir);
        let properties = Obj::new()
            .with("semantic_role", "source-module")
            .with("source_sha256", file.at("sha256").clone())
            .with("path", Json::String(path_js.clone()))
            .with("logical_module_key", Json::String(path_js.clone()))
            .with("module_format", module_format(&path_js, ir))
            .with(
                "import_relationships",
                links
                    .iter()
                    .filter(|link| matches!(link.at("kind").str(), "import" | "require"))
                    .count(),
            )
            .with(
                "type_relationships",
                links
                    .iter()
                    .filter(|link| link.at("kind").str() == "type-import")
                    .count(),
            )
            .with("export_relationships", exports.len())
            .with("export_names", super::json::strings(dedup(&exports)))
            .with(
                "type_export_names",
                super::json::strings(dedup(&type_exports)),
            )
            .with("omitted_export_names", 0.0);
        let evidence = ast_observation(
            &EvidenceInput::new(
                file.at("sha256").str(),
                &path_js,
                "recover-source-module",
                coverage.clone(),
            )
            .range(program.at("location"))
            .limitations(string_list_js(ir.at("limitations"))),
        );
        let source = context.accumulator.add_node(NodeInput {
            kind: "javascript-module".into(),
            identity: artifact_local_identity(
                file.at("sha256").str(),
                "source-module",
                JsString::from(file.at("container_sha256").str())
                    .concat_str(":")
                    .concat(&path_js),
            ),
            observations: vec![ObservationInput::new_js(
                Some(path_js.clone()),
                properties,
                evidence,
            )],
        });
        context.source_module_nodes.insert(path_js, source.clone());
        add_ast_contains_edge(
            context,
            &asset,
            &source,
            file,
            program.at("location"),
            &coverage,
            Obj::new().with(
                "logical_module_key",
                Json::String(file.at("path").text().clone()),
            ),
        );
    }
}

struct Relationship<'r> {
    file: &'r Json,
    ir: &'r Json,
    link: &'r Json,
}

struct Target {
    node: AppNode,
    path: Option<JsString>,
    file: Option<Json>,
    status: String,
    limitations: Vec<JsString>,
    resolution: Json,
}

/// `addJavaScriptModuleRelationshipsSteps`; returns the self-import count.
pub fn add_module_relationships(context: &mut GraphContext<'_>) -> usize {
    let mut self_imports = 0;
    let files = context.files().to_vec();
    for analyzed in &files {
        let file = analyzed.at("file");
        let semantic = analyzed.at("semantic");
        let Some(source) = context
            .source_module_nodes
            .get(file.at("path").text())
            .cloned()
        else {
            continue;
        };
        if semantic.is_null() {
            continue;
        }
        let ir = semantic.at("ir");
        for link in ir.at("moduleLinks").arr() {
            if link.at("kind").str() == "type-import" {
                continue;
            }
            let input = Relationship { file, ir, link };
            if matches!(
                link.at("kind").str(),
                "export" | "re-export" | "commonjs-export"
            ) {
                add_export(context, &input, &source, &mut self_imports);
            } else if !link.at("specifier").is_null() {
                let imported_name = link.at("importedName");
                let origin = Obj::new()
                    .with("specifier", link.at("specifier").clone())
                    .with(
                        "importedPath",
                        Json::Array(if imported_name.is_null() {
                            Vec::new()
                        } else {
                            vec![imported_name.clone()]
                        }),
                    );
                add_import(context, &input, &source, &mut self_imports, &origin.into());
            }
        }
    }
    self_imports
}

fn add_export(
    context: &mut GraphContext<'_>,
    input: &Relationship<'_>,
    source: &AppNode,
    self_imports: &mut usize,
) {
    let Some(exported) = input.link.at("exportedName").as_js_string() else {
        return;
    };
    let file = input.file;
    let path = file.at("path").text().clone();
    let sha = file.at("sha256").str();
    let base = semantic_coverage(input.ir);
    let shapes = export_return_shapes(input.ir, input.link, &path, &base);
    let properties = Obj::new()
        .with("semantic_role", "export-binding")
        .with("module_path", Json::String(path.clone()))
        .with("relationship_kind", input.link.at("kind").clone())
        .with("exported_name", Json::String(exported.clone()))
        .with("local_name", input.link.at("localName").clone())
        .with("imported_name", input.link.at("importedName").clone())
        .with("declared_specifier", input.link.at("specifier").clone());
    let evidence = ast_observation(
        &EvidenceInput::new(sha, &path, "recover-module-export", base.clone())
            .range(input.link.at("location"))
            .limitations(string_list_js(input.ir.at("limitations"))),
    );
    let mut observations = vec![ObservationInput::new_js(
        Some(path.concat_str(":").concat(&exported)),
        properties,
        evidence,
    )];
    if let Some((properties, range, coverage, limitations)) = shapes {
        let evidence = static_inference(
            &EvidenceInput::new(sha, &path, "recover-export-return-shapes", coverage)
                .range(&range)
                .limitations(limitations),
            None,
        );
        observations.push(ObservationInput::new_js(
            Some(
                path.concat_str(":")
                    .concat(&exported)
                    .concat_str(":return-shapes"),
            ),
            properties,
            evidence,
        ));
    }
    let node = context.accumulator.add_node(NodeInput {
        kind: "javascript-module".into(),
        identity: artifact_local_identity(
            sha,
            "module-export",
            &composite_key(vec![
                file.at("container_sha256").clone(),
                Json::String(path.clone()),
                Json::String(exported.clone()),
            ]),
        ),
        observations,
    });
    context.accumulator.add_edge(EdgeInput {
        source: source.node_id.clone(),
        target: node.node_id.clone(),
        relation: "exposes".into(),
        properties: relationship_properties(input.link, None, None),
        evidence: relationship_evidence(input, "expose-module-export", &[], "high"),
    });
    if let Some(origin) = origin_for_export(input.ir, input.link) {
        add_import(context, input, &node, self_imports, &origin);
    }
}

fn add_import(
    context: &mut GraphContext<'_>,
    input: &Relationship<'_>,
    source: &AppNode,
    self_imports: &mut usize,
    origin: &Json,
) {
    let target = resolve_target(context, input, origin.at("specifier").text());
    if target.node.node_id == source.node_id {
        *self_imports += 1;
        return;
    }
    let confidence = match target.status.as_str() {
        "resolved" => "high",
        "external" => "medium",
        _ => "low",
    };
    let properties = relationship_properties(input.link, Some(&target), Some(origin));
    let evidence = relationship_evidence(
        input,
        "resolve-semantic-module-relationship",
        &target.limitations,
        confidence,
    );
    context.accumulator.add_edge(EdgeInput {
        source: source.node_id.clone(),
        target: target.node.node_id.clone(),
        relation: "imports".into(),
        properties,
        evidence,
    });
}

fn resolve_target(
    context: &mut GraphContext<'_>,
    input: &Relationship<'_>,
    specifier: &JsString,
) -> Target {
    let path = input.file.at("path").text().clone();
    let kind = input.link.at("kind").str();
    let reference = if kind == "require" || kind == "commonjs-export" {
        "require"
    } else {
        "static-import"
    };
    let mode = context.resolver.module_resolution_mode(
        &path,
        reference,
        input.link.at("resolutionMode").as_str(),
    );
    let mut request =
        ResolveRequest::new_exact(specifier, &path, &JsString::from("module-specifier"));
    request.module_kind = Some(mode);
    let resolution = context.resolve(&request);
    let status = resolution.at("resolution_status").str().to_owned();
    let limitations = limitations(&resolution);
    if status != "resolved" {
        let node = unresolved_module_node(context, input, specifier, &resolution);
        return Target {
            node,
            path: None,
            file: None,
            status,
            limitations,
            resolution,
        };
    }
    let resolved_js = resolution.at("resolved_path").text().clone();
    let file = context.files_by_path.get(&resolved_js).cloned();
    let Some(node) = context
        .source_module_nodes
        .get(&resolved_js)
        .or_else(|| context.file_nodes.get(&resolved_js))
        .cloned()
    else {
        let node = unresolved_module_node(context, input, specifier, &resolution);
        return Target {
            node,
            path: None,
            file: None,
            status: "unresolved".into(),
            limitations: vec![JsString::from(
                "resolved path is absent from the graph context",
            )],
            resolution,
        };
    };
    Target {
        node,
        path: Some(resolved_js),
        file,
        status,
        limitations,
        resolution,
    }
}

fn unresolved_module_node(
    context: &mut GraphContext<'_>,
    input: &Relationship<'_>,
    specifier: &JsString,
    resolution: &Json,
) -> AppNode {
    let status = resolution.at("resolution_status").str();
    let mut properties = Obj::new()
        .with("semantic_role", "module-reference")
        .with("declared_specifier", Json::String(specifier.clone()))
        .with("resolution_status", status);
    properties.extend_from(&resolution_properties(Some(resolution)));
    let evidence = static_inference(
        &EvidenceInput::new(
            input.file.at("sha256").str(),
            input.file.at("path").text(),
            "retain-unresolved-semantic-module",
            semantic_coverage(input.ir),
        )
        .range(input.link.at("location"))
        .limitations(string_list_js(input.ir.at("limitations"))),
        Some("low"),
    );
    context.accumulator.add_node(NodeInput {
        kind: "javascript-module".into(),
        identity: artifact_local_identity(
            input.file.at("sha256").str(),
            "unresolved-semantic-module",
            JsString::from(status).concat_str(":").concat(specifier),
        ),
        observations: vec![ObservationInput::new_js(
            Some(specifier.clone()),
            properties,
            evidence,
        )],
    })
}

fn origin_for_export(ir: &Json, link: &Json) -> Option<Json> {
    if !link.at("specifier").is_null() {
        let mut origin = Obj::new();
        if let Some(mode) = link.get("resolutionMode") {
            origin.set("resolutionMode", mode.clone());
        }
        origin.set("specifier", link.at("specifier").clone());
        let imported_name = link.at("importedName");
        origin.set(
            "importedPath",
            Json::Array(if imported_name.is_null() {
                Vec::new()
            } else {
                vec![imported_name.clone()]
            }),
        );
        return Some(origin.into());
    }
    let local = link.at("localName").text().clone();
    let program = program_scope(ir).map(|scope| scope.at("scopeId").clone());
    let binding = ir.at("bindings").arr().iter().find(|binding| {
        binding.at("name").text() == &local && Some(binding.at("scopeId")) == program.as_ref()
    })?;
    let provenance = binding.at("provenance");
    let origins = provenance.at("origins").arr();
    (provenance.at("status").str() == "module" && origins.len() == 1).then(|| origins[0].clone())
}

fn relationship_properties(link: &Json, target: Option<&Target>, origin: Option<&Json>) -> Obj {
    let mut properties = Obj::new().with("module_link_kind", link.at("kind").clone());
    properties.extend_from(&resolution_mode_properties(
        link.get("resolutionMode").map(Json::str),
    ));
    let imported_path = origin.map(|origin| origin.at("importedPath").clone());
    properties.set(
        "specifier",
        origin.map_or_else(
            || link.at("specifier").clone(),
            |origin| origin.at("specifier").clone(),
        ),
    );
    properties.set(
        "imported_name",
        match &imported_path {
            Some(path) => path
                .arr()
                .last()
                .cloned()
                .unwrap_or_else(|| link.at("importedName").clone()),
            None => link.at("importedName").clone(),
        },
    );
    properties.set(
        "imported_path",
        imported_path.unwrap_or_else(|| Json::Array(Vec::new())),
    );
    properties.set("local_name", link.at("localName").clone());
    properties.set("exported_name", link.at("exportedName").clone());
    properties.set(
        "resolved_path",
        target.and_then(|target| target.path.clone()),
    );
    properties.set(
        "resolution_status",
        target.map(|target| target.status.clone()),
    );
    properties.extend_from(&resolution_properties(
        target.map(|target| &target.resolution),
    ));
    let target_file = target.and_then(|target| target.file.as_ref());
    properties.set(
        "target_file_kind",
        target_file.map(|file| file.at("kind").clone()),
    );
    let json_status = target_file
        .filter(|file| matches!(file.at("kind").str(), "json" | "package-json"))
        .map(|file| json_status(file));
    properties.set("target_json_status", json_status);
    properties
}

/// `jsonStatus`: whether the file text parses as JSON (`JSON.parse`).
fn json_status(file: &Json) -> &'static str {
    let text = file.at("text");
    if text.at("included").as_bool() != Some(true) {
        return "unavailable";
    }
    if serde_json::from_str::<serde::de::IgnoredAny>(text.at("value").str()).is_ok() {
        "included"
    } else {
        "invalid"
    }
}

fn relationship_evidence(
    input: &Relationship<'_>,
    operation: &str,
    extra: &[JsString],
    confidence: &str,
) -> Json {
    let mut limitations = string_list_js(input.ir.at("limitations"));
    limitations.extend(
        semantic_resource_limits(input.ir.at("coverage"))
            .iter()
            .map(|limit| JsString::from(semantic_resource_limit_reason(limit))),
    );
    limitations.extend(extra.iter().cloned());
    static_inference(
        &EvidenceInput::new(
            input.file.at("sha256").str(),
            input.file.at("path").text(),
            operation,
            semantic_coverage(input.ir),
        )
        .range(input.link.at("location"))
        .limitations(limitations),
        Some(confidence),
    )
}
