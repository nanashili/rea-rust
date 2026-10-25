//! `JavaScriptArtifactGraphBundlers`: Webpack/Rspack chunks, modules and runtime edges.

use super::super::semantic::value_types::JsString;
use super::application_graph::{AppNode, EdgeInput, NodeInput, ObservationInput};
use super::context::{
    GraphContext, add_ast_contains_edge, artifact_local_identity, javascript_analysis_coverage,
    lookup_key, self_reference_omissions, string_list_js,
};
use super::evidence::{EvidenceInput, ast_observation, static_inference};
use super::json::{Json, Obj, composite_key};

struct Record {
    file: Json,
    registration: Json,
    chunk: AppNode,
    coverage: Json,
}

/// `addJavaScriptBundlerNodes`; returns self-reference limitations.
pub fn add_bundler_nodes(context: &mut GraphContext<'_>) -> Vec<String> {
    let mut self_async_chunks = 0;
    let files = context.files().to_vec();
    for analyzed in &files {
        let file = analyzed.at("file");
        let javascript = analyzed.at("javascript");
        let path_js = file.at("path").text().clone();
        let Some(asset) = context.asset_nodes.get(&path_js).cloned() else {
            continue;
        };
        if javascript.is_null() {
            continue;
        }
        let coverage = javascript_analysis_coverage(javascript);
        let limitations = string_list_js(javascript.at("limitations"));
        let mut records = Vec::new();
        for registration in javascript.at("bundler_registrations").arr() {
            let chunk = create_chunk_node(context, file, registration, &coverage, &limitations);
            add_ast_contains_edge(
                context,
                &asset,
                &chunk,
                file,
                registration.at("location"),
                &coverage,
                Obj::new().with("bundler", registration.at("bundler").clone()),
            );
            let runtime = registration.at("runtime").str();
            for key in registration.at("chunk_keys").arr() {
                context.chunk_nodes.insert(
                    lookup_key(file.at("path").text().clone(), runtime, key.text().clone()),
                    chunk.clone(),
                );
            }
            records.push(Record {
                file: file.clone(),
                registration: registration.clone(),
                chunk: chunk.clone(),
                coverage: coverage.clone(),
            });
            add_module_nodes(context, file, registration, &chunk, &coverage, &limitations);
        }
        for record in &records {
            self_async_chunks += add_runtime_edges(context, record);
        }
    }
    self_reference_omissions(
        self_async_chunks,
        "bundler async-chunk reference",
        "bundler async-chunk references",
        "the requesting chunk",
    )
}

fn create_chunk_node(
    context: &mut GraphContext<'_>,
    file: &Json,
    registration: &Json,
    coverage: &Json,
    limitations: &[JsString],
) -> AppNode {
    let runtime = registration.at("runtime").str();
    let keys = string_list_js(registration.at("chunk_keys"));
    let label = JsString::from(runtime)
        .concat_str(":")
        .concat(&JsString::join(keys, ","));
    let properties = Obj::new()
        .with("path", file.at("path").clone())
        .with("bundler", registration.at("bundler").clone())
        .with("runtime", runtime)
        .with("chunk_keys", registration.at("chunk_keys").clone())
        .with(
            "unknown_chunk_keys",
            registration.at("unknown_chunk_keys").clone(),
        )
        .with(
            "runtime_require_name",
            registration.at("runtime_require_name").clone(),
        )
        .with(
            "runtime_module_cache_status",
            registration.at("runtime_module_cache_status").clone(),
        )
        .with(
            "entry_module_keys",
            registration.at("entry_module_keys").clone(),
        )
        .with(
            "unknown_entry_module_keys",
            registration.at("unknown_entry_module_keys").clone(),
        )
        .with(
            "async_chunk_keys",
            registration.at("async_chunk_keys").clone(),
        )
        .with(
            "unknown_async_chunk_keys",
            registration.at("unknown_async_chunk_keys").clone(),
        )
        .with("module_count", registration.at("modules").arr().len());
    let evidence = ast_observation(
        &EvidenceInput::new(
            file.at("sha256").str(),
            file.at("path").text(),
            "extract-bundler-registration",
            coverage.clone(),
        )
        .range(registration.at("location"))
        .limitations(limitations.to_vec()),
    );
    context.accumulator.add_node(NodeInput {
        kind: "javascript-chunk".into(),
        identity: artifact_local_identity(
            file.at("sha256").str(),
            "bundler-chunk",
            &composite_key(vec![runtime.into(), registration.at("chunk_keys").clone()]),
        ),
        observations: vec![ObservationInput::new_js(Some(label), properties, evidence)],
    })
}

fn add_module_nodes(
    context: &mut GraphContext<'_>,
    file: &Json,
    registration: &Json,
    chunk: &AppNode,
    coverage: &Json,
    limitations: &[JsString],
) {
    let runtime = registration.at("runtime").str();
    let entries = registration.at("entry_module_keys").arr();
    for module in registration.at("modules").arr() {
        let key = module.at("module_key");
        let properties = Obj::new()
            .with("path", file.at("path").clone())
            .with("bundler", registration.at("bundler").clone())
            .with("runtime", runtime)
            .with("chunk_keys", registration.at("chunk_keys").clone())
            .with("module_key", key.clone())
            .with(
                "factory_require_name",
                module.at("factory_require_name").clone(),
            )
            .with("runtime_entry", entries.contains(key))
            .with("source_sha256", module.at("source_sha256").clone())
            .with(
                "structural_fingerprint_sha256",
                module.at("structural_fingerprint_sha256").clone(),
            )
            .with(
                "structural_fingerprint_algorithm",
                module.at("structural_fingerprint_algorithm").clone(),
            )
            .with("exports", module.at("exports").clone());
        let evidence = ast_observation(
            &EvidenceInput::new(
                file.at("sha256").str(),
                file.at("path").text(),
                "extract-bundler-module",
                coverage.clone(),
            )
            .range(module.at("location"))
            .limitations(limitations.to_vec()),
        );
        let node = context.accumulator.add_node(NodeInput {
            kind: "javascript-module".into(),
            identity: artifact_local_identity(
                file.at("sha256").str(),
                &format!("{runtime}:module"),
                key.text().clone(),
            ),
            observations: vec![ObservationInput::new_js(
                Some(key.text().clone()),
                properties,
                evidence,
            )],
        });
        context.module_nodes.insert(
            lookup_key(file.at("path").text().clone(), runtime, key.text().clone()),
            node.clone(),
        );
        add_ast_contains_edge(
            context,
            chunk,
            &node,
            file,
            module.at("location"),
            coverage,
            Obj::new()
                .with("bundler", registration.at("bundler").clone())
                .with("runtime", runtime)
                .with("chunk_keys", registration.at("chunk_keys").clone())
                .with("module_key", key.clone()),
        );
    }
}

fn add_runtime_edges(context: &mut GraphContext<'_>, record: &Record) -> usize {
    let mut self_async = 0;
    let Record {
        file,
        registration,
        chunk,
        coverage,
    } = record;
    let path = file.at("path").text().clone();
    let runtime = registration.at("runtime").str();
    for key in registration.at("entry_module_keys").arr() {
        let resolved = context
            .module_nodes
            .get(&lookup_key(path.clone(), runtime, key.text().clone()))
            .cloned();
        let target = resolved
            .clone()
            .unwrap_or_else(|| unresolved_node(context, record, key.text(), true));
        let evidence = static_inference(
            &EvidenceInput::new(
                file.at("sha256").str(),
                &path,
                "resolve-bundler-entry-module",
                coverage.clone(),
            )
            .range(registration.at("location")),
            Some(if resolved.is_none() { "low" } else { "high" }),
        );
        context.accumulator.add_edge(EdgeInput {
            source: chunk.node_id.clone(),
            target: target.node_id,
            relation: "loads".into(),
            properties: Obj::new()
                .with("kind", "bundler-entry-module")
                .with("bundler", registration.at("bundler").clone())
                .with("runtime", runtime)
                .with("module_key", key.clone())
                .with(
                    "resolution_status",
                    if resolved.is_none() {
                        "not-found"
                    } else {
                        "resolved"
                    },
                ),
            evidence,
        });
    }
    for key in registration.at("async_chunk_keys").arr() {
        let resolved = context
            .chunk_nodes
            .get(&lookup_key(path.clone(), runtime, key.text().clone()))
            .cloned();
        if resolved.as_ref().map(|node| &node.node_id) == Some(&chunk.node_id) {
            self_async += 1;
            continue;
        }
        let target = resolved
            .clone()
            .unwrap_or_else(|| unresolved_node(context, record, key.text(), false));
        let evidence = static_inference(
            &EvidenceInput::new(
                file.at("sha256").str(),
                &path,
                "resolve-bundler-async-chunk",
                coverage.clone(),
            )
            .range(registration.at("location")),
            Some(if resolved.is_none() { "low" } else { "high" }),
        );
        context.accumulator.add_edge(EdgeInput {
            source: chunk.node_id.clone(),
            target: target.node_id,
            relation: "imports".into(),
            properties: Obj::new()
                .with("kind", "bundler-async-chunk")
                .with("bundler", registration.at("bundler").clone())
                .with("runtime", runtime)
                .with("chunk_key", key.clone())
                .with(
                    "resolution_status",
                    if resolved.is_none() {
                        "not-found"
                    } else {
                        "resolved"
                    },
                ),
            evidence,
        });
    }
    self_async
}

fn unresolved_node(
    context: &mut GraphContext<'_>,
    record: &Record,
    key: &JsString,
    module: bool,
) -> AppNode {
    let runtime = record.registration.at("runtime").str();
    let (kind, namespace, role, key_name, operation) = if module {
        (
            "javascript-module",
            "unresolved-entry-module",
            "bundler-module-reference",
            "module_key",
            "retain-unresolved-bundler-entry-module",
        )
    } else {
        (
            "javascript-chunk",
            "unresolved-async-chunk",
            "bundler-chunk-reference",
            "chunk_key",
            "retain-unresolved-bundler-async-chunk",
        )
    };
    let properties = Obj::new()
        .with("semantic_role", role)
        .with("bundler", record.registration.at("bundler").clone())
        .with("runtime", runtime)
        .with(key_name, Json::String(key.clone()))
        .with("resolution_status", "not-found");
    let evidence = static_inference(
        &EvidenceInput::new(
            record.file.at("sha256").str(),
            record.file.at("path").text(),
            operation,
            record.coverage.clone(),
        )
        .range(record.registration.at("location")),
        Some("low"),
    );
    context.accumulator.add_node(NodeInput {
        kind: kind.into(),
        identity: artifact_local_identity(
            record.file.at("sha256").str(),
            &format!("{runtime}:{namespace}"),
            key,
        ),
        observations: vec![ObservationInput::new_js(
            Some(key.clone()),
            properties,
            evidence,
        )],
    })
}
