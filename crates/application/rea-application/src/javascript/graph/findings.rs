//! `JavaScriptArtifactGraphFindings`: references, workers, endpoints, storage,
//! discovered roles and source-map links.

use super::super::semantic::value_types::JsString;
use super::application_graph::{AppNode, NodeInput, ObservationInput};
use super::context::{
    GraphContext, InferenceEdge, RoleNode, add_static_inference_edge, artifact_local_identity,
    create_electron_role_node, javascript_analysis_coverage, link_electron_role_to_asset,
    lookup_key, self_reference_omissions, source_node_for,
};
use super::evidence::{EvidenceInput, ast_observation, static_inference};
use super::json::{Json, Obj, sha256_text};
use super::resolution::{ResolveRequest, limitations, resolution_properties};

struct Finding<'f> {
    file: &'f Json,
    asset: &'f AppNode,
    value: &'f Json,
    coverage: &'f Json,
}

#[derive(Clone)]
struct Resolved {
    path: Option<JsString>,
    file: Option<Json>,
    node: Option<AppNode>,
    limitations: Vec<JsString>,
    status: Option<String>,
    resolution: Option<Json>,
}

/// `addJavaScriptStaticFindingsSteps`; returns self-reference limitations.
pub fn add_static_findings(context: &mut GraphContext<'_>) -> Vec<String> {
    let mut self_references = 0;
    let files = context.files().to_vec();
    for analyzed in &files {
        let file = analyzed.at("file");
        let javascript = analyzed.at("javascript");
        let path = file.at("path").text().clone();
        let Some(asset) = context.asset_nodes.get(&path).cloned() else {
            continue;
        };
        if javascript.is_null() {
            continue;
        }
        let coverage = javascript_analysis_coverage(javascript);
        for value in javascript.at("references").arr() {
            add_reference(
                context,
                &Finding {
                    file,
                    asset: &asset,
                    value,
                    coverage: &coverage,
                },
                &mut self_references,
            );
        }
        for value in javascript.at("endpoints").arr() {
            add_endpoint(
                context,
                &Finding {
                    file,
                    asset: &asset,
                    value,
                    coverage: &coverage,
                },
            );
        }
        for value in javascript.at("storage").arr() {
            add_storage(
                context,
                &Finding {
                    file,
                    asset: &asset,
                    value,
                    coverage: &coverage,
                },
            );
        }
        for value in javascript.at("role_paths").arr() {
            add_role(
                context,
                &Finding {
                    file,
                    asset: &asset,
                    value,
                    coverage: &coverage,
                },
            );
        }
        for value in javascript.at("source_map_urls").arr() {
            add_source_map(
                context,
                &Finding {
                    file,
                    asset: &asset,
                    value,
                    coverage: &coverage,
                },
            );
        }
    }
    self_reference_omissions(
        self_references,
        "static reference",
        "static references",
        "the referencing module",
    )
}

fn finding_source(context: &GraphContext<'_>, input: &Finding<'_>) -> AppNode {
    source_node_for(
        context,
        input.file.at("path").text(),
        input.value.at("module_key"),
        input.value.get("module_runtime"),
    )
    .unwrap_or_else(|| input.asset.clone())
}

fn add_reference(context: &mut GraphContext<'_>, input: &Finding<'_>, self_references: &mut usize) {
    let source = finding_source(context, input);
    let value = input.value;
    let kind = value.at("kind").str();
    let resolved = if value.at("specifier").is_null() {
        None
    } else {
        resolve_reference(context, input.file.at("path").text(), value, input.coverage)
    };
    let file_sha = input.file.at("sha256").str();
    let file_path = input.file.at("path").text().clone();
    if kind == "worker" || kind == "service-worker" {
        let resolution = resolved
            .as_ref()
            .and_then(|resolved| resolved.resolution.as_ref());
        let status: Json = resolved
            .as_ref()
            .and_then(|resolved| resolved.status.clone())
            .into();
        let mut properties = Obj::new()
            .with_static("declared_specifier", value.at("specifier").clone())
            .with_static("expression", value.at("expression").clone())
            .with_static(
                "resolved_path",
                resolved.as_ref().and_then(|resolved| resolved.path.clone()),
            )
            .with_static("resolution_status", status.clone());
        properties.extend_from(&resolution_properties(resolution));
        let reference_limitations = resolved
            .as_ref()
            .map(|resolved| resolved.limitations.clone())
            .unwrap_or_default();
        let evidence = static_inference(
            &EvidenceInput::new(
                file_sha,
                &file_path,
                "discover-worker",
                input.coverage.clone(),
            )
            .range(value.at("location"))
            .limitations(reference_limitations.clone()),
            None,
        );
        let key = value
            .at("specifier")
            .as_js_string()
            .cloned()
            .unwrap_or_else(|| value.at("expression").text().clone());
        let worker = context.accumulator.add_node(NodeInput {
            kind: if kind == "worker" {
                "worker"
            } else {
                "service-worker"
            }
            .into(),
            identity: artifact_local_identity(file_sha, kind, &key),
            observations: vec![ObservationInput::new_js(
                value.at("specifier").as_js_string().cloned(),
                properties,
                evidence,
            )],
        });
        let mut edge_properties = Obj::new()
            .with_static("kind", kind)
            .with_static("resolution_status", status);
        edge_properties.extend_from(&resolution_properties(resolution));
        add_static_inference_edge(
            context,
            InferenceEdge {
                source: &source,
                target: &worker,
                file: input.file,
                range: value.at("location"),
                coverage: input.coverage,
                relation: "loads",
                properties: edge_properties,
                confidence: None,
                limitations: Some(reference_limitations),
            },
        );
        if let Some(Resolved {
            path: Some(path),
            node: Some(node),
            limitations,
            ..
        }) = &resolved
        {
            add_static_inference_edge(
                context,
                InferenceEdge {
                    source: &worker,
                    target: node,
                    file: input.file,
                    range: value.at("location"),
                    coverage: input.coverage,
                    relation: "maps_to",
                    properties: Obj::new().with_static("resolved_path", path.clone()),
                    confidence: None,
                    limitations: Some(limitations.clone()),
                },
            );
        }
        return;
    }
    if resolved
        .as_ref()
        .and_then(|resolved| resolved.node.as_ref())
        .map(|node| &node.node_id)
        == Some(&source.node_id)
    {
        *self_references += 1;
        return;
    }
    let target = match resolved.as_ref().and_then(|resolved| resolved.node.clone()) {
        Some(node) => node,
        None => unresolved_reference_node(context, input.file, value, input.coverage, None),
    };
    let resolution_mode = if matches!(kind, "static-import" | "dynamic-import" | "require") {
        Json::from(
            context
                .resolver
                .module_resolution_mode(&file_path, kind, None),
        )
    } else {
        Json::Null
    };
    let mut properties = Obj::new()
        .with_static("kind", kind)
        .with_static("specifier", value.at("specifier").clone())
        .with_static("expression", value.at("expression").clone())
        .with_static("resolution_mode", resolution_mode)
        .with_static(
            "resolved_path",
            resolved.as_ref().and_then(|resolved| resolved.path.clone()),
        )
        .with_static(
            "resolution_status",
            resolved
                .as_ref()
                .and_then(|resolved| resolved.status.clone()),
        );
    properties.extend_from(&resolution_properties(
        resolved
            .as_ref()
            .and_then(|resolved| resolved.resolution.as_ref()),
    ));
    let relation = if resolved
        .as_ref()
        .and_then(|resolved| resolved.file.as_ref())
        .map(|file| file.at("kind").str())
        == Some("native-addon")
    {
        "loads"
    } else {
        "imports"
    };
    add_static_inference_edge(
        context,
        InferenceEdge {
            source: &source,
            target: &target,
            file: input.file,
            range: value.at("location"),
            coverage: input.coverage,
            relation,
            properties,
            confidence: None,
            limitations: resolved
                .as_ref()
                .map(|resolved| resolved.limitations.clone()),
        },
    );
}

fn compact_js_string_identity_key(value: &JsString) -> JsString {
    let prefix = "value-sha256:";
    let digest = format!("{prefix}{}", Json::String(value.clone()).digest());
    if value.len() <= digest.encode_utf16().count()
        && !value
            .units()
            .starts_with(&prefix.encode_utf16().collect::<Vec<_>>())
    {
        value.clone()
    } else {
        JsString::from(digest)
    }
}

fn add_endpoint(context: &mut GraphContext<'_>, input: &Finding<'_>) {
    let source = finding_source(context, input);
    let value = input.value;
    let text = value.at("value").text().clone();
    let kind = value.at("kind").str();
    let key = compact_js_string_identity_key(&text);
    let candidate = value.at("interpretation").str() == "candidate";
    let partial = value.at("resolution").str() == "partial";
    let candidate_limitation = "The unbound method-like argument is only a candidate; its receiver does not establish a network call.";
    let partial_limitation = "The request target is not an exact literal; the endpoint value retains the unresolved source expression.";
    let label = format!(
        "{kind} {}",
        if candidate {
            "endpoint candidate"
        } else {
            "endpoint"
        }
    );
    let mut identity_parts = vec![
        value
            .get("interpretation")
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or_else(|| Json::from("literal")),
    ];
    if partial {
        identity_parts.push("partial".into());
        identity_parts.push(value.at("location").clone());
    }
    identity_parts.push(key.into());
    let mut properties = Obj::new()
        .with_static("endpoint_kind", value.at("kind").clone())
        .with_static("value", text.clone())
        .with_static("mechanism", value.at("mechanism").clone());
    if candidate {
        properties.set("interpretation", value.at("interpretation").clone());
    }
    if partial {
        properties.set("resolution", value.at("resolution").clone());
    }
    let sha = input.file.at("sha256").str();
    let path = input.file.at("path").text().clone();
    let evidence = if candidate {
        static_inference(
            &EvidenceInput::new(
                sha,
                &path,
                "classify-static-endpoint-candidate",
                input.coverage.clone(),
            )
            .range(value.at("location"))
            .limitations(vec![JsString::from(candidate_limitation)]),
            Some("low"),
        )
    } else {
        let mut evidence_input = EvidenceInput::new(
            sha,
            &path,
            "discover-static-endpoint",
            input.coverage.clone(),
        )
        .range(value.at("location"));
        if partial {
            evidence_input.limitations = Some(vec![JsString::from(partial_limitation)]);
        }
        ast_observation(&evidence_input)
    };
    let node_label = if text.len() <= label.encode_utf16().count() {
        text
    } else {
        JsString::from(label)
    };
    // `Json::stringify` is the Rust representation of the TypeScript
    // `JSON.stringify` identity contract, including insertion order and
    // UTF-16 string escaping.
    let node = context.accumulator.add_node(NodeInput {
        kind: "endpoint".into(),
        identity: artifact_local_identity(sha, kind, &Json::array(identity_parts).stringify()),
        observations: vec![ObservationInput::new_js(
            Some(node_label),
            properties,
            evidence,
        )],
    });
    let mut edge_properties = Obj::new().with_static("mechanism", value.at("mechanism").clone());
    if candidate {
        edge_properties.set("interpretation", value.at("interpretation").clone());
    }
    if partial {
        edge_properties.set("resolution", value.at("resolution").clone());
    }
    let (confidence, limitations) = if candidate {
        (
            Some("low"),
            Some(vec![JsString::from(candidate_limitation)]),
        )
    } else if partial {
        (None, Some(vec![JsString::from(partial_limitation)]))
    } else {
        (None, None)
    };
    add_static_inference_edge(
        context,
        InferenceEdge {
            source: &source,
            target: &node,
            file: input.file,
            range: value.at("location"),
            coverage: input.coverage,
            relation: if kind == "route" { "exposes" } else { "calls" },
            properties: edge_properties,
            confidence,
            limitations,
        },
    );
}

fn add_storage(context: &mut GraphContext<'_>, input: &Finding<'_>) {
    let value = input.value;
    let candidate = value.at("interpretation").str() == "candidate";
    let limitation = "The constructor name is only a candidate; an unchanged SQLite module API origin is unproven.";
    let source = finding_source(context, input);
    let kind = value.at("kind").str();
    let sha = input.file.at("sha256").str();
    let path = input.file.at("path").text().clone();
    let mut properties = Obj::new()
        .with_static("storage_kind", kind)
        .with_static("name", value.at("name").clone())
        .with_static("mechanism", value.at("mechanism").clone());
    if candidate {
        properties.set("interpretation", "candidate");
    }
    let evidence = if candidate {
        static_inference(
            &EvidenceInput::new(
                sha,
                &path,
                "classify-static-storage-candidate",
                input.coverage.clone(),
            )
            .range(value.at("location"))
            .limitations(vec![JsString::from(limitation)]),
            Some("low"),
        )
    } else {
        ast_observation(
            &EvidenceInput::new(
                sha,
                &path,
                "discover-static-storage",
                input.coverage.clone(),
            )
            .range(value.at("location")),
        )
    };
    let namespace = if candidate {
        format!("{kind}:candidate")
    } else {
        kind.to_owned()
    };
    let key = value
        .at("name")
        .as_js_string()
        .cloned()
        .unwrap_or_else(|| value.at("mechanism").text().clone());
    let label = value
        .at("name")
        .as_js_string()
        .cloned()
        .unwrap_or_else(|| JsString::from(kind));
    let node = context.accumulator.add_node(NodeInput {
        kind: "storage".into(),
        identity: artifact_local_identity(sha, &namespace, &key),
        observations: vec![ObservationInput::new_js(Some(label), properties, evidence)],
    });
    let mut edge_properties = Obj::new().with_static("mechanism", value.at("mechanism").clone());
    if candidate {
        edge_properties.set("interpretation", "candidate");
    }
    add_static_inference_edge(
        context,
        InferenceEdge {
            source: &source,
            target: &node,
            file: input.file,
            range: value.at("location"),
            coverage: input.coverage,
            relation: "persists_to",
            properties: edge_properties,
            confidence: candidate.then_some("low"),
            limitations: candidate.then(|| vec![JsString::from(limitation)]),
        },
    );
}

fn add_role(context: &mut GraphContext<'_>, input: &Finding<'_>) {
    let value = input.value;
    let role = value.at("role").str();
    let resolution_context = value.at("resolution_context").str();
    let path = input.file.at("path").text().clone();
    let declared_path = value.at("path").text().clone();
    let mut request =
        ResolveRequest::new_exact(&declared_path, &path, &JsString::from(resolution_context));
    request.runtime_path_kind = if role == "preload"
        || (role == "renderer" && resolution_context == "filesystem-expression")
    {
        Some("exact-file")
    } else if role == "renderer" && resolution_context == "module-specifier" {
        Some("url-resource")
    } else {
        None
    };
    let resolution = context.resolve(&request);
    let role_node = create_electron_role_node(
        context,
        RoleNode {
            kind: if role == "preload" {
                "electron-preload"
            } else {
                "electron-renderer"
            },
            anchor: input.file,
            resolution: &resolution,
            mechanism: value.at("mechanism").str(),
            range: Some(value.at("location")),
            coverage: Some(input.coverage),
        },
    );
    let source = finding_source(context, input);
    add_static_inference_edge(
        context,
        InferenceEdge {
            source: &source,
            target: &role_node,
            file: input.file,
            range: value.at("location"),
            coverage: input.coverage,
            relation: "loads",
            properties: Obj::new().with_static("mechanism", value.at("mechanism").clone()),
            confidence: None,
            limitations: None,
        },
    );
    link_electron_role_to_asset(
        context,
        &role_node,
        input.file,
        &resolution,
        Some(value.at("location")),
        Some(input.coverage),
    );
}

fn add_source_map(context: &mut GraphContext<'_>, input: &Finding<'_>) {
    let value = input.value;
    let declared = value.at("declared_url").text().clone();
    // Node's crypto hash API UTF-8 encodes lone UTF-16 surrogates as U+FFFD.
    // Keep that compatibility conversion confined to the digest input; the
    // declared URL retained in graph properties remains the original value.
    let declared_sha = sha256_text(&String::from_utf16_lossy(declared.units()));
    let sha = input.file.at("sha256").str();
    let path = input.file.at("path").text().clone();
    let resolution = context.resolve(&ResolveRequest::new_exact(
        &declared,
        &path,
        &JsString::from("url-reference"),
    ));
    let resolved_path = resolution
        .get("resolved_path")
        .and_then(Json::as_js_string)
        .cloned();
    let resolved_file = resolved_path
        .as_ref()
        .and_then(|path| context.files_by_path.get(path))
        .cloned();
    let resolved_node = resolved_path
        .as_ref()
        .and_then(|path| context.file_nodes.get(path))
        .cloned();
    let available = resolved_file.as_ref().map(|file| file.at("kind").str()) == Some("source-map")
        && resolved_node.is_some();
    let resolution_limitations = limitations(&resolution);
    let limitations = if available || !resolution_limitations.is_empty() {
        resolution_limitations
    } else {
        vec!["The declared reference does not identify an available source-map projection.".into()]
    };
    let identity = match (&resolved_node, available) {
        (Some(node), true) => node.identity.clone(),
        _ => artifact_local_identity(sha, "unresolved-source-map", &declared_sha),
    };
    let mut properties = Obj::new()
        .with_static("declared_url", declared.clone())
        .with_static("declared_url_sha256", declared_sha.as_str())
        .with_static("resolved_path", resolved_path.clone())
        .with_static(
            "resolution_status",
            resolution.at("resolution_status").clone(),
        );
    properties.extend_from(&resolution_properties(Some(&resolution)));
    properties.set("available", available);
    let evidence = static_inference(
        &EvidenceInput::new(sha, &path, "discover-source-map", input.coverage.clone())
            .range(value.at("location"))
            .limitations(limitations.clone()),
        Some("medium"),
    );
    let target = context.accumulator.add_node(NodeInput {
        kind: "source-map".into(),
        identity,
        observations: vec![ObservationInput::new_js(
            Some(JsString::from("source map reference")),
            properties,
            evidence,
        )],
    });
    let mut edge_properties = Obj::new()
        .with_static("declared_url_sha256", declared_sha.as_str())
        .with_static("resolved_path", resolved_path)
        .with_static(
            "resolution_status",
            resolution.at("resolution_status").clone(),
        );
    edge_properties.extend_from(&resolution_properties(Some(&resolution)));
    add_static_inference_edge(
        context,
        InferenceEdge {
            source: input.asset,
            target: &target,
            file: input.file,
            range: value.at("location"),
            coverage: input.coverage,
            relation: "maps_to",
            properties: edge_properties,
            confidence: None,
            limitations: Some(limitations),
        },
    );
}

fn resolve_reference(
    context: &mut GraphContext<'_>,
    source_path: &JsString,
    reference: &Json,
    coverage: &Json,
) -> Option<Resolved> {
    let specifier_js = reference.at("specifier").text().clone();
    let source = context.files_by_path.get(source_path).cloned()?;
    let specifier = &specifier_js;
    let kind = reference.at("kind").str();
    let worker = kind == "worker" || kind == "service-worker";
    if !worker && let Some(chunk) = resolve_chunk_reference(context, source_path, reference) {
        return Some(chunk);
    }
    let runtime = reference.get("module_runtime");
    let module = if worker {
        None
    } else {
        runtime.and_then(Json::as_js_string).and_then(|runtime| {
            context
                .module_nodes
                .get(&lookup_key(source_path.clone(), runtime, specifier.clone()))
                .cloned()
        })
    };
    if let Some(module) = module {
        return Some(Resolved {
            path: Some(source_path.concat_str("#module:").concat(specifier)),
            file: Some(source.clone()),
            node: Some(module),
            limitations: Vec::new(),
            status: None,
            resolution: None,
        });
    }
    let resolution = if worker {
        context.resolve(&ResolveRequest::new_exact(
            specifier,
            source_path,
            &JsString::from("url-reference"),
        ))
    } else {
        let mut request = ResolveRequest::new_exact(
            &specifier_js,
            source_path,
            &JsString::from("module-specifier"),
        );
        if matches!(kind, "require" | "static-import" | "dynamic-import") {
            request.module_kind = Some(context.resolver.module_resolution_mode(
                source_path,
                kind,
                None,
            ));
        }
        context.resolve(&request)
    };
    let status = resolution.at("resolution_status").str().to_owned();
    let Some(path_js) = resolution
        .get("resolved_path")
        .and_then(Json::as_js_string)
        .cloned()
    else {
        let node = if worker {
            None
        } else {
            Some(unresolved_reference_node(
                context,
                &source,
                reference,
                coverage,
                Some(&resolution),
            ))
        };
        return Some(Resolved {
            path: None,
            file: None,
            node,
            limitations: limitations(&resolution),
            status: Some(status),
            resolution: Some(resolution),
        });
    };
    let file = context.files_by_path.get(&path_js).cloned()?;
    let node = context.file_nodes.get(&path_js).cloned()?;
    Some(Resolved {
        path: Some(path_js),
        file: Some(file),
        node: Some(node),
        limitations: limitations(&resolution),
        status: Some(status),
        resolution: Some(resolution),
    })
}

fn resolve_chunk_reference(
    context: &GraphContext<'_>,
    source_path: &JsString,
    reference: &Json,
) -> Option<Resolved> {
    let key = reference.at("specifier").text().strip_prefix("chunk:")?;
    let file = context.files_by_path.get(source_path).cloned()?;
    let analyzed = context
        .files()
        .iter()
        .find(|analyzed| analyzed.at("file").at("path").text() == source_path)?;
    let javascript = analyzed.at("javascript");
    if javascript.is_null() {
        return None;
    }
    let runtime = reference.get("module_runtime");
    let module_key = reference.at("module_key");
    let mut unique: Vec<AppNode> = Vec::new();
    for registration in javascript.at("bundler_registrations").arr() {
        let admitted = match runtime {
            None => module_key.is_null(),
            Some(runtime) => {
                registration.at("runtime") == runtime
                    && registration
                        .at("modules")
                        .arr()
                        .iter()
                        .any(|module| module.at("module_key") == module_key)
            }
        };
        if !admitted {
            continue;
        }
        if let Some(node) = context.chunk_nodes.get(&lookup_key(
            source_path.clone(),
            registration.at("runtime").text().clone(),
            key.clone(),
        )) {
            if let Some(existing) = unique
                .iter_mut()
                .find(|existing| existing.node_id == node.node_id)
            {
                *existing = node.clone();
            } else {
                unique.push(node.clone());
            }
        }
    }
    if unique.len() != 1 {
        return None;
    }
    Some(Resolved {
        path: Some(source_path.concat_str("#chunk:").concat(&key)),
        file: Some(file),
        node: unique.pop(),
        limitations: Vec::new(),
        status: None,
        resolution: None,
    })
}

fn unresolved_reference_node(
    context: &mut GraphContext<'_>,
    file: &Json,
    reference: &Json,
    coverage: &Json,
    resolution: Option<&Json>,
) -> AppNode {
    let kind = reference.at("kind").str();
    let key = reference
        .at("specifier")
        .as_js_string()
        .cloned()
        .unwrap_or_else(|| reference.at("expression").text().clone());
    let mut properties = Obj::new()
        .with_static("reference_kind", kind)
        .with_static("specifier", reference.at("specifier").clone())
        .with_static("expression", reference.at("expression").clone())
        .with_static("resolution", "unresolved");
    if let Some(resolution) = resolution {
        properties.set(
            "resolution_status",
            resolution.at("resolution_status").clone(),
        );
    }
    properties.extend_from(&resolution_properties(resolution));
    let mut evidence_limitations = vec![JsString::from(
        "The static reference could not be resolved within the inventoried artifact.",
    )];
    if let Some(resolution) = resolution {
        evidence_limitations.extend(limitations(resolution));
    }
    let evidence = static_inference(
        &EvidenceInput::new(
            file.at("sha256").str(),
            file.at("path").text(),
            "resolve-static-reference",
            coverage.clone(),
        )
        .range(reference.at("location"))
        .limitations(evidence_limitations),
        Some("low"),
    );
    context.accumulator.add_node(NodeInput {
        kind: "javascript-module".into(),
        identity: artifact_local_identity(
            file.at("sha256").str(),
            "unresolved-reference",
            JsString::from(kind).concat_str(":").concat(&key),
        ),
        observations: vec![ObservationInput::new_js(
            reference.at("specifier").as_js_string().cloned(),
            properties,
            evidence,
        )],
    })
}
