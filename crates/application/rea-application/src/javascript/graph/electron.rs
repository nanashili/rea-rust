//! `ElectronBoundaryGraph*` and the IPC record/pairing part of
//! `ElectronBoundaryAnalysis` that graph construction consumes.

use super::super::semantic::value_types::JsString;
use super::application_graph::{AppNode, NodeInput, ObservationInput};
use super::context::{
    GraphContext, RoleNode, artifact_local_identity, create_electron_role_node,
    javascript_analysis_coverage, link_electron_role_to_asset, source_node_for,
};
use super::evidence::{EvidenceInput, ast_observation, static_inference};
use super::json::{Json, Obj, composite_key, js_int, sha256_text};
use super::resolution::{ResolveRequest, limitations, resolution_properties};

/// One IPC fact retaining its exact owning artifact.
#[derive(Clone)]
pub struct IpcRecord {
    /// Deterministic record key.
    pub key: JsString,
    /// Owning file.
    pub file: Json,
    /// IPC finding.
    pub finding: Json,
}

fn point_key(point: &Json) -> String {
    format!(
        "{}:{}",
        js_int(point.at("line").num()),
        js_int(point.at("column").num())
    )
}

fn ipc_record_key(path: &Json, finding: &Json) -> JsString {
    let channel = if finding.at("channel").is_null() {
        finding.at("channel_expression").text().clone()
    } else {
        finding.at("channel").text().clone()
    };
    let identity = JsString::join(
        [
            path.text().clone(),
            JsString::from(point_key(finding.at("location").at("start"))),
            finding.at("side").text().clone(),
            finding.at("operation").text().clone(),
            channel,
            JsString::from(finding.at("handler_location").stringify()),
        ],
        "\0",
    );
    match finding.get("invocation_location") {
        None => identity,
        Some(invocation) => identity
            .concat_str("\0")
            .concat_str(&point_key(invocation.at("start"))),
    }
}

/// `collectElectronIpcRecords`.
pub fn collect_ipc_records(analysis: &Json) -> Vec<IpcRecord> {
    let mut records: Vec<IpcRecord> = analysis
        .at("files")
        .arr()
        .iter()
        .flat_map(|analyzed| {
            let file = analyzed.at("file");
            analyzed
                .at("javascript")
                .at("electron")
                .at("ipc")
                .arr()
                .iter()
                .map(move |finding| IpcRecord {
                    key: ipc_record_key(file.at("path"), finding),
                    file: file.clone(),
                    finding: finding.clone(),
                })
        })
        .collect();
    records.sort_by(|left, right| left.key.compare_code_points(&right.key));
    records
}

fn is_renderer_transmission(record: &IpcRecord) -> bool {
    record.finding.at("side").str() == "renderer"
        && matches!(record.finding.at("mode").str(), "send" | "invoke")
}

fn is_main_handler(record: &IpcRecord) -> bool {
    record.finding.at("side").str() == "main"
        && matches!(record.finding.at("mode").str(), "listen" | "handle")
}

fn compatible_modes(transmission: &Json, handler: &Json) -> bool {
    if transmission.at("mode").str() == "invoke" {
        handler.at("mode").str() == "handle"
    } else if transmission.at("operation").str() == "send-to-host" {
        false
    } else {
        transmission.at("mode").str() == "send" && handler.at("mode").str() == "listen"
    }
}

/// `classifyElectronIpcPairings`: `(transmission, candidates)` per pairable transmission.
pub fn classify_pairings(records: &[IpcRecord]) -> Vec<(&IpcRecord, Vec<&IpcRecord>)> {
    let handlers: Vec<&IpcRecord> = records
        .iter()
        .filter(|record| is_main_handler(record))
        .collect();
    records
        .iter()
        .filter(|record| {
            is_renderer_transmission(record)
                && record.finding.at("operation").str() != "send-to-host"
        })
        .map(|transmission| {
            let candidates = if transmission.finding.at("channel").is_null() {
                Vec::new()
            } else {
                handlers
                    .iter()
                    .copied()
                    .filter(|handler| {
                        handler.finding.at("channel") == transmission.finding.at("channel")
                            && compatible_modes(&transmission.finding, &handler.finding)
                    })
                    .collect()
            };
            (transmission, candidates)
        })
        .collect()
}

/// `unambiguousElectronIpcPairings`.
pub fn unambiguous_pairings(records: &[IpcRecord]) -> Vec<(IpcRecord, IpcRecord)> {
    classify_pairings(records)
        .into_iter()
        .filter(|(_, candidates)| candidates.len() == 1)
        .map(|(transmission, candidates)| (transmission.clone(), candidates[0].clone()))
        .collect()
}

/// `electronFindingSourceNode`.
fn finding_source(
    context: &GraphContext<'_>,
    file: &Json,
    module_key: &Json,
    runtime: Option<&Json>,
) -> Option<AppNode> {
    if module_key.is_null() {
        let path = file.at("path").text().clone();
        return context
            .asset_nodes
            .get(&path)
            .or_else(|| context.file_nodes.get(&path))
            .cloned();
    }
    let path = file.at("path").text().clone();
    source_node_for(context, &path, module_key, runtime).or_else(|| {
        context
            .asset_nodes
            .get(&path)
            .or_else(|| context.file_nodes.get(&path))
            .cloned()
    })
}

fn observation_identity(context: &GraphContext<'_>, scope: &str, key: &JsString) -> Json {
    // Node's crypto hash API UTF-8 encodes lone UTF-16 surrogates as U+FFFD.
    // Keep that compatibility conversion confined to the digest input; all
    // graph values continue to retain the original `JsString`.
    let hash_key = String::from_utf16_lossy(key.units());
    Obj::new()
        .with("strategy", "observation-fingerprint")
        .with("stability", "observation-only")
        .with(
            "observation_sha256",
            sha256_text(&format!("{}\0{scope}\0{hash_key}", context.root_sha256())),
        )
        .with("scope", scope)
        .into()
}

/// `electronRangeKey`.
fn range_key(range: &Json) -> String {
    format!(
        "{}-{}",
        point_key(range.at("start")),
        point_key(range.at("end"))
    )
}

fn compare_point(left: &Json, right: &Json) -> f64 {
    if left.at("line").num() == right.at("line").num() {
        left.at("column").num() - right.at("column").num()
    } else {
        left.at("line").num() - right.at("line").num()
    }
}

fn range_contains(outer: &Json, inner: &Json) -> bool {
    compare_point(outer.at("start"), inner.at("start")) <= 0.0
        && compare_point(outer.at("end"), inner.at("end")) >= 0.0
}

struct ElectronEdge<'e> {
    source: &'e AppNode,
    target: &'e AppNode,
    file: &'e Json,
    range: &'e Json,
    coverage: &'e Json,
    relation: &'e str,
    operation: &'e str,
    properties: Obj,
    confidence: Option<&'e str>,
    limitations: Option<Vec<JsString>>,
}

fn add_edge(context: &mut GraphContext<'_>, input: ElectronEdge<'_>, ast: bool) {
    let path = input.file.at("path").text().clone();
    let mut evidence_input = EvidenceInput::new(
        input.file.at("sha256").str(),
        &path,
        input.operation,
        input.coverage.clone(),
    )
    .range(input.range);
    evidence_input.limitations = input.limitations;
    let evidence = if ast {
        ast_observation(&evidence_input)
    } else {
        static_inference(&evidence_input, input.confidence)
    };
    context
        .accumulator
        .add_edge(super::application_graph::EdgeInput {
            source: input.source.node_id.clone(),
            target: input.target.node_id.clone(),
            relation: input.relation.into(),
            properties: input.properties,
            evidence,
        });
}

/// `addElectronBoundaries`.
pub fn add_electron_boundaries(context: &mut GraphContext<'_>) {
    add_window_boundaries(context);
    add_ipc_boundaries(context);
    add_native_boundaries(context);
    add_call_paths(context);
}

fn add_window_boundaries(context: &mut GraphContext<'_>) {
    let files = context.files().to_vec();
    for analyzed in &files {
        let file = analyzed.at("file");
        let javascript = analyzed.at("javascript");
        if javascript.is_null() {
            continue;
        }
        let coverage = javascript_analysis_coverage(javascript);
        let electron = javascript.at("electron");
        for value in electron.at("browser_windows").arr() {
            if let Some(source) = finding_source(
                context,
                file,
                value.at("module_key"),
                value.get("module_runtime"),
            ) {
                add_browser_window(context, file, &source, value, &coverage);
            }
        }
        for value in electron.at("context_bridge_apis").arr() {
            if let Some(source) = finding_source(
                context,
                file,
                value.at("module_key"),
                value.get("module_runtime"),
            ) {
                add_context_bridge(context, file, &source, value, &coverage);
            }
        }
        for value in electron.at("utility_processes").arr() {
            if let Some(source) = finding_source(
                context,
                file,
                value.at("module_key"),
                value.get("module_runtime"),
            ) {
                add_utility_process(context, file, &source, value, &coverage);
            }
        }
    }
}

fn add_browser_window(
    context: &mut GraphContext<'_>,
    file: &Json,
    source: &AppNode,
    value: &Json,
    coverage: &Json,
) {
    let path = file.at("path").text().clone();
    let sha = file.at("sha256").str();
    let location = value.at("location");
    let key = range_key(location);
    let mut properties = Obj::new()
        .with("source_path", Json::String(path.clone()))
        .with("options_status", value.at("options_status").clone())
        .with(
            "web_preferences_status",
            value.at("web_preferences_status").clone(),
        )
        .with("web_preferences", value.at("web_preferences").clone())
        .with("preload_path", value.at("preload_path").clone())
        .with(
            "preload_resolution_context",
            value.at("preload_resolution_context").clone(),
        );
    let resolved_sources = value.get("resolution_sources");
    if let Some(sources) = resolved_sources {
        properties.set(
            "resolution_sources",
            Json::Array(
                sources
                    .arr()
                    .iter()
                    .map(|location| {
                        let mut entry = Obj::new().with("source", Json::String(path.clone()));
                        entry.extend_from(&location.obj());
                        Json::from(entry)
                    })
                    .collect(),
            ),
        );
    }
    properties.set("absence_means_default", false);
    let evidence_input = EvidenceInput::new(
        sha,
        &path,
        if resolved_sources.is_none() {
            "observe-browser-window-construction"
        } else {
            "resolve-browser-window-constant-options"
        },
        coverage.clone(),
    )
    .range(location)
    .limitations(vec![JsString::from(
        "Only explicitly present webPreferences are reported; omitted properties are not interpreted as Electron defaults.",
    )]);
    let evidence = if resolved_sources.is_none() {
        ast_observation(&evidence_input)
    } else {
        static_inference(&evidence_input, None)
    };
    let window = context.accumulator.add_node(NodeInput {
        kind: "browser-window".into(),
        identity: artifact_local_identity(sha, "electron-browser-window", &key),
        observations: vec![ObservationInput::new_js(
            Some(JsString::from(format!("BrowserWindow@{key}"))),
            properties,
            evidence,
        )],
    });
    add_edge(
        context,
        ElectronEdge {
            source,
            target: &window,
            file,
            range: location,
            coverage,
            relation: "contains",
            operation: "locate-browser-window-construction",
            properties: Obj::new().with("source_path", Json::String(path.clone())),
            confidence: None,
            limitations: None,
        },
        true,
    );
    let Some(declared) = value.at("preload_path").as_js_string() else {
        return;
    };
    let mut request = ResolveRequest::new_exact(
        declared,
        &path,
        value.at("preload_resolution_context").text(),
    );
    request.runtime_path_kind = Some("exact-file");
    let resolution = context.resolve(&request);
    let role = create_electron_role_node(
        context,
        RoleNode {
            kind: "electron-preload",
            anchor: file,
            resolution: &resolution,
            mechanism: "BrowserWindow:webPreferences.preload",
            range: Some(location),
            coverage: Some(coverage),
        },
    );
    let mut properties = Obj::new()
        .with("declared_path", Json::String(declared.clone()))
        .with(
            "resolution_context",
            resolution.at("resolution_context").clone(),
        )
        .with("resolved_path", resolution.at("resolved_path").clone())
        .with(
            "resolution_status",
            resolution.at("resolution_status").clone(),
        )
        .with("limitations", resolution.at("limitations").clone());
    properties.extend_from(&resolution_properties(Some(&resolution)));
    add_edge(
        context,
        ElectronEdge {
            source: &window,
            target: &role,
            file,
            range: location,
            coverage,
            relation: "loads",
            operation: "associate-browser-window-preload",
            properties,
            confidence: None,
            limitations: None,
        },
        false,
    );
    link_electron_role_to_asset(
        context,
        &role,
        file,
        &resolution,
        Some(location),
        Some(coverage),
    );
}

fn add_context_bridge(
    context: &mut GraphContext<'_>,
    file: &Json,
    source: &AppNode,
    value: &Json,
    coverage: &Json,
) {
    let sha = file.at("sha256").str();
    let path = file.at("path").text().clone();
    let location = value.at("location");
    let api = value
        .at("api_key")
        .as_js_string()
        .or_else(|| value.at("api_key_expression").as_js_string())
        .cloned()
        .unwrap_or_else(|| JsString::from("[missing]"));
    let properties = Obj::new()
        .with("world", value.at("world").clone())
        .with("world_id", value.at("world_id").clone())
        .with("api_key", value.at("api_key").clone())
        .with("api_key_expression", value.at("api_key_expression").clone())
        .with("api_status", value.at("api_status").clone())
        .with("members", value.at("members").clone())
        .with("unknown_members", value.at("unknown_members").clone())
        .with(
            "resolution_basis",
            value
                .get("resolution_basis")
                .filter(|basis| !basis.is_null())
                .cloned()
                .unwrap_or_else(|| "direct-syntax".into()),
        );
    let evidence_input =
        EvidenceInput::new(sha, &path, "observe-context-bridge-api", coverage.clone())
            .range(location);
    let evidence = if value.at("resolution_basis").str() == "wrapper-substitution" {
        static_inference(&evidence_input, None)
    } else {
        ast_observation(&evidence_input)
    };
    let bridge = context.accumulator.add_node(NodeInput {
        kind: "context-bridge-api".into(),
        identity: artifact_local_identity(
            sha,
            "electron-context-bridge",
            JsString::join(
                [
                    value.at("world").text().clone(),
                    api.clone(),
                    JsString::from(range_key(location)),
                ],
                ":",
            ),
        ),
        observations: vec![ObservationInput::new_js(
            value.at("api_key").as_js_string().cloned(),
            properties,
            evidence,
        )],
    });
    add_edge(
        context,
        ElectronEdge {
            source,
            target: &bridge,
            file,
            range: location,
            coverage,
            relation: "exposes",
            operation: "map-context-bridge-exposure",
            properties: Obj::new()
                .with("world", value.at("world").clone())
                .with("api_key", value.at("api_key").clone())
                .with(
                    "resolution",
                    if value.at("api_key").is_null() {
                        "dynamic"
                    } else {
                        "literal"
                    },
                ),
            confidence: None,
            limitations: None,
        },
        false,
    );
}

fn add_utility_process(
    context: &mut GraphContext<'_>,
    file: &Json,
    source: &AppNode,
    value: &Json,
    coverage: &Json,
) {
    let path = file.at("path").text().clone();
    let sha = file.at("sha256").str();
    let location = value.at("location");
    let resolution = value.at("module_path").as_js_string().map(|declared| {
        let mut request = ResolveRequest::new_exact(
            declared,
            &path,
            value.at("module_resolution_context").text(),
        );
        request.runtime_path_kind = Some("node-entrypoint");
        context.resolve(&request)
    });
    let mut resolution_props = Obj::new()
        .with(
            "resolved_path",
            resolution
                .as_ref()
                .map_or(Json::Null, |r| r.at("resolved_path").clone()),
        )
        .with(
            "resolution_status",
            resolution
                .as_ref()
                .map_or(Json::Null, |r| r.at("resolution_status").clone()),
        );
    resolution_props.extend_from(&resolution_properties(resolution.as_ref()));
    let module_or_expression = value
        .at("module_path")
        .as_js_string()
        .or_else(|| value.at("module_expression").as_js_string())
        .cloned()
        .unwrap_or_default();
    let label = value
        .at("service_name")
        .as_js_string()
        .or_else(|| value.at("module_path").as_js_string())
        .cloned();
    let mut observations = vec![ObservationInput::new_js(
        label,
        Obj::new()
            .with("module_path", value.at("module_path").clone())
            .with(
                "module_resolution_context",
                value.at("module_resolution_context").clone(),
            )
            .with("module_expression", value.at("module_expression").clone())
            .with("service_name", value.at("service_name").clone()),
        ast_observation(
            &EvidenceInput::new(sha, &path, "observe-utility-process-fork", coverage.clone())
                .range(location),
        ),
    )];
    if let Some(resolution) = &resolution {
        observations.push(ObservationInput::new_js(
            Some(JsString::from("utility process entrypoint resolution")),
            resolution_props.clone(),
            static_inference(
                &EvidenceInput::new(
                    sha,
                    &path,
                    "resolve-utility-process-entrypoint",
                    coverage.clone(),
                )
                .range(location)
                .limitations(limitations(resolution)),
                None,
            ),
        ));
    }
    let utility = context.accumulator.add_node(NodeInput {
        kind: "electron-utility".into(),
        identity: artifact_local_identity(
            sha,
            "electron-utility-process",
            JsString::join(
                [module_or_expression, JsString::from(range_key(location))],
                ":",
            ),
        ),
        observations,
    });
    let mut properties = Obj::new()
        .with("declared_path", value.at("module_path").clone())
        .with("expression", value.at("module_expression").clone());
    properties.extend_from(&resolution_props);
    add_edge(
        context,
        ElectronEdge {
            source,
            target: &utility,
            file,
            range: location,
            coverage,
            relation: "loads",
            operation: "map-utility-process-launch",
            properties,
            confidence: None,
            limitations: Some(
                resolution
                    .as_ref()
                    .map(limitations)
                    .unwrap_or_default()
                    .into_iter()
                    .map(JsString::from)
                    .collect(),
            ),
        },
        false,
    );
    let (Some(declared), Some(resolution)) = (value.at("module_path").as_js_string(), &resolution)
    else {
        return;
    };
    let resolved_js = resolution.at("resolved_path").text().clone();
    let Some(target) = context
        .asset_nodes
        .get(&resolved_js)
        .or_else(|| context.file_nodes.get(&resolved_js))
        .cloned()
    else {
        return;
    };
    let mut properties = Obj::new()
        .with("declared_path", Json::String(declared.clone()))
        .with(
            "resolution_context",
            resolution.at("resolution_context").clone(),
        )
        .with("resolved_path", Json::String(resolved_js.clone()))
        .with(
            "resolution_status",
            resolution.at("resolution_status").clone(),
        );
    properties.extend_from(&resolution_properties(Some(resolution)));
    add_edge(
        context,
        ElectronEdge {
            source: &utility,
            target: &target,
            file,
            range: location,
            coverage,
            relation: "maps_to",
            operation: "resolve-utility-process-entrypoint",
            properties,
            confidence: None,
            limitations: None,
        },
        false,
    );
}

fn coverage_for(context: &GraphContext<'_>, file: &Json) -> Option<Json> {
    let analyzed = context
        .files()
        .iter()
        .find(|analyzed| analyzed.at("file").at("path") == file.at("path"))?;
    let javascript = analyzed.at("javascript");
    (!javascript.is_null()).then(|| javascript_analysis_coverage(javascript))
}

fn add_ipc_boundaries(context: &mut GraphContext<'_>) {
    let records = collect_ipc_records(&context.analysis);
    let mut handlers: std::collections::HashMap<JsString, AppNode> =
        std::collections::HashMap::new();
    let mut sources: std::collections::HashMap<JsString, AppNode> =
        std::collections::HashMap::new();
    for record in &records {
        let Some(coverage) = coverage_for(context, &record.file) else {
            continue;
        };
        let finding = &record.finding;
        let Some(source) = finding_source(
            context,
            &record.file,
            finding.at("module_key"),
            finding.get("module_runtime"),
        ) else {
            continue;
        };
        sources.insert(record.key.clone(), source.clone());
        let channel = add_channel_node(context, record, &coverage);
        let mode = finding.at("mode").str();
        if mode == "listen" || mode == "handle" {
            let handler = add_handler_node(context, record, &source, &channel, &coverage);
            handlers.insert(record.key.clone(), handler);
            continue;
        }
        add_edge(
            context,
            ElectronEdge {
                source: &source,
                target: &channel,
                file: &record.file,
                range: finding.at("location"),
                coverage: &coverage,
                relation: if mode == "invoke" { "invokes" } else { "sends" },
                operation: "map-ipc-transmission",
                properties: Obj::new()
                    .with("side", finding.at("side").clone())
                    .with("operation", finding.at("operation").clone())
                    .with("channel", finding.at("channel").clone())
                    .with(
                        "channel_expression",
                        finding.at("channel_expression").clone(),
                    )
                    .with(
                        "resolution",
                        if finding.at("channel").is_null() {
                            "dynamic"
                        } else {
                            "literal"
                        },
                    ),
                confidence: None,
                limitations: None,
            },
            false,
        );
    }
    // Sender validations.
    let files = context.files().to_vec();
    for analyzed in &files {
        let file = analyzed.at("file");
        let javascript = analyzed.at("javascript");
        if javascript.is_null() {
            continue;
        }
        let coverage = javascript_analysis_coverage(javascript);
        for validation in javascript.at("electron").at("sender_validations").arr() {
            let containing = records
                .iter()
                .filter(|record| {
                    record.file.at("path") == file.at("path")
                        && !record.finding.at("handler_location").is_null()
                        && range_contains(
                            record.finding.at("handler_location"),
                            validation.at("location"),
                        )
                })
                .min_by(|left, right| {
                    magnitude(left.finding.at("handler_location"))
                        .total_cmp(&magnitude(right.finding.at("handler_location")))
                });
            let target = match containing {
                None => finding_source(
                    context,
                    file,
                    validation.at("module_key"),
                    validation.get("module_runtime"),
                ),
                Some(record) => handlers.get(&record.key).cloned(),
            };
            let Some(target) = target else { continue };
            let path = file.at("path").text().clone();
            let properties = Obj::new()
                .with("fact_kind", "sender-validation-candidate")
                .with("subject", validation.at("subject").clone())
                .with("mechanism", validation.at("mechanism").clone())
                .with("expected", validation.at("expected").clone())
                .with("enforcement", validation.at("enforcement").clone());
            let evidence = ast_observation(
                &EvidenceInput::new(file.at("sha256").str(), &path, "observe-ipc-sender-validation-candidate", coverage.clone())
                    .range(validation.at("location"))
                    .limitations(vec![JsString::from("A comparison or string check is visible, but static syntax alone does not prove rejection, ordering, or complete sender validation.")]),
            );
            context.accumulator.add_node(NodeInput {
                kind: target.kind.clone(),
                identity: target.identity.clone(),
                observations: vec![ObservationInput::new_js(
                    validation
                        .at("subject")
                        .as_js_string()
                        .cloned()
                        .map(|subject| {
                            JsString::join([subject, JsString::from(" validation candidate")], "")
                        }),
                    properties,
                    evidence,
                )],
            });
        }
    }
    for (transmission, handler) in unambiguous_pairings(&records) {
        let (Some(source), Some(target), Some(coverage)) = (
            sources.get(&transmission.key).cloned(),
            handlers.get(&handler.key).cloned(),
            coverage_for(context, &transmission.file),
        ) else {
            continue;
        };
        add_edge(
            context,
            ElectronEdge {
                source: &source,
                target: &target,
                file: &transmission.file,
                range: transmission.finding.at("location"),
                coverage: &coverage,
                relation: if transmission.finding.at("mode").str() == "invoke" {
                    "invokes"
                } else {
                    "sends"
                },
                operation: "pair-ipc-literal-channel",
                properties: Obj::new()
                    .with("channel", transmission.finding.at("channel").clone())
                    .with("pairing_basis", "unique-exact-literal-channel")
                    .with("handler_path", handler.file.at("path").clone())
                    .with("handler_operation", handler.finding.at("operation").clone()),
                confidence: None,
                limitations: Some(vec![JsString::from(
                    "Literal channel equality does not prove that the handler is registered or reachable at runtime.",
                )]),
            },
            false,
        );
    }
}

fn magnitude(range: &Json) -> f64 {
    if range.is_null() {
        return 9_007_199_254_740_991.0;
    }
    (range.at("end").at("line").num() - range.at("start").at("line").num()) * 1_000_000.0
        + range.at("end").at("column").num()
        - range.at("start").at("column").num()
}

fn wrapper(finding: &Json) -> bool {
    finding.at("resolution_basis").str() == "wrapper-substitution"
}

fn add_channel_node(
    context: &mut GraphContext<'_>,
    record: &IpcRecord,
    coverage: &Json,
) -> AppNode {
    let finding = &record.finding;
    let file = &record.file;
    let identity_key = match finding.at("channel").as_js_string() {
        None => JsString::from("dynamic:").concat(&record.key),
        Some(channel) => JsString::from("literal:").concat(channel),
    };
    let identity = if wrapper(finding) {
        artifact_local_identity(
            file.at("sha256").str(),
            "electron-inferred-ipc-channel",
            &identity_key,
        )
    } else {
        observation_identity(context, "electron-ipc-channel", &identity_key)
    };
    let mut properties = Obj::new()
        .with("side", finding.at("side").clone())
        .with("operation", finding.at("operation").clone())
        .with("mode", finding.at("mode").clone())
        .with("channel", finding.at("channel").clone())
        .with(
            "channel_expression",
            finding.at("channel_expression").clone(),
        )
        .with(
            "resolution",
            if finding.at("channel").is_null() {
                "dynamic"
            } else {
                "literal"
            },
        );
    if let Some(invocation) = finding.get("invocation_location") {
        properties.set("invocation_location", invocation.clone());
    }
    let limitations = if wrapper(finding) {
        vec!["The channel is inferred through lexical wrapper substitution; runtime registration and dispatch remain unverified.".to_owned()]
    } else if finding.at("channel").is_null() {
        vec![
            "The channel expression is dynamic; its runtime value and pairings remain unknown."
                .to_owned(),
        ]
    } else {
        Vec::new()
    };
    let path = file.at("path").text().clone();
    let evidence_input = EvidenceInput::new(
        file.at("sha256").str(),
        &path,
        "observe-ipc-channel-expression",
        coverage.clone(),
    )
    .range(finding.at("location"))
    .limitations(limitations);
    let evidence = if wrapper(finding) {
        static_inference(&evidence_input, None)
    } else {
        ast_observation(&evidence_input)
    };
    let label = finding
        .at("channel")
        .as_js_string()
        .or_else(|| finding.at("channel_expression").as_js_string())
        .cloned();
    context.accumulator.add_node(NodeInput {
        kind: "ipc-channel".into(),
        identity,
        observations: vec![ObservationInput::new_js(label, properties, evidence)],
    })
}

fn add_handler_node(
    context: &mut GraphContext<'_>,
    record: &IpcRecord,
    source: &AppNode,
    channel: &AppNode,
    coverage: &Json,
) -> AppNode {
    let finding = &record.finding;
    let file = &record.file;
    let handler_range = if finding.at("handler_location").is_null() {
        finding.at("location")
    } else {
        finding.at("handler_location")
    };
    let channel_text = finding
        .at("channel")
        .as_js_string()
        .or_else(|| finding.at("channel_expression").as_js_string())
        .cloned()
        .unwrap_or_default();
    let mut properties = Obj::new()
        .with("side", finding.at("side").clone())
        .with("operation", finding.at("operation").clone())
        .with("mode", finding.at("mode").clone())
        .with("channel", finding.at("channel").clone())
        .with(
            "channel_expression",
            finding.at("channel_expression").clone(),
        )
        .with("handler_kind", finding.at("handler_kind").clone())
        .with("handler_location", finding.at("handler_location").clone());
    if let Some(invocation) = finding.get("invocation_location") {
        properties.set("invocation_location", invocation.clone());
    }
    let path = file.at("path").text().clone();
    let evidence_input = EvidenceInput::new(
        file.at("sha256").str(),
        &path,
        "observe-ipc-handler",
        coverage.clone(),
    )
    .range(handler_range);
    let evidence = if wrapper(finding) {
        static_inference(&evidence_input, None)
    } else {
        ast_observation(&evidence_input)
    };
    let handler = context.accumulator.add_node(NodeInput {
        kind: "ipc-handler".into(),
        identity: artifact_local_identity(
            file.at("sha256").str(),
            "electron-ipc-handler",
            JsString::join(
                [
                    finding.at("side").text().clone(),
                    finding.at("operation").text().clone(),
                    channel_text,
                    JsString::from(range_key(handler_range)),
                ],
                ":",
            ),
        ),
        observations: vec![ObservationInput::new_js(
            finding.at("channel").as_js_string().cloned(),
            properties,
            evidence,
        )],
    });
    add_edge(
        context,
        ElectronEdge {
            source,
            target: &handler,
            file,
            range: handler_range,
            coverage,
            relation: "contains",
            operation: "locate-ipc-handler",
            properties: Obj::new()
                .with("side", finding.at("side").clone())
                .with("operation", finding.at("operation").clone()),
            confidence: None,
            limitations: None,
        },
        true,
    );
    let mut properties = Obj::new()
        .with("channel", finding.at("channel").clone())
        .with(
            "channel_expression",
            finding.at("channel_expression").clone(),
        )
        .with(
            "resolution",
            if finding.at("channel").is_null() {
                "dynamic"
            } else {
                "literal"
            },
        );
    if let Some(invocation) = finding.get("invocation_location") {
        properties.set("invocation_location", invocation.clone());
    }
    add_edge(
        context,
        ElectronEdge {
            source: &handler,
            target: channel,
            file,
            range: finding.at("location"),
            coverage,
            relation: "handles",
            operation: "map-ipc-handler-registration",
            properties,
            confidence: None,
            limitations: None,
        },
        false,
    );
    handler
}

fn add_native_boundaries(context: &mut GraphContext<'_>) {
    let files = context.files().to_vec();
    for analyzed in &files {
        let file = analyzed.at("file");
        let javascript = analyzed.at("javascript");
        if javascript.is_null() {
            continue;
        }
        let coverage = javascript_analysis_coverage(javascript);
        for value in javascript.at("electron").at("native_addon_bindings").arr() {
            add_native_binding(context, file, value, &coverage);
        }
    }
}

fn add_native_binding(context: &mut GraphContext<'_>, file: &Json, value: &Json, coverage: &Json) {
    let Some(source) = finding_source(
        context,
        file,
        value.at("module_key"),
        value.get("module_runtime"),
    ) else {
        return;
    };
    let path_js = file.at("path").text().clone();
    let specifier_js = value.at("specifier").text().clone();
    let mut request =
        ResolveRequest::new_exact(&specifier_js, &path_js, &JsString::from("module-specifier"));
    request.module_kind = value
        .get("module_kind")
        .and_then(Json::as_str)
        .map(str::to_owned);
    let resolved_js = context.resolve(&request).at("resolved_path").text().clone();
    let addon = context.file_nodes.get(&resolved_js).cloned();
    let members = value.at("members");
    let namespace = value.get("namespace_access").cloned().unwrap_or(Json::Null);
    let dynamic = value
        .get("dynamic_member_access")
        .cloned()
        .unwrap_or(Json::Null);
    let label = {
        let text: Vec<JsString> = members
            .arr()
            .iter()
            .map(|member| {
                if member.text().is_empty() {
                    JsString::from("\"\"")
                } else {
                    member.text().clone()
                }
            })
            .collect();
        let joined = JsString::join(text, ", ");
        if joined.is_empty() {
            specifier_js.clone()
        } else {
            joined
        }
    };
    let binding = context.accumulator.add_node(NodeInput {
        kind: "native-export".into(),
        identity: observation_identity(
            context,
            "javascript-requested-native-export",
            &JsString::from(composite_key(vec![
                Json::String(path_js.clone()),
                Json::String(specifier_js.clone()),
                value.at("binding_kind").clone(),
                members.clone(),
                namespace.clone(),
                dynamic.clone(),
                range_key(value.at("location")).into(),
            ])),
        ),
        observations: vec![ObservationInput::new_js(
            Some(label),
            Obj::new()
                .with("specifier", Json::String(specifier_js.clone()))
                .with("binding_kind", value.at("binding_kind").clone())
                .with("requested_members", members.clone())
                .with("namespace_access", namespace.clone())
                .with("dynamic_member_access", dynamic.clone())
                .with("resolved_path", Json::String(resolved_js.clone()))
                .with("native_export_verification", "not-performed"),
            ast_observation(
                &EvidenceInput::new(file.at("sha256").str(), &path_js, "observe-native-addon-binding", coverage.clone())
                    .range(value.at("location"))
                    .limitations(vec![JsString::from("JavaScript syntax identifies requested member names; it does not prove that the native binary exports or implements them.")]),
            ),
        )],
    });
    add_edge(
        context,
        ElectronEdge {
            source: &source,
            target: &binding,
            file,
            range: value.at("location"),
            coverage,
            relation: if value.at("binding_kind").str() == "re-export" {
                "exposes"
            } else {
                "imports"
            },
            operation: "map-native-addon-binding",
            properties: Obj::new()
                .with("specifier", Json::String(specifier_js.clone()))
                .with("binding_kind", value.at("binding_kind").clone())
                .with("requested_members", members.clone())
                .with("namespace_access", namespace.clone())
                .with("dynamic_member_access", dynamic.clone()),
            confidence: None,
            limitations: Some(vec![JsString::from(
                "Requested JavaScript members are not verified native exports.",
            )]),
        },
        false,
    );
    let Some(addon) = addon else {
        return;
    };
    add_edge(
        context,
        ElectronEdge {
            source: &addon,
            target: &binding,
            file,
            range: value.at("location"),
            coverage,
            relation: "exposes",
            operation: "associate-native-addon-requested-exports",
            properties: Obj::new()
                .with("resolved_path", Json::String(resolved_js.clone()))
                .with("requested_members", members.clone())
                .with("namespace_access", namespace)
                .with("dynamic_member_access", dynamic)
                .with("verified", false),
            confidence: Some("medium"),
            limitations: Some(vec![JsString::from(
                "The .node artifact path is resolved, but requested JavaScript members have not been verified against native symbols.",
            )]),
        },
        false,
    );
}

struct ProjectedPath {
    file: Json,
    path: Json,
    coverage: Json,
    nodes: Vec<AppNode>,
}

fn add_call_paths(context: &mut GraphContext<'_>) {
    let mut projected: Vec<ProjectedPath> = Vec::new();
    let candidate = "Lexical wrapper substitution is a static candidate; guards, runtime overrides and execution remain unverified.";
    let files = context.files().to_vec();
    for analyzed in &files {
        let file = analyzed.at("file");
        let javascript = analyzed.at("javascript");
        if javascript.is_null() {
            continue;
        }
        let coverage = javascript_analysis_coverage(javascript);
        for path in javascript.at("electron").at("call_paths").arr() {
            let path_id = sha256_text(&path.stringify());
            let entry_path = path.get("entry_path").cloned();
            let steps = path.at("steps").arr();
            let nodes: Vec<AppNode> = steps
                .iter()
                .enumerate()
                .map(|(index, step)| {
                    let mut properties = Obj::new()
                        .with("path_id", path_id.as_str())
                        .with("entry", path.at("entry").clone());
                    if let Some(entry_path) = &entry_path {
                        properties.set("entry_path", entry_path.clone());
                    }
                    properties.set("entry_kind", path.at("entry_kind").clone());
                    properties.set("channel", path.at("channel").clone());
                    properties.set("terminal", path.at("terminal").clone());
                    properties.set("step_kind", step.at("kind").clone());
                    properties.set("step_index", index);
                    properties.set("module_key", step.at("module_key").clone());
                    properties.set("module_runtime", step.at("module_runtime").clone());
                    properties.set("conditions", path.at("conditions").clone());
                    properties.set("resolution", "candidate");
                    let evidence = static_inference(
                        &EvidenceInput::new(
                            file.at("sha256").str(),
                            file.at("path").text(),
                            "substitute-electron-wrapper",
                            coverage.clone(),
                        )
                        .range(step.at("location"))
                        .limitations(vec![JsString::from(candidate)]),
                        None,
                    );
                    context.accumulator.add_node(NodeInput {
                        kind: "javascript-expression".into(),
                        identity: artifact_local_identity(
                            file.at("sha256").str(),
                            "electron-call-path-step",
                            &format!("{path_id}:{index}"),
                        ),
                        observations: vec![ObservationInput::new_js(
                            step.at("label").as_js_string().cloned(),
                            properties,
                            evidence,
                        )],
                    })
                })
                .collect();
            if let (Some(first), Some(entry)) = (nodes.first(), steps.first()) {
                let runtime = entry
                    .get("module_runtime")
                    .filter(|runtime| !runtime.is_null());
                if let Some(owner) = finding_source(context, file, entry.at("module_key"), runtime)
                {
                    let mut properties = Obj::new()
                        .with("path_id", path_id.as_str())
                        .with("entry", path.at("entry").clone());
                    if let Some(entry_path) = &entry_path {
                        properties.set("entry_path", entry_path.clone());
                    }
                    properties.set("resolution", "candidate");
                    add_edge(
                        context,
                        ElectronEdge {
                            source: &owner,
                            target: first,
                            file,
                            range: entry.at("location"),
                            coverage: &coverage,
                            relation: "contains",
                            operation: "locate-electron-wrapper-path",
                            properties,
                            confidence: None,
                            limitations: None,
                        },
                        false,
                    );
                }
            }
            for index in 1..nodes.len() {
                let previous = &steps[index - 1];
                let step = &steps[index];
                let mut properties = Obj::new()
                    .with("path_id", path_id.as_str())
                    .with("entry", path.at("entry").clone());
                if let Some(entry_path) = &entry_path {
                    properties.set("entry_path", entry_path.clone());
                }
                properties.set("channel", path.at("channel").clone());
                properties.set("resolution", "candidate");
                properties.set("conditions", path.at("conditions").clone());
                add_edge(
                    context,
                    ElectronEdge {
                        source: &nodes[index - 1],
                        target: &nodes[index],
                        file,
                        range: step.at("location"),
                        coverage: &coverage,
                        relation: if matches!(
                            previous.at("kind").str(),
                            "exposure" | "factory" | "ipc"
                        ) {
                            "maps_to"
                        } else {
                            "calls"
                        },
                        operation: "trace-electron-wrapper-path",
                        properties,
                        confidence: None,
                        limitations: None,
                    },
                    false,
                );
            }
            projected.push(ProjectedPath {
                file: file.clone(),
                path: path.clone(),
                coverage: coverage.clone(),
                nodes,
            });
        }
    }
    let records = collect_ipc_records(&context.analysis);
    for (transmission, handler) in unambiguous_pairings(&records) {
        let sources: Vec<&ProjectedPath> = projected
            .iter()
            .filter(|path| {
                path.path.at("entry_kind").str() == "bridge-member"
                    && path_matches(path, &transmission)
            })
            .collect();
        let targets: Vec<&ProjectedPath> = projected
            .iter()
            .filter(|path| {
                path.path.at("entry_kind").str() == "ipc-handler" && path_matches(path, &handler)
            })
            .collect();
        for from in &sources {
            for to in &targets {
                let (Some(source), Some(target)) = (from.nodes.last(), to.nodes.first()) else {
                    continue;
                };
                add_edge(
                    context,
                    ElectronEdge {
                        source,
                        target,
                        file: &from.file,
                        range: transmission.finding.at("location"),
                        coverage: &from.coverage,
                        relation: if transmission.finding.at("mode").str() == "invoke" {
                            "invokes"
                        } else {
                            "sends"
                        },
                        operation: "join-electron-wrapper-paths",
                        properties: Obj::new()
                            .with("channel", transmission.finding.at("channel").clone())
                            .with("pairing_basis", "unique-exact-literal-channel")
                            .with("resolution", "candidate")
                            .with("handler_path", to.file.at("path").clone())
                            .with("bridge_conditions", from.path.at("conditions").clone())
                            .with("handler_conditions", to.path.at("conditions").clone()),
                        confidence: None,
                        limitations: Some(vec![JsString::from(
                            "The unique static channel match does not establish runtime registration, sender acceptance, or dispatch.",
                        )]),
                    },
                    false,
                );
            }
        }
    }
}

fn path_matches(projected: &ProjectedPath, record: &IpcRecord) -> bool {
    let finding = &record.finding;
    let source_kind = if matches!(finding.at("mode").str(), "send" | "invoke") {
        "terminal"
    } else {
        "ipc"
    };
    let steps = projected.path.at("steps").arr();
    projected.file.at("path") == record.file.at("path")
        && projected.path.at("channel") == finding.at("channel")
        && steps.iter().any(|step| {
            step.at("kind").str() == source_kind
                && range_key(step.at("location")) == range_key(finding.at("location"))
        })
        && finding.get("invocation_location").is_none_or(|invocation| {
            steps.iter().any(|step| {
                matches!(step.at("kind").str(), "call" | "exposure")
                    && range_key(step.at("location")) == range_key(invocation)
            })
        })
}
