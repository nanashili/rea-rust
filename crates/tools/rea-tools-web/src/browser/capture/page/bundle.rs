//! Capture and statically analyze the scripts observed on one authorized page.

use super::super::connection::{self, TargetFacts};
use super::source_maps;
use super::{CapturedPage, Options, capture_page_with_sources};
use crate::cdp::{self, BrowserScope, Refinement};
use rea_application::javascript::graph::json::{Json as GraphJson, Obj};
use rea_application::javascript::worker::{self, WorkerFailure, WorkerLimits, WorkerRequest};
use rea_core::analysis_error::AnalysisError;
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use url::Url;

pub(super) const OPERATION: &str = "analyze_web_bundle";
const PREDICATE: &str = "rea.web-bundle-analysis";
const SOURCE_MAP_DECODER_BYTES: usize = 4 * 1024 * 1024;
const SOURCE_MAP_MAX_ROWS: usize = 262_144;
const SOURCE_MAP_MAX_SEGMENTS: usize = 262_144;

pub(super) fn register(registry: &mut Registry) {
    registry.handle(OPERATION, |context, input| analyze(context, &input));
}

struct Input {
    scope: BrowserScope,
    target_id: String,
    options: Options,
    observation_ms_explicit: bool,
    include_options_explicit: bool,
    include_script_sources_explicit: bool,
    fetch_source_maps: bool,
    fetch_source_maps_explicit: bool,
    max_heap_mb: Option<u64>,
    max_heap_mb_explicit: bool,
    analysis_timeout: Duration,
    analysis_timeout_explicit: bool,
    total_analysis_timeout: Duration,
    total_analysis_timeout_explicit: bool,
}

fn parse_input(input: &Value) -> Result<Input, ToolOutput> {
    let mut issues = Vec::<Refinement>::new();
    let scope = cdp::parse_scope(input, &mut issues);
    let target_id = input
        .get("target_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_default();
    if target_id.is_empty() {
        issues.push(Refinement::new(
            vec![json!("target_id")],
            "Too small: expected string to have >=1 characters",
        ));
    }
    let bool_value = |name: &str| input.get(name).and_then(Value::as_bool).unwrap_or(false);
    let has_value = |name: &str| input.get(name).is_some();
    let include_storage_keys = bool_value("include_storage_keys");
    if bool_value("include_storage_fingerprints") && !include_storage_keys {
        issues.push(Refinement::new(
            vec![json!("include_storage_fingerprints")],
            "Storage fingerprints require storage key capture",
        ));
    }
    if input.get("include_script_sources").and_then(Value::as_bool) == Some(false) {
        issues.push(Refinement::new(
            vec![json!("include_script_sources")],
            "include_script_sources must be true for web bundle analysis",
        ));
    }
    if let Some(value) = input.get("max_heap_mb").and_then(Value::as_u64) {
        if !(128..=16_384).contains(&value) {
            issues.push(Refinement::new(
                vec![json!("max_heap_mb")],
                "Expected an integer between 128 and 16384 MiB",
            ));
        }
    }
    for name in ["analysis_timeout_ms", "total_analysis_timeout_ms"] {
        if let Some(value) = input.get(name).and_then(Value::as_u64) {
            if value == 0 || value > i32::MAX as u64 {
                issues.push(Refinement::new(
                    vec![json!(name)],
                    "Expected an integer between 1 and 2147483647 milliseconds",
                ));
            }
        }
    }
    let options = Options {
        observation_ms: input
            .get("observation_ms")
            .and_then(Value::as_u64)
            .unwrap_or(500),
        include_accessibility_text: bool_value("include_accessibility_text"),
        include_console_text: bool_value("include_console_text"),
        include_json_body_shapes: bool_value("include_json_body_shapes"),
        include_websocket_shapes: bool_value("include_websocket_shapes"),
        include_storage_keys,
        include_storage_fingerprints: bool_value("include_storage_fingerprints"),
        include_script_sources: true,
    };
    let bounded =
        |name: &str, default: u64| input.get(name).and_then(Value::as_u64).unwrap_or(default);
    match scope {
        Some(scope) if issues.is_empty() => Ok(Input {
            scope,
            target_id,
            options,
            observation_ms_explicit: has_value("observation_ms"),
            include_options_explicit: has_value("include_accessibility_text"),
            include_script_sources_explicit: has_value("include_script_sources"),
            fetch_source_maps: bool_value("fetch_source_maps"),
            fetch_source_maps_explicit: has_value("fetch_source_maps"),
            max_heap_mb: input.get("max_heap_mb").and_then(Value::as_u64),
            max_heap_mb_explicit: has_value("max_heap_mb"),
            analysis_timeout: Duration::from_millis(bounded("analysis_timeout_ms", 30_000)),
            analysis_timeout_explicit: has_value("analysis_timeout_ms"),
            total_analysis_timeout: Duration::from_millis(bounded(
                "total_analysis_timeout_ms",
                300_000,
            )),
            total_analysis_timeout_explicit: has_value("total_analysis_timeout_ms"),
        }),
        _ => Err(cdp::refinement_failure(OPERATION, issues)),
    }
}

fn analyze(context: &ToolContext<'_>, input: &Value) -> ToolOutput {
    let input = match parse_input(input) {
        Ok(input) => input,
        Err(failure) => return failure,
    };
    if context.cancellation.reason().is_some() {
        return ToolOutput::Failure(AnalysisError::cancelled(OPERATION));
    }
    let outcome = connection::with_target_session(
        OPERATION,
        &input.scope,
        &input.target_id,
        &context.cancellation,
        |connection, facts| analyze_capture(connection, facts, &input, context),
    );
    match outcome {
        Ok(result) => {
            if context.cancellation.reason().is_some() {
                return ToolOutput::Failure(AnalysisError::cancelled(OPERATION));
            }
            let parameters = parameters(&input);
            let parameters = value_to_graph_json(&parameters);
            match super::super::super::browser_observation_raw_evidence(
                OPERATION, PREDICATE, parameters, result,
            ) {
                Ok(evidence) => ToolOutput::RawEvidence(evidence),
                Err(error) => ToolOutput::Failure(error),
            }
        }
        Err(error) => ToolOutput::Failure(error),
    }
}

fn analyze_capture(
    connection: &mut super::super::connection::Connection<'_>,
    facts: &TargetFacts<'_>,
    input: &Input,
    context: &ToolContext<'_>,
) -> Result<GraphJson, AnalysisError> {
    let captured = capture_page_with_sources(connection, facts, &input.options, context)?;
    let source_maps = if input.fetch_source_maps {
        let origins = allowed_origins(input, &captured.inspection);
        let (included, failures) = source_maps::fetch(
            &captured.source_map_requests,
            &origins,
            &context.cancellation,
        );
        source_map_result(included, failures, captured.source_map_requests.len())
    } else {
        json!({"status":"not_requested","requested":0,"processed":0,"items":[]})
    };
    if context.cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(OPERATION));
    }
    let analysis = analyze_scripts(&captured, input, context)?;
    Ok(build_analysis(&captured.inspection, analysis, source_maps))
}

fn analyze_scripts(
    captured: &CapturedPage,
    input: &Input,
    context: &ToolContext<'_>,
) -> Result<Vec<AnalysisResult>, AnalysisError> {
    let scripts = captured.inspection["scripts"]["items"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let deadline = Instant::now() + input.total_analysis_timeout;
    let mut results = Vec::new();
    for script in scripts {
        let key = script["script_key"].as_str().unwrap_or_default().to_owned();
        let Some(source) = script["source"]["artifact"]["text"].as_str() else {
            continue;
        };
        if context.cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(OPERATION));
        }
        if Instant::now() >= deadline {
            results.push(AnalysisResult::value(unavailable(
                &key,
                "deadline",
                "Total bundle analysis timeout elapsed.",
            )));
            continue;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = input.analysis_timeout.min(remaining);
        let response = worker::analyze_source_with_worker(
            &WorkerRequest {
                max_heap_mb: None,
                node_budget: 20_000,
                unknown_budget: 20_000,
                file: None,
                source: source.to_owned(),
                path: script["url"].as_str().map(str::to_owned),
            },
            &WorkerLimits {
                max_heap_mb: input.max_heap_mb,
                timeout,
            },
            || context.cancellation.reason().is_some(),
        );
        results.push(match response {
            Ok(response) => {
                let static_analysis = serde_json::from_str(response.static_analysis.get())
                    .map_err(|error| {
                        AnalysisError::output(
                            OPERATION,
                            format!("Native JavaScript analysis returned invalid JSON: {error}"),
                        )
                    })?;
                analyzed_result(&key, &script, static_analysis)
            }
            Err(error) if error.is_cancelled() => AnalysisResult::value(unavailable(
                &key,
                "cancelled",
                "JavaScript analysis was cancelled.",
            )),
            Err(error) if error.is_timeout() => AnalysisResult::value(unavailable(
                &key,
                "deadline",
                "Per-script JavaScript analysis timeout elapsed.",
            )),
            Err(WorkerFailure::ResourceConstraint { reason, .. }) => {
                AnalysisResult::value(unavailable(&key, "resource_constraint", &reason))
            }
            Err(error) => {
                AnalysisResult::value(unavailable(&key, "worker_failure", &error.to_string()))
            }
        });
    }
    Ok(results)
}

struct AnalysisResult {
    value: Value,
    observations: GraphJson,
}

impl AnalysisResult {
    fn value(value: Value) -> Self {
        Self {
            value,
            observations: GraphJson::Object(Obj::new()),
        }
    }
}

fn analyzed_result(key: &str, script: &Value, static_analysis: Value) -> AnalysisResult {
    let parse_status = match static_analysis["parse_status"].as_str().unwrap_or("failed") {
        "complete" => "parsed",
        "partial" => "recovered",
        _ => "failed",
    };
    let failed = parse_status == "failed";
    let (observations, routes, endpoint_candidates, webmcp_declarations, web_unknowns) = if failed {
        (
            json!({"edges":[],"routes":[],"endpoints":[],"webmcp_declarations":[]}),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    } else {
        let source = script["source"]["artifact"]["text"]
            .as_str()
            .unwrap_or_default();
        observations(&static_analysis, source, script["url"].as_str(), key)
    };
    let source = script["source"]["artifact"]["text"]
        .as_str()
        .unwrap_or_default();
    let mut inferred = inferences(source, script, key);
    inferred.extend(route_inferences(&routes, script, key));
    let value = json!({
        "status":"analyzed", "script_key":key, "parse_status":parse_status,
        "visited_ast_nodes": if failed { 0 } else { static_analysis["visited_ast_nodes"].as_u64().unwrap_or(0) },
        "widened_return_references":false, "observations":observations,
        "inferences":inferred,
        "web_unknowns":web_unknowns
    });
    let mut observations = value_to_graph_json(&value["observations"]);
    if let GraphJson::Object(mut object) = observations {
        object.set("routes", GraphJson::array(routes));
        object.set(
            "inferences",
            GraphJson::array(endpoint_inferences(&endpoint_candidates, script, key)),
        );
        object.set("webmcp_declarations", GraphJson::array(webmcp_declarations));
        observations = GraphJson::Object(object);
    }
    AnalysisResult {
        value,
        observations,
    }
}

fn route_inferences(observations: &[GraphJson], script: &Value, key: &str) -> Vec<Value> {
    let artifact_sha256 = script["source"]["artifact"]["sha256"]
        .as_str()
        .unwrap_or_default();
    let mut seen = BTreeSet::new();
    observations
        .iter()
        .filter_map(|route| {
            let mechanism = route["mechanism"].str();
            if mechanism.is_empty() {
                return None;
            }
            let call = mechanism.strip_prefix("call:")?;
            let value = if call.ends_with("useRoutes") || call.ends_with("createBrowserRouter") {
                "React Router-compatible route API"
            } else {
                "Generic route registration API"
            };
            if !seen.insert(value) {
                return None;
            }
            Some(json!({
                "kind": "route_framework",
                "value": value,
                "confidence": "medium",
                "basis": [{
                    "script_key": key,
                    "artifact_sha256": artifact_sha256,
                    "line": route["location"]["line"].as_u64().unwrap_or_default(),
                    "column": route["location"]["column"].as_u64().unwrap_or_default(),
                    "detector": mechanism
                }]
            }))
        })
        .collect()
}

fn observations(
    static_analysis: &Value,
    source: &str,
    path: Option<&str>,
    key: &str,
) -> (
    Value,
    Vec<GraphJson>,
    Vec<GraphJson>,
    Vec<GraphJson>,
    Vec<Value>,
) {
    let edges = static_edges(static_analysis, key);
    let endpoints = static_endpoints(static_analysis, key);
    let web_observations = web_source_observations(source, path);
    let (routes, endpoint_candidates, webmcp_declarations, web_unknowns) = match web_observations {
        Ok(observations) => (
            web_source_routes(&observations, key),
            web_source_endpoint_candidates(&observations, key),
            web_source_declarations(&observations, key),
            Vec::new(),
        ),
        Err(diagnostics) => (Vec::new(), Vec::new(), Vec::new(), diagnostics),
    };

    (
        json!({
            "edges": edges,
            "routes": [],
            "endpoints": endpoints,
            "webmcp_declarations": [],
            "inferences": []
        }),
        routes,
        endpoint_candidates,
        webmcp_declarations,
        web_unknowns,
    )
}

fn web_source_observations(
    source: &str,
    path: Option<&str>,
) -> Result<rea_application::javascript::static_analysis::web::WebObservations, Vec<Value>> {
    rea_application::javascript::static_analysis::web::analyze(source, path).map_err(
        |diagnostics| {
            diagnostics
                .into_iter()
                .map(|diagnostic| {
                    json!({
                        "message": diagnostic.message,
                        "byte_offset": diagnostic.byte_offset,
                    })
                })
                .collect()
        },
    )
}

fn static_edges(static_analysis: &Value, key: &str) -> Vec<Value> {
    static_analysis["references"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|reference| {
            let specifier = reference["specifier"]
                .as_str()
                .or_else(|| reference["expression"].as_str())?;
            let kind = match reference["kind"].as_str()? {
                "static-import" => "static_import",
                "dynamic-import" => "dynamic_import",
                "require" => "require",
                "worker" | "service-worker" => "worker_import",
                _ => return None,
            };

            Some(json!({
                "from_script_key": key,
                "kind": kind,
                "specifier": specifier,
                "resolved_url": null,
                "location": location(&reference["location"], key),
            }))
        })
        .collect()
}

fn static_endpoints(static_analysis: &Value, key: &str) -> Vec<Value> {
    static_analysis["endpoints"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|endpoint| {
            if endpoint["mechanism"]
                .as_str()
                .is_some_and(is_http_endpoint_candidate_mechanism)
            {
                return None;
            }
            Some(json!({
                "value": endpoint["value"].as_str()?,
                "mechanism": endpoint["mechanism"].as_str().unwrap_or("static"),
                "location": location(&endpoint["location"], key),
            }))
        })
        .collect()
}

fn is_http_endpoint_candidate_mechanism(mechanism: &str) -> bool {
    let Some(call) = mechanism.strip_prefix("call:") else {
        return false;
    };
    let method = call.rsplit('.').next().unwrap_or(call);
    matches!(
        method,
        "get" | "post" | "put" | "patch" | "delete" | "head" | "options"
    )
}

fn web_source_routes(
    web_observations: &rea_application::javascript::static_analysis::web::WebObservations,
    key: &str,
) -> Vec<GraphJson> {
    web_observations
        .routes
        .iter()
        .cloned()
        .map(|route| attach_script_location(route, key))
        .collect()
}

fn web_source_declarations(
    web_observations: &rea_application::javascript::static_analysis::web::WebObservations,
    key: &str,
) -> Vec<GraphJson> {
    web_observations
        .webmcp_declarations
        .iter()
        .cloned()
        .map(|declaration| attach_script_location(declaration, key))
        .collect()
}

fn web_source_endpoint_candidates(
    web_observations: &rea_application::javascript::static_analysis::web::WebObservations,
    key: &str,
) -> Vec<GraphJson> {
    web_observations
        .endpoint_candidates
        .iter()
        .cloned()
        .map(|candidate| attach_script_location(candidate, key))
        .collect()
}

fn endpoint_inferences(candidates: &[GraphJson], script: &Value, key: &str) -> Vec<GraphJson> {
    let artifact_sha256 = script["source"]["artifact"]["sha256"]
        .as_str()
        .unwrap_or_default();
    candidates
        .iter()
        .map(|candidate| {
            GraphJson::Object(
                Obj::new()
                    .with("kind", "endpoint_candidate")
                    .with("value", candidate["value"].clone())
                    .with("confidence", "low")
                    .with(
                        "basis",
                        GraphJson::array(vec![GraphJson::Object(
                            Obj::new()
                                .with("script_key", key)
                                .with("artifact_sha256", artifact_sha256)
                                .with("line", candidate["location"]["line"].clone())
                                .with("column", candidate["location"]["column"].clone())
                                .with("detector", candidate["mechanism"].clone()),
                        )]),
                    ),
            )
        })
        .collect()
}

fn attach_script_location(finding: GraphJson, script_key: &str) -> GraphJson {
    let mut finding = finding.obj();
    if let Some(GraphJson::Object(mut location)) = finding.remove("location") {
        location.set("script_key", script_key);
        finding.set("location", GraphJson::Object(location));
    }
    GraphJson::Object(finding)
}

fn location(value: &Value, key: &str) -> Value {
    json!({"script_key":key,"line":value["start"]["line"],"column":value["start"]["column"]})
}

fn inferences(source: &str, script: &Value, key: &str) -> Vec<Value> {
    let artifact_sha256 = script["source"]["artifact"]["sha256"]
        .as_str()
        .unwrap_or_default();
    [
        (
            "webpack",
            "webpack-runtime",
            &["__webpack_require__" as &str][..],
            "high",
            "bundle_runtime",
        ),
        (
            "Vite",
            "vite-runtime",
            &["__vite__", "import.meta.hot"][..],
            "medium",
            "bundle_runtime",
        ),
        (
            "React",
            "react-runtime",
            &["__REACT_DEVTOOLS_GLOBAL_HOOK__", "React.createElement"][..],
            "medium",
            "vendor_fingerprint",
        ),
        (
            "Vue",
            "vue-runtime",
            &["__VUE__", "createApp("][..],
            "medium",
            "vendor_fingerprint",
        ),
        (
            "Next.js",
            "next-runtime",
            &["__NEXT_DATA__", "/_next/"][..],
            "high",
            "vendor_fingerprint",
        ),
        (
            "Angular",
            "angular-runtime",
            &["ɵɵdefineComponent"][..],
            "high",
            "vendor_fingerprint",
        ),
        (
            "Svelte",
            "svelte-runtime",
            &["svelte/internal"][..],
            "medium",
            "vendor_fingerprint",
        ),
    ]
    .into_iter()
    .filter_map(|(value, detector, patterns, confidence, kind)| {
        patterns
            .iter()
            .any(|pattern| source.contains(pattern))
            .then(|| {
                json!({
                    "kind": kind,
                    "value": value,
                    "confidence": confidence,
                    "basis": [{
                        "script_key": key,
                        "artifact_sha256": artifact_sha256,
                        "line": null,
                        "column": null,
                        "detector": detector
                    }]
                })
            })
    })
    .collect()
}

fn unavailable(key: &str, reason: &str, detail: &str) -> Value {
    json!({"status":"unavailable","script_key":key,"reason":reason,"detail":detail})
}

fn build_analysis(
    inspection: &Value,
    results: Vec<AnalysisResult>,
    source_maps: Value,
) -> GraphJson {
    let scripts = inspection["scripts"]["items"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let source_scripts = scripts
        .iter()
        .filter(|script| script["source"]["included"] == true)
        .collect::<Vec<_>>();
    let mut edges = Vec::new();
    let mut endpoints: Vec<Value> = Vec::new();
    let mut inferences: Vec<Value> = Vec::new();
    let mut parsed_scripts = 0_u64;
    let mut parse_failures = 0_u64;
    let mut visited = 0_u64;
    let mut unknowns = Vec::new();
    let mut exact_routes: Vec<GraphJson> = Vec::new();
    let mut exact_inferences: Vec<GraphJson> = Vec::new();
    let mut exact_webmcp: Vec<GraphJson> = Vec::new();
    for result in &results {
        exact_routes.extend(result.observations["routes"].arr().iter().cloned());
        exact_inferences.extend(result.observations["inferences"].arr().iter().cloned());
        exact_webmcp.extend(
            result.observations["webmcp_declarations"]
                .arr()
                .iter()
                .cloned(),
        );
        let result = &result.value;
        if result["status"] == "analyzed" {
            if result["parse_status"] == "failed" {
                parse_failures += 1;
            } else {
                parsed_scripts += 1;
            }
            visited += result["visited_ast_nodes"].as_u64().unwrap_or(0);
            edges.extend(
                result["observations"]["edges"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default(),
            );
            endpoints.extend(
                result["observations"]["endpoints"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default(),
            );
            inferences.extend(result["inferences"].as_array().cloned().unwrap_or_default());
            if result["parse_status"] == "recovered" {
                unknowns.push(json!({
                    "dimension": "javascript_ast",
                    "reason": "The parser recovered from errors in one or more source artifacts; findings may be incomplete",
                    "affected_script_keys": [result["script_key"]]
                }));
            }
            if let Some(diagnostics) = result["web_unknowns"].as_array() {
                if !diagnostics.is_empty() {
                    unknowns.push(json!({
                        "dimension": "javascript_web_analysis",
                        "reason": "The web-specific AST analysis could not parse this source artifact; route and WebMCP findings may be incomplete.",
                        "affected_script_keys": [result["script_key"]],
                        "diagnostics": diagnostics,
                    }));
                }
            }
        } else {
            unknowns.push(json!({
                "dimension": "javascript_analysis",
                "reason": result["detail"].as_str().unwrap_or("Analysis was unavailable for this captured script."),
                "affected_script_keys": [result["script_key"]]
            }));
        }
    }
    let unavailable_source_keys = scripts
        .iter()
        .filter(|script| script["source"]["included"] != true)
        .filter_map(|script| script["script_key"].as_str())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if !unavailable_source_keys.is_empty() {
        unknowns.push(json!({
            "dimension": "script_source",
            "reason": "Source artifacts were not captured.",
            "affected_script_keys": unavailable_source_keys
        }));
    }
    let artifacts = source_scripts
        .iter()
        .map(|script| {
            let artifact = &script["source"]["artifact"];
            json!({
                "sha256": artifact["sha256"],
                "bytes": artifact["bytes"],
                "media_type": artifact["media_type"],
                "charset": artifact["charset"],
                "text_available": true
            })
        })
        .collect::<Vec<_>>();
    let completeness_status = if unknowns.is_empty() {
        "complete"
    } else {
        "partial"
    };
    let value = json!({
        "capture": {
            "target_url": inspection["target"]["url"],
            "scripts_observed": inspection["scripts"]["total"],
            "scripts_analyzed": results.len(),
            "source_artifacts": artifacts
        },
        "observations": {
            "chunks": {
                "nodes": source_scripts.iter().map(|script| json!({
                    "script_key": script["script_key"],
                    "url": script["url"],
                    "artifact_sha256": script["source"]["artifact"]["sha256"],
                    "bytes": script["source"]["artifact"]["bytes"]
                })).collect::<Vec<_>>(),
                "edges": edges
            },
            "endpoints": endpoints,
            "source_maps": source_maps
        },
        "inferences": inferences,
        "unknowns": unknowns,
        "completeness": {
            "status": completeness_status,
            "parsed_scripts": parsed_scripts,
            "parse_failures": parse_failures,
            "visited_ast_nodes": visited
        },
        "limitations": bundle_limitations()
    });
    let mut exact = value_to_graph_json(&value);
    if let GraphJson::Object(mut root) = exact {
        let mut all_inferences = inferences
            .iter()
            .map(value_to_graph_json)
            .collect::<Vec<_>>();
        all_inferences.extend(exact_inferences);
        root.set("inferences", GraphJson::array(all_inferences));
        if let Some(GraphJson::Object(mut observations)) = root.remove("observations") {
            observations.set("routes", GraphJson::array(exact_routes));
            observations.set("webmcp_declarations", GraphJson::array(exact_webmcp));
            root.set("observations", GraphJson::Object(observations));
        }
        exact = GraphJson::Object(root);
    }
    exact
}

fn value_to_graph_json(value: &Value) -> GraphJson {
    match value {
        Value::Null => GraphJson::Null,
        Value::Bool(value) => GraphJson::Bool(*value),
        Value::Number(value) => GraphJson::Number(value.as_f64().unwrap_or_default()),
        Value::String(value) => GraphJson::from(value.clone()),
        Value::Array(values) => GraphJson::array(values.iter().map(value_to_graph_json).collect()),
        Value::Object(values) => GraphJson::Object(values.iter().fold(
            rea_application::javascript::graph::json::Obj::new(),
            |object, (key, value)| object.with(key.clone(), value_to_graph_json(value)),
        )),
    }
}

fn bundle_limitations() -> Vec<Value> {
    vec![
        json!(
            "Static bundle findings are observations or bounded inferences; REA does not execute captured JavaScript."
        ),
        json!(
            "Bare string arguments of unbound HTTP-method-named calls are low-confidence endpoint candidates; form, translation, storage and other APIs can use the same syntax. URL-shaped findings still do not prove network execution."
        ),
        json!(
            "Endpoint candidates are deduplicated by script, value and detector; basis retains only the first matching source coordinate. They are not a complete call-site inventory or a runtime occurrence count. completeness.status=\"complete\" describes examination of captured source, not a call-site census."
        ),
        json!(
            "String-built routes and endpoints, encrypted configuration, and server-side behavior may remain unknown."
        ),
        json!(
            "Page-declared WebMCP metadata is untrusted and is never registered or invoked as an REA tool."
        ),
    ]
}

fn source_map_result(
    included: Vec<source_maps::FetchedSourceMap>,
    failures: Vec<source_maps::SourceMapFetchFailure>,
    requested: usize,
) -> Value {
    if requested == 0 {
        return json!({"status":"not_requested","requested":0,"processed":0,"items":[]});
    }

    let mut items = Vec::new();
    for map in included {
        let Ok(text) = String::from_utf8(map.bytes.clone()) else {
            items.push(json!({"script_key":map.script_key,"declared_url":map.declared_url,"effective_url":map.effective_url,"status":"invalid","limitation":"Source-map response is not valid UTF-8.","artifact":null,"original_sources":[],"original_module_edges":[],"mappings":[]}));
            continue;
        };
        items.push(parse_source_map_item(&map, &text));
    }
    for failure in failures {
        items.push(json!({"script_key":failure.script_key,"declared_url":failure.declared_url,"effective_url":null,"status":failure.status,"limitation":failure.reason,"artifact":null,"original_sources":[],"original_module_edges":[],"mappings":[]}));
    }
    let has_partial = items.iter().any(|item| item["status"] == "partial");
    let has_included = items.iter().any(|item| item["status"] == "included");
    let status =
        if has_partial || (has_included && items.iter().any(|item| item["status"] != "included")) {
            "partial"
        } else if has_included {
            "included"
        } else {
            "unavailable"
        };
    let mut result = json!({
        "status": status,
        "requested": requested,
        "processed": items.len(),
        "items": items,
    });
    if status != "included" {
        result["limitation"] = json!(
            "One or more source-map declarations were unavailable or only partially interpreted."
        );
    }
    result
}

fn parse_source_map_item(map: &source_maps::FetchedSourceMap, text: &str) -> Value {
    let context = || json!({"script_key":map.script_key,"declared_url":map.declared_url,"effective_url":map.effective_url});
    let invalid = |limitation: &str| {
        let mut item = context();
        item["status"] = json!("invalid");
        item["limitation"] = json!(limitation);
        item["artifact"] = Value::Null;
        item["original_sources"] = json!([]);
        item["original_module_edges"] = json!([]);
        item["mappings"] = json!([]);
        item
    };
    if text.len() > SOURCE_MAP_DECODER_BYTES {
        return invalid("Source-map exceeds the 4 MiB decoder budget.");
    }
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return invalid("Source-map JSON is invalid.");
    };
    if value["version"].as_u64() != Some(3) {
        return invalid("Source-map must be a version 3 map.");
    }
    if value["sections"].is_array() {
        return parse_indexed_source_map(map, text, &value, &invalid);
    }
    let Some(sources) = value["sources"].as_array() else {
        return invalid("Source-map sources must be an array.");
    };
    let Some(mapping_text) = value["mappings"].as_str() else {
        return invalid("Source-map mappings must be a string.");
    };
    let source_root = value["sourceRoot"].as_str().unwrap_or("");
    let mut original_sources = Vec::new();
    for (index, source) in sources.iter().enumerate() {
        let source_name = source
            .as_str()
            .map(|raw| resolve_source_name(raw, source_root, &map.effective_url));
        let content = value["sourcesContent"]
            .as_array()
            .and_then(|values| values.get(index))
            .and_then(Value::as_str);
        original_sources.push(json!({
            "source_index":index,
            "declaration_index":index,
            "source":source_name,
            "artifact":content.map(|content| json!({"sha256":format!("{:x}",Sha256::digest(content.as_bytes())),"bytes":content.len(),"media_type":source_media_type(source_name.as_deref().unwrap_or("")),"charset":"utf-8","text_available":true})).unwrap_or(Value::Null)
        }));
    }
    let decoded = match decode_mappings(
        mapping_text,
        sources.len(),
        value["names"].as_array().map(Vec::as_slice),
    ) {
        Ok(decoded) => decoded,
        Err(reason) => return invalid(&reason),
    };
    let artifact = json!({"sha256":format!("{:x}",Sha256::digest(text.as_bytes())),"bytes":text.len(),"media_type":"application/source-map+json","charset":"utf-8","text":text});
    let mut item = context();
    item["status"] = json!("included");
    item["limitation"] = Value::Null;
    item["artifact"] = artifact;
    item["original_sources"] = Value::Array(original_sources);
    item["original_module_edges"] = json!([]);
    item["mappings"] = Value::Array(decoded.into_iter().map(|(line, column, source, original_line, original_column, name)| json!({"source_index":source,"declaration_index":source,"generated_line":line,"generated_column":column,"source":source.and_then(|index| item_source(&item["original_sources"], index)),"original_line":original_line,"original_column":original_column,"name":name})).collect());
    item
}

struct IndexedLeaf {
    map: Value,
    line: usize,
    column: usize,
    stop: Option<(usize, usize)>,
}

fn parse_indexed_source_map(
    source_map: &source_maps::FetchedSourceMap,
    text: &str,
    value: &Value,
    invalid: &dyn Fn(&str) -> Value,
) -> Value {
    let Some(sections) = value["sections"].as_array() else {
        return invalid("Indexed source-map sections must be an array.");
    };
    let mut leaves = Vec::new();
    if let Err(reason) = collect_indexed_leaves(sections, 0, 0, None, &mut leaves) {
        return invalid(&reason);
    }
    let mut original_sources = Vec::new();
    let mut mappings = Vec::new();
    let mut edges = Vec::new();
    let mut declaration_base = 0usize;
    let mut partial = false;
    for leaf in leaves {
        let Ok(bytes) = serde_json::to_vec(&leaf.map) else {
            return invalid("Indexed source-map leaf could not be serialized.");
        };
        let child = source_maps::FetchedSourceMap {
            script_key: source_map.script_key.clone(),
            declared_url: source_map.declared_url.clone(),
            effective_url: source_map.effective_url.clone(),
            bytes,
        };
        let Ok(child_text) = String::from_utf8(child.bytes.clone()) else {
            return invalid("Indexed source-map leaf is not valid UTF-8.");
        };
        let child_item = parse_source_map_item(&child, &child_text);
        if child_item["status"] != "included" {
            partial = true;
            continue;
        }
        let child_sources = child_item["original_sources"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        for mut source in child_sources {
            source["declaration_index"] =
                json!(declaration_base + source["source_index"].as_u64().unwrap_or(0) as usize);
            original_sources.push(source);
        }
        for mut mapping in child_item["mappings"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            let local_line = mapping["generated_line"].as_u64().unwrap_or(1) as usize - 1;
            let local_column = mapping["generated_column"].as_u64().unwrap_or(0) as usize;
            let generated_line = leaf.line + local_line;
            let generated_column = local_column + if local_line == 0 { leaf.column } else { 0 };
            if let Some(stop) = leaf.stop
                && (generated_line > stop.0
                    || (generated_line == stop.0 && generated_column >= stop.1))
            {
                continue;
            }
            mapping["generated_line"] = json!(generated_line + 1);
            mapping["generated_column"] = json!(generated_column);
            if let Some(index) = mapping["source_index"].as_u64() {
                mapping["declaration_index"] = json!(declaration_base + index as usize);
            }
            mappings.push(mapping);
        }
        edges.extend(
            child_item["original_module_edges"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
        );
        declaration_base += child_item["original_sources"]
            .as_array()
            .map_or(0, Vec::len);
    }
    let artifact = json!({"sha256":format!("{:x}",Sha256::digest(text.as_bytes())),"bytes":text.len(),"media_type":"application/source-map+json","charset":"utf-8","text":text});
    let status = if partial { "partial" } else { "included" };
    json!({"script_key":source_map.script_key,"declared_url":source_map.declared_url,"effective_url":source_map.effective_url,"status":status,"limitation":if partial { Some("One or more indexed source-map leaves were invalid or incomplete.") } else { None::<&str> },"artifact":artifact,"original_sources":original_sources,"original_module_edges":edges,"mappings":mappings})
}

fn collect_indexed_leaves(
    sections: &[Value],
    base_line: usize,
    base_column: usize,
    parent_stop: Option<(usize, usize)>,
    leaves: &mut Vec<IndexedLeaf>,
) -> Result<(), String> {
    let mut previous = None;
    for (index, section) in sections.iter().enumerate() {
        let offset_line = usize::try_from(
            section["offset"]["line"]
                .as_u64()
                .ok_or_else(|| "Indexed section offset line is invalid.".to_owned())?,
        )
        .map_err(|_| "Indexed section offset line is too large.".to_owned())?;
        let offset_column = usize::try_from(
            section["offset"]["column"]
                .as_u64()
                .ok_or_else(|| "Indexed section offset column is invalid.".to_owned())?,
        )
        .map_err(|_| "Indexed section offset column is too large.".to_owned())?;
        let offset = (
            base_line
                .checked_add(offset_line)
                .ok_or_else(|| "Indexed section line offset overflowed.".to_owned())?,
            offset_column
                .checked_add(if offset_line == 0 { base_column } else { 0 })
                .ok_or_else(|| "Indexed section column offset overflowed.".to_owned())?,
        );
        if previous.is_some_and(|previous| offset <= previous) {
            return Err("Indexed section offsets must be strictly increasing.".to_owned());
        }
        previous = Some(offset);
        if parent_stop.is_some_and(|stop| offset >= stop) {
            return Err("Nested source-map section overlaps its enclosing boundary.".to_owned());
        }
        let next = sections.get(index + 1).and_then(|next| {
            let line = usize::try_from(next["offset"]["line"].as_u64().unwrap_or(0)).ok()?;
            let column = usize::try_from(next["offset"]["column"].as_u64().unwrap_or(0)).ok()?;
            Some((
                base_line.checked_add(line)?,
                column.checked_add(if line == 0 { base_column } else { 0 })?,
            ))
        });
        let stop = next.or(parent_stop);
        if let Some(map) = section.get("map") {
            if let Some(child_sections) = map["sections"].as_array() {
                collect_indexed_leaves(child_sections, offset.0, offset.1, stop, leaves)?;
            } else if map.is_object() {
                leaves.push(IndexedLeaf {
                    map: map.clone(),
                    line: offset.0,
                    column: offset.1,
                    stop,
                });
            } else {
                return Err("Indexed source-map section requires an embedded map.".to_owned());
            }
        } else if section.get("url").is_some() {
            return Err("External source-map section URL is not fetched.".to_owned());
        } else {
            return Err("Indexed source-map section requires an embedded map.".to_owned());
        }
    }
    Ok(())
}

fn source_media_type(source: &str) -> &'static str {
    let path = source.split(['?', '#']).next().unwrap_or(source);
    match path
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "ts" => "text/typescript",
        "tsx" => "text/tsx",
        "jsx" => "text/jsx",
        "css" => "text/css",
        "json" => "application/json",
        _ => "text/javascript",
    }
}

fn item_source(sources: &Value, index: usize) -> Option<String> {
    sources.as_array()?.get(index)?["source"]
        .as_str()
        .map(str::to_owned)
}

fn resolve_source_name(raw: &str, root: &str, map_url: &str) -> String {
    let root = if root.is_empty() || root.ends_with('/') {
        root.to_owned()
    } else {
        format!("{root}/")
    };
    let root_url = Url::parse(map_url)
        .ok()
        .and_then(|url| url.join(&root).ok());
    root_url
        .and_then(|url| url.join(raw).ok())
        .map(|url| url.to_string())
        .unwrap_or_else(|| format!("{root}{raw}"))
}

fn decode_mappings(
    mapping_text: &str,
    source_count: usize,
    names: Option<&[Value]>,
) -> Result<Vec<(usize, usize, Option<usize>, usize, usize, Option<String>)>, String> {
    let mut output = Vec::new();
    let mut source = 0_i64;
    let mut original_line = 0_i64;
    let mut original_column = 0_i64;
    let mut name = 0_i64;
    for (line_index, row) in mapping_text.split(';').enumerate() {
        if line_index >= SOURCE_MAP_MAX_ROWS {
            return Err("Source-map exceeds the generated-row decoder budget.".to_owned());
        }
        let mut generated_column = 0_i64;
        for encoded in row.split(',').filter(|segment| !segment.is_empty()) {
            if output.len() >= SOURCE_MAP_MAX_SEGMENTS {
                return Err("Source-map exceeds the decoded-segment budget.".to_owned());
            }
            let values = decode_vlq(encoded)?;
            if !matches!(values.len(), 1 | 4 | 5) {
                return Err("Source-map segment has an invalid field count.".to_owned());
            }
            generated_column += values[0];
            if generated_column < 0 {
                return Err("Source-map generated column became negative.".to_owned());
            }
            if values.len() == 1 {
                continue;
            }
            source += values[1];
            original_line += values[2];
            original_column += values[3];
            if source < 0
                || original_line < 0
                || original_column < 0
                || source as usize >= source_count
            {
                return Err("Source-map original location is invalid.".to_owned());
            }
            let segment_name = if values.len() == 5 {
                name += values[4];
                if name < 0 {
                    return Err("Source-map name index became negative.".to_owned());
                }
                names
                    .and_then(|values| values.get(name as usize))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            } else {
                None
            };
            output.push((
                line_index + 1,
                generated_column as usize,
                Some(source as usize),
                original_line as usize + 1,
                original_column as usize,
                segment_name,
            ));
        }
    }
    Ok(output)
}

fn decode_vlq(segment: &str) -> Result<Vec<i64>, String> {
    let mut values = Vec::new();
    let mut value = 0_i64;
    let mut shift = 0_u32;
    for byte in segment.bytes() {
        let digit = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            .bytes()
            .position(|candidate| candidate == byte)
            .ok_or_else(|| "Source-map VLQ contains an invalid character.".to_owned())?
            as i64;
        value |= (digit & 31) << shift;
        if digit & 32 == 0 {
            let negative = value & 1 != 0;
            let magnitude = value >> 1;
            values.push(if negative { -magnitude } else { magnitude });
            value = 0;
            shift = 0;
        } else {
            shift += 5;
            if shift > 60 {
                return Err("Source-map VLQ is too large.".to_owned());
            }
        }
    }
    if shift != 0 {
        return Err("Source-map VLQ is truncated.".to_owned());
    }
    Ok(values)
}

fn allowed_origins(input: &Input, inspection: &Value) -> BTreeSet<String> {
    if input.scope.allowed_origins.is_empty() {
        inspection["target"]["origin"]
            .as_str()
            .into_iter()
            .map(str::to_owned)
            .collect()
    } else {
        input.scope.allowed_origins.iter().cloned().collect()
    }
}

fn parameters(input: &Input) -> Value {
    let mut parameters = json!({
        "cdp_endpoint": input.scope.endpoint.recorded,
        "allowed_origins": input.scope.allowed_origins,
        "target_id": input.target_id,
    });
    let object = parameters
        .as_object_mut()
        .expect("bundle parameters are always a JSON object");

    if input.observation_ms_explicit {
        object.insert(
            "observation_ms".to_owned(),
            json!(input.options.observation_ms),
        );
    }
    if input.include_options_explicit {
        object.extend([
            (
                "include_accessibility_text".to_owned(),
                json!(input.options.include_accessibility_text),
            ),
            (
                "include_console_text".to_owned(),
                json!(input.options.include_console_text),
            ),
            (
                "include_json_body_shapes".to_owned(),
                json!(input.options.include_json_body_shapes),
            ),
            (
                "include_websocket_shapes".to_owned(),
                json!(input.options.include_websocket_shapes),
            ),
            (
                "include_storage_keys".to_owned(),
                json!(input.options.include_storage_keys),
            ),
            (
                "include_storage_fingerprints".to_owned(),
                json!(input.options.include_storage_fingerprints),
            ),
        ]);
        if input.include_script_sources_explicit {
            object.insert(
                "include_script_sources".to_owned(),
                json!(input.options.include_script_sources),
            );
        }
    }
    if input.fetch_source_maps_explicit {
        object.insert(
            "fetch_source_maps".to_owned(),
            json!(input.fetch_source_maps),
        );
        if input.max_heap_mb_explicit {
            object.insert("max_heap_mb".to_owned(), json!(input.max_heap_mb));
        }
        if input.analysis_timeout_explicit {
            object.insert(
                "analysis_timeout_ms".to_owned(),
                json!(input.analysis_timeout.as_millis()),
            );
        }
        if input.total_analysis_timeout_explicit {
            object.insert(
                "total_analysis_timeout_ms".to_owned(),
                json!(input.total_analysis_timeout.as_millis()),
            );
        }
    }

    parameters
}
