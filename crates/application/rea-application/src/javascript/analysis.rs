//! Application-owned composition of JavaScript artifact facts.
//!
//! This module is intentionally a narrow seam between acquisition and graph
//! construction.  Source producers remain the owners of their facts: the
//! semantic producer owns the semantic IR and the static contract owns parse
//! status, references, and source accounting.  The returned value is the
//! canonical graph JSON shape rather than a second application-only model.

use serde_json::Value;
use std::ops::ControlFlow;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Duration;

use oxc_allocator::Allocator;

use super::acquisition::{JavaScriptArtifactFileSet, canonical_file_json};
use super::artifact_files::{JavaScriptArtifactFile, JavaScriptArtifactFileKind, JavaScriptText};
use super::contracts::static_analysis::{ElectronFindings, ParseStatus, StaticAnalysis};
use super::graph::SemanticLimits;
use super::graph::json::{Json, Obj, parse};
use super::non_js;
use super::parser::parse_javascript_analysis_program;
use super::semantic::state::ResolutionMode;
use super::semantic::value_types::JsString;
use super::worker::{WorkerFileMetadata, WorkerLimits, WorkerRequest, analyze_source_with_worker};

/// Operational controls for the isolated source-analysis stage.
#[derive(Clone, Debug)]
pub struct JavaScriptAnalysisOptions {
    pub worker_limits: WorkerLimits,
    pub semantic_limits: SemanticLimits,
}

#[derive(Clone, Debug)]
pub enum AnalysisInterruption {
    Cancelled(String),
    Timeout { timeout_ms: u128, message: String },
    ResourceConstraint { limits: Json, message: String },
    Failure(String),
}

impl AnalysisInterruption {
    pub fn message(&self) -> &str {
        match self {
            Self::Cancelled(message)
            | Self::Timeout { message, .. }
            | Self::ResourceConstraint { message, .. }
            | Self::Failure(message) => message,
        }
    }
}

impl Default for JavaScriptAnalysisOptions {
    fn default() -> Self {
        Self {
            worker_limits: WorkerLimits {
                max_heap_mb: Some(1024),
                timeout: Duration::from_millis(300_000),
            },
            semantic_limits: SemanticLimits::default(),
        }
    }
}

impl JavaScriptAnalysisOptions {
    pub fn from_input(input: &Value) -> Self {
        let object = input.as_object();
        let max_heap_mb = object
            .and_then(|value| value.get("max_heap_mb"))
            .and_then(Value::as_u64)
            .or(Some(1024));
        let timeout_ms = object
            .and_then(|value| value.get("analysis_timeout_ms"))
            .and_then(Value::as_u64)
            .unwrap_or(300_000);
        Self {
            worker_limits: WorkerLimits {
                max_heap_mb,
                timeout: Duration::from_millis(timeout_ms),
            },
            semantic_limits: SemanticLimits {
                total_nodes: count(object, "max_semantic_nodes", 100_000),
                file_nodes: count(object, "max_semantic_nodes_per_file", 20_000),
                total_unknowns: count(object, "max_semantic_unknowns", 100_000),
                file_unknowns: count(object, "max_semantic_unknowns_per_file", 20_000),
            },
        }
    }
}

fn count(object: Option<&serde_json::Map<String, Value>>, field: &str, fallback: usize) -> usize {
    object
        .and_then(|value| value.get(field))
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(fallback)
}

/// Facts for one acquired file, in the shape consumed by the graph builder.
#[derive(Clone, Debug)]
pub struct JavaScriptFileAnalysis {
    pub value: Json,
}

/// Aggregate facts for an acquired artifact set.
#[derive(Clone, Debug)]
pub struct JavaScriptArtifactAnalysis {
    pub value: Json,
    /// Whether analysis stopped after retaining the files completed so far.
    pub interrupted: bool,
    pub interruption: Option<AnalysisInterruption>,
}

/// Analyze every acquired file while retaining already-produced files when a
/// caller checkpoint requests cancellation.
pub fn analyze_artifact_files<B>(
    file_set: &JavaScriptArtifactFileSet<'_>,
    options: &JavaScriptAnalysisOptions,
    mut checkpoint: impl FnMut() -> ControlFlow<B>,
) -> JavaScriptArtifactAnalysis {
    let mut files = Vec::with_capacity(file_set.files.len());
    let mut visited_ast_nodes = 0_u64;
    let mut findings = 0_u64;
    let mut modules = 0_u64;
    let mut parse_failures = 0_u64;
    let mut semantic_nodes = 0_usize;
    let mut semantic_unknowns = 0_usize;
    let mut packages = Vec::new();
    let mut json_modules = Vec::new();
    let mut html_scripts = Vec::new();
    let mut html_inline_scripts = Vec::new();
    let mut source_maps = Vec::new();
    let mut limitations = vec![
        "JavaScript and HTML were parsed as inert text; bundle bootstrap code was never executed."
            .to_owned(),
        "Static paths and relationships may remain unresolved when expressions are dynamic or obfuscated."
            .to_owned(),
    ];

    let mut interrupted = false;
    let mut interruption = None;
    for file in &file_set.files {
        if checkpoint().is_break() {
            interrupted = true;
            break;
        }

        if !matches!(
            &file.text,
            &JavaScriptText::Excluded(
                super::artifact_files::TextExclusionReason::OutsideAnalysisScope
            )
        ) {
            match file.kind {
                JavaScriptArtifactFileKind::PackageJson => {
                    packages.push(non_js::package_observation(file));
                }
                JavaScriptArtifactFileKind::Json => {
                    let observation = non_js::json_module_observation(file);
                    if observation.at("status").str() == "invalid" {
                        parse_failures = parse_failures.saturating_add(1);
                    }
                    json_modules.push(observation);
                }
                JavaScriptArtifactFileKind::Html => {
                    let (scripts, inline) = non_js::html_observations(file);
                    html_scripts.extend(scripts);
                    if let Some(inline) = inline {
                        limitations.push(non_js::html_inline_limitation(&inline));
                        html_inline_scripts.push(inline);
                    }
                }
                JavaScriptArtifactFileKind::SourceMap => {
                    let observation = non_js::source_map_observation(file);
                    source_maps.push(observation);
                }
                JavaScriptArtifactFileKind::JavaScript
                | JavaScriptArtifactFileKind::NativeAddon => {}
            }
        }

        let remaining_nodes = options
            .semantic_limits
            .total_nodes
            .saturating_sub(semantic_nodes)
            .min(options.semantic_limits.file_nodes);
        let remaining_unknowns = options
            .semantic_limits
            .total_unknowns
            .saturating_sub(semantic_unknowns)
            .min(options.semantic_limits.file_unknowns);
        let (analyzed, file_interruption) = match analyze_file(
            file,
            options,
            remaining_nodes,
            remaining_unknowns,
            &mut checkpoint,
        ) {
            ControlFlow::Continue(value) => value,
            ControlFlow::Break(_) => {
                interrupted = true;
                interruption = Some(AnalysisInterruption::Cancelled(
                    "JavaScript source analysis was cancelled.".to_owned(),
                ));
                break;
            }
        };
        let javascript = analyzed.at("javascript");
        if !javascript.is_null() {
            visited_ast_nodes = visited_ast_nodes
                .saturating_add(javascript.at("visited_ast_nodes").num().max(0.0) as u64);
            findings = findings.saturating_add(static_finding_count(javascript));
            modules = modules.saturating_add(
                javascript
                    .at("bundler_registrations")
                    .arr()
                    .iter()
                    .map(|registration| registration.at("modules").arr().len() as u64)
                    .sum::<u64>(),
            );
            if javascript.at("parse_status").str() == "failed" {
                parse_failures = parse_failures.saturating_add(1);
            }
        }
        if let Some(reason) = analyzed.get("analysis_failure") {
            limitations.push(reason.at("reason").str().to_owned());
        }
        let semantic = analyzed.at("semantic");
        let module_links = semantic.at("metadata").at("moduleLinks");
        let module_links = if module_links.is_null() {
            semantic.at("ir").at("moduleLinks").arr().len() as u64
        } else {
            module_links.num().max(0.0) as u64
        };
        findings = findings.saturating_add(module_links);
        semantic_nodes =
            semantic_nodes.saturating_add(semantic.at("projection").at("nodes").arr().len());
        semantic_unknowns =
            semantic_unknowns.saturating_add(semantic.at("projection").at("unknowns").arr().len());
        files.push(analyzed);
        if let Some(file_interruption) = file_interruption {
            interrupted = true;
            interruption = Some(file_interruption);
            break;
        }
    }

    findings = findings
        .saturating_add(html_scripts.len() as u64)
        .saturating_add(
            html_inline_scripts
                .iter()
                .map(|observation| observation.at("script_count").num().max(0.0) as u64)
                .sum::<u64>(),
        );

    let omitted = file_set
        .unavailable_relevant_files
        .iter()
        .map(|file| unavailable_file(file))
        .collect::<Vec<_>>();
    let mut all_files = files;
    all_files.extend(omitted);

    JavaScriptArtifactAnalysis {
        value: Obj::new()
            .with("files", Json::array(all_files))
            .with("packages", Json::array(packages))
            .with("json_modules", Json::array(json_modules))
            .with("html_scripts", Json::array(html_scripts))
            .with("html_inline_scripts", Json::array(html_inline_scripts))
            .with("source_maps", Json::array(source_maps))
            .with("visited_ast_nodes", visited_ast_nodes as usize)
            .with("findings", findings as usize)
            .with("modules", modules as usize)
            .with("parse_failures", parse_failures as usize)
            .with(
                "limitations",
                Json::array({
                    if interrupted {
                        limitations.push(
                            "Analysis was cancelled after retaining completed source facts; unvisited files remain unknown."
                                .to_owned(),
                        );
                    }
                    limitations.into_iter().map(Json::from).collect()
                }),
            )
            .into(),
        interrupted,
        interruption,
    }
}

fn static_finding_count(javascript: &Json) -> u64 {
    let direct_count = [
        "references",
        "endpoints",
        "storage",
        "role_paths",
        "source_map_urls",
        "bundler_registrations",
    ]
    .into_iter()
    .map(|field| javascript.at(field).arr().len() as u64)
    .sum::<u64>();
    let electron_count = [
        "browser_windows",
        "context_bridge_apis",
        "ipc",
        "sender_validations",
        "utility_processes",
        "native_addon_bindings",
    ]
    .into_iter()
    .map(|field| javascript.at("electron").at(field).arr().len() as u64)
    .sum::<u64>();
    direct_count.saturating_add(electron_count)
}

fn analyze_file<B>(
    file: &JavaScriptArtifactFile,
    options: &JavaScriptAnalysisOptions,
    node_budget: usize,
    unknown_budget: usize,
    checkpoint: &mut impl FnMut() -> ControlFlow<B>,
) -> ControlFlow<B, (Json, Option<AnalysisInterruption>)> {
    let Some(source) = (match (&file.kind, &file.text) {
        (JavaScriptArtifactFileKind::JavaScript, JavaScriptText::Included(source)) => {
            source.as_str().map(str::to_owned)
        }
        _ => None,
    }) else {
        return ControlFlow::Continue((
            Obj::new()
                .with("file", file_value(file))
                .with("javascript", Json::Null)
                .with("semantic", Json::Null)
                .into(),
            None,
        ));
    };

    checkpoint()?;
    let worker_result = analyze_source_with_worker(
        &WorkerRequest {
            max_heap_mb: options.worker_limits.max_heap_mb,
            node_budget,
            unknown_budget,
            file: Some(WorkerFileMetadata {
                path: file.path.clone(),
                container_sha256: file.container_sha256.clone(),
                sha256: file.sha256.clone(),
                bytes: file.bytes,
                inventory_artifact_id: file.inventory_artifact_id.clone(),
                kind: "javascript".to_owned(),
                unpacked: file.unpacked,
            }),
            source,
            path: Some(file.path.clone()),
        },
        &options.worker_limits,
        || checkpoint().is_break(),
    );
    let (static_result_json, semantic_json, projection_json, metadata_json, semantic_failure) =
        match worker_result {
            Ok(response) => (
                response.static_analysis,
                response.semantic_ir,
                response.semantic_projection,
                response.semantic_metadata,
                response.semantic_failure,
            ),
            Err(failure) => {
                let interruption = worker_failure_interruption(&failure);
                if let Some(static_analysis) = failure
                    .static_checkpoint()
                    .and_then(|value| parse(value.get()).ok())
                {
                    return ControlFlow::Continue((
                        Obj::new()
                            .with("file", file_value(file))
                            .with("javascript", static_analysis)
                            .with("semantic", Json::Null)
                            .with(
                                "analysis_failure",
                                Obj::new()
                                    .with("scope", javascript_analysis_scope())
                                    .with("status", "partial")
                                    .with("reason", failure.to_string())
                                    .with("error", Json::Null)
                                    .with("limits", worker_failure_limits(&failure)),
                            )
                            .into(),
                        Some(interruption),
                    ));
                }
                return ControlFlow::Continue((
                    analysis_failure_file(
                        file_value(file),
                        &file.path,
                        &failure.to_string(),
                        worker_failure_limits(&failure),
                    ),
                    Some(interruption),
                ));
            }
        };
    checkpoint()?;
    let static_result = match serde_json::from_str::<StaticAnalysis>(static_result_json.get()) {
        Ok(value) => value,
        Err(error) => {
            let interruption = AnalysisInterruption::Failure(format!(
                "{}: worker static-analysis response was invalid: {error}",
                file.path
            ));
            return ControlFlow::Continue((
                analysis_failure_file(
                    file_value(file),
                    &file.path,
                    interruption.message(),
                    Json::Null,
                ),
                Some(interruption),
            ));
        }
    };
    let static_json = serialized(&static_result);
    drop(static_result);

    if let Some(failure) = semantic_failure {
        let interruption = AnalysisInterruption::Failure(format!(
            "{}: {} semantic analysis failed: {}",
            file.path, failure.phase, failure.reason
        ));
        return ControlFlow::Continue((
            Obj::new()
                .with("file", file_value(file))
                .with("javascript", static_json)
                .with("semantic", Json::Null)
                .with(
                    "analysis_failure",
                    Obj::new()
                        .with("scope", javascript_analysis_scope())
                        .with("status", "partial")
                        .with("reason", interruption.message())
                        .with("error", Json::Null)
                        .with("limits", Json::Null),
                )
                .into(),
            Some(interruption),
        ));
    }
    let semantic = match semantic_json {
        Some(value) => match parse(value.get()) {
            Ok(value) => Some(value),
            Err(error) => {
                let interruption = AnalysisInterruption::Failure(format!(
                    "{}: worker semantic response was invalid: {error}",
                    file.path
                ));
                return ControlFlow::Continue((
                    analysis_failure_file(
                        file_value(file),
                        &file.path,
                        interruption.message(),
                        Json::Null,
                    ),
                    Some(interruption),
                ));
            }
        },
        None => None,
    };
    let projection = match projection_json {
        Some(value) => match parse(value.get()) {
            Ok(value) => Some(value),
            Err(error) => {
                let interruption = AnalysisInterruption::Failure(format!(
                    "{}: worker semantic projection was invalid: {error}",
                    file.path
                ));
                return ControlFlow::Continue((
                    analysis_failure_file(
                        file_value(file),
                        &file.path,
                        interruption.message(),
                        Json::Null,
                    ),
                    Some(interruption),
                ));
            }
        },
        None => None,
    };
    let metadata = match metadata_json {
        Some(value) => match parse(value.get()) {
            Ok(value) => Some(value),
            Err(error) => {
                let interruption = AnalysisInterruption::Failure(format!(
                    "{}: worker semantic metadata was invalid: {error}",
                    file.path
                ));
                return ControlFlow::Continue((
                    analysis_failure_file(
                        file_value(file),
                        &file.path,
                        interruption.message(),
                        Json::Null,
                    ),
                    Some(interruption),
                ));
            }
        },
        None => None,
    };
    let mut result = Obj::new()
        .with("file", file_value(file))
        .with("javascript", static_json);
    if semantic.is_none() && projection.is_none() && metadata.is_none() {
        result.set("semantic", Json::Null);
    } else {
        let mut semantic_value = Obj::new();
        if let Some(metadata) = metadata {
            semantic_value.set("metadata", metadata);
        }
        if let Some(semantic) = semantic {
            semantic_value.set("ir", semantic);
        }
        if let Some(projection) = projection {
            semantic_value.set("projection", projection);
        }
        result.set("semantic", semantic_value);
    }
    ControlFlow::Continue((result.into(), None))
}

fn worker_failure_interruption(failure: &super::worker::WorkerFailure) -> AnalysisInterruption {
    if failure.is_cancelled() {
        AnalysisInterruption::Cancelled(failure.to_string())
    } else if failure.is_timeout() {
        let timeout_ms = match failure.primary_failure() {
            super::worker::WorkerFailure::Timeout { timeout_ms } => *timeout_ms,
            _ => unreachable!("worker timeout classification must expose timeout details"),
        };
        AnalysisInterruption::Timeout {
            timeout_ms,
            message: failure.to_string(),
        }
    } else if failure.is_resource_constraint() {
        AnalysisInterruption::ResourceConstraint {
            limits: worker_failure_limits(failure),
            message: failure.to_string(),
        }
    } else {
        AnalysisInterruption::Failure(failure.to_string())
    }
}

fn analysis_failure_file(file: Json, path: &str, reason: &str, limits: Json) -> Json {
    Obj::new()
        .with("file", file)
        .with("javascript", Json::Null)
        .with("semantic", Json::Null)
        .with(
            "analysis_failure",
            Obj::new()
                .with("scope", javascript_analysis_scope())
                .with("status", "interrupted")
                .with("reason", format!("{path}: {reason}"))
                .with("error", Json::Null)
                .with("limits", limits),
        )
        .into()
}

fn javascript_analysis_scope() -> Json {
    Obj::new()
        .with("operation", "analyze-javascript-source")
        .with("authority", "ast-static-analysis")
        .into()
}

fn worker_failure_limits(failure: &super::worker::WorkerFailure) -> Json {
    match failure.primary_failure() {
        super::worker::WorkerFailure::Timeout { timeout_ms } => Obj::new()
            .with("worker_timeout_ms", *timeout_ms as usize)
            .into(),
        super::worker::WorkerFailure::ResourceConstraint { requested_mb, .. } => Obj::new()
            .with(
                "worker_heap_limit_bytes",
                requested_mb.saturating_mul(1024 * 1024) as usize,
            )
            .into(),
        _ => Json::Null,
    }
}

/// Produce the static-source checkpoint used by both the worker and the
/// application workflow. Parse failures remain a typed static result so the
/// caller can retain inventory and source facts without inventing a provider
/// execution error.
pub fn analyze_source_for_static_analysis(source: &str, path: Option<&str>) -> StaticAnalysis {
    match super::static_analysis::analyze::analyze_source(source, path) {
        Ok(analysis) => analysis,
        Err(_) => failed_static_analysis(),
    }
}

fn failed_static_analysis() -> StaticAnalysis {
    StaticAnalysis {
        parse_status: ParseStatus::Failed,
        parse_error_count: 1,
        visited_ast_nodes: 0,
        references: Vec::new(),
        endpoints: Vec::new(),
        storage: Vec::new(),
        bundler_registrations: Vec::new(),
        role_paths: Vec::new(),
        source_map_urls: Vec::new(),
        vendors: Vec::new(),
        electron: empty_electron_findings(),
        limitations: vec![
            "JavaScript source could not be parsed; absence of findings is not evidence of absence."
                .to_owned(),
            "JavaScript syntax was parsed as data and was never evaluated.".to_owned(),
        ],
    }
}

fn empty_electron_findings() -> ElectronFindings {
    ElectronFindings {
        call_paths: None,
        browser_windows: Vec::new(),
        context_bridge_apis: Vec::new(),
        ipc: Vec::new(),
        sender_validations: Vec::new(),
        utility_processes: Vec::new(),
        native_addon_bindings: Vec::new(),
    }
}

fn serialized<T: serde::Serialize>(value: &T) -> Json {
    super::graph::direct_serializer::serialize(value)
        .expect("analysis contract is serializable and valid JSON")
}

fn file_value(file: &JavaScriptArtifactFile) -> Json {
    canonical_file_json(file)
}

fn unavailable_file(file: &super::artifact_files::JavaScriptUnanalyzedArtifactFile) -> Json {
    let mut metadata = Obj::new()
        .with("path", file.path.clone())
        .with("container_sha256", file.container_sha256.clone())
        .with("kind", file.artifact_kind.clone())
        .with("unpacked", false)
        .with(
            "text",
            Obj::new()
                .with("included", false)
                .with("reason", "unavailable"),
        );
    if let Some(sha256) = &file.sha256 {
        metadata.set("sha256", sha256.clone());
    }
    if let Some(bytes) = file.bytes {
        metadata.set("bytes", bytes as usize);
    }
    if let Some(inventory_artifact_id) = &file.inventory_artifact_id {
        metadata.set("inventory_artifact_id", inventory_artifact_id.clone());
    }
    metadata.set(
        "inventory_occurrence_id",
        file.inventory_occurrence_id.clone(),
    );
    metadata.set("hash_status", file.hash_status.clone());
    metadata.set(
        "limitations",
        Json::array(file.limitations.iter().cloned().map(Json::from).collect()),
    );
    Obj::new()
        .with("file", metadata)
        .with("javascript", Json::Null)
        .with("semantic", Json::Null)
        .with(
            "analysis_failure",
            Obj::new()
                .with("scope", javascript_analysis_scope())
                .with("status", "not-started")
                .with("reason", file.limitations.join("; "))
                .with("error", Json::Null)
                .with("limits", Json::Null),
        )
        .into()
}

struct ProjectedSemanticResponse {
    projection: Box<serde_json::value::RawValue>,
    metadata: Box<serde_json::value::RawValue>,
}

fn project_semantic_response(
    ir_json: Json,
    file: &Json,
    node_budget: usize,
    unknown_budget: usize,
    paths: &[Json],
) -> Result<ProjectedSemanticResponse, super::worker::WorkerSemanticFailure> {
    let metadata_module_links = ir_json.at("moduleLinks").arr().len();
    let metadata_coverage = ir_json.at("coverage").clone();
    let metadata_module_ir = compact_module_ir(&ir_json);
    let projection_json =
        super::graph::project_file(file, &ir_json, node_budget, unknown_budget, paths).map_err(
            |error| super::worker::WorkerSemanticFailure {
                phase: "project-file".to_owned(),
                reason: format!("{error:?}"),
            },
        )?;
    drop(ir_json);

    let projection_text = projection_json.canonical();
    drop(projection_json);
    let projection =
        serde_json::value::RawValue::from_string(projection_text).map_err(|error| {
            super::worker::WorkerSemanticFailure {
                phase: "serialize-projection".to_owned(),
                reason: error.to_string(),
            }
        })?;
    let metadata = Obj::new()
        .with("moduleLinks", metadata_module_links)
        .with("coverage", metadata_coverage)
        .with("moduleIr", metadata_module_ir);
    let metadata = serde_json::value::RawValue::from_string(Json::from(metadata).canonical())
        .map_err(|error| super::worker::WorkerSemanticFailure {
            phase: "serialize-semantic-metadata".to_owned(),
            reason: error.to_string(),
        })?;

    Ok(ProjectedSemanticResponse {
        projection,
        metadata,
    })
}

/// Retain only the semantic facts consumed by source-module relationships.
/// The full IR remains owned by the worker and is never transferred when the
/// worker projection succeeds.
fn compact_module_ir(ir: &Json) -> Json {
    let links = ir.at("moduleLinks").arr();
    let callable_ids: Vec<JsString> = links
        .iter()
        .filter_map(|link| link.at("callableId").as_js_string().cloned())
        .collect();
    let callables = ir
        .at("callables")
        .arr()
        .iter()
        .filter(|callable| {
            callable
                .at("callableId")
                .as_js_string()
                .is_some_and(|id| callable_ids.contains(id))
        })
        .map(|callable| {
            Obj::new()
                .with("callableId", callable.at("callableId").clone())
                .with("kind", callable.at("kind").clone())
                .with("location", callable.at("location").clone())
                .with("returnSites", callable.at("returnSites").clone())
                .with("returnCoverage", callable.at("returnCoverage").clone())
                .into()
        })
        .collect();
    let bindings = ir
        .at("bindings")
        .arr()
        .iter()
        .map(|binding| {
            Obj::new()
                .with("name", binding.at("name").clone())
                .with("scopeId", binding.at("scopeId").clone())
                .with("provenance", binding.at("provenance").clone())
                .into()
        })
        .collect();
    let scopes = ir
        .at("scopes")
        .arr()
        .iter()
        .filter(|scope| scope.at("kind").str() == "program")
        .map(|scope| {
            Obj::new()
                .with("kind", scope.at("kind").clone())
                .with("scopeId", scope.at("scopeId").clone())
                .with("location", scope.at("location").clone())
                .into()
        })
        .collect();

    Obj::new()
        .with("moduleLinks", Json::array(links.to_vec()))
        .with("callables", Json::array(callables))
        .with("bindings", Json::array(bindings))
        .with("scopes", Json::array(scopes))
        .with("coverage", ir.at("coverage").clone())
        .with("limitations", ir.at("limitations").clone())
        .into()
}

struct WorkerSourceAnalysis {
    static_analysis: Box<serde_json::value::RawValue>,
    call_paths: Vec<Json>,
    semantic_ir: Result<
        Option<super::contracts::semantic_ir::SemanticIr>,
        super::worker::WorkerSemanticFailure,
    >,
}

pub(crate) fn analyze_source_for_worker_with_checkpoint(
    source: &str,
    path: Option<&str>,
    node_budget: usize,
    unknown_budget: usize,
    metadata: Option<&super::worker::WorkerFileMetadata>,
    checkpoint: impl FnOnce(&serde_json::value::RawValue),
) -> super::worker::WorkerResponse {
    // Source analysis owns the arena and producer caches. Release them before
    // expanding the owned IR into graph JSON and serializing the projection.
    let analysis = analyze_worker_source(source, path, checkpoint);
    let projected = catch_semantic_failure(|| {
        let Some(ir) = analysis.semantic_ir? else {
            return Ok(None);
        };
        let ir_json = super::graph::direct_serializer::serialize_semantic_ir(ir)
            .expect("semantic IR contract is serializable and valid JSON");

        let file = worker_semantic_file(path, metadata);
        project_semantic_response(
            ir_json,
            &file,
            node_budget,
            unknown_budget,
            &analysis.call_paths,
        )
        .map(Some)
    });

    let (semantic_projection, semantic_metadata, semantic_failure) = match projected {
        Ok(Some(result)) => (Some(result.projection), Some(result.metadata), None),
        Ok(None) => (None, None, None),
        Err(failure) => (None, None, Some(failure)),
    };
    super::worker::WorkerResponse {
        static_analysis: analysis.static_analysis,
        semantic_ir: None,
        semantic_projection,
        semantic_metadata,
        semantic_failure,
    }
}

fn analyze_worker_source(
    source: &str,
    path: Option<&str>,
    checkpoint: impl FnOnce(&serde_json::value::RawValue),
) -> WorkerSourceAnalysis {
    let allocator = Allocator::default();
    let parsed = match parse_javascript_analysis_program(&allocator, source, path) {
        Ok(parsed) => parsed,
        Err(_) => {
            let static_analysis = serde_json::value::to_raw_value(&failed_static_analysis())
                .expect("static analysis contract is serializable");
            checkpoint(&static_analysis);
            return WorkerSourceAnalysis {
                static_analysis,
                call_paths: Vec::new(),
                semantic_ir: Ok(None),
            };
        }
    };

    let prepared = super::semantic::analysis::prepare_state(&parsed, ResolutionMode::Import);
    let (static_result, mut prepared) =
        super::static_analysis::analyze::analyze_source_with_prepared_state(
            source, path, &parsed, prepared,
        );
    let static_analysis = serde_json::value::to_raw_value(&static_result)
        .expect("static analysis contract is serializable");
    checkpoint(&static_analysis);
    let call_paths = serialized(&static_result.electron.call_paths)
        .arr()
        .to_vec();
    let parse_status = static_result.parse_status;
    drop(static_result);

    // Preserve the completed static checkpoint when semantic analysis fails.
    let semantic_ir = if parse_status == ParseStatus::Failed {
        Ok(None)
    } else {
        catch_semantic_failure(|| {
            match super::semantic::analysis::analyze_prepared_source_with_checkpoint(
                &parsed,
                &mut prepared,
                || ControlFlow::<()>::Continue(()),
            ) {
                ControlFlow::Continue(result) => result,
                ControlFlow::Break(()) => unreachable!("the default checkpoint never cancels"),
            }
            .map(Some)
            .map_err(|errors| super::worker::WorkerSemanticFailure {
                phase: "analyze-source".to_owned(),
                reason: format_diagnostics(&errors),
            })
        })
    };
    WorkerSourceAnalysis {
        static_analysis,
        call_paths,
        semantic_ir,
    }
}

fn catch_semantic_failure<T>(
    operation: impl FnOnce() -> Result<T, super::worker::WorkerSemanticFailure>,
) -> Result<T, super::worker::WorkerSemanticFailure> {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or_else(|payload| {
        Err(super::worker::WorkerSemanticFailure {
            phase: "semantic-pipeline-panic".to_owned(),
            reason: panic_reason(payload),
        })
    })
}

fn worker_semantic_file(
    path: Option<&str>,
    metadata: Option<&super::worker::WorkerFileMetadata>,
) -> Json {
    let Some(metadata) = metadata else {
        return Obj::new().with("path", path.unwrap_or("<source>")).into();
    };
    Obj::new()
        .with("path", metadata.path.clone())
        .with("container_sha256", metadata.container_sha256.clone())
        .with("sha256", metadata.sha256.clone())
        .with("bytes", metadata.bytes as usize)
        .with(
            "inventory_artifact_id",
            metadata.inventory_artifact_id.clone(),
        )
        .with("kind", metadata.kind.clone())
        .with("unpacked", metadata.unpacked)
        .into()
}

fn panic_reason(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_owned();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "semantic pipeline panicked without a textual reason".to_owned()
}

fn format_diagnostics(diagnostics: &[super::parser::RawDiagnostic]) -> String {
    diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.clone())
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::javascript::graph::builder::build_application_graph;
    use crate::javascript::graph::resolution::{ArtifactPathResolver, ResolveRequest};

    struct TestResolver;

    impl ArtifactPathResolver for TestResolver {
        fn resolve(&self, _request: &ResolveRequest<'_>) -> Json {
            Obj::new()
                .with("resolution_status", "not-applicable")
                .with("limitations", Json::array(Vec::new()))
                .into()
        }

        fn module_resolution_mode(
            &self,
            _source_path: &JsString,
            _reference_kind: &str,
            _explicit_mode: Option<&str>,
        ) -> String {
            "commonjs".to_owned()
        }
    }

    #[test]
    fn interrupted_file_graph_preserves_scope_evidence() {
        let digest = "a".repeat(64);
        let file = Obj::new()
            .with("path", "worker.js")
            .with("sha256", digest.clone())
            .with("kind", "javascript")
            .with("text", Obj::new().with("included", true));
        let interrupted =
            analysis_failure_file(file.into(), "worker.js", "worker timed out", Json::Null);
        let snapshot = Obj::new()
            .with(
                "manifest",
                Obj::new()
                    .with("root_artifact_id", "art_root")
                    .with("root_sha256", digest.clone())
                    .with("root_format", "directory")
                    .with("manifest_id", "manifest_test")
                    .with("graph_sha256", digest.clone()),
            )
            .with(
                "nodes",
                Json::array(vec![
                    Obj::new()
                        .with("artifact_id", "art_root")
                        .with("sha256", digest.clone())
                        .with("size", 1_usize)
                        .into(),
                ]),
            )
            .with("integrity_contradictions", Json::array(Vec::new()));
        let file_set = Obj::new()
            .with("containers", Json::array(Vec::new()))
            .with("packages", Json::array(Vec::new()))
            .with("json_modules", Json::array(Vec::new()))
            .with("source_maps", Json::array(Vec::new()))
            .with("html_inline_scripts", Json::array(Vec::new()))
            .with("unavailable_relevant_files", Json::array(Vec::new()));
        let analysis = Obj::new().with("files", Json::array(vec![interrupted]));

        let graph = build_application_graph(
            &snapshot.into(),
            &file_set.into(),
            &analysis.into(),
            &TestResolver,
        )
        .expect("minimal interrupted analysis graph");
        let unknown_node = graph
            .at("nodes")
            .arr()
            .iter()
            .find(|node| {
                node.at("kind").str() == "unknown"
                    && node.at("observations").arr().iter().any(|observation| {
                        observation.at("properties").at("analysis_status").str() == "interrupted"
                    })
            })
            .expect("interrupted analysis observation");
        let evidence = unknown_node
            .at("observations")
            .arr()
            .iter()
            .find(|observation| {
                observation.at("properties").at("analysis_status").str() == "interrupted"
            })
            .expect("interrupted observation")
            .at("evidence");

        assert_eq!(evidence.at("authority").str(), "ast-static-analysis");
        assert_eq!(
            evidence.at("extractor").at("operation").str(),
            "analyze-javascript-source"
        );
    }

    #[test]
    fn compact_module_ir_keeps_import_export_graph_facts() {
        let ir = Obj::new()
            .with(
                "moduleLinks",
                Json::array(vec![
                    Obj::new()
                        .with("kind", "export")
                        .with("callableId", "callable-1")
                        .with("exportedName", "run")
                        .into(),
                ]),
            )
            .with(
                "callables",
                Json::array(vec![
                    Obj::new()
                        .with("callableId", "callable-1")
                        .with("kind", "function")
                        .with("returnSites", Json::array(vec![]))
                        .with("returnCoverage", Obj::new().with("status", "complete"))
                        .with("body", Json::array(vec![Json::from("large-unused-fact")]))
                        .into(),
                ]),
            )
            .with(
                "bindings",
                Json::array(vec![
                    Obj::new()
                        .with("name", "run")
                        .with("scopeId", "program")
                        .with("provenance", Obj::new().with("status", "module"))
                        .with("unused", Json::array(vec![Json::from("large-unused-fact")]))
                        .into(),
                ]),
            )
            .with(
                "scopes",
                Json::array(vec![
                    Obj::new()
                        .with("kind", "program")
                        .with("scopeId", "program")
                        .with("locals", Json::array(vec![Json::from("large-unused-fact")]))
                        .into(),
                ]),
            )
            .with("coverage", Obj::new().with("status", "complete"))
            .with("limitations", Json::array(vec![]));

        let ir: Json = ir.into();
        let compact = compact_module_ir(&ir);
        assert_eq!(compact.at("moduleLinks"), ir.at("moduleLinks"));
        assert_eq!(compact.at("callables").arr().len(), 1);
        assert_eq!(compact.at("bindings").arr()[0].at("name").str(), "run");
        assert_eq!(compact.at("scopes").arr().len(), 1);
        assert!(compact.at("callables").arr()[0].get("body").is_none());
        assert!(compact.at("bindings").arr()[0].get("unused").is_none());
        assert!(compact.at("scopes").arr()[0].get("locals").is_none());
    }

    #[test]
    fn worker_compact_metadata_retains_real_module_graph_facts() {
        let response = analyze_source_for_worker_with_checkpoint(
            r#"
                import { helper } from "./dep.js";
                export function run() {
                    return helper();
                }
            "#,
            Some("src/main.js"),
            10_000,
            10_000,
            None,
            |_| {},
        );

        assert!(response.semantic_failure.is_none());
        let metadata = parse(
            response
                .semantic_metadata
                .as_ref()
                .expect("semantic metadata")
                .get(),
        )
        .expect("valid semantic metadata");
        let module_ir = metadata.at("moduleIr");
        let links = module_ir.at("moduleLinks").arr();
        assert!(links.iter().any(|link| {
            link.at("kind").str() == "import" && link.at("specifier").str() == "./dep.js"
        }));
        let export_link = links
            .iter()
            .find(|link| {
                link.at("kind").str() == "export" && link.at("exportedName").str() == "run"
            })
            .expect("export link");
        let callable_id = export_link.at("callableId").str();
        let callable = module_ir
            .at("callables")
            .arr()
            .iter()
            .find(|callable| callable.at("callableId").str() == callable_id)
            .expect("exported callable");
        assert!(!callable.at("returnSites").arr().is_empty());
        assert!(!module_ir.at("scopes").arr().is_empty());
        assert!(module_ir.at("coverage").is_object());
        assert!(module_ir.at("limitations").is_array());
    }
}
