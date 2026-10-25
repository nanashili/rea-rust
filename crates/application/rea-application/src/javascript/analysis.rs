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

use super::acquisition::{JavaScriptArtifactFileSet, canonical_file_json};
use super::artifact_files::{JavaScriptArtifactFile, JavaScriptArtifactFileKind, JavaScriptText};
use super::contracts::static_analysis::{ElectronFindings, ParseStatus, StaticAnalysis};
use super::graph::SemanticLimits;
use super::graph::json::{Json, Obj, parse};
use super::non_js;
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
        findings = findings.saturating_add(semantic.at("ir").at("moduleLinks").arr().len() as u64);
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
            .with("files", Json::Array(all_files))
            .with("packages", Json::Array(packages))
            .with("json_modules", Json::Array(json_modules))
            .with("html_scripts", Json::Array(html_scripts))
            .with("html_inline_scripts", Json::Array(html_inline_scripts))
            .with("source_maps", Json::Array(source_maps))
            .with("visited_ast_nodes", visited_ast_nodes as usize)
            .with("findings", findings as usize)
            .with("modules", modules as usize)
            .with("parse_failures", parse_failures as usize)
            .with(
                "limitations",
                Json::Array({
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
    let file_value = file_value(file);
    let Some(source) = (match (&file.kind, &file.text) {
        (JavaScriptArtifactFileKind::JavaScript, JavaScriptText::Included(source)) => {
            source.as_str().map(str::to_owned)
        }
        _ => None,
    }) else {
        return ControlFlow::Continue((
            Obj::new()
                .with("file", file_value)
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
    let (static_result_json, semantic_json, projection_json, semantic_failure) = match worker_result
    {
        Ok(response) => (
            response.static_analysis.get().to_owned(),
            response.semantic_ir.map(|value| value.get().to_owned()),
            response
                .semantic_projection
                .map(|value| value.get().to_owned()),
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
                        .with("file", file_value)
                        .with("javascript", static_analysis)
                        .with("semantic", Json::Null)
                        .with(
                            "analysis_failure",
                            Obj::new()
                                .with("scope", "analyze-javascript-source")
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
                    file_value,
                    &file.path,
                    &failure.to_string(),
                    worker_failure_limits(&failure),
                ),
                Some(interruption),
            ));
        }
    };
    checkpoint()?;
    let static_result = match serde_json::from_str::<StaticAnalysis>(&static_result_json) {
        Ok(value) => value,
        Err(error) => {
            let interruption = AnalysisInterruption::Failure(format!(
                "{}: worker static-analysis response was invalid: {error}",
                file.path
            ));
            return ControlFlow::Continue((
                analysis_failure_file(file_value, &file.path, interruption.message(), Json::Null),
                Some(interruption),
            ));
        }
    };

    if let Some(failure) = semantic_failure {
        let interruption = AnalysisInterruption::Failure(format!(
            "{}: {} semantic analysis failed: {}",
            file.path, failure.phase, failure.reason
        ));
        return ControlFlow::Continue((
            Obj::new()
                .with("file", file_value)
                .with("javascript", serialized(&static_result))
                .with("semantic", Json::Null)
                .with(
                    "analysis_failure",
                    Obj::new()
                        .with("scope", "analyze-javascript-source")
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
        Some(value) => match parse(&value) {
            Ok(value) => Some(value),
            Err(error) => {
                let interruption = AnalysisInterruption::Failure(format!(
                    "{}: worker semantic response was invalid: {error}",
                    file.path
                ));
                return ControlFlow::Continue((
                    analysis_failure_file(
                        file_value,
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
        Some(value) => match parse(&value) {
            Ok(value) => Some(value),
            Err(error) => {
                let interruption = AnalysisInterruption::Failure(format!(
                    "{}: worker semantic projection was invalid: {error}",
                    file.path
                ));
                return ControlFlow::Continue((
                    analysis_failure_file(
                        file_value,
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
        .with("file", file_value)
        .with("javascript", serialized(&static_result));
    if semantic.is_none() {
        result.set("semantic", Json::Null);
    } else {
        let mut semantic_value = Obj::new().with("ir", semantic.unwrap_or(Json::Null));
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
                .with("scope", "analyze-javascript-source")
                .with("status", "interrupted")
                .with("reason", format!("{path}: {reason}"))
                .with("error", Json::Null)
                .with("limits", limits),
        )
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
    let text = serde_json::to_string(value).expect("analysis contract is serializable");
    parse(&text).expect("analysis contract is valid JSON")
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
        Json::Array(file.limitations.iter().cloned().map(Json::from).collect()),
    );
    Obj::new()
        .with("file", metadata)
        .with("javascript", Json::Null)
        .with("semantic", Json::Null)
        .with(
            "analysis_failure",
            Obj::new()
                .with("scope", "analyze-javascript-source")
                .with("status", "not-started")
                .with("reason", file.limitations.join("; "))
                .with("error", Json::Null)
                .with("limits", Json::Null),
        )
        .into()
}

pub(crate) fn analyze_source_for_worker_with_checkpoint(
    source: &str,
    path: Option<&str>,
    node_budget: usize,
    unknown_budget: usize,
    metadata: Option<&super::worker::WorkerFileMetadata>,
    checkpoint: impl FnOnce(&serde_json::value::RawValue),
) -> super::worker::WorkerResponse {
    let static_result = analyze_source_for_static_analysis(source, path);
    let static_raw = serde_json::value::to_raw_value(&static_result)
        .expect("static analysis contract is serializable");
    checkpoint(&static_raw);

    // A syntax failure is already a complete static checkpoint. The
    // semantic parser cannot recover facts from a source that did not yield
    // an AST, and reporting that second parser failure would turn the
    // TypeScript workflow's successful partial file into an execution error.
    if static_result.parse_status == ParseStatus::Failed {
        return super::worker::WorkerResponse {
            static_analysis: static_raw,
            semantic_ir: None,
            semantic_projection: None,
            semantic_failure: None,
        };
    }

    let semantic_attempt =
        catch_unwind(AssertUnwindSafe(
            || match super::semantic::analysis::analyze_source(source, path) {
                Ok(ir) => {
                    let ir_json = serialized(&ir);
                    let paths = serialized(&static_result)
                        .at("electron")
                        .at("call_paths")
                        .arr()
                        .to_vec();
                    let file = metadata.map_or_else(
                        || Obj::new().with("path", path.unwrap_or("<source>")).into(),
                        |metadata| {
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
                        },
                    );
                    match super::graph::project_file(
                        &file,
                        &ir_json,
                        node_budget,
                        unknown_budget,
                        &paths,
                    ) {
                        Ok(value) => {
                            let projection =
                                serde_json::value::RawValue::from_string(value.canonical());
                            match projection {
                                Ok(projection) => match serde_json::value::to_raw_value(&ir) {
                                    Ok(ir) => (Some(ir), Some(projection), None),
                                    Err(error) => (
                                        None,
                                        None,
                                        Some(super::worker::WorkerSemanticFailure {
                                            phase: "serialize-ir".to_owned(),
                                            reason: error.to_string(),
                                        }),
                                    ),
                                },
                                Err(error) => (
                                    None,
                                    None,
                                    Some(super::worker::WorkerSemanticFailure {
                                        phase: "serialize-projection".to_owned(),
                                        reason: error.to_string(),
                                    }),
                                ),
                            }
                        }
                        Err(error) => (
                            None,
                            None,
                            Some(super::worker::WorkerSemanticFailure {
                                phase: "project-file".to_owned(),
                                reason: format!("{error:?}"),
                            }),
                        ),
                    }
                }
                Err(errors) => (
                    None,
                    None,
                    Some(super::worker::WorkerSemanticFailure {
                        phase: "analyze-source".to_owned(),
                        reason: format_diagnostics(&errors),
                    }),
                ),
            },
        ));
    let (semantic_ir, semantic_projection, semantic_failure) = match semantic_attempt {
        Ok(result) => result,
        Err(payload) => (
            None,
            None,
            Some(super::worker::WorkerSemanticFailure {
                phase: "semantic-pipeline-panic".to_owned(),
                reason: panic_reason(payload),
            }),
        ),
    };
    super::worker::WorkerResponse {
        static_analysis: static_raw,
        semantic_ir,
        semantic_projection,
        semantic_failure,
    }
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
