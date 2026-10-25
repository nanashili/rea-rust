//! Web trace adapters backed by the shared application readers.
//!
//! The adapter verifies and loads the selected local export when a caller uses
//! the public manifest-path form. Retained artifacts remain the preferred
//! Evidence path; an optional resolver batch is still supplied by the browser
//! adapter when live native resolution is available.
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation, SubjectTarget};
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const MODULE: &str = "trace_web_module_imports";
const SOURCE: &str = "trace_web_source_location";

pub(crate) fn register(registry: &mut Registry) {
    registry.handle(MODULE, |context, input| trace_module(context, input));
    registry.handle(SOURCE, |context, input| trace_source(context, input));
}

fn artifacts(
    input: &Value,
    operation: &str,
    cancellation: &Cancellation,
) -> Result<Value, AnalysisError> {
    match input.get("artifacts") {
        Some(value) => Ok(value.clone()),
        None => load_selected_artifacts(input, operation, cancellation),
    }
}

fn subject(result: &Value) -> Option<SubjectTarget> {
    let source = result.get("source")?;
    Some(SubjectTarget {
        path: source.get("path")?.as_str()?.to_owned(),
        sha256: source.get("sha256")?.as_str()?.to_owned(),
        format: "file".to_owned(),
        architecture: None,
    })
}

fn evidence(
    operation: &str,
    predicate: &str,
    provider_id: &str,
    provider_name: &str,
    input: Value,
    result: Value,
    raw: Option<Value>,
    subject: Option<SubjectTarget>,
) -> Result<Evidence, AnalysisError> {
    let limitations = result
        .get("limitations")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let mut locations = result
        .get("source")
        .and_then(|source| source.get("path"))
        .and_then(Value::as_str)
        .map(|path| vec![json!({ "kind": "artifact-path", "path": path })])
        .unwrap_or_default();
    if let Some(path) = result
        .get("manifest")
        .and_then(|manifest| manifest.get("path"))
        .and_then(Value::as_str)
    {
        locations.push(json!({ "kind": "artifact-path", "path": path }));
    }
    if let Some(path) = result
        .get("source_map")
        .and_then(|map| map.get("path"))
        .and_then(Value::as_str)
    {
        locations.push(json!({ "kind": "artifact-path", "path": path }));
    }
    let links = result
        .get("manifest")
        .and_then(|manifest| manifest.get("source_evidence_id"))
        .and_then(Value::as_str)
        .map(|id| vec![id.to_owned()])
        .unwrap_or_default();
    let provider = EvidenceProvider::new(provider_id, provider_name, Some("1".to_owned()));
    let mut observation = Observation::new(operation, input, result)
        .predicate(predicate)
        .confidence("derived")
        .authority("historical-reference")
        .limitations(limitations)
        .locations(locations)
        .links(links);
    if let Some(raw) = raw {
        observation = observation.raw(raw);
    }
    rea_mcp::support::evidence(subject.as_ref(), &provider, observation)
}

fn trace_module(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    if let Err(error) = context.check_cancelled() {
        return ToolOutput::Failure(error);
    }
    let artifacts = match artifacts(&input, MODULE, &context.cancellation) {
        Ok(value) => value,
        Err(error) => return ToolOutput::Failure(error),
    };
    let live_resolver = match live_resolver_batch(context, &input, &artifacts) {
        Ok(value) => value,
        Err(error) => return ToolOutput::Failure(error),
    };
    let raw_resolver = live_resolver
        .as_ref()
        .and_then(|value| value.get("raw_result"))
        .cloned()
        .or_else(|| {
            input
                .get("resolver_batch")
                .and_then(|value| value.get("raw_result"))
                .cloned()
        });
    let result = rea_application::web::module_trace::trace_with_artifacts(
        &input,
        &artifacts,
        live_resolver
            .as_ref()
            .or_else(|| input.get("resolver_batch")),
    )
    .map_err(AnalysisError::from)
    .and_then(|result| {
        let subject = subject(&result);
        evidence(
            MODULE,
            "rea.analysis",
            "rea-web-module-trace",
            "REA captured module relationship trace",
            input.clone(),
            result,
            raw_resolver,
            subject,
        )
    });
    match result {
        Ok(evidence) => ToolOutput::Evidence(evidence),
        Err(error) => ToolOutput::Failure(error),
    }
}

#[cfg(feature = "browser-scenario")]
fn live_resolver_batch(
    context: &ToolContext<'_>,
    input: &Value,
    artifacts: &Value,
) -> Result<Option<Value>, AnalysisError> {
    if input.get("resolver_batch").is_some()
        || context.session.env("REA_BROWSER_EXECUTABLE").is_none()
    {
        return Ok(None);
    }
    let Some(source) = artifacts.get("source").and_then(Value::as_str) else {
        return Ok(None);
    };
    let (imports, _, _) = rea_application::web::module_trace::collect_web_module_imports(source);
    let specifiers = imports
        .into_iter()
        .filter_map(|item| item.specifier)
        .collect::<Vec<_>>();
    let Some(importer) = input
        .get("importer_url")
        .and_then(Value::as_str)
        .or_else(|| {
            artifacts
                .pointer("/manifest/scripts")
                .and_then(Value::as_array)
                .and_then(|scripts| {
                    input
                        .get("script_index")
                        .and_then(Value::as_u64)
                        .and_then(|index| scripts.get(index as usize))
                        .and_then(|script| script.get("url"))
                        .and_then(Value::as_str)
                })
        })
    else {
        return Ok(None);
    };
    let import_map = artifacts.get("importMap");
    let Some(executable) = context.session.env("REA_BROWSER_EXECUTABLE") else {
        return Ok(None);
    };
    let environment = context
        .session
        .environment()
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    crate::browser_scenario::resolve_module(
        executable,
        &environment,
        importer,
        &specifiers,
        import_map.filter(|value| !value.is_null()),
        &context.cancellation,
    )
    .map(Some)
}

#[cfg(not(feature = "browser-scenario"))]
fn live_resolver_batch(
    _: &ToolContext<'_>,
    _: &Value,
    _: &Value,
) -> Result<Option<Value>, AnalysisError> {
    Ok(None)
}

fn trace_source(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    if let Err(error) = context.check_cancelled() {
        return ToolOutput::Failure(error);
    }
    let artifacts = match artifacts(&input, SOURCE, &context.cancellation) {
        Ok(value) => value,
        Err(error) => return ToolOutput::Failure(error),
    };
    let map = match load_source_map_text(&input, &context.cancellation) {
        Ok(map) => map,
        Err(error) => return ToolOutput::Failure(error),
    };
    let result = rea_application::web::capture_workflows::trace_web_source_location_with_evidence(
        &input, &map, &artifacts,
    )
    .map_err(AnalysisError::from)
    .and_then(|result| {
        let subject = subject(&result);
        evidence(
            SOURCE,
            "rea.analysis",
            "rea-web-source-location",
            "REA captured source-map point trace",
            input.clone(),
            result,
            Some(json!({"source_map_text": map})),
            subject,
        )
    });
    match result {
        Ok(evidence) => ToolOutput::Evidence(evidence),
        Err(error) => ToolOutput::Failure(error),
    }
}

fn load_source_map_text(
    input: &Value,
    cancellation: &Cancellation,
) -> Result<String, AnalysisError> {
    if let Some(text) = input.get("source_map_text").and_then(Value::as_str) {
        return Ok(text.to_owned());
    }

    let Some(path) = input.pointer("/source_map/path").and_then(Value::as_str) else {
        return Err(AnalysisError::input(
            SOURCE,
            vec![rea_core::analysis_error::InputIssue::new(
                &["source_map", "path"],
                "missing_required",
                "source_map.path is required",
            )],
        ));
    };
    let bytes = read_bounded(
        path,
        4 * 1024 * 1024,
        SOURCE,
        "source_map.path",
        cancellation,
    )?;
    String::from_utf8(bytes).map_err(|_| {
        AnalysisError::input(
            SOURCE,
            vec![rea_core::analysis_error::InputIssue::new(
                &["source_map", "path"],
                "invalid_value",
                "source map is not valid UTF-8",
            )],
        )
    })
}

/// Read the manifest-owned source files for direct CLI calls. MCP callers may
/// still provide retained artifacts from a prior Evidence operation; the
/// filesystem path is only a fallback for the CLI's selected manifest input.
fn load_selected_artifacts(
    input: &Value,
    operation: &str,
    cancellation: &Cancellation,
) -> Result<Value, AnalysisError> {
    let manifest_path = input
        .get("manifest_path")
        .and_then(Value::as_str)
        .ok_or_else(|| unavailable(operation, "manifest_path is required"))?;
    let manifest_bytes = read_bounded(
        manifest_path,
        32 * 1024 * 1024,
        operation,
        "manifest_path",
        cancellation,
    )?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes).map_err(|error| {
        invalid_input(
            operation,
            "manifest_path",
            format!("Manifest is not valid JSON: {error}"),
        )
    })?;
    let script_index = input
        .get("script_index")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            invalid_input(
                operation,
                "script_index",
                "script_index must be a non-negative integer",
            )
        })? as usize;
    let script = manifest
        .get("scripts")
        .and_then(Value::as_array)
        .and_then(|scripts| scripts.get(script_index))
        .ok_or_else(|| {
            invalid_input(
                operation,
                "script_index",
                "script_index is outside the manifest",
            )
        })?;
    let content = script
        .get("content")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            invalid_input(
                operation,
                "script_index",
                "selected script has invalid content",
            )
        })?;
    if content.get("state").and_then(Value::as_str) != Some("exported") {
        return Err(AnalysisError::capability_unavailable(
            "rea-web-static",
            operation,
            "selected_source_unavailable",
        ));
    }
    let relative = content
        .get("relative_path")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            invalid_input(
                operation,
                "script_index",
                "selected script has no relative source path",
            )
        })?;
    let root = Path::new(manifest_path).parent().ok_or_else(|| {
        invalid_input(
            operation,
            "manifest_path",
            "manifest has no parent directory",
        )
    })?;
    let source_path = contained_source_path(root, relative, operation)?;
    let source_bytes = read_bounded(
        source_path.to_string_lossy().as_ref(),
        16 * 1024 * 1024,
        operation,
        "manifest_path",
        cancellation,
    )?;
    let source_sha = digest(&source_bytes);
    let expected_sha = content
        .get("sha256")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let expected_bytes = content
        .get("bytes")
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX);
    if source_sha != expected_sha || source_bytes.len() as u64 != expected_bytes {
        return Err(AnalysisError::artifact_changed(
            operation,
            source_path.to_string_lossy(),
            "selected source bytes or digest differ from the manifest",
        ));
    }
    let source = String::from_utf8(source_bytes.clone()).map_err(|_| {
        invalid_input(
            operation,
            "manifest_path",
            "selected source is not valid UTF-8",
        )
    })?;
    let import_map = load_import_map(input, operation, cancellation)?;
    Ok(json!({
        "manifest": manifest,
        "manifestFile": {"path": manifest_path, "sha256": digest(&manifest_bytes), "bytes": manifest_bytes.len()},
        "sourceFile": {"path": source_path.to_string_lossy(), "sha256": source_sha, "bytes": source.len()},
        "source": source,
        "importMap": import_map,
    }))
}

fn load_import_map(
    input: &Value,
    operation: &str,
    cancellation: &Cancellation,
) -> Result<Value, AnalysisError> {
    let Some(selection) = input.get("import_map") else {
        return Ok(Value::Null);
    };
    let path = selection
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            invalid_input(
                operation,
                "import_map.path",
                "import_map.path must be a string",
            )
        })?;
    let base_url = selection
        .get("base_url")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            invalid_input(
                operation,
                "import_map.base_url",
                "import_map.base_url must be a string",
            )
        })?;
    let bytes = read_bounded(
        path,
        4 * 1024 * 1024,
        operation,
        "import_map.path",
        cancellation,
    )?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        invalid_input(
            operation,
            "import_map.path",
            format!("Import map is not valid JSON: {error}"),
        )
    })?;
    Ok(json!({
        "file": {"path": path, "sha256": digest(&bytes), "bytes": bytes.len()},
        "baseUrl": base_url,
        "value": value,
    }))
}

fn contained_source_path(
    root: &Path,
    relative: &str,
    operation: &str,
) -> Result<PathBuf, AnalysisError> {
    if relative.is_empty()
        || Path::new(relative).is_absolute()
        || relative.split('/').any(|part| part == "..")
    {
        return Err(invalid_input(
            operation,
            "manifest_path",
            "selected source path escapes the manifest directory",
        ));
    }
    let path = root.join("files").join(relative);
    let canonical_root = std::fs::canonicalize(root).map_err(|_| {
        invalid_input(
            operation,
            "manifest_path",
            "manifest directory is unavailable",
        )
    })?;
    let canonical_path = std::fs::canonicalize(&path).map_err(|_| {
        invalid_input(
            operation,
            "manifest_path",
            "selected source file is unavailable",
        )
    })?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err(invalid_input(
            operation,
            "manifest_path",
            "selected source path escapes the manifest directory",
        ));
    }
    // Preserve the selected export's lexical path in Evidence. The canonical
    // path above is used only for containment, matching the TypeScript reader's
    // sourceFile identity while still rejecting symlink escapes.
    Ok(path)
}

fn read_bounded(
    path: &str,
    limit: usize,
    operation: &str,
    field: &str,
    cancellation: &Cancellation,
) -> Result<Vec<u8>, AnalysisError> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        invalid_input(operation, field, format!("Unable to read {path}: {error}"))
    })?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(invalid_input(
            operation,
            field,
            format!("Selected file is not a regular file within the {limit}-byte limit"),
        ));
    }
    let bytes = std::fs::read(path).map_err(|error| {
        invalid_input(operation, field, format!("Unable to read {path}: {error}"))
    })?;
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(operation));
    }
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn invalid_input(operation: &str, field: &str, message: impl Into<String>) -> AnalysisError {
    AnalysisError::input(
        operation,
        vec![rea_core::analysis_error::InputIssue::new(
            &[field],
            "invalid_value",
            message,
        )],
    )
}

fn unavailable(operation: &str, message: &str) -> AnalysisError {
    AnalysisError::capability_unavailable("rea-web-static", operation, message)
}
