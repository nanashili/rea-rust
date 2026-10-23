//! Typed dispatch for offline web and JavaScript workflows.
//!
//! This adapter accepts caller-selected local artifacts and inline retained
//! Evidence. It never connects to a browser, executes JavaScript, or fetches a
//! source map. Filesystem publication is delegated to the application owner so
//! the runtime cannot silently acquire capture or publication semantics.

use rea_application::{javascript, web};
use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Offline web operations understood by this adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebStaticOperation {
    AnalyzeBundle,
    ExportScripts,
    CompareSourceToBundle,
    TraceModuleImports,
    TraceSourceLocation,
    RecoverSources,
    CompareExportShapes,
    CompareApplicationVersions,
}

impl WebStaticOperation {
    /// Parse the public operation name used by MCP and CLI callers.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            web::bundle_analysis::OPERATION => Ok(Self::AnalyzeBundle),
            web::script_export::OPERATION => Ok(Self::ExportScripts),
            javascript::source_comparison::OPERATION => Ok(Self::CompareSourceToBundle),
            web::module_trace::OPERATION => Ok(Self::TraceModuleImports),
            web::source_location::OPERATION => Ok(Self::TraceSourceLocation),
            "recover_javascript_sources" => Ok(Self::RecoverSources),
            javascript::export_comparison::OPERATION => Ok(Self::CompareExportShapes),
            javascript::version_comparison::OPERATION => Ok(Self::CompareApplicationVersions),
            _ => Err(unknown_operation(name)),
        }
    }

    /// Return the stable public operation name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::AnalyzeBundle => web::bundle_analysis::OPERATION,
            Self::ExportScripts => web::script_export::OPERATION,
            Self::CompareSourceToBundle => javascript::source_comparison::OPERATION,
            Self::TraceModuleImports => web::module_trace::OPERATION,
            Self::TraceSourceLocation => web::source_location::OPERATION,
            Self::RecoverSources => "recover_javascript_sources",
            Self::CompareExportShapes => javascript::export_comparison::OPERATION,
            Self::CompareApplicationVersions => javascript::version_comparison::OPERATION,
        }
    }
}

/// Dispatch one offline web operation.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = WebStaticOperation::parse(operation)?;
    dispatch_typed(operation, &input)
}

/// Dispatch an already-parsed operation without acquiring external state.
pub fn dispatch_typed(operation: WebStaticOperation, input: &Value) -> Result<Value, Failure> {
    match operation {
        WebStaticOperation::AnalyzeBundle => {
            web::bundle_analysis::validate_input(input)?;
            Err(provider_owned(operation, "bundle capture and analysis"))
        }
        WebStaticOperation::ExportScripts => export_scripts(input),
        WebStaticOperation::CompareSourceToBundle => javascript::source_comparison::compare(input),
        WebStaticOperation::TraceModuleImports => trace_module_imports(input),
        WebStaticOperation::TraceSourceLocation => trace_source_location(input),
        WebStaticOperation::RecoverSources => {
            Err(provider_owned(operation, "JavaScript source recovery"))
        }
        WebStaticOperation::CompareExportShapes => {
            javascript::export_comparison::compare_javascript_export_shapes(input)
        }
        WebStaticOperation::CompareApplicationVersions => compare_versions(input),
    }
}

fn export_scripts(input: &Value) -> Result<Value, Failure> {
    web::script_export::export_capture(input)
}

fn trace_module_imports(input: &Value) -> Result<Value, Failure> {
    web::module_trace::validate_input(input)?;
    if let Some(artifacts) = input.get("artifacts") {
        return web::module_trace::trace_with_artifacts(
            input,
            artifacts,
            input.get("resolver_batch"),
        );
    }
    let source = input
        .get("source")
        .and_then(Value::as_str)
        .ok_or_else(|| missing_artifact("source"))?;
    let (imports, analysis_status, diagnostics) =
        web::module_trace::collect_web_module_imports(source);
    let imports = imports
        .into_iter()
        .map(|item| {
            json!({
                "kind": item.kind,
                "specifier": item.specifier,
                "expression": item.expression,
                "start": {
                    "offset": item.start.offset,
                    "line": item.start.line,
                    "column": item.start.column,
                },
                "end": {
                    "offset": item.end.offset,
                    "line": item.end.line,
                    "column": item.end.column,
                },
            })
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "manifest_path": input["manifest_path"],
        "script_index": input["script_index"],
        "imports": imports,
        "analysis_status": analysis_status,
        "diagnostics": diagnostics,
        "execution": "not-performed",
        "limitations": [
            "Computed imports and runtime loader behavior remain unknown.",
            "The supplied source is analyzed as inert text.",
        ],
    }))
}

fn trace_source_location(input: &Value) -> Result<Value, Failure> {
    web::source_location::validate_input(input)?;
    let source_map = input
        .get("source_map_text")
        .and_then(Value::as_str)
        .ok_or_else(|| missing_artifact("source_map_text"))?;

    if let Some(artifacts) = input.get("artifacts") {
        return rea_application::web::capture_workflows::trace_web_source_location_with_evidence(
            input, source_map, artifacts,
        );
    }

    web::source_location::trace_web_source_location(input, source_map)
}

fn compare_versions(input: &Value) -> Result<Value, Failure> {
    let raw = javascript::version_comparison::compare(input, None)?;
    serde_json::from_str(raw.get()).map_err(|error| invalid_result(error.to_string()))
}

fn provider_owned(operation: WebStaticOperation, owner: &str) -> Failure {
    Failure::new(
        "unsupported_request",
        "unsupported_request",
        format!(
            "{} remains owned by the browser or filesystem provider and is not an offline retained-facts operation",
            owner
        ),
        false,
        "Supply the provider-produced artifact or route this operation through its owning adapter."
            .into(),
        BTreeMap::from([
            ("operation", Detail::Text(operation.name().into())),
            ("execution", Detail::Text("not-performed".into())),
        ]),
    )
}

fn missing_artifact(field: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("explicit artifact field {field} is required"),
        false,
        "Provide the selected artifact bytes or retained Evidence inline; no browser or provider access is performed."
            .into(),
        BTreeMap::new(),
    )
}

fn invalid_result(reason: String) -> Failure {
    Failure::new(
        "invalid_result",
        "invalid_result",
        format!("version comparison result is not valid JSON: {reason}"),
        false,
        "Retry with authenticated inline application Evidence.".into(),
        BTreeMap::new(),
    )
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        format!("web static operation is unknown: {name}"),
        false,
        "Select one of the supported offline web operations.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(name.into()))]),
    )
}
