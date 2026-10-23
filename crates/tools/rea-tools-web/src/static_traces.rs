//! Offline web trace adapters backed by the shared application readers.
//!
//! These handlers intentionally accept retained artifact facts only. Live CDP
//! resolution remains owned by the future browser adapter; a request without
//! the required captured artifacts fails explicitly.
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation, SubjectTarget};
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Value, json};

const MODULE: &str = "trace_web_module_imports";
const SOURCE: &str = "trace_web_source_location";

pub(crate) fn register(registry: &mut Registry) {
    registry.handle(MODULE, |context, input| trace_module(context, input));
    registry.handle(SOURCE, |context, input| trace_source(context, input));
}

fn artifacts<'a>(input: &'a Value, operation: &str) -> Result<&'a Value, AnalysisError> {
    input.get("artifacts").ok_or_else(|| {
        AnalysisError::capability_unavailable(
            "rea-web-static",
            operation,
            "The native static web trace requires captured manifest and source artifacts; live browser resolution is not available in this build.",
        )
    })
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
    let locations = result
        .get("source")
        .and_then(|source| source.get("path"))
        .and_then(Value::as_str)
        .map(|path| vec![json!({ "kind": "artifact-path", "path": path })])
        .unwrap_or_default();
    let provider = EvidenceProvider::new("rea-web-static", provider_name, Some("1".to_owned()));
    let mut observation = Observation::new(operation, input, result)
        .predicate(predicate)
        .confidence("derived")
        .authority("historical-reference")
        .limitations(limitations)
        .locations(locations);
    if let Some(raw) = raw {
        observation = observation.raw(raw);
    }
    rea_mcp::support::evidence(subject.as_ref(), &provider, observation)
}

fn trace_module(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    if let Err(error) = context.check_cancelled() {
        return ToolOutput::Failure(error);
    }
    let artifacts = match artifacts(&input, MODULE) {
        Ok(value) => value,
        Err(error) => return ToolOutput::Failure(error),
    };
    let result = rea_application::web::module_trace::trace_with_artifacts(
        &input,
        artifacts,
        input.get("resolver_batch"),
    )
    .map_err(AnalysisError::from)
    .and_then(|result| {
        let subject = subject(&result);
        evidence(
            MODULE,
            "rea.web-module-trace",
            "REA captured module relationship trace",
            input.clone(),
            result,
            None,
            subject,
        )
    });
    match result {
        Ok(evidence) => ToolOutput::Evidence(evidence),
        Err(error) => ToolOutput::Failure(error),
    }
}

fn trace_source(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    if let Err(error) = context.check_cancelled() {
        return ToolOutput::Failure(error);
    }
    let artifacts = match artifacts(&input, SOURCE) {
        Ok(value) => value,
        Err(error) => return ToolOutput::Failure(error),
    };
    let map = input
        .get("source_map_text")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let result = rea_application::web::capture_workflows::trace_web_source_location_with_evidence(
        &input, map, artifacts,
    )
    .map_err(AnalysisError::from)
    .and_then(|result| {
        let subject = subject(&result);
        evidence(
            SOURCE,
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
