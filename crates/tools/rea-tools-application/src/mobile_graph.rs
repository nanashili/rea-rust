//! Execution-free mobile application inventory projection tools.
//!
//! Compatibility owner:
//! `src/server/registerApplicationTools/projectMobileApplicationGraph.ts`.
use rea_application::javascript::graph::json::{self, Json};
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::evidence::record::EvidenceRecord;
use rea_core::failure::Failure;
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Value, value::RawValue};

const ANDROID_OPERATION: &str = "project_android_application_graph";
const APPLE_OPERATION: &str = "project_apple_application_graph";
const HARMONY_OPERATION: &str = "project_harmony_application_graph";

pub fn register(registry: &mut Registry) {
    register_one(registry, ANDROID_OPERATION);
    register_one(registry, APPLE_OPERATION);
    register_one(registry, HARMONY_OPERATION);
}

fn register_one(registry: &mut Registry, operation: &'static str) {
    registry.handle_application_validated(operation, move |context, input| {
        ordinary_output(context, operation, input)
    });
    registry.handle_raw_application_validated(operation, move |context, input| {
        raw_output(context, operation, input)
    });
}

fn ordinary_output(context: &ToolContext<'_>, operation: &str, input: Value) -> ToolOutput {
    let raw = match serde_json::to_string(&input) {
        Ok(raw) => raw,
        Err(error) => return ToolOutput::Failure(input_error(operation, error.to_string())),
    };
    let raw = match RawValue::from_string(raw) {
        Ok(raw) => raw,
        Err(error) => return ToolOutput::Failure(input_error(operation, error.to_string())),
    };
    raw_output(context, operation, &raw)
}

fn raw_output(context: &ToolContext<'_>, operation: &str, input: &RawValue) -> ToolOutput {
    if let Err(error) = context.check_cancelled() {
        return ToolOutput::Failure(error);
    }
    let graph_input = match json::parse(input.get()) {
        Ok(input) => input,
        Err(error) => return ToolOutput::Failure(input_error(operation, error.to_string())),
    };
    project_and_record_sources(context, operation, &graph_input)
}

fn project_and_record_sources(
    context: &ToolContext<'_>,
    operation: &str,
    graph_input: &Json,
) -> ToolOutput {
    let validation = match operation {
        ANDROID_OPERATION => {
            rea_application::android::application_graph::validate_input(graph_input)
        }
        APPLE_OPERATION => rea_application::apple::application_graph::validate_input(graph_input),
        HARMONY_OPERATION => {
            rea_application::harmony::application_graph::validate_input(graph_input)
        }
        _ => return ToolOutput::Failure(input_error(operation, "unknown mobile graph operation")),
    };
    if let Err(error) = validation {
        return failure_output(error);
    }
    let evidence = match operation {
        ANDROID_OPERATION => {
            rea_application::android::application_graph::project_evidence(&graph_input)
        }
        APPLE_OPERATION => {
            rea_application::apple::application_graph::project_evidence(&graph_input)
        }
        HARMONY_OPERATION => {
            rea_application::harmony::application_graph::project_evidence(&graph_input)
        }
        _ => return ToolOutput::Failure(input_error(operation, "unknown mobile graph operation")),
    };
    let raw = match evidence {
        Ok(raw) => raw,
        Err(error) => return failure_output(error),
    };
    let record = match EvidenceRecord::parse(&raw) {
        Ok(record) => record,
        Err(error) => {
            return ToolOutput::Failure(AnalysisError::evidence_integrity(error.to_string()));
        }
    };
    if let Err(error) = context.check_cancelled() {
        return ToolOutput::Failure(error);
    }
    let sources = match source_records(operation, graph_input) {
        Ok(sources) => sources,
        Err(error) => return ToolOutput::Failure(error),
    };
    for source in sources {
        if let Err(error) = context.session.record_raw(&source) {
            return ToolOutput::Failure(error);
        }
    }
    if let Err(error) = context.check_cancelled() {
        return ToolOutput::Failure(error);
    }
    ToolOutput::RawEvidence(record)
}

fn failure_output(failure: Failure) -> ToolOutput {
    let operation = failure.operation().unwrap_or("mobile_graph").to_owned();
    let message = failure.to_string();
    ToolOutput::Failure(AnalysisError::input(
        operation,
        vec![InputIssue {
            path: Vec::new(),
            reason: "invalid_value",
            message: Some(message),
            expected: None,
            minimum: None,
            maximum: None,
        }],
    ))
}

fn source_records(
    operation: &str,
    graph_input: &Json,
) -> Result<Vec<Box<RawValue>>, AnalysisError> {
    let values = graph_input
        .get("inventory_evidence")
        .and_then(Json::as_array)
        .ok_or_else(|| input_error(operation, "inventory_evidence must be an array"))?;
    values
        .iter()
        .map(|source| {
            RawValue::from_string(source.stringify())
                .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))
        })
        .collect()
}

fn input_error(operation: &str, message: impl Into<String>) -> AnalysisError {
    AnalysisError::input_message(operation, message.into(), Vec::new())
}
