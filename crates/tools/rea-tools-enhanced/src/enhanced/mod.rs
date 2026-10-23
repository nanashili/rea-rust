//! Enhanced binary workflows composed from provider operations.
//!
//! Compatibility owners: `executeEnhancedTool` / `executeFunctionTool`
//! (`server/registerEnhancedTools.ts`) and `EnhancedTools.executeValidated`
//! (`application/EnhancedTools.ts`).
pub mod batch;
pub mod call_path;
pub mod dispatch;
pub mod function;
pub mod graph;
pub mod literal;
pub mod overview;
pub mod symbols;

use crate::analysis::{Analysis, ProgressSink};
use crate::workflow::{create_workflow_evidence, record_workflow_unknowns};
use rea_core::analysis_error::AnalysisError;
use rea_mcp::{ToolContext, ToolOutput};
use rea_tools_binary::port::{
    AnalysisPort, WorkflowSnapshot, active_target, allows_snapshot_replay, analysis_profile,
    record_workflow_snapshot, with_admitted_analysis,
};
use serde_json::{Map, Value};

/// Every enhanced tool bound by this family.
pub const TOOLS: [&str; 14] = [
    "trace_native_values",
    "inspect_native_dispatch_metadata",
    "get_objc_classes",
    "get_objc_protocols",
    "batch_decompile",
    "get_call_graph",
    "analyze_swift_types",
    "find_xrefs_to_name",
    "binary_overview",
    "analyze_function",
    "inspect_native_api",
    "trace_feature",
    "trace_call_path",
    "trace_native_ui_action",
];

/// `jsonParameters` in the parsed input's shape order.
pub fn ordered_parameters(context: &ToolContext<'_>, input: &Value) -> Map<String, Value> {
    let empty = Map::new();
    let input = input.as_object().unwrap_or(&empty);
    let mut ordered = Map::new();
    if let Some(properties) = context
        .contract
        .input_schema()
        .get("properties")
        .and_then(Value::as_object)
    {
        for key in properties.keys() {
            if let Some(value) = input.get(key) {
                ordered.insert(key.clone(), value.clone());
            }
        }
    }
    for (key, value) in input {
        if !ordered.contains_key(key) {
            ordered.insert(key.clone(), value.clone());
        }
    }
    ordered
}

fn text<'a>(input: &'a Map<String, Value>, key: &str) -> &'a str {
    input.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn optional_text<'a>(input: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    input.get(key).and_then(Value::as_str)
}

/// `EnhancedTools.executeValidated` for one composed workflow.
fn dispatch(
    analysis: &Analysis<'_>,
    name: &str,
    input: &Map<String, Value>,
) -> Result<Value, AnalysisError> {
    match name {
        "inspect_native_dispatch_metadata" => dispatch::inspect(
            analysis,
            input
                .get("max_records")
                .and_then(Value::as_u64)
                .unwrap_or(5_000),
        ),
        "get_objc_classes" => symbols::objc_classes(analysis, text(input, "pattern")),
        "get_objc_protocols" => symbols::objc_protocols(analysis),
        "batch_decompile" => {
            let addresses = input
                .get("addresses")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>();
            batch::batch_decompile(analysis, &addresses)
        }
        "get_call_graph" => graph::call_graph(
            analysis,
            text(input, "address"),
            optional_text(input, "direction").unwrap_or("forward"),
        ),
        "analyze_swift_types" => symbols::analyze_swift_types(
            analysis,
            optional_text(input, "category"),
            optional_text(input, "pattern"),
        ),
        "find_xrefs_to_name" => symbols::find_xrefs(analysis, text(input, "name")),
        "binary_overview" => overview::binary_overview(analysis),
        "inspect_native_api" => function::inspect_native_api(analysis, text(input, "procedure")),
        "trace_feature" => literal::trace_literal_feature(
            analysis,
            text(input, "query"),
            input
                .get("case_sensitive")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        ),
        "trace_call_path" => call_path::trace_call_path(
            analysis,
            text(input, "start"),
            optional_text(input, "goal"),
            optional_text(input, "direction").unwrap_or("forward"),
        ),
        "trace_native_values" => {
            crate::native::value_trace::trace_native_values(analysis, &Value::Object(input.clone()))
        }
        "trace_native_ui_action" => crate::native::ui_action::trace_native_ui_action(
            analysis,
            &Value::Object(input.clone()),
        ),
        other => Err(AnalysisError::capability_unavailable(
            "rea",
            other,
            "This operation is not available in the native runtime build.",
        )),
    }
}

/// Retain a successful composed result: Evidence, replay binding, unknowns.
fn finish_workflow(
    context: &ToolContext<'_>,
    name: &str,
    parameters: Map<String, Value>,
    result: Value,
    limitations: Vec<String>,
) -> ToolOutput {
    let session = context.session;
    let target = active_target(session);
    let upstream = analysis_profile(session, None);
    let evidence = match create_workflow_evidence(
        target.as_ref(),
        name,
        Value::Object(parameters),
        result.clone(),
        upstream.as_ref(),
        limitations,
    ) {
        Ok(evidence) => evidence,
        Err(error) => return ToolOutput::Failure(error),
    };
    if let Err(error) = session.record(&evidence) {
        return ToolOutput::Failure(error);
    }
    if name != "trace_native_ui_action"
        && allows_snapshot_replay(session, name)
        && !evidence.value()["analysis_profile"].is_null()
    {
        let snapshot = WorkflowSnapshot {
            operation: name.to_owned(),
            parameters: evidence.value()["parameters"].clone(),
            evidence: evidence.value().clone(),
        };
        if let Err(error) = record_workflow_snapshot(session, snapshot) {
            return ToolOutput::Failure(error);
        }
    }
    if let Err(error) = record_workflow_unknowns(session, name, &result, evidence.id()) {
        return ToolOutput::Failure(error);
    }
    ToolOutput::Evidence(evidence)
}

/// One admitted enhanced tool call.
fn admitted(context: &ToolContext<'_>, port: &dyn AnalysisPort, input: &Value) -> ToolOutput {
    let name = context.name_static();
    let progress = ProgressSink::new(context.progress.clone());
    progress.report(name, "started", false);
    let parameters = ordered_parameters(context, input);
    if name == "analyze_function" {
        return function::execute_function_tool(context, port, &parameters);
    }
    let analysis = Analysis::new(
        port,
        context.cancellation.clone(),
        Some(progress.provider_callback()),
    );
    let result = dispatch(&analysis, name, &parameters);
    progress.report(
        name,
        if result.is_ok() {
            "completed"
        } else {
            "failed"
        },
        true,
    );
    match result {
        Ok(value) => finish_workflow(
            context,
            name,
            parameters,
            value,
            analysis.source_limitations(),
        ),
        Err(error) => ToolOutput::Failure(error),
    }
}

/// Handler shared by every enhanced tool.
pub fn execute(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    match with_admitted_analysis(
        context.session,
        context.name(),
        &context.cancellation,
        |port| admitted(context, port, &input),
    ) {
        Ok(output) => output,
        Err(error) => ToolOutput::Failure(error),
    }
}
