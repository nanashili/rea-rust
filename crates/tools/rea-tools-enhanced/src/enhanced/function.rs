//! Function dossiers and native API boundary inspection.
//!
//! Compatibility owners: `executeFunctionAnalysisEvidence`
//! (`FunctionAnalysisEvidence.ts`), `executeFunctionTool`
//! (`registerEnhancedTools.ts`), `#inspectNativeApi` (`EnhancedTools.ts`) and
//! `projectNativeApiInspection` (`native/NativeApiInspection.ts`).
use crate::analysis::{Analysis, ProgressSink, params};
use crate::domain::dossier::{native_api_inspection_result, parse_function_dossier};
use rea_analysis::ExecutionOptions;
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, Observation};
use rea_mcp::{ToolContext, ToolOutput};
use rea_tools_binary::port::AnalysisPort;
use serde_json::{Map, Value, json};

/// `executeFunctionAnalysisEvidence`: the provider's own observation of a
/// validated dossier.
fn function_analysis_evidence(
    context: &ToolContext<'_>,
    port: &dyn AnalysisPort,
    arguments: &Map<String, Value>,
    progress: &ProgressSink,
) -> Result<Evidence, AnalysisError> {
    let mut options = ExecutionOptions::new(context.cancellation.clone());
    options.progress = Some(progress.provider_callback());
    let execution = port.execute("analyze_function", arguments, &options)?;
    let dossier = parse_function_dossier(&execution.result)?;
    let target = rea_tools_binary::port::active_target(context.session);
    let subject = execution
        .subject
        .clone()
        .or_else(|| target.as_ref().map(rea_analysis::BinaryTarget::subject));
    let mut observation = Observation::new(
        "analyze_function",
        Value::Object(arguments.clone()),
        dossier,
    )
    .limitations(execution.limitations.clone())
    .locations(execution.locations.clone());
    if let Some(raw) = &execution.raw_result {
        observation = observation.raw(raw.clone());
    }
    if let Some(coverage) = &execution.relationship_coverage {
        observation = observation.coverage(coverage.clone());
    }
    if let Some(profile) = &execution.analysis_profile {
        observation = observation.profile(profile.clone());
    }
    Evidence::create(
        subject.as_ref(),
        &execution.provider.evidence_provider(),
        observation,
    )
    .map_err(|error| AnalysisError::output("analyze_function", error.to_string()))
}

/// `executeFunctionTool`: deliver the provider dossier Evidence.
pub fn execute_function_tool(
    context: &ToolContext<'_>,
    port: &dyn AnalysisPort,
    parameters: &Map<String, Value>,
) -> ToolOutput {
    let progress = ProgressSink::new(context.progress.clone());
    let arguments = params([(
        "procedure",
        parameters.get("procedure").cloned().unwrap_or(Value::Null),
    )]);
    let result = function_analysis_evidence(context, port, &arguments, &progress);
    progress.report(
        "analyze_function",
        if result.is_ok() {
            "completed"
        } else {
            "failed"
        },
        true,
    );
    match result {
        Ok(evidence) => match context.session.record(&evidence) {
            Ok(()) => ToolOutput::Evidence(evidence),
            Err(error) => ToolOutput::Failure(error),
        },
        Err(error) => ToolOutput::Failure(error),
    }
}

fn unavailable_boundary() -> Value {
    json!({
        "available": false,
        "reason": "The selected provider did not expose a structured native API boundary model.",
        "residual_unknowns": [
            "What are the function's return and parameter boundary types?",
            "Does this function dispatch through a jump table with recoverable data addresses?",
        ],
    })
}

/// `availableResidualUnknowns`.
fn available_residual_unknowns(boundary: &Value) -> Vec<String> {
    let mut unknowns: Vec<String> = Vec::new();
    for table in boundary["jump_tables"].as_array().into_iter().flatten() {
        let dispatch = table["dispatch_address"].as_str().unwrap_or_default();
        let empty = |key: &str| table[key].as_array().is_none_or(Vec::is_empty);
        if empty("default_targets") {
            unknowns.push(format!(
                "Which default or out-of-range path, if any, belongs to the dispatch at {dispatch}?"
            ));
        }
        if empty("mappings") {
            unknowns.push(format!(
                "Which case values and targets belong to the dispatch at {dispatch}?"
            ));
        }
        if empty("data_sources") {
            unknowns.push(format!(
                "What backing data address produced the jump table dispatched at {dispatch}?"
            ));
        }
        if table["data_sources"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|source| source["entry_count"].is_null() || source["entry_size_bytes"].is_null())
        {
            unknowns.push(format!(
                "What are the exact entry size and count for candidate jump-table data dispatched at {dispatch}?"
            ));
        }
        if table["mappings"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|mapping| mapping["case_value"].is_null())
        {
            unknowns.push(format!(
                "Which source-level case values correspond to every target dispatched at {dispatch}?"
            ));
        }
    }
    let values = std::iter::once(&boundary["return_type"])
        .chain(boundary["parameters"].as_array().into_iter().flatten());
    for value in values {
        if value["confidence"] == "low" {
            unknowns.push(format!(
                "Can the inferred {} type {} be confirmed with imported metadata or an ABI probe?",
                value["role"].as_str().unwrap_or_default(),
                value["data_type"].as_str().unwrap_or_default()
            ));
        }
    }
    crate::js::unique_in_order(unknowns)
}

/// `projectNativeApiInspection`.
pub fn project_native_api_inspection(dossier: &Value) -> Result<Value, AnalysisError> {
    let boundary = match &dossier["native_api"] {
        Value::Null => unavailable_boundary(),
        boundary => boundary.clone(),
    };
    let available = boundary["available"] == Value::Bool(true);
    let unsupported_branches: Vec<&str> = if available {
        Vec::new()
    } else {
        vec!["structured-boundary-types", "jump-table-data-mapping"]
    };
    let residual_unknowns: Vec<Value> = if available {
        available_residual_unknowns(&boundary)
            .into_iter()
            .map(Value::String)
            .collect()
    } else {
        boundary["residual_unknowns"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    };
    let projection_observations = if available {
        json!([
            "return and parameter boundary types",
            "confidence and inference evidence",
            "jump-table dispatch, data, and target addresses",
        ])
    } else {
        json!([boundary["reason"]])
    };
    let preserved = if residual_unknowns.is_empty() {
        json!(["no additional structured-boundary unknowns"])
    } else {
        Value::Array(residual_unknowns.clone())
    };
    let inspection = json!({
        "procedure": {
            "address": dossier["procedure"]["address"],
            "name": dossier["procedure"]["name"],
        },
        "boundary": boundary,
        "substeps": [
            {
                "operation": "analyze_function",
                "status": "completed",
                "observations": [
                    "provider function dossier",
                    "provider pseudocode classification",
                    "provider control-flow observations",
                ],
            },
            {
                "operation": "project_native_api_boundary",
                "status": if available { "completed" } else { "unsupported" },
                "observations": projection_observations,
            },
            {
                "operation": "preserve_residual_unknowns",
                "status": "completed",
                "observations": preserved,
            },
        ],
        "unsupported_branches": unsupported_branches,
        "residual_unknowns": residual_unknowns,
    });
    native_api_inspection_result()
        .parse(&inspection)
        .map_err(|issue| {
            AnalysisError::output(
                "inspect_native_api",
                format!(
                    "function dossier does not satisfy the native API inspection contract: {issue}"
                ),
            )
        })
}

/// `#inspectNativeApi`.
pub fn inspect_native_api(
    analysis: &Analysis<'_>,
    procedure: &str,
) -> Result<Value, AnalysisError> {
    let result = analysis.call(
        "analyze_function",
        &params([("procedure", json!(procedure))]),
        false,
    )?;
    let dossier = parse_function_dossier(&result)?;
    project_native_api_inspection(&dossier)
}
