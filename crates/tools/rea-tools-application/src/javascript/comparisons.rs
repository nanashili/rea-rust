//! JavaScript application comparison tools backed by the shared application
//! workflow implementations.
use super::{graph_evidence, workflow_evidence};
use crate::support;
use rea_core::analysis_error::AnalysisError;
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::Value;

pub(crate) fn register(registry: &mut Registry) {
    registry.handle("compare_application_versions", |context, input| {
        compare_versions(context, input)
    });
    registry.handle("compare_source_to_bundle", |context, input| {
        compare_source_to_bundle(context, input)
    });
    registry.handle("compare_javascript_export_shapes", |context, input| {
        compare_export_shapes(context, input)
    });
}

fn resolve_field(
    context: &ToolContext<'_>,
    input: &Value,
    key: &str,
) -> Result<Value, AnalysisError> {
    graph_evidence::resolve_evidence_input(context, input.get(key).unwrap_or(&Value::Null))
}

fn resolved_input(
    context: &ToolContext<'_>,
    input: &Value,
    fields: &[&str],
) -> Result<Value, AnalysisError> {
    let mut object = input.as_object().cloned().unwrap_or_default();
    for field in fields {
        object.insert((*field).to_owned(), resolve_field(context, input, field)?);
    }
    Ok(Value::Object(object))
}

fn evidence_from_raw(
    raw: Box<serde_json::value::RawValue>,
) -> Result<rea_core::evidence::envelope::Evidence, AnalysisError> {
    let value: Value = serde_json::from_str(raw.get())
        .map_err(|error| AnalysisError::output("javascript_comparison", error.to_string()))?;
    rea_mcp::support::adopt_evidence(value)
}

fn has_unknown(evidence: &rea_core::evidence::envelope::Evidence) -> bool {
    let result = &evidence.value()["normalized_result"];
    result["summary"]["unknown"].as_u64().unwrap_or(0) > 0
        || result["coverage"]["status"] == "partial"
        || result["coverage"]["status"] == "truncated"
}

fn unknown(
    kind: &'static str,
) -> impl FnOnce(&rea_core::evidence::envelope::Evidence) -> Option<Value> {
    move |evidence| has_unknown(evidence).then(|| support::comparison_unknown(evidence, kind))
}

fn compare_versions(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let input = match resolved_input(context, &input, &["left", "right"]) {
        Ok(input) => input,
        Err(error) => return ToolOutput::Failure(error),
    };
    let native = |key: &str| -> Result<Vec<Value>, AnalysisError> {
        input
            .get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| graph_evidence::resolve_evidence_input(context, item))
                    .collect::<Result<Vec<_>, _>>()
            })
            .unwrap_or_else(|| Ok(Vec::new()))
    };
    let left_native = match native("left_native_observations") {
        Ok(value) => value,
        Err(error) => return ToolOutput::Failure(error),
    };
    let right_native = match native("right_native_observations") {
        Ok(value) => value,
        Err(error) => return ToolOutput::Failure(error),
    };
    let mut input = input;
    input["left_native_observations"] = Value::Array(left_native.clone());
    input["right_native_observations"] = Value::Array(right_native.clone());
    let left = input["left"].clone();
    let right = input["right"].clone();
    let result = rea_application::javascript::version_comparison::compare(&input, None)
        .map_err(|failure| AnalysisError::from(failure))
        .and_then(evidence_from_raw);
    let sources = std::iter::once(left)
        .chain(std::iter::once(right))
        .chain(left_native)
        .chain(right_native)
        .collect::<Vec<_>>();
    support::deliver_with_unknown(
        context.session,
        &sources,
        result,
        unknown("application-version-comparison"),
    )
}

fn compare_source_to_bundle(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let application = match resolve_field(context, &input, "application") {
        Ok(value) => value,
        Err(error) => return ToolOutput::Failure(error),
    };
    let mut request = input;
    request["application"] = application.clone();
    let result = rea_application::javascript::source_comparison::compare(&request)
        .map_err(AnalysisError::from)
        .and_then(|result| {
            let parameters = request.clone();
            workflow_evidence::create(
                "rea.source-to-bundle-comparison",
                "compare_source_to_bundle",
                parameters,
                result,
            )
        });
    support::deliver_with_unknown(
        context.session,
        &[application],
        result,
        unknown("source-to-bundle-comparison"),
    )
}

fn compare_export_shapes(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let left = match resolve_field(context, &input, "left") {
        Ok(value) => value,
        Err(error) => return ToolOutput::Failure(error),
    };
    let right = match resolve_field(context, &input, "right") {
        Ok(value) => value,
        Err(error) => return ToolOutput::Failure(error),
    };
    let mut request = input;
    request["left"] = left.clone();
    request["right"] = right.clone();
    let result =
        rea_application::javascript::export_comparison::compare_javascript_export_shapes(&request)
            .map_err(AnalysisError::from)
            .and_then(|result| {
                workflow_evidence::create(
                    "rea.javascript-export-shape-comparison",
                    "compare_javascript_export_shapes",
                    request.clone(),
                    result,
                )
            });
    support::deliver_with_unknown(
        context.session,
        &[left, right],
        result,
        unknown("javascript-export-shape-comparison"),
    )
}
