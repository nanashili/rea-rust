//! Shared CLI/MCP admission, execution and Evidence composition for the five
//! Android tools, plus contract registration.
//!
//! Compatibility owners: `src/server/registerAndroidTools.ts`,
//! `src/application/android/{AndroidAnalysisService,AndroidPackageInspection,
//! AndroidSearchEvidenceSummary}.ts` and the analysis-view retention in
//! `src/application/analysisView/AnalysisViewService.ts`.

use super::analysis::AndroidRequest;
use super::provider;
use super::release::JADX_PROVIDER_ID;
use crate::common::target::parse_binary_target;
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::Evidence;
use rea_mcp::support::{self, string};
use rea_mcp::{Registry, Session, ToolContext, ToolOutput};
use serde_json::{Value, json};
use std::sync::Arc;

/// Bind every JADX tool to its exact catalog contract.
pub fn register(registry: &mut Registry) {
    registry.handle("inspect_android_package", |context, input| {
        inspect_package(context, input)
    });
    registry.handle("search_android_classes", |context, input| {
        search_classes(context, input)
    });
    registry.handle("inspect_android_class", |context, input| {
        simple(context, input, "inspect_android_class")
    });
    registry.handle("inspect_android_method", |context, input| {
        simple(context, input, "inspect_android_method")
    });
    registry.handle("trace_android_references", |context, input| {
        simple(context, input, "trace_android_references")
    });
}

/// Build the validated request from the (schema-validated) input.
fn request_of(operation: &'static str, input: &Value) -> AndroidRequest {
    AndroidRequest {
        operation,
        path: string(input, "path").to_owned(),
        class_name: input
            .get("class_name")
            .and_then(Value::as_str)
            .map(str::to_owned),
        method_name: input
            .get("method_name")
            .and_then(Value::as_str)
            .map(str::to_owned),
        overload_index: input.get("overload_index").and_then(Value::as_u64),
        query: input
            .get("query")
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}

/// `AndroidAnalysisService.execute`: cancellation, admission, provider,
/// Evidence composition and late-cancellation completion.
fn execute(context: &ToolContext<'_>, request: &AndroidRequest) -> Result<Evidence, AnalysisError> {
    if context.cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(request.operation));
    }
    let target = parse_binary_target(&request.path, &context.cancellation)?;
    let state = provider::state(context.session);
    if state.is_closing() {
        return Err(AnalysisError::cancelled(request.operation));
    }
    // Serialize every operation on this session (single-provider ordering).
    let _turn = state
        .turn
        .acquire(&context.cancellation)
        .map_err(|_| AnalysisError::cancelled(request.operation))?;
    let environment = context.session.environment().clone();
    provider::execute(
        &state,
        &target,
        request,
        &environment,
        &context.cancellation,
    )
}

/// `inspect_android_class`, `inspect_android_method`, `trace_android_references`.
fn simple(context: &ToolContext<'_>, input: Value, operation: &'static str) -> ToolOutput {
    let request = request_of(operation, &input);
    execute(context, &request).into()
}

/// `inspect_android_package` with optional `detail: "summary"` delivery.
fn inspect_package(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let operation = "inspect_android_package";
    if context.cancellation.reason().is_some() {
        return AnalysisError::cancelled(operation).into();
    }
    let detail = input.get("detail").and_then(Value::as_str);
    // Native sessions always retain Evidence, so requireAnalysisViewRetention
    // always succeeds; no additional guard is needed here.
    let request = request_of(operation, &input);
    let executed = match execute(context, &request) {
        Ok(evidence) => evidence,
        Err(error) => return error.into(),
    };
    if detail != Some("summary") {
        return ToolOutput::Evidence(executed);
    }
    summarize_package(context.session, executed, operation).into()
}

/// Retain the complete package Evidence, then deliver the summary view.
fn summarize_package(
    session: &Arc<Session>,
    evidence: Evidence,
    operation: &str,
) -> Result<Evidence, AnalysisError> {
    session.record(&evidence)?;
    let source = session
        .evidence(summary_evidence_id(&evidence))
        .ok_or_else(|| {
            AnalysisError::evidence_integrity("retained Android package Evidence is missing")
        })?;
    let projected = rea_application::analysis_view::project(&source, &json!({ "kind": "summary" }))
        .map_err(AnalysisError::from)?;
    let value: Value = serde_json::from_str(projected.get())
        .map_err(|error| AnalysisError::output(operation, error.to_string()))?;
    support::adopt_evidence(value)
}

fn summary_evidence_id(evidence: &Evidence) -> &str {
    evidence
        .value()
        .get("evidence_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// `search_android_classes`: retain the complete Evidence and deliver the
/// bounded summary (elided `list_classes` page bodies, `inventory_elided`,
/// `complete_evidence_id`, evidence link).
fn search_classes(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let operation = "search_android_classes";
    let request = request_of(operation, &input);
    let evidence = match execute(context, &request) {
        Ok(evidence) => evidence,
        Err(error) => return error.into(),
    };
    summarize_search(context.session, evidence).into()
}

/// `summarizeRetainedAndroidSearch(evidence, recordEvidence)`.
fn summarize_search(session: &Arc<Session>, evidence: Evidence) -> Result<Evidence, AnalysisError> {
    session.record(&evidence)?;
    let value = evidence.value();
    let evidence_id = value
        .get("evidence_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let subject = value.get("subject").cloned().unwrap_or(Value::Null);
    let provider = value.get("provider").cloned().unwrap_or(Value::Null);
    let raw = value.get("raw_result").cloned().unwrap_or(Value::Null);
    let summarized = summarize_raw(&raw, &evidence_id);

    let mut observation = rea_core::evidence::envelope::Observation::new(
        value
            .get("operation")
            .and_then(Value::as_str)
            .unwrap_or("search_android_classes"),
        value.get("parameters").cloned().unwrap_or(Value::Null),
        value
            .get("normalized_result")
            .cloned()
            .unwrap_or(Value::Null),
    );
    observation.raw_result = Some(summarized);
    observation.confidence = value
        .get("confidence")
        .and_then(Value::as_str)
        .map(str::to_owned);
    observation.limitations = value
        .get("limitations")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    observation.locations = value
        .get("locations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    observation.evidence_links = vec![evidence_id];

    let provider = subject_provider(&provider);
    let subject_target = subject_target(&subject);
    support::evidence(subject_target.as_ref(), &provider, observation)
}

/// Replace inventoried `list_classes` page bodies with their pagination audit.
fn summarize_raw(raw: &Value, evidence_id: &str) -> Value {
    let Some(object) = raw.as_object() else {
        return raw.clone();
    };
    let Some(calls) = object.get("calls").and_then(Value::as_array) else {
        return raw.clone();
    };
    let mut result = object.clone();
    result.insert("complete_evidence_id".into(), json!(evidence_id));
    let summarized_calls: Vec<Value> = calls.iter().map(summarize_inventory_call).collect();
    result.insert("calls".into(), Value::Array(summarized_calls));
    Value::Object(result)
}

fn summarize_inventory_call(call: &Value) -> Value {
    let Some(object) = call.as_object() else {
        return call.clone();
    };
    if object.get("operation").and_then(Value::as_str) != Some("list_classes") {
        return call.clone();
    }
    let Some(response) = object.get("response").and_then(Value::as_object) else {
        return call.clone();
    };
    let Some(content) = response.get("content").and_then(Value::as_array) else {
        return call.clone();
    };
    let mut elided = false;
    let new_content: Vec<Value> = content
        .iter()
        .map(|entry| {
            let Some(entry_object) = entry.as_object() else {
                return entry.clone();
            };
            let Some(text) = entry_object.get("text").and_then(Value::as_str) else {
                return entry.clone();
            };
            match elide_inventory_text(text) {
                Some(summarized) => {
                    elided = true;
                    let mut new_entry = entry_object.clone();
                    new_entry.insert("text".into(), json!(summarized));
                    Value::Object(new_entry)
                }
                None => entry.clone(),
            }
        })
        .collect();
    if !elided {
        return call.clone();
    }
    let mut new_response = response.clone();
    new_response.insert("content".into(), Value::Array(new_content));
    let mut new_call = object.clone();
    new_call.insert("inventory_elided".into(), Value::Bool(true));
    new_call.insert("response".into(), Value::Object(new_response));
    Value::Object(new_call)
}

/// `elideInventoryText(text)`: replace the `items` array with its count.
fn elide_inventory_text(text: &str) -> Option<String> {
    let page: Value = serde_json::from_str(text).ok()?;
    let object = page.as_object()?;
    let items = object.get("items").and_then(Value::as_array)?;
    let mut audited = object.clone();
    audited.remove("items");
    audited.insert("items_omitted".into(), json!(items.len()));
    serde_json::to_string(&Value::Object(audited)).ok()
}

/// Reconstruct the subject target from a retained Evidence subject.
fn subject_target(subject: &Value) -> Option<rea_core::evidence::envelope::SubjectTarget> {
    let object = subject.as_object()?;
    let path = object.get("local_path").and_then(Value::as_str)?;
    let sha256 = object
        .get("digest")
        .and_then(|digest| digest.get("sha256"))
        .and_then(Value::as_str)?;
    let format = object
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or("apk");
    let architecture = object
        .get("architecture")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Some(rea_core::evidence::envelope::SubjectTarget {
        path: path.to_owned(),
        sha256: sha256.to_owned(),
        format: format.to_owned(),
        architecture,
    })
}

/// Reconstruct the provider identity from a retained Evidence provider.
fn subject_provider(provider: &Value) -> rea_core::evidence::envelope::EvidenceProvider {
    let id = provider
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or(JADX_PROVIDER_ID);
    let name = provider
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("JADX headless");
    let version = provider
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_owned);
    rea_core::evidence::envelope::EvidenceProvider::new(id, name, version)
}

/// Keep the cancellation import used even if the compiler elides it elsewhere.
#[allow(dead_code)]
fn _cancellation_link(cancellation: &Cancellation) -> bool {
    cancellation.reason().is_none()
}
