//! `inspect_analysis_view`: selected views of completed, authenticated Evidence.
//!
//! Compatibility owners: `src/server/registerAnalysisViewTool.ts`,
//! `src/application/analysisView/AnalysisViewService.ts` and the dispatch in
//! `src/domain/analysisView/analysisView.ts`. Source-specific projectors own
//! parent admission and selection; this module owns source resolution, the
//! shared route, the view digest and the derived Evidence boundary.
use crate::common::schema;
use crate::common::view::{OPERATION, Parent, ViewCache, view_error};
use crate::common::{self, json};
use rea_application::javascript::graph::json as graph_json;
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, Observation};
use rea_core::evidence::record::EvidenceRecord;
use rea_mcp::{Registry, Session, ToolContext, ToolOutput};
use serde_json::{Value, json, value::RawValue};
use std::sync::Arc;

mod addressed_inventory;
mod managed_artifact;
mod managed_members;

mod android_package;
mod binary_layout;
mod dart_aot;
mod desktop_application;
mod evm_interface;
mod il2cpp_metadata;
mod macho;
mod native_function;
mod wasm_artifact;

mod artifact_inventory;
mod interface_builder;
mod javascript_application;

mod api_surface;
mod environment_manifest;
mod pcap_capture;
mod web_network;
mod web_network_capture;

/// Bind the selected-view tool to its exact contract.
pub fn register(registry: &mut Registry) {
    registry.handle_application_validated(OPERATION, |context: &ToolContext<'_>, input: Value| {
        match handle(context, input) {
            Ok(output) => output,
            Err(error) => ToolOutput::Failure(error),
        }
    });
    registry.handle_raw_application_validated(OPERATION, |context, input| {
        match handle_raw(context, input) {
            Ok(output) => output,
            Err(error) => ToolOutput::Failure(error),
        }
    });
}

fn handle(context: &ToolContext<'_>, input: Value) -> Result<ToolOutput, AnalysisError> {
    context.check_cancelled()?;
    let parsed = parse_view_request(&input)?;
    let source = parsed
        .get("source")
        .ok_or_else(|| AnalysisError::input(OPERATION, Vec::new()))?;
    let view = parsed
        .get("view")
        .ok_or_else(|| AnalysisError::input(OPERATION, Vec::new()))?;

    let exact_source =
        graph_json::parse(&serde_json::to_string(source).map_err(|error| {
            AnalysisError::input_message(OPERATION, error.to_string(), Vec::new())
        })?)
        .map_err(|error| AnalysisError::input_message(OPERATION, error.to_string(), Vec::new()))?;
    let exact_view =
        graph_json::parse(&serde_json::to_string(view).map_err(|error| {
            AnalysisError::input_message(OPERATION, error.to_string(), Vec::new())
        })?)
        .map_err(|error| AnalysisError::input_message(OPERATION, error.to_string(), Vec::new()))?;
    if let Some(evidence) = exact_project(context.session, &exact_source, &exact_view)? {
        context.check_cancelled()?;
        return Ok(ToolOutput::RawEvidence(evidence));
    }

    let evidence = inspect_validated(context.session, source, view)?;
    context.check_cancelled()?;
    Ok(ToolOutput::Evidence(evidence))
}

/// Preserve raw JavaScript view selectors through the MCP transport. The
/// graph parser retains escaped lone UTF-16 units; only non-JavaScript views
/// fall back to the established application-owned Value path.
fn handle_raw(context: &ToolContext<'_>, input: &RawValue) -> Result<ToolOutput, AnalysisError> {
    context.check_cancelled()?;

    // Keep the frozen application schema as the first validator whenever the
    // request is representable as a Rust value. This preserves defaults and
    // refinements for the ordinary case.
    if let Ok(decoded) = serde_json::from_str::<Value>(input.get()) {
        return handle(context, decoded);
    }

    let arguments =
        graph_json::parse(input.get()).map_err(|_| AnalysisError::input(OPERATION, Vec::new()))?;
    let schema_root = rea_mcp::schema::published_view_input_schema()
        .ok_or_else(|| AnalysisError::input(OPERATION, Vec::new()))?;
    let parsed = rea_application::javascript::application_view_validation::parse_input(
        &arguments,
        &schema_root,
    )?;
    let source = parsed
        .get("source")
        .ok_or_else(|| AnalysisError::input(OPERATION, Vec::new()))?;
    let view = parsed
        .get("view")
        .ok_or_else(|| AnalysisError::input(OPERATION, Vec::new()))?;

    if let Some(projected) = exact_project(context.session, source, view)? {
        context.check_cancelled()?;
        return Ok(ToolOutput::RawEvidence(projected));
    }
    Err(AnalysisError::input(OPERATION, Vec::new()))
}

fn exact_project(
    session: &Session,
    source: &graph_json::Json,
    view: &graph_json::Json,
) -> Result<Option<EvidenceRecord>, AnalysisError> {
    let record = match source.at("kind").as_str() {
        Some("retained-evidence") => {
            let Some(evidence_id) = source.at("evidence_id").as_str() else {
                return Ok(None);
            };
            let Some(raw) = session.evidence_raw(evidence_id) else {
                return Ok(None);
            };
            graph_json::parse(raw.get()).map_err(|error| {
                AnalysisError::evidence_integrity(format!(
                    "Retained Evidence is not exact JSON: {error}"
                ))
            })?
        }
        Some("inline") => {
            let evidence = source
                .get("evidence")
                .ok_or_else(|| AnalysisError::input(OPERATION, Vec::new()))?;
            let raw = RawValue::from_string(evidence.stringify()).map_err(|error| {
                AnalysisError::input_message(OPERATION, error.to_string(), Vec::new())
            })?;
            let authenticated = EvidenceRecord::parse(&raw).map_err(|error| {
                AnalysisError::input_message(OPERATION, error.to_string(), Vec::new())
            })?;
            graph_json::parse(authenticated.raw().get()).map_err(|error| {
                AnalysisError::evidence_integrity(format!(
                    "Inline Evidence is not exact JSON: {error}"
                ))
            })?
        }
        _ => return Ok(None),
    };

    let operation = record.at("operation").as_str();
    let projected = match operation {
        Some("inventory_artifact") | Some("inspect_artifact") => {
            let raw = rea_application::artifacts::inventory_view::project_raw(&record, view)
                .map_err(|error| {
                    AnalysisError::input_message(OPERATION, error.to_string(), Vec::new())
                })?;
            EvidenceRecord::parse(&raw).map_err(|error| {
                AnalysisError::evidence_integrity(format!(
                    "Projected inventory view is invalid: {error}"
                ))
            })?
        }
        Some("analyze_javascript_application") => {
            let projected =
                rea_application::javascript::application_view_exact::project_raw(&record, view)?;
            validate_exact_projection(&projected)?;
            projected
        }
        _ => return Ok(None),
    };

    Ok(Some(projected))
}

fn validate_exact_projection(projected: &EvidenceRecord) -> Result<(), AnalysisError> {
    let normalized_result =
        graph_json::parse(projected.normalized_result().get()).map_err(|error| {
            AnalysisError::evidence_integrity(format!(
                "Projected JavaScript analysis view normalized_result is not exact JSON: {error}"
            ))
        })?;
    if let Some(root) = rea_mcp::schema::published_view_result_schema() {
        rea_application::javascript::application_view_validation::validate(
            &normalized_result,
            &root,
        )?;
    }
    Ok(())
}

/// Parse the complete request with the application schema, applying defaults
/// before source authentication or view projection.
fn parse_view_request(input: &Value) -> Result<Value, AnalysisError> {
    let root = schema::tool_input_schema(OPERATION)
        .ok_or_else(|| AnalysisError::input(OPERATION, Vec::new()))?;
    let metadata = rea_core::schema::SchemaMetadata {
        prefixed_digests: &[rea_core::digests::EVIDENCE_ID],
        ..rea_core::schema::SchemaMetadata::default()
    };
    let parsed = schema::parse_named_strict(&root, input, metadata)
        .map_err(|issues| schema::input_error_from_issues(OPERATION, &issues, input, Vec::new()))?;
    let view = parsed.get("view").cloned().unwrap_or(Value::Null);
    if crate::common::view::view_kind(&view) == "environment-manifest" {
        environment_manifest::refine_request(&view)?;
    }
    Ok(parsed)
}

/// `inspectAnalysisViewValidated`: authenticate the source, project the view
/// and seal it as Evidence linked to its parent.
pub fn inspect_validated(
    session: &Session,
    source: &Value,
    view: &Value,
) -> Result<Evidence, AnalysisError> {
    let kind = json::str_at(source, "kind").unwrap_or_default();
    let (record, sealed, admitted_bytes) = if kind == "inline" {
        let evidence = source.get("evidence").unwrap_or(&Value::Null);
        let admitted_bytes = admit_inline(view, evidence)?;
        (
            Arc::new(authenticate_inline(evidence)?),
            false,
            admitted_bytes,
        )
    } else {
        let evidence_id = json::str_at(source, "evidence_id").unwrap_or_default();
        (common::retained_evidence(session, evidence_id)?, true, 0)
    };
    let cache = session.state::<ViewCache>();
    project_record(&record, view, sealed, Some(&cache), admitted_bytes)
}

/// `summarizeRetainedAnalysis`: retain the complete record, then project its
/// summary view from the retained record.
pub fn summarize_retained(
    session: &Session,
    evidence: Evidence,
) -> Result<Evidence, AnalysisError> {
    session.record(&evidence)?;
    let evidence_id = evidence.id().to_owned();
    let record = Arc::new(evidence.into_value());
    common::remember_retained(session, &evidence_id, Arc::clone(&record));
    let cache = session.state::<ViewCache>();
    project_record(
        &record,
        &json!({ "kind": "summary" }),
        true,
        Some(&cache),
        0,
    )
}

/// Grouping views admit the complete inline envelope with their accumulator
/// before authentication; the reservation carries into the projection.
fn admit_inline(view: &Value, evidence: &Value) -> Result<usize, AnalysisError> {
    match crate::common::view::view_kind(view) {
        "api-surface" => api_surface::admit_inline(view, evidence),
        "environment-manifest" => environment_manifest::admit_inline(view, evidence),
        // Ordinary inline admission inspects structure only; parsed JSON values
        // cannot carry cycles, accessors or prototypes, and the transport parser
        // bounds nesting below the original depth limit.
        _ => Ok(0),
    }
}

fn authenticate_inline(evidence: &Value) -> Result<Value, AnalysisError> {
    common::authenticate(evidence)
}

fn project_record(
    record: &Value,
    view: &Value,
    sealed: bool,
    cache: Option<&ViewCache>,
    admitted_bytes: usize,
) -> Result<Evidence, AnalysisError> {
    let evidence_id = json::str_at(record, "evidence_id").unwrap_or_default();
    let operation = json::str_at(record, "operation").unwrap_or_default();
    let subject = record.get("subject").unwrap_or(&Value::Null);
    let parent = Parent {
        evidence_id,
        operation,
        normalized_result: record.get("normalized_result").unwrap_or(&Value::Null),
        subject,
        limitations: common::limitations_of(record),
        parameters: record.get("parameters").unwrap_or(&Value::Null),
        sealed,
        cache,
        admitted_bytes,
    };
    let result = project_analysis_view(&parent, view)?;
    if let Some(subject_sha256) = subject
        .get("digest")
        .and_then(|digest| digest.get("sha256"))
        .and_then(Value::as_str)
    {
        let artifact_sha256 = result
            .get("artifact")
            .and_then(|artifact| artifact.get("sha256"));
        if artifact_sha256.and_then(Value::as_str) != Some(subject_sha256) {
            let rendered = match artifact_sha256 {
                Some(Value::String(text)) => text.clone(),
                Some(other) => other.to_string(),
                None => "undefined".into(),
            };
            return Err(AnalysisError::evidence_integrity(format!(
                "Parent subject SHA-256 {subject_sha256} differs from analysis artifact SHA-256 {rendered}."
            )));
        }
    }
    create_view_evidence(record, &parent, view, result)
}

/// `projectAnalysisView`: route, project and seal one selected view.
pub fn project_analysis_view(parent: &Parent<'_>, view: &Value) -> Result<Value, AnalysisError> {
    let digest = parent.digest();
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !parent.evidence_id.starts_with("ev_")
    {
        return Err(view_error(
            &["source"],
            "invalid_format",
            "Parent Evidence ID is not a digest-backed identifier.",
        ));
    }
    let projected = dispatch(parent, view)?;
    seal(projected)
}

fn dispatch(parent: &Parent<'_>, view: &Value) -> Result<Value, AnalysisError> {
    let kind = crate::common::view::view_kind(view);
    match kind {
        "api-surface" => return api_surface::project(parent, view),
        "environment-manifest" => return environment_manifest::project(parent, view),
        _ => {}
    }
    match parent.operation {
        "inspect_web_network_capture" => web_network_capture::project(parent, view),
        "inspect_pcap_capture" => pcap_capture::project(parent, view),
        "inspect_binary_layout" => binary_layout::project(parent, view),
        "analyze_javascript_application" => javascript_application::project(parent, view),
        "analyze_function" => native_function::project(parent, view),
        "inspect_desktop_application" => desktop_application::project(parent, view),
        "inspect_wasm_artifact" => wasm_artifact::project(parent, view),
        "inspect_macho" => macho::project(parent, view),
        "decode_interface_builder" => interface_builder::project(parent, view),
        "inspect_evm_interface" => evm_interface::project(parent, view),
        "list_procedures" => {
            addressed_inventory::project(parent, view, addressed_inventory::PROCEDURES)
        }
        "list_strings" => addressed_inventory::project(parent, view, addressed_inventory::STRINGS),
        "inspect_managed_artifact" => managed_artifact::project(parent, view),
        "inspect_managed_members" => managed_members::project(parent, view),
        "inspect_android_package" => android_package::project(parent, view),
        "inspect_dart_aot" => dart_aot::project(parent, view),
        "inspect_il2cpp_metadata" => il2cpp_metadata::project(parent, view),
        "inspect_artifact" | "inventory_artifact" => artifact_inventory::project(parent, view),
        _ => Err(unsupported_parent(parent)),
    }
}

/// `sealAnalysisView`: attach the content digest, then parse the result with
/// the published view contract (defaults applied, unknown keys rejected).
fn seal(projection: Value) -> Result<Value, AnalysisError> {
    let digest = json::canonical_digest(&projection, "Analysis view")?;
    let mut sealed = projection;
    let Some(object) = sealed.as_object_mut() else {
        return Err(AnalysisError::output(
            OPERATION,
            "Analysis view projection is not an object.",
        ));
    };
    object.insert("view_digest".into(), Value::String(digest));
    let Some(root) = schema::view_result_schema() else {
        return Ok(sealed);
    };
    schema::parse_strict(&root, &sealed).map_err(|issues| {
        AnalysisError::output(
            OPERATION,
            format!(
                "Analysis view result does not satisfy its contract: {}",
                schema::describe(&issues)
            ),
        )
    })
}

fn unsupported_parent(parent: &Parent<'_>) -> AnalysisError {
    let reason = if parent.operation == "capture_browser_scenario" {
        "Parent Evidence operation \"capture_browser_scenario\" supports only the environment-manifest view.".to_owned()
    } else {
        format!(
            "Parent Evidence operation {} does not support analysis views. Use completed binary layout, JavaScript application, native function, procedure inventory, artifact inventory/inspection, WASM, Mach-O, Interface Builder, EVM, managed artifact or member, Android package, Dart AOT, IL2CPP metadata, or web network capture Evidence.",
            Value::String(parent.operation.to_owned())
        )
    };
    AnalysisError::unsupported_target(OPERATION, parent_artifact_path(parent), reason)
}

fn parent_artifact_path(parent: &Parent<'_>) -> String {
    if let Some(path) = parent
        .normalized_result
        .get("artifact")
        .and_then(|artifact| artifact.get("path"))
        .and_then(Value::as_str)
    {
        return path.to_owned();
    }
    if let Some(path) = parent
        .normalized_result
        .get("input_path")
        .and_then(Value::as_str)
    {
        return path.to_owned();
    }
    parent.evidence_id.to_owned()
}

/// `createAnalysisViewEvidence`.
fn create_view_evidence(
    record: &Value,
    parent: &Parent<'_>,
    view: &Value,
    result: Value,
) -> Result<Evidence, AnalysisError> {
    let target = common::subject_target(parent.subject);
    let result_kind = json::str_at(&result, "kind").unwrap_or_default().to_owned();
    let templated = matches!(result_kind.as_str(), "api-surface" | "environment-manifest")
        && result
            .get("templated_groups")
            .and_then(Value::as_u64)
            .is_some_and(|count| count > 0);
    let limitations = json::strings(result.get("limitations").unwrap_or(&Value::Null));
    let mut locations = Vec::new();
    if let Some(path) = result
        .get("artifact")
        .and_then(|artifact| artifact.get("path"))
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
    {
        locations.push(json!({ "kind": "artifact-path", "path": path }));
    }
    if result_kind == "native"
        && let Some(address) = result
            .get("procedure_address")
            .and_then(Value::as_str)
            .filter(|address| !address.is_empty())
    {
        locations.push(json!({ "kind": "address", "address": address }));
    }
    let relationship_coverage = record
        .get("relationship_coverage")
        .filter(|coverage| result_kind == "native" && !coverage.is_null())
        .cloned();
    let authority = json::str_at(record, "authority")
        .unwrap_or("shipped-artifact")
        .to_owned();
    let mut observation = Observation::new(
        OPERATION,
        json!({ "parent_evidence_id": parent.evidence_id, "view": view }),
        result,
    )
    .predicate("rea.analysis-view")
    .confidence(if templated { "inferred" } else { "derived" })
    .authority(authority)
    .limitations(limitations)
    .locations(locations)
    .links(vec![parent.evidence_id.to_owned()]);
    observation.raw_result = Some(Value::Null);
    if let Some(coverage) = relationship_coverage {
        observation = observation.coverage(coverage);
    }
    common::create_evidence(
        OPERATION,
        target.as_ref(),
        &common::analysis_view_provider(),
        observation,
    )
}
