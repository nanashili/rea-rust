//! WASM artifact family: `inspect_wasm_artifact` and `compare_wasm_interfaces`.
//!
//! Compatibility owners: `src/server/registerWasmTools.ts`,
//! `src/composition/wasm.ts`, `src/application/wasm/WasmArtifactService.ts`,
//! `src/application/wasm/WasmInterfaceComparisonService.ts`,
//! `src/application/EvidenceInputResolver.ts` (`resolvePairedEvidenceRequest`)
//! and `src/server/sessionEvidence.ts` (`recordSessionEvidenceSources`).
//!
//! The real WABT execution and the verified WAT/objdump parsing are ported in
//! this family's own `producer` submodule (`WabtArtifactProvider` and friends);
//! the paired typed-interface comparison is reused from
//! `rea_application::wasm::comparison`. This module reproduces the TypeScript
//! server/service layers around those producers: the absolute-path input
//! refinement (`WasmArtifactService`), the delivery-only `detail` stripping,
//! the service-layer re-validation of the returned report, the exact paired-
//! Evidence resolution error classes (`resolveEvidenceInput` /
//! `EvidenceReferenceError`) and the post-success recording of comparison
//! sources before the derived record is delivered.
use crate::common::{adopt_failure, adopt_raw_evidence, summary_view};
use rea_application::wasm;
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::evidence::envelope::Evidence;
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Map, Value, json};

mod producer;

/// Bind both WASM tools to their frozen catalog contracts.
pub(crate) fn register(registry: &mut Registry) {
    registry.handle(producer::OPERATION, inspect_wasm_artifact);
    registry.handle(wasm::comparison::OPERATION, compare_wasm_interfaces);
}

// ---------------------------------------------------------------------------
// inspect_wasm_artifact
// ---------------------------------------------------------------------------

/// `registerWasmTools` inspect binding composed over `WasmArtifactService`.
fn inspect_wasm_artifact(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    // `createEvidenceToolHandler`: cancellation is observed before admission.
    if let Err(error) = context.check_cancelled() {
        return error.into();
    }
    match inspect(context, input) {
        Ok(output) => output,
        Err(error) => error.into(),
    }
}

fn inspect(context: &ToolContext<'_>, input: Value) -> Result<ToolOutput, AnalysisError> {
    let object = input
        .as_object()
        .cloned()
        .ok_or_else(|| AnalysisError::input(producer::OPERATION, Vec::new()))?;
    // `WasmArtifactService.inspect`: the absolute-path refinement the frozen
    // input schema cannot express. Order and issue paths mirror the service.
    let mut issues: Vec<InputIssue> = Vec::new();
    if let Some(path) = object.get("path").and_then(Value::as_str)
        && !is_absolute(path)
    {
        issues.push(absolute_path_issue(&["path"]));
    }
    collect_relative(&object, "glue_paths", &mut issues);
    collect_relative(&object, "candidate_paths", &mut issues);
    if !issues.is_empty() {
        return Err(AnalysisError::input(producer::OPERATION, issues));
    }
    // The delivery-only `detail` selection is stripped before the service, so
    // committed Evidence parameters match `input.data` exactly.
    let detail = object
        .get("detail")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut parameters = object;
    parameters.remove("detail");
    let producer_input = Value::Object(parameters);
    // The verified real-WABT producer owns execution and parsing.
    let evidence = producer::inspect(context, &producer_input)?;
    // `WasmArtifactService` re-validation: the adapter must not change the
    // selected artifact identity or the requested glue/candidate selection.
    revalidate_report(&evidence, &producer_input)?;
    // `detail === "summary"` delivers the retained summary view; otherwise the
    // complete Evidence is delivered and retained by the server.
    if detail.as_deref() == Some("summary") {
        return Ok(summary_view(context, evidence).into());
    }
    Ok(ToolOutput::Evidence(evidence))
}

/// `WasmArtifactService` output guard: the returned report must preserve the
/// selected artifact identity and the requested glue/candidate ordering,
/// otherwise the adapter returned malformed data (`AnalysisOutputError`).
fn revalidate_report(evidence: &Evidence, input: &Value) -> Result<(), AnalysisError> {
    let malformed = || {
        AnalysisError::output(
            producer::OPERATION,
            "WABT adapter returned malformed data or changed the selected artifact identity.",
        )
    };
    let envelope = evidence.value();
    let report = envelope.get("normalized_result").ok_or_else(malformed)?;
    let subject = envelope.get("subject");
    let input_path = input
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(malformed)?;
    let artifact = report.get("artifact").ok_or_else(malformed)?;
    let artifact_path = artifact
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(malformed)?;
    let artifact_sha = artifact
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(malformed)?;
    if artifact_path != input_path {
        return Err(malformed());
    }
    // `wasmArtifactMatchesSubject`: a selected local file identity.
    if !subject_matches(subject, artifact_path, artifact_sha) {
        return Err(malformed());
    }
    // `report.glue.map(item => item.artifact.path)` equals `input.glue_paths`.
    let report_glue: Vec<&str> = array_items(report.get("glue"))
        .iter()
        .map(|item| {
            item.get("artifact")
                .and_then(|artifact| artifact.get("path"))
                .and_then(Value::as_str)
                .unwrap_or_default()
        })
        .collect();
    let input_glue: Vec<&str> = string_array(input.get("glue_paths"));
    if report_glue != input_glue {
        return Err(malformed());
    }
    // `report.candidates.map(item => item.path)` equals the de-duplicated
    // `[input.path, ...input.candidate_paths]` sequence (first occurrence).
    let report_candidates: Vec<&str> = array_items(report.get("candidates"))
        .iter()
        .map(|item| item.get("path").and_then(Value::as_str).unwrap_or_default())
        .collect();
    let mut expected_candidates: Vec<&str> = Vec::new();
    for path in std::iter::once(input_path).chain(string_array(input.get("candidate_paths"))) {
        if !expected_candidates.contains(&path) {
            expected_candidates.push(path);
        }
    }
    if report_candidates != expected_candidates {
        return Err(malformed());
    }
    Ok(())
}

/// `wasmArtifactMatchesSubject` applied to the committed envelope subject
/// (`local_path`, `digest.sha256`, `format`).
fn subject_matches(subject: Option<&Value>, path: &str, sha256: &str) -> bool {
    let Some(subject) = subject.and_then(Value::as_object) else {
        return false;
    };
    subject.get("local_path").and_then(Value::as_str) == Some(path)
        && subject
            .get("digest")
            .and_then(|digest| digest.get("sha256"))
            .and_then(Value::as_str)
            == Some(sha256)
        && subject.get("format").and_then(Value::as_str) == Some("file")
}

/// Collect absolute-path issues for one path array, preserving index order.
fn collect_relative(object: &Map<String, Value>, field: &str, issues: &mut Vec<InputIssue>) {
    for (index, value) in array_items(object.get(field)).iter().enumerate() {
        if let Some(path) = value.as_str()
            && !is_absolute(path)
        {
            issues.push(indexed_absolute_issue(field, index));
        }
    }
}

/// `AnalysisInputIssue` for a non-absolute `path` (`node:path` `isAbsolute`).
fn absolute_path_issue(path: &[&str]) -> InputIssue {
    InputIssue::new(
        path,
        "invalid_format",
        "Expected an absolute filesystem path on this host.",
    )
}

/// `AnalysisInputIssue` for a non-absolute entry in `glue_paths`/`candidate_paths`.
fn indexed_absolute_issue(field: &str, index: usize) -> InputIssue {
    let mut issue = InputIssue::new(
        &[field],
        "invalid_format",
        "Expected an absolute filesystem path on this host.",
    );
    issue.path = vec![Value::String(field.to_owned()), json!(index)];
    issue
}

// ---------------------------------------------------------------------------
// compare_wasm_interfaces
// ---------------------------------------------------------------------------

/// `registerWasmTools` comparison binding over `compareWasmInterfaces`.
fn compare_wasm_interfaces(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    if let Err(error) = context.check_cancelled() {
        return error.into();
    }
    match compare(context, input) {
        Ok(output) => output,
        Err(error) => error.into(),
    }
}

fn compare(context: &ToolContext<'_>, input: Value) -> Result<ToolOutput, AnalysisError> {
    let object = input
        .as_object()
        .ok_or_else(|| AnalysisError::input(wasm::comparison::OPERATION, Vec::new()))?;
    // `resolvePairedEvidenceRequest`: resolve `left` then `right` to complete
    // Evidence, with the exact `EvidenceReferenceError` classes for a missing
    // or identity-mismatched retained reference.
    let left = resolve_evidence_input(context, object.get("left"))?;
    let right = resolve_evidence_input(context, object.get("right"))?;
    // Feed the resolved complete Evidence inline so the producer never takes
    // its own retained-reference path; identity authentication and semantic
    // validation stay with `compareWasmInterfaces`.
    let mut resolved = object.clone();
    resolved.insert("left".into(), left.value().clone());
    resolved.insert("right".into(), right.value().clone());
    let resolved_input = Value::Object(resolved);
    let raw = wasm::comparison::compare(&resolved_input, None, &context.cancellation)
        .map_err(adopt_failure)?;
    let derived = adopt_raw_evidence(&raw)?;
    // `recordSessionEvidenceSources`: record both sources in order after the
    // comparison succeeds, before the derived record is delivered.
    context.session.record(&left)?;
    context.session.record(&right)?;
    Ok(ToolOutput::Evidence(derived))
}

/// `resolveEvidenceInput`: a complete inline Evidence is returned as-is; a
/// `retained-evidence` reference is resolved from the session ledger with the
/// exact missing / identity-mismatch error classes.
fn resolve_evidence_input(
    context: &ToolContext<'_>,
    input: Option<&Value>,
) -> Result<Evidence, AnalysisError> {
    let value =
        input.ok_or_else(|| AnalysisError::evidence_integrity("Missing paired Evidence input"))?;
    // `"kind" in input` selects the reference branch.
    if value.get("kind").is_some() {
        let evidence_id = value
            .get("evidence_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                AnalysisError::evidence_reference(
                    "",
                    "missing",
                    "Evidence retained in this session",
                    None,
                )
            })?;
        let Some(record) = context.session.evidence(evidence_id) else {
            return Err(AnalysisError::evidence_reference(
                evidence_id,
                "missing",
                "Evidence retained in this session",
                None,
            ));
        };
        let actual = record
            .get("evidence_id")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if actual.as_deref() != Some(evidence_id) {
            return Err(AnalysisError::evidence_reference(
                evidence_id,
                "identity_mismatch",
                evidence_id,
                actual,
            ));
        }
        return crate::common::adopt_evidence_value(record);
    }
    // Complete inline Evidence: authenticate the envelope before use.
    crate::common::adopt_evidence_value(value.clone())
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

/// `node:path` `isAbsolute` on this host.
#[cfg(windows)]
fn is_absolute(path: &str) -> bool {
    // Windows treats `\\` / `/`-rooted and drive-absolute paths as absolute.
    std::path::Path::new(path).is_absolute() || path.starts_with('\\') || path.starts_with('/')
}

/// `node:path` `isAbsolute` on POSIX hosts.
#[cfg(not(windows))]
fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
}

fn array_items(value: Option<&Value>) -> &[Value] {
    value
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn string_array(value: Option<&Value>) -> Vec<&str> {
    array_items(value)
        .iter()
        .map(|item| item.as_str().unwrap_or_default())
        .collect()
}
