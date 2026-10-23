//! Provider-neutral managed-code workflow tools.
//!
//! Compatibility owners: `src/server/registerManagedWorkflowTools.ts` and
//! `src/server/registerManagedWorkflowTools/**`, their application services
//! (`src/application/managed/**`) and domain logic (`src/domain/managed/**`).
//!
//! The four tools consume authenticated managed inspection Evidence and
//! native observations; none of them read raw PE bytes, so this module does
//! not depend on `src/dotnet/**`.
mod application_graph;
mod error;
mod graph_builder;
mod inspection;
mod member_comparison;
mod native_verification;
mod reconstruction;
mod unknown;

use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::Evidence;
use rea_mcp::session::record_error;
use rea_mcp::{Registry, Session, ToolOutput};
use serde_json::Value;
use std::sync::Arc;

/// Bind each managed workflow tool to its exact catalog name.
pub fn register(registry: &mut Registry) {
    registry.handle("compare_managed_members", |context, input| {
        member_comparison::handle(context, input)
    });
    registry.handle("verify_managed_native_boundaries", |context, input| {
        native_verification::handle(context, input)
    });
    registry.handle("import_managed_reconstruction", |context, input| {
        reconstruction::handle(context, input)
    });
    registry.handle("project_managed_application_graph", |context, input| {
        application_graph::handle(context, input)
    });
}

/// `parseEvidence`: authenticate a caller-supplied record, returning the
/// canonical value. Failures become `EvidenceIntegrityError`.
fn authenticate(value: &Value) -> Result<Value, AnalysisError> {
    crate::common::authenticate(value)
}

/// `resolveManaged*Evidence`/`resolveNativeEvidence`: authenticate one record
/// and require its operation and predicate type.
///
/// When `expected_operation` is `None`, the workflow owns which authentic
/// operations it can use (see `resolveNativeEvidence`).
fn resolve_expected(
    value: &Value,
    expected_operation: Option<&str>,
) -> Result<Value, AnalysisError> {
    let record = authenticate(value)?;
    if let Some(expected) = expected_operation {
        let operation = record
            .get("operation")
            .and_then(Value::as_str)
            .unwrap_or("");
        let predicate = record
            .get("predicate_type")
            .and_then(Value::as_str)
            .unwrap_or("");
        if operation != expected || predicate != "rea.analysis" {
            return Err(AnalysisError::evidence_integrity(format!(
                "Expected {expected} Evidence, received {operation}"
            )));
        }
    }
    Ok(record)
}

/// `recordSessionEvidenceSources`: record each source in order, stopping at
/// the first session rejection.
fn record_sources(session: &Arc<Session>, sources: &[&Value]) -> Result<(), AnalysisError> {
    for source in sources {
        record_authenticated(session, source)?;
    }
    Ok(())
}

/// Record one already-authenticated canonical Evidence value as a source.
fn record_authenticated(session: &Arc<Session>, value: &Value) -> Result<(), AnalysisError> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))?;
    session.record_raw(&raw)
}

/// `recordDerivedEvidence`: retain derived Evidence, atomically with its
/// supported unknown when one applies. An identical re-record is idempotent.
fn record_derived(
    session: &Arc<Session>,
    evidence: &Evidence,
    unknown: Option<Value>,
) -> Result<(), AnalysisError> {
    match unknown {
        None => session.record(evidence),
        Some(input) => {
            let evidence_raw = evidence
                .to_raw()
                .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))?;
            let input_raw = serde_json::value::to_raw_value(&input)
                .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))?;
            session
                .records()
                .record_evidence_with_unknown(&evidence_raw, &input_raw)
                .map_err(record_error)
        }
    }
}

/// Deliver a derived Evidence result, recording it (with its unknown) first.
fn deliver(session: &Arc<Session>, evidence: Evidence, unknown: Option<Value>) -> ToolOutput {
    match record_derived(session, &evidence, unknown) {
        Ok(()) => ToolOutput::Evidence(evidence),
        Err(error) => ToolOutput::Failure(error),
    }
}
