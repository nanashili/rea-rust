//! Provider-neutral orchestration decisions for one Rust Ghidra operation.
//!
//! The worker and session modules own transport, target identity and process
//! cleanup.  This module owns the ordering around a completed observation:
//! profile admission happens before dispatch, late interruption keeps the
//! observation, and a worker failure invalidates the session before it can be
//! reused.  The returned decisions leave the actual invalidation with the
//! session owner.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

use crate::ghidra_rust::execution_control::{
    ExecutionInterruption, GhidraRustExecutionControl,
};
use crate::ghidra_rust::operations::GhidraRustOperation;

pub const PROVIDER_ID: &str = "ghidra-rust";
pub const PROFILE_REQUIRED_REASON: &str =
    "The operation requires the selected Rust worker profile.";

/// One completed worker observation before provider-neutral Evidence wrapping.
pub struct GhidraRustObservation {
    pub result: Value,
    pub raw_result: Option<Value>,
    pub limitations: Vec<String>,
}

/// The producer's typed classification is supplied by the worker/session
/// owner; this module never guesses a failure class from display text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GhidraRustFailureKind {
    CapabilityUnavailable,
    Cancelled,
    Timeout,
    ProviderAdapter,
    Other,
}

/// A failure plus facts needed to preserve the TypeScript lifecycle rules.
pub struct GhidraRustFailure {
    pub failure: Failure,
    pub kind: GhidraRustFailureKind,
    pub cleanup_incomplete: bool,
    pub worker_started: bool,
}

/// The caller decides how to perform invalidation after this module has
/// selected the correct failure.  Keeping that side effect outside the
/// reducer prevents cleanup from replacing the original substantive error.
pub enum GhidraRustExecutionDecision {
    Success(Value),
    ReturnFailure(Failure),
    InvalidateWorker(Failure),
}

/// Check the Rust profile before any non-health operation can dispatch.
pub fn require_profile(
    operation: GhidraRustOperation,
    profile_matches: bool,
) -> Result<(), Failure> {
    if operation == GhidraRustOperation::Health || profile_matches {
        return Ok(());
    }

    Err(capability_failure(operation, PROFILE_REQUIRED_REASON))
}

/// Finish a successful dispatch while preserving observations for late
/// interruption or an already-recorded worker failure.
pub fn finish(
    operation: GhidraRustOperation,
    input: Value,
    observation: GhidraRustObservation,
    control: &mut GhidraRustExecutionControl,
    interruption: Option<GhidraRustFailure>,
    worker_failure: Option<GhidraRustFailure>,
) -> GhidraRustExecutionDecision {
    let evidence = evidence(operation, input, &observation);

    if let Some(mut interruption) = interruption {
        retain_observation(&mut interruption.failure, &evidence);
        return interruption_decision(interruption);
    }

    if control.interruption().is_some() {
        let mut failure = interruption_without_typed_failure(operation, control);
        retain_observation(&mut failure, &evidence);
        return finish_interruption_decision(failure, control.interruption());
    }

    if let Some(mut worker_failure) = worker_failure {
        retain_observation(&mut worker_failure.failure, &evidence);
        return GhidraRustExecutionDecision::InvalidateWorker(worker_failure.failure);
    }

    GhidraRustExecutionDecision::Success(observation.result)
}

/// Apply the failure path after dispatch itself returned an error.
///
/// `timeout_failure` is created by the execution-control owner so its
/// diagnostics and cancellation cause remain authoritative.  The primary
/// failure is retained when cleanup composition is required.
pub fn failure(
    operation: GhidraRustOperation,
    control: &mut GhidraRustExecutionControl,
    primary: GhidraRustFailure,
    timeout_failure: Option<GhidraRustFailure>,
) -> GhidraRustExecutionDecision {
    let interruption = control.interruption();
    let is_deadline_cancellation = primary.kind == GhidraRustFailureKind::Cancelled
        && interruption == Some(ExecutionInterruption::Timeout);

    if primary.kind == GhidraRustFailureKind::Cancelled
        && interruption == Some(ExecutionInterruption::Closing)
    {
        if primary.cleanup_incomplete {
            return GhidraRustExecutionDecision::ReturnFailure(compose_cleanup_failure(
                operation,
                capability_failure(
                    operation,
                    "The provider client is closing and cannot finish this operation.",
                ),
                primary.failure,
            ));
        }
        return GhidraRustExecutionDecision::ReturnFailure(primary.failure);
    }

    if primary.kind == GhidraRustFailureKind::ProviderAdapter && primary.worker_started {
        return GhidraRustExecutionDecision::InvalidateWorker(primary.failure);
    }

    if !is_deadline_cancellation {
        return GhidraRustExecutionDecision::ReturnFailure(primary.failure);
    }

    let Some(mut timeout) = timeout_failure else {
        return GhidraRustExecutionDecision::ReturnFailure(primary.failure);
    };
    if primary.cleanup_incomplete {
        timeout.failure = compose_cleanup_failure(operation, timeout.failure, primary.failure);
    }
    GhidraRustExecutionDecision::ReturnFailure(timeout.failure)
}

fn interruption_decision(failure: GhidraRustFailure) -> GhidraRustExecutionDecision {
    if failure.kind == GhidraRustFailureKind::CapabilityUnavailable {
        GhidraRustExecutionDecision::ReturnFailure(failure.failure)
    } else {
        GhidraRustExecutionDecision::InvalidateWorker(failure.failure)
    }
}

fn finish_interruption_decision(
    failure: Failure,
    interruption: Option<ExecutionInterruption>,
) -> GhidraRustExecutionDecision {
    match interruption {
        Some(ExecutionInterruption::Closing) => {
            GhidraRustExecutionDecision::ReturnFailure(failure)
        }
        Some(ExecutionInterruption::Cancelled | ExecutionInterruption::Timeout) | None => {
            GhidraRustExecutionDecision::InvalidateWorker(failure)
        }
    }
}

fn evidence(operation: GhidraRustOperation, input: Value, observation: &GhidraRustObservation) -> Value {
    json!({
        "operation": operation.as_str(),
        "input": input,
        "result": observation.result.clone(),
        "raw_result": observation.raw_result.clone(),
        "limitations": observation.limitations.clone(),
        "confidence": "observed",
    })
}

fn retain_observation(failure: &mut Failure, evidence: &Value) {
    if let Err(error) = failure.retain(evidence) {
        failure.detail(
            "partial_observation_error",
            Detail::Text(format!("could not retain Ghidra observation: {error}")),
        );
    }
}

fn capability_failure(operation: GhidraRustOperation, reason: &str) -> Failure {
    Failure::new(
        "capability_unavailable",
        "unsupported_provider",
        format!("Provider {PROVIDER_ID} cannot execute {}: {reason}", operation.as_str()),
        true,
        "Select a matching Rust worker profile and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(operation.as_str().into())),
            ("provider_id", Detail::Text(PROVIDER_ID.into())),
        ]),
    )
}

fn interruption_without_typed_failure(
    operation: GhidraRustOperation,
    control: &mut GhidraRustExecutionControl,
) -> Failure {
    let interruption = control.interruption();
    let (code, category, reason) = match interruption {
        Some(ExecutionInterruption::Cancelled) => (
            "cancelled",
            "cancelled",
            "Analysis operation was cancelled.",
        ),
        Some(ExecutionInterruption::Closing) => (
            "capability_unavailable",
            "unsupported_provider",
            "The provider client is closing and cannot finish this operation.",
        ),
        Some(ExecutionInterruption::Timeout) => (
            "provider_timeout",
            "timeout",
            "The Rust provider operation exceeded its deadline.",
        ),
        None => (
            "execution_failure",
            "execution_failure",
            "The Rust provider could not complete its operation.",
        ),
    };
    Failure::new(
        code,
        category,
        reason.into(),
        code == "cancelled" || code == "provider_timeout",
        "Retry the operation after resolving the provider interruption.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(operation.as_str().into())),
            ("provider_id", Detail::Text(PROVIDER_ID.into())),
        ]),
    )
}

fn compose_cleanup_failure(
    operation: GhidraRustOperation,
    primary: Failure,
    cleanup: Failure,
) -> Failure {
    let mut details = BTreeMap::from([
        ("operation", Detail::Text(operation.as_str().into())),
        ("provider_id", Detail::Text(PROVIDER_ID.into())),
        ("cleanup", Detail::Text("incomplete".into())),
    ]);
    details.insert("primary_failure", serialized_detail(&primary));
    details.insert("cleanup_failure", serialized_detail(&cleanup));
    Failure::new(
        "cleanup_incomplete",
        "execution_failure",
        "The Rust provider operation failed and cleanup remains incomplete.".into(),
        false,
        "Retry cleanup before starting another Rust provider operation.".into(),
        details,
    )
}

fn serialized_detail(value: &Failure) -> Detail {
    match serde_json::to_raw_value(value) {
        Ok(raw) => Detail::Raw(raw),
        Err(error) => Detail::Text(format!("could not serialize retained failure: {error}")),
    }
}

