//! `capture_process_scenario` handler.
//!
//! Compatibility owners: `registerProcessTools` and
//! `recordProcessResidualUnknowns` (`registerSessionTools.ts`),
//! `captureProcessScenario` (`ProcessHarness.ts`),
//! `createProcessCaptureEvidence` (`ProcessEvidence.ts`) and
//! `ProcessCaptureResourceScope` (`ProcessCaptureLifecycle.ts`).

use super::capture::{self, CaptureFailure, CaptureHost, RetainedResources, report_failure, report_resources};
use super::paths::resolve_runtime_paths;
use super::scenario::{Scenario, refinements};
use crate::input_failure::refinement_failure;
use rea_application::ledger::artifact_records::{RecordError, UnknownMutationFailure};
use rea_core::analysis_error::{AnalysisError, ErrorKind};
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation};
use rea_mcp::session::{SessionResource, record_error};
use rea_mcp::{Session, ToolContext, ToolOutput};
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};

const OPERATION: &str = "capture_process_scenario";

/// `PROCESS_PROVIDER` (`processEvidenceProvider.ts`).
fn provider() -> EvidenceProvider {
    EvidenceProvider::new("rea-process", "REA process capture", Some("3".to_owned()))
}

/// `ProcessCaptureResourceScope`: owners whose first cleanup did not finish.
#[derive(Default)]
pub struct ProcessCaptureResources {
    pending: Mutex<Vec<RetainedResources>>,
}

impl ProcessCaptureResources {
    /// Retry every retained owner; failures stay retained.
    fn retry(&self) -> Result<(), AnalysisError> {
        let mut pending = self.pending.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut reasons = Vec::new();
        let mut resources: Vec<String> = Vec::new();
        pending.retain_mut(|owner| match capture::release_retained(owner) {
            Ok(()) => false,
            Err(reason) => {
                for resource in report_resources(&owner.report) {
                    if !resources.contains(&resource) {
                        resources.push(resource);
                    }
                }
                reasons.push(reason);
                true
            }
        });
        if reasons.is_empty() {
            return Ok(());
        }
        let reason = reasons.join("; ");
        Err(process_capture_error(
            format!("Process capture cleanup remains incomplete: {reason}"),
            "cleanup_incomplete",
            false,
            Some(reason.clone()),
            None,
        )
        .with_cleanup(reason, resources))
    }

    fn retain(&self, owner: RetainedResources) {
        self.pending.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(owner);
    }
}

impl SessionResource for ProcessCaptureResources {
    fn close(&self) -> Result<(), AnalysisError> {
        self.retry()
    }
}

fn process_capture_error(message: String, reason: &str, cancelled: bool, execution_failure: Option<String>, cleanup_report: Option<Value>) -> AnalysisError {
    let user_message = if cancelled {
        "Process capture was cancelled. Start it again when ready.".to_owned()
    } else {
        message.clone()
    };
    ErrorKind::ProcessCapture {
        execution_failure: execution_failure.or_else(|| Some(message.clone())),
        message,
        user_message: Some(user_message),
        cancelled,
        reason: reason.to_owned(),
        cleanup_report,
    }
    .into()
}

/// `resolveProcessResult` / `withFinalization` projection of a failed run.
fn failure_error(failure: CaptureFailure) -> AnalysisError {
    let cleanup = failure.cleanup_report.as_ref().and_then(report_failure);
    let resources = failure.cleanup_report.as_ref().map(report_resources).unwrap_or_default();
    let mut error = if failure.cancelled {
        let error = process_capture_error(failure.message, "cancelled", true, failure.execution_failure, failure.cleanup_report);
        match cleanup {
            Some(reason) => error.with_cleanup(reason, resources),
            None => error,
        }
    } else if let Some(reason) = cleanup {
        process_capture_error(reason.clone(), "cleanup_incomplete", false, failure.execution_failure, failure.cleanup_report).with_cleanup(reason, resources)
    } else {
        process_capture_error(failure.message, "capture_failed", false, failure.execution_failure, failure.cleanup_report)
    };
    if let Some(partial) = failure.partial_observation {
        error = error.retain_partial_observation(partial);
    }
    error
}

/// `processEvidenceParameters`.
fn parameters(input: &Scenario) -> Value {
    let executable_name = input.executable.rsplit('/').find(|part| !part.is_empty()).unwrap_or_default();
    json!({
        "executable_name": executable_name,
        "argument_count": input.arguments.len(),
        "event_count": input.events.len(),
        "filesystem_observation_path_count": input.filesystem_observation_paths.len(),
        "normalization": input.normalization(),
    })
}

fn evidence(input: &Scenario, capture: Value) -> Result<Evidence, AnalysisError> {
    let manifest = &capture["manifest"];
    let platform = manifest["platform"].as_str().unwrap_or_default().to_owned();
    let architecture = manifest["architecture"].as_str().unwrap_or_default().to_owned();
    let limitations = capture["limitations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let observation = Observation::new(OPERATION, parameters(input), capture)
        .predicate("rea.process-capture")
        .confidence("observed")
        .authority("controlled-replay")
        .environment(json!({
            "id": format!("{platform}-{architecture}"),
            "platform": platform,
            "architecture": architecture,
            "isolation": "process",
        }))
        .limitations(limitations);
    Evidence::create(None, &provider(), observation).map_err(|error| AnalysisError::output(OPERATION, error.to_string()))
}

/// `recordProcessResidualUnknowns`.
fn record_residual_unknowns(session: &Arc<Session>, evidence: &Evidence) -> Result<(), AnalysisError> {
    let value = evidence.value();
    let environment = value["environment"].clone();
    let subject = match rea_tools_binary::port::active_target(session) {
        Some(target) => Some(serde_json::value::to_raw_value(&target.subject_json()).map_err(|error| AnalysisError::evidence_integrity(error.to_string()))?),
        None => None,
    };
    let residuals = value["normalized_result"]["residual_unknowns"].as_array().cloned().unwrap_or_default();
    for residual in residuals {
        let scope = residual["scope"].as_str().unwrap_or_default();
        let mut input = Map::new();
        input.insert("question".into(), json!(format!("Was {scope} behavior fully observed during capture? (Evidence {})", evidence.id())));
        input.insert("severity".into(), json!("medium"));
        input.insert("domain".into(), json!(format!("process-{scope}")));
        input.insert("required_authority".into(), json!("controlled-replay"));
        input.insert("required_confidence".into(), json!("observed"));
        input.insert("required_environment".into(), environment.clone());
        input.insert(
            "recommended_probes".into(),
            json!([{"operation": OPERATION, "rationale": "Repeat with a scenario that observes the missing behavior."}]),
        );
        input.insert("relationships".into(), json!([]));
        input.insert("supporting_evidence_ids".into(), json!([evidence.id()]));
        input.insert("contradicting_evidence_ids".into(), json!([]));
        let raw = serde_json::value::to_raw_value(&Value::Object(input)).map_err(|error| AnalysisError::evidence_integrity(error.to_string()))?;
        match session.records().record_unknown(&raw, subject.as_deref()) {
            Ok(_) | Err(RecordError::UnknownMutation(UnknownMutationFailure::AlreadyExists)) => {}
            Err(error) => return Err(record_error(error)),
        }
    }
    Ok(())
}

/// Handler for `capture_process_scenario`.
pub fn capture_process_scenario(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let scenario = Scenario::from_input(&input);
    let issues = refinements(&scenario);
    if !issues.is_empty() {
        return refinement_failure(context, issues);
    }
    match run(context, &scenario) {
        Ok(evidence) => ToolOutput::Evidence(evidence),
        Err(error) => ToolOutput::Failure(error),
    }
}

fn run(context: &ToolContext<'_>, input: &Scenario) -> Result<Evidence, AnalysisError> {
    if !cfg!(unix) {
        let reason = "Process capture requires a Linux or macOS host.";
        return Err(AnalysisError::capability_unavailable("rea-process", OPERATION, reason).with_user_message(reason));
    }
    let resources = context.session.state::<ProcessCaptureResources>();
    context.session.own_once(Arc::clone(&resources));
    // Admission retries resources a previous capture could not release.
    resources.retry()?;
    if context.cancellation.reason().is_some() {
        return Err(failure_error(CaptureFailure {
            message: "process capture was cancelled".to_owned(),
            cancelled: true,
            execution_failure: None,
            cleanup_report: None,
            partial_observation: None,
            retained: None,
        }));
    }
    let environment = context.session.environment().clone();
    let resolved = resolve_runtime_paths(input, &environment)?;
    let cancellation = context.cancellation.clone();
    let cancelled = move || cancellation.reason().is_some();
    let progress = |phase: &str, message: String| context.progress.report(phase, &message);
    let host = CaptureHost {
        environment: &environment,
        cancelled: &cancelled,
        progress: &progress,
    };
    let capture = match capture::run(&resolved, &host) {
        Ok(capture) => capture,
        Err(mut failure) => {
            if let Some(owner) = failure.retained.take() {
                resources.retain(owner);
            }
            return Err(failure_error(failure));
        }
    };
    let evidence = evidence(input, capture)?;
    context.session.record(&evidence)?;
    record_residual_unknowns(context.session, &evidence)?;
    Ok(evidence)
}
