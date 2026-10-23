//! Shared stable-file lifecycle for read-only artifact analysis workflows.
//!
//! Format readers own byte interpretation and Evidence projection. This module
//! owns path admission, stable reads, cancellation, close retry, and retention.

use rea_core::{
    cancellation::Cancellation,
    evidence::{ArtifactEvidence, Provider},
    failure::{Detail, Failure, InputIssue},
};
use rea_host::fs::stable_file::{
    self, CloseFailure, FileAccess, IoKind, ReadFailure, ReadIssue, Snapshot,
};
use serde::Serialize;
use serde_json::value::RawValue;
use std::{collections::BTreeMap, fmt::Debug, path::Path, sync::Arc};

const EXECUTION_MESSAGE: &str = "Analysis could not complete. Run `rea doctor` and review the reported details; repeating the unchanged request is not expected to succeed.";
const CLEANUP_MESSAGE: &str = "Provider cleanup could not be fully confirmed. Review the reported local resources before opening another target.";

#[derive(Serialize)]
struct CleanupFailureDiagnostic {
    resource: String,
    reason: String,
    system_code: Option<&'static str>,
    resource_released: bool,
}

/// Completion determines whether failed file owners are retried immediately or
/// retained for a later request/session close.
#[derive(Clone, Copy)]
pub enum Completion {
    OneShot,
    Session,
}

/// Analysis-specific identity, limits, and projection over one stable snapshot.
pub trait ArtifactAnalyzer: Default + Send + Sync + 'static {
    const OPERATION: &'static str;
    const PROVIDER: Provider;
    const MAX_INPUT_BYTES: usize;

    fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure>;
}

/// One shared stable-file owner for all static artifact analyzers.
pub struct ArtifactInspection<F: FileAccess, A: ArtifactAnalyzer> {
    access: Arc<F>,
    analyzer: std::marker::PhantomData<A>,
    retained: Vec<(String, ReadFailure<F>)>,
    records: Arc<crate::ledger::artifact_records::ArtifactRecords>,
}

impl<F: FileAccess, A: ArtifactAnalyzer> ArtifactInspection<F, A> {
    pub fn new(access: Arc<F>) -> Self {
        Self::with_records(
            access,
            Arc::new(crate::ledger::artifact_records::ArtifactRecords::default()),
        )
    }

    pub fn with_records(
        access: Arc<F>,
        records: Arc<crate::ledger::artifact_records::ArtifactRecords>,
    ) -> Self {
        Self {
            access,
            analyzer: std::marker::PhantomData,
            retained: Vec::new(),
            records,
        }
    }

    pub fn records(&self) -> &Arc<crate::ledger::artifact_records::ArtifactRecords> {
        &self.records
    }

    /// Retry every retained owner, preserving owners whose cleanup still fails.
    pub fn close(&mut self) -> Result<(), Failure> {
        self.close_for(A::OPERATION)
    }

    fn close_for(&mut self, operation: &'static str) -> Result<(), Failure> {
        close_retained_read_failures(&mut self.retained, operation, A::PROVIDER)
    }

    /// Run one complete static inspection and retain its Evidence when requested.
    pub fn inspect(
        &mut self,
        path: &str,
        cancellation: &Cancellation,
        completion: Completion,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        self.inspect_with(
            path,
            A::MAX_INPUT_BYTES,
            cancellation,
            completion,
            |path, snapshot, _| A::build_evidence(path, snapshot),
        )
    }

    /// Run an analyzer with caller-selected input bounds and request context.
    /// Specialized static workflows use this to preserve the same file owner
    /// while applying operation-specific budgets and cooperative cancellation.
    pub fn inspect_with(
        &mut self,
        path: &str,
        maximum_bytes: usize,
        cancellation: &Cancellation,
        completion: Completion,
        analyze: impl FnOnce(&str, Snapshot, &Cancellation) -> Result<Arc<ArtifactEvidence>, Failure>,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        self.inspect_with_operation(
            A::OPERATION,
            path,
            maximum_bytes,
            cancellation,
            completion,
            analyze,
        )
    }

    /// Run an analyzer while preserving the selected workflow's operation
    /// identity through request validation, cancellation, and cleanup.
    pub fn inspect_with_operation(
        &mut self,
        operation: &'static str,
        path: &str,
        maximum_bytes: usize,
        cancellation: &Cancellation,
        completion: Completion,
        analyze: impl FnOnce(&str, Snapshot, &Cancellation) -> Result<Arc<ArtifactEvidence>, Failure>,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        self.inspect_with_operation_and_read_failure_projection(
            operation,
            path,
            maximum_bytes,
            cancellation,
            completion,
            analyze,
            |issue, path| read_failure(operation, A::PROVIDER, issue, path),
        )
    }

    /// Run an analyzer with an operation-specific projection for stable-read failures.
    ///
    /// File ownership, cleanup retry, and session retention remain shared. The
    /// projection only changes the caller-facing interpretation of the initial
    /// read issue, which lets workflows preserve their own selected limits.
    pub fn inspect_with_read_failure_projection(
        &mut self,
        path: &str,
        maximum_bytes: usize,
        cancellation: &Cancellation,
        completion: Completion,
        analyze: impl FnOnce(&str, Snapshot, &Cancellation) -> Result<Arc<ArtifactEvidence>, Failure>,
        project_read_issue: impl Fn(&ReadIssue, &str) -> Failure,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        self.inspect_with_operation_and_read_failure_projection(
            A::OPERATION,
            path,
            maximum_bytes,
            cancellation,
            completion,
            analyze,
            project_read_issue,
        )
    }

    fn inspect_with_operation_and_read_failure_projection(
        &mut self,
        operation: &'static str,
        path: &str,
        maximum_bytes: usize,
        cancellation: &Cancellation,
        completion: Completion,
        analyze: impl FnOnce(&str, Snapshot, &Cancellation) -> Result<Arc<ArtifactEvidence>, Failure>,
        project_read_issue: impl Fn(&ReadIssue, &str) -> Failure,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        validate_request(operation, path, cancellation)?;
        self.close_for(operation)?;

        if maximum_bytes == 0 || maximum_bytes > A::MAX_INPUT_BYTES {
            return Err(invalid_for(
                operation,
                "invalid_value",
                format!(
                    "The requested file-read limit must be between 1 and {} bytes.",
                    A::MAX_INPUT_BYTES
                ),
            ));
        }

        let snapshot = self.read_snapshot_with_limit_and_projection(
            path,
            maximum_bytes,
            cancellation,
            completion,
            &project_read_issue,
            operation,
        )?;
        ensure_active(operation, cancellation)?;

        let evidence = analyze(path, snapshot, cancellation)?;
        self.record_if_session(&evidence, completion)?;
        return_evidence_or_cancellation(operation, evidence, cancellation)
    }

    #[cfg(test)]
    pub(crate) fn read_snapshot(
        &mut self,
        path: &str,
        cancellation: &Cancellation,
        completion: Completion,
    ) -> Result<Snapshot, Failure> {
        self.read_snapshot_with_limit(path, A::MAX_INPUT_BYTES, cancellation, completion)
    }

    #[cfg(test)]
    fn read_snapshot_with_limit(
        &mut self,
        path: &str,
        maximum_bytes: usize,
        cancellation: &Cancellation,
        completion: Completion,
    ) -> Result<Snapshot, Failure> {
        self.read_snapshot_with_limit_and_projection(
            path,
            maximum_bytes,
            cancellation,
            completion,
            &|issue, path| read_failure(A::OPERATION, A::PROVIDER, issue, path),
            A::OPERATION,
        )
    }

    fn read_snapshot_with_limit_and_projection(
        &mut self,
        path: &str,
        maximum_bytes: usize,
        cancellation: &Cancellation,
        completion: Completion,
        project_read_issue: &impl Fn(&ReadIssue, &str) -> Failure,
        operation: &'static str,
    ) -> Result<Snapshot, Failure> {
        match stable_file::read(
            self.access.clone(),
            Path::new(path),
            maximum_bytes,
            cancellation,
        ) {
            Ok(snapshot) => Ok(snapshot),
            Err(failure) => Err(self.project_read_failure(
                operation,
                path,
                completion,
                *failure,
                project_read_issue,
            )),
        }
    }

    fn project_read_failure(
        &mut self,
        operation: &'static str,
        path: &str,
        completion: Completion,
        failure: ReadFailure<F>,
        project_read_issue: &impl Fn(&ReadIssue, &str) -> Failure,
    ) -> Failure {
        project_retained_read_failure(
            &mut self.retained,
            operation,
            A::PROVIDER,
            path,
            completion,
            failure,
            project_read_issue,
            None,
        )
    }

    fn record_if_session(
        &self,
        evidence: &Arc<ArtifactEvidence>,
        completion: Completion,
    ) -> Result<(), Failure> {
        if !matches!(completion, Completion::Session) {
            return Ok(());
        }

        self.records
            .record(evidence.clone())
            .map_err(crate::ledger::artifact_records::RecordError::into_failure)
    }
}

/// Project a stable-read failure while preserving the exact cleanup owner.
///
/// Specialized artifact readers use the same lifecycle settlement as the
/// shared analyzer. They may attach an operation-specific partial observation
/// when the stable reader completed bytes before cancellation or cleanup
/// failed.
pub(crate) fn project_retained_read_failure<F: FileAccess>(
    retained: &mut Vec<(String, ReadFailure<F>)>,
    operation: &'static str,
    provider: Provider,
    path: &str,
    completion: Completion,
    mut failure: ReadFailure<F>,
    project_read_issue: impl Fn(&ReadIssue, &str) -> Failure,
    partial_observation: Option<&RawValue>,
) -> Failure {
    let retry = if matches!(completion, Completion::OneShot) && failure.retained.is_some() {
        Some(failure.retry_cleanup())
    } else {
        None
    };

    let primary = failure
        .primary
        .as_ref()
        .map(|issue| project_read_issue(issue, path));
    let unresolved = failure.retained.is_some();
    let mut projected = match (unresolved, primary) {
        (true, Some(primary)) => {
            let reason = latest_cleanup_reason(&failure);
            let mut projected = cleanup(operation, provider, vec![path.to_owned()], reason);
            attach_failure(&mut projected, "primary_failure", &primary);
            projected
        }
        (true, None) => cleanup(
            operation,
            provider,
            vec![path.to_owned()],
            latest_cleanup_reason(&failure),
        ),
        (false, Some(primary)) => primary,
        (false, None) => execution(operation, provider, path, latest_cleanup_reason(&failure)),
    };

    let diagnostics = cleanup_failure_diagnostics(path, &failure.cleanup_failures);
    if !diagnostics.is_empty() {
        attach_cleanup_failure_diagnostics(&mut projected, diagnostics);
    }

    attach_partial_observation(&mut projected, partial_observation);
    attach_cleanup_retry(&mut projected, retry);

    if unresolved {
        retained.push((path.to_owned(), failure));
    }

    projected
}

/// Retry and retain every stable-file owner using the shared cleanup contract.
pub(crate) fn close_retained_read_failures<F: FileAccess>(
    retained: &mut Vec<(String, ReadFailure<F>)>,
    operation: &'static str,
    provider: Provider,
) -> Result<(), Failure> {
    let mut failed_attempts = Vec::new();

    for (path, failure) in retained.iter_mut() {
        if let Err(error) = failure.retry_cleanup() {
            let previous_attempts = failure.cleanup_failures.len().saturating_sub(1);
            failed_attempts.extend(cleanup_failure_diagnostics(
                path,
                &failure.cleanup_failures[..previous_attempts],
            ));
            failed_attempts.push(cleanup_failure_diagnostic(path, &error));
        }
    }

    retained.retain(|(_, failure)| failure.retained.is_some());

    if failed_attempts.is_empty() {
        return Ok(());
    }

    let reason = describe_cleanup_failures(&failed_attempts);
    let unresolved_resources = retained
        .iter()
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    let mut projected = if unresolved_resources.is_empty() {
        execution(
            operation,
            provider,
            failed_attempts
                .first()
                .map(|failure| failure.resource.as_str())
                .unwrap_or_default(),
            reason,
        )
    } else {
        cleanup(operation, provider, unresolved_resources, reason)
    };
    attach_cleanup_failure_diagnostics(&mut projected, failed_attempts);
    Err(projected)
}

fn attach_partial_observation(projected: &mut Failure, observation: Option<&RawValue>) {
    let Some(observation) = observation else {
        return;
    };

    if let Err(error) = projected.retain(observation) {
        projected.detail("partial_observation_failure", text(error.to_string()));
    }
}

fn attach_cleanup_retry(projected: &mut Failure, retry: Option<Result<(), CloseFailure>>) {
    match retry {
        Some(Ok(())) => projected.detail("cleanup_retry", text("released")),
        Some(Err(error)) => {
            let state = if error.resource_released {
                "released_with_error"
            } else {
                "retained"
            };
            projected.detail(
                "cleanup_retry",
                Detail::Fields(BTreeMap::from([
                    ("state", text(state)),
                    ("reason", text(error.error.to_string())),
                ])),
            );
        }
        None => {}
    }
}

fn validate_request(
    operation: &'static str,
    path: &str,
    cancellation: &Cancellation,
) -> Result<(), Failure> {
    if let Some(reason) = cancellation.reason() {
        return Err(cancelled(operation, Some(reason)));
    }
    if path.contains('\0') || !Path::new(path).is_absolute() {
        return Err(invalid_for(
            operation,
            "invalid_format",
            "Expected an absolute filesystem path on this host.".into(),
        ));
    }

    Ok(())
}

fn ensure_active(operation: &'static str, cancellation: &Cancellation) -> Result<(), Failure> {
    if let Some(reason) = cancellation.reason() {
        return Err(cancelled(operation, Some(reason)));
    }

    Ok(())
}

fn return_evidence_or_cancellation(
    operation: &'static str,
    evidence: Arc<ArtifactEvidence>,
    cancellation: &Cancellation,
) -> Result<Arc<ArtifactEvidence>, Failure> {
    let Some(reason) = cancellation.reason() else {
        return Ok(evidence);
    };

    let mut failure = cancelled(operation, Some(reason));
    attach_failure(&mut failure, "partial_observation", evidence.as_ref());
    Err(failure)
}

fn details(operation: &'static str) -> BTreeMap<&'static str, Detail> {
    BTreeMap::from([("operation", text(operation))])
}

pub fn invalid_for(operation: &'static str, reason: &'static str, message: String) -> Failure {
    let mut fields = details(operation);
    fields.insert(
        "issues",
        Detail::Issues(vec![InputIssue {
            path: vec!["path".into()],
            reason,
            message,
            expected: None,
        }]),
    );
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Analysis input is invalid. Check the arguments and try again.".into(),
        true,
        "Correct the listed arguments and retry.".into(),
        fields,
    )
}

fn cancelled(operation: &'static str, reason: Option<&str>) -> Failure {
    let mut fields = details(operation);
    fields.insert("cleanup", text("complete"));
    if let Some(reason) = reason {
        fields.insert("cancellation_reason", text(reason));
    }
    let message = "Analysis was cancelled. Start it again when ready.";
    Failure::new(
        "cancelled",
        "cancelled",
        message.into(),
        true,
        message.into(),
        fields,
    )
}

fn execution(operation: &'static str, provider: Provider, path: &str, reason: String) -> Failure {
    let mut fields = details(operation);
    fields.insert("provider_id", text(provider.id));
    fields.insert(
        "diagnostics",
        Detail::Fields(BTreeMap::from([
            ("path", text(path)),
            ("reason", text(reason)),
        ])),
    );
    Failure::new(
        "execution_failure",
        "execution_failure",
        EXECUTION_MESSAGE.into(),
        false,
        EXECUTION_MESSAGE.into(),
        fields,
    )
}

fn cleanup(
    operation: &'static str,
    provider: Provider,
    resources: Vec<String>,
    reason: String,
) -> Failure {
    let mut fields = details(operation);
    fields.insert("provider_id", text(provider.id));
    fields.insert("cleanup", text("incomplete"));
    fields.insert("resources", Detail::Texts(resources));
    fields.insert(
        "diagnostics",
        Detail::Fields(BTreeMap::from([("reason", text(reason))])),
    );
    fields.insert("execution_failure", text("execution_failure"));
    Failure::new(
        "cleanup_incomplete",
        "execution_failure",
        CLEANUP_MESSAGE.into(),
        false,
        CLEANUP_MESSAGE.into(),
        fields,
    )
}

fn resource(
    operation: &'static str,
    kind: &'static str,
    reason: String,
    limit: &'static str,
    maximum: usize,
) -> Failure {
    let mut fields = details(operation);
    fields.insert("resource", text(kind));
    fields.insert("reason", text(reason.clone()));
    fields.insert(
        "reported_limits",
        Detail::Fields(BTreeMap::from([(limit, Detail::Count(maximum as u64))])),
    );
    let action = match kind {
        "capacity" => {
            "Wait for an active analysis to complete, then retry within the reported admission limits."
        }
        "transport" => {
            "Discover retained records with get_evidence_bundle and detail: summary, then inspect compatible records through inspect_analysis_view using an exact Evidence reference. Export complete retained session evidence through export_evidence_bundle to a caller-selected path, or use complete CLI JSON output. The connection remains usable."
        }
        "file-size" => {
            "Review the reported worker file-size limits and write failure. Retry with a sufficient file-size allowance for the evidence reply; REA retains tighter inherited limits."
        }
        _ => {
            "Review the reported worker memory limits and available host memory. Retry with sufficient memory or a smaller artifact; REA retains tighter inherited limits."
        }
    };
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        reason,
        kind == "capacity",
        action.into(),
        fields,
    )
}

pub(crate) fn read_failure(
    operation: &'static str,
    provider: Provider,
    issue: &ReadIssue,
    path: &str,
) -> Failure {
    match issue {
        ReadIssue::Cancelled(reason) => cancelled(operation, Some(reason)),
        ReadIssue::InvalidPath => invalid_for(
            operation,
            "invalid_format",
            format!("Expected a regular file without a symlink: {path}"),
        ),
        ReadIssue::Limit { maximum_bytes } => resource(
            operation,
            "file-size",
            format!("Selected artifact exceeds {maximum_bytes} bytes: {path}"),
            "maximum_input_bytes",
            *maximum_bytes,
        ),
        ReadIssue::Allocation { requested_bytes } => resource(
            operation,
            "memory",
            format!("Could not allocate admitted artifact storage for {path}"),
            "maximum_bytes",
            *requested_bytes,
        ),
        ReadIssue::Changed(stage) => {
            let mut fields = details(operation);
            fields.insert("path", text(path));
            fields.insert("reason", text(format!("Artifact changed {stage}: {path}")));
            fields.insert("boundary", text("stable-artifact-read"));
            Failure::new(
                "artifact_changed",
                "integrity_mismatch",
                "The selected artifact changed during acquisition; no stable snapshot was decoded."
                    .into(),
                true,
                "Wait until the selected file is stable. For an active binary session, reopen the target with open_binary before retrying so REA acquires its current identity; for a CLI command or target-free tool, rerun the operation."
                    .into(),
                fields,
            )
        }
        ReadIssue::Io { error, .. }
            if matches!(
                error.kind,
                IoKind::NotFound | IoKind::NotDirectory | IoKind::SymlinkLoop | IoKind::NameTooLong
            ) =>
        {
            invalid_for(
                operation,
                "invalid_value",
                format!(
                    "Selected artifact could not be read ({}): {path}.",
                    error.system_code.unwrap_or("unknown")
                ),
            )
        }
        ReadIssue::Io { stage, error } if error.kind == IoKind::AccessDenied => {
            let mut fields = details(operation);
            fields.insert("path", text(path));
            fields.insert("system_code", text(error.system_code.unwrap_or("unknown")));
            fields.insert("stage", text(*stage));
            fields.insert("boundary", text("filesystem-read"));
            Failure::new(
                "access_denied",
                "unavailable",
                "Host filesystem permissions denied read access to the selected path.".into(),
                false,
                "Check the current process's read access to the selected path. Retry with a readable local file."
                    .into(),
                fields,
            )
        }
        ReadIssue::Io { error, .. } => execution(operation, provider, path, error.to_string()),
        ReadIssue::InvalidRead => execution(
            operation,
            provider,
            path,
            "Artifact stream did not return admitted bytes".into(),
        ),
    }
}

fn cleanup_failure_diagnostic(resource: &str, failure: &CloseFailure) -> CleanupFailureDiagnostic {
    CleanupFailureDiagnostic {
        resource: resource.to_owned(),
        reason: failure.error.to_string(),
        system_code: failure.error.system_code,
        resource_released: failure.resource_released,
    }
}

fn cleanup_failure_diagnostics(
    resource: &str,
    failures: &[CloseFailure],
) -> Vec<CleanupFailureDiagnostic> {
    failures
        .iter()
        .map(|failure| cleanup_failure_diagnostic(resource, failure))
        .collect()
}

fn describe_cleanup_failures(failures: &[CleanupFailureDiagnostic]) -> String {
    failures
        .iter()
        .map(|failure| format!("{}: {}", failure.resource, failure.reason))
        .collect::<Vec<_>>()
        .join("; ")
}

fn attach_cleanup_failure_diagnostics(
    projected: &mut Failure,
    diagnostics: Vec<CleanupFailureDiagnostic>,
) {
    match serde_json::value::to_raw_value(&diagnostics) {
        Ok(diagnostics) => {
            projected.detail("cleanup_failures", Detail::Raw(diagnostics));
        }
        Err(error) => {
            let descriptions = diagnostics
                .iter()
                .map(|failure| {
                    format!(
                        "{}: {} (system code: {}; resource released: {})",
                        failure.resource,
                        failure.reason,
                        failure.system_code.unwrap_or("unknown"),
                        failure.resource_released
                    )
                })
                .collect();
            projected.detail("cleanup_failures", Detail::Texts(descriptions));
            projected.detail("cleanup_failure_encoding", text(error.to_string()));
        }
    }
}

fn attach_failure<T: Serialize + Debug>(projected: &mut Failure, name: &'static str, value: &T) {
    match serde_json::value::to_raw_value(value) {
        Ok(value) => projected.detail(name, Detail::Raw(value)),
        Err(error) => {
            projected.detail(name, text(format!("{value:?}")));
            projected.detail("detail_encoding_failure", text(error.to_string()));
        }
    }
}

fn latest_cleanup_reason<F: FileAccess>(failure: &ReadFailure<F>) -> String {
    failure
        .latest_cleanup_failure()
        .map(|failure| failure.error.to_string())
        .unwrap_or_else(|| "file read did not complete".into())
}

fn text(value: impl Into<String>) -> Detail {
    Detail::Text(value.into())
}
