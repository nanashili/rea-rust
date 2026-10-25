//! Stable local-file import for canonical Evidence bundles.

use crate::binary::rust::Completion;
use crate::ledger::artifact_records::{ArtifactRecords, ImportReceipt, RecordError};
use rea_core::{
    cancellation::Cancellation,
    evidence::{
        bundle::{EvidenceBundle, EvidenceBundleError},
        record::EvidenceRecordError,
    },
    failure::{Detail, Failure},
};
use rea_host::fs::stable_file::{self, FileAccess, IoKind, ReadFailure, ReadIssue};
use serde::Serialize;
use serde_json::{Value, value::RawValue};
use std::{collections::BTreeMap, path::Path, sync::Arc};

pub const OPERATION: &str = "import_evidence_bundle";
pub const MAX_BUNDLE_BYTES: usize = 256 * 1024 * 1024;
const FAILURE_MESSAGE: &str =
    "Evidence bundle import failed. Check the selected local file and try again.";

#[derive(Serialize)]
struct CleanupFailureDiagnostic {
    resource: String,
    reason: String,
    system_code: Option<&'static str>,
    resource_released: bool,
}

/// Owns failed file releases until cleanup succeeds or the server ends.
pub struct BundleImporter<F: FileAccess> {
    access: Arc<F>,
    retained: Vec<(String, &'static str, ReadFailure<F>)>,
}

impl<F: FileAccess> BundleImporter<F> {
    pub fn new(access: Arc<F>) -> Self {
        Self {
            access,
            retained: Vec::new(),
        }
    }

    /// Retry every retained release; independent owners are all attempted.
    pub fn close(&mut self) -> Result<(), Failure> {
        let mut failed_attempts = Vec::new();
        let mut operation = None;

        for (path, retained_operation, failure) in &mut self.retained {
            if let Err(error) = failure.retry_cleanup() {
                operation.get_or_insert(*retained_operation);
                let previous_attempts = failure.cleanup_failures.len().saturating_sub(1);
                failed_attempts.extend(cleanup_failure_diagnostics(
                    path,
                    &failure.cleanup_failures[..previous_attempts],
                ));
                failed_attempts.push(cleanup_failure_diagnostic(path, &error));
            }
        }

        self.retained
            .retain(|(_, _, failure)| failure.retained.is_some());

        if failed_attempts.is_empty() {
            return Ok(());
        }

        let operation = operation.unwrap_or(OPERATION);
        let reason = describe_cleanup_failures(&failed_attempts);
        let unresolved = self
            .retained
            .iter()
            .map(|(path, _, _)| path.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let unresolved_failures = failed_attempts
            .iter()
            .filter(|failure| {
                !failure.resource_released && unresolved.contains(failure.resource.as_str())
            })
            .map(|failure| (failure.resource.clone(), failure.reason.clone()))
            .collect::<Vec<_>>();
        let mut projected = if unresolved_failures.is_empty() {
            execution_failure(
                operation,
                failed_attempts
                    .first()
                    .map(|failure| failure.resource.as_str())
                    .unwrap_or_default(),
                reason,
            )
        } else {
            cleanup_failure(operation, unresolved_failures)
        };
        attach_cleanup_failure_diagnostics(&mut projected, failed_attempts);
        Err(projected)
    }

    /// Read, authenticate, then atomically merge the complete bundle.
    pub fn import(
        &mut self,
        records: &ArtifactRecords,
        path: &str,
        cancellation: &Cancellation,
        completion: Completion,
    ) -> Result<ImportReceipt, Failure> {
        let bundle = self.load(path, cancellation, completion)?;
        records
            .import(bundle)
            .map_err(RecordError::into_import_failure)
    }

    /// Read and authenticate a complete bundle while retaining cleanup ownership.
    pub fn load(
        &mut self,
        path: &str,
        cancellation: &Cancellation,
        completion: Completion,
    ) -> Result<EvidenceBundle, Failure> {
        self.load_with_operation(path, cancellation, completion, OPERATION)
    }

    /// Read and authenticate a bundle with the owning caller's failure identity.
    pub fn load_with_operation(
        &mut self,
        path: &str,
        cancellation: &Cancellation,
        completion: Completion,
        operation: &'static str,
    ) -> Result<EvidenceBundle, Failure> {
        if let Some(reason) = cancellation.reason() {
            return Err(cancelled(operation, Some(reason)));
        }
        validate_path(path, operation)?;
        self.close()?;

        let snapshot = match stable_file::read(
            self.access.clone(),
            Path::new(path),
            MAX_BUNDLE_BYTES,
            cancellation,
        ) {
            Ok(snapshot) => snapshot,
            Err(mut failure) => {
                let retry =
                    if matches!(completion, Completion::OneShot) && failure.retained.is_some() {
                        Some(failure.retry_cleanup())
                    } else {
                        None
                    };
                let mut projected = read_failure(&failure, path, operation);
                attach_cleanup_failure_diagnostics(
                    &mut projected,
                    cleanup_failure_diagnostics(path, &failure.cleanup_failures),
                );
                attach_cleanup_retry(&mut projected, retry);
                if failure.retained.is_some() {
                    self.retained.push((path.to_owned(), operation, *failure));
                }
                return Err(projected);
            }
        };

        if let Some(reason) = cancellation.reason() {
            return Err(cancelled(operation, Some(reason)));
        }

        let source = String::from_utf8(snapshot.bytes).map_err(|error| {
            integrity_failure(
                operation,
                format!("Evidence bundle is not valid UTF-8: {error}"),
            )
        })?;
        let raw = RawValue::from_string(source).map_err(|error| {
            integrity_failure(
                operation,
                format!("Evidence bundle is not valid JSON: {error}"),
            )
        })?;
        let bundle = EvidenceBundle::parse(&raw).map_err(|error| {
            let (reason, schema_path) = bundle_validation_details(&error);
            integrity_failure_with_path(operation, reason, schema_path)
        })?;

        if let Some(reason) = cancellation.reason() {
            return Err(cancelled(operation, Some(reason)));
        }
        Ok(bundle)
    }
}

fn validate_path(path: &str, operation: &'static str) -> Result<(), Failure> {
    if path.contains('\0') {
        return Err(invalid_path(
            operation,
            "invalid_format",
            "Local filesystem paths cannot contain NUL".into(),
        ));
    }
    if !Path::new(path).is_absolute() {
        return Err(invalid_path(
            operation,
            "invalid_value",
            "path must be an absolute local filesystem path (for example /tmp/evidence.json or C:\\rea\\evidence.json)".into(),
        ));
    }
    Ok(())
}

fn read_failure<F: FileAccess>(
    failure: &ReadFailure<F>,
    path: &str,
    operation: &'static str,
) -> Failure {
    if failure.retained.is_some() {
        let reason = failure
            .latest_cleanup_failure()
            .map(|cleanup| cleanup.error.to_string())
            .unwrap_or_else(|| "file release was not confirmed".into());
        return cleanup_failure(operation, vec![(path.to_owned(), reason)]);
    }

    match failure.primary.as_ref() {
        Some(ReadIssue::Cancelled(reason)) => cancelled(operation, Some(reason)),
        Some(ReadIssue::InvalidPath) => invalid_path(
            operation,
            "invalid_format",
            format!("Expected a regular file without a symlink: {path}"),
        ),
        Some(ReadIssue::Limit { maximum_bytes }) => resource_failure(
            operation,
            "file-size",
            format!("Evidence bundle exceeds {maximum_bytes} bytes: {path}"),
            "maximum_input_bytes",
            *maximum_bytes,
        ),
        Some(ReadIssue::Allocation { requested_bytes }) => resource_failure(
            operation,
            "memory",
            format!("Could not allocate admitted Evidence bundle storage for {path}"),
            "maximum_bytes",
            *requested_bytes,
        ),
        Some(ReadIssue::Changed(stage)) => Failure::new(
            "artifact_changed",
            "integrity_mismatch",
            "The selected Evidence bundle changed during acquisition; no result was produced."
                .into(),
            true,
            "Wait until the selected file is stable, then retry.".into(),
            BTreeMap::from([
                ("operation", Detail::Text(operation.into())),
                ("path", Detail::Text(path.into())),
                (
                    "reason",
                    Detail::Text(format!("Evidence bundle changed {stage}")),
                ),
                (
                    "boundary",
                    Detail::Text("stable-evidence-bundle-read".into()),
                ),
            ]),
        ),
        Some(ReadIssue::Io { error, .. })
            if matches!(
                error.kind,
                IoKind::NotFound | IoKind::NotDirectory | IoKind::SymlinkLoop | IoKind::NameTooLong
            ) =>
        {
            invalid_path(
                operation,
                "invalid_value",
                format!(
                    "Selected Evidence bundle could not be read ({}): {path}",
                    error.system_code.unwrap_or("unknown")
                ),
            )
        }
        Some(ReadIssue::Io { error, .. }) if error.kind == IoKind::AccessDenied => Failure::new(
            "access_denied",
            "unavailable",
            "Host filesystem permissions denied read access to the selected Evidence bundle."
                .into(),
            false,
            "Check the current process's read access to the selected path.".into(),
            BTreeMap::from([
                ("operation", Detail::Text(operation.into())),
                ("path", Detail::Text(path.into())),
                (
                    "system_code",
                    Detail::Text(error.system_code.unwrap_or("unknown").into()),
                ),
                ("boundary", Detail::Text("filesystem-read".into())),
            ]),
        ),
        Some(ReadIssue::Io { error, .. }) => execution_failure(operation, path, error.to_string()),
        Some(ReadIssue::InvalidRead) => execution_failure(
            operation,
            path,
            "Evidence bundle stream did not return admitted bytes".into(),
        ),
        None => execution_failure(
            operation,
            path,
            failure
                .latest_cleanup_failure()
                .map(|cleanup| cleanup.error.to_string())
                .unwrap_or_else(|| "Evidence bundle read did not complete".into()),
        ),
    }
}

fn invalid_path(operation: &'static str, reason: &'static str, message: String) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Analysis input is invalid. Check the arguments and try again.".into(),
        true,
        "Correct the listed arguments and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(operation.into())),
            (
                "issues",
                Detail::Issues(vec![rea_core::failure::InputIssue {
                    path: vec!["path".into()],
                    reason,
                    message,
                    expected: None,
                }]),
            ),
        ]),
    )
}

fn cancelled(operation: &'static str, reason: Option<&str>) -> Failure {
    let message = if operation == OPERATION {
        "Evidence bundle import was cancelled. No records were imported."
    } else {
        "Evidence bundle comparison was cancelled. No comparison was produced."
    };
    let mut details = BTreeMap::from([
        ("operation", Detail::Text(operation.into())),
        ("cleanup", Detail::Text("complete".into())),
    ]);
    if let Some(reason) = reason {
        details.insert("cancellation_reason", Detail::Text(reason.into()));
    }
    Failure::new(
        "cancelled",
        "cancelled",
        message.into(),
        true,
        "Start the operation again when ready.".into(),
        details,
    )
}

fn cleanup_failure_diagnostic(
    resource: &str,
    failure: &rea_host::fs::stable_file::CloseFailure,
) -> CleanupFailureDiagnostic {
    CleanupFailureDiagnostic {
        resource: resource.to_owned(),
        reason: failure.error.to_string(),
        system_code: failure.error.system_code,
        resource_released: failure.resource_released,
    }
}

fn cleanup_failure_diagnostics(
    resource: &str,
    failures: &[rea_host::fs::stable_file::CloseFailure],
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
            projected.detail("cleanup_failure_encoding", Detail::Text(error.to_string()));
        }
    }
}

fn attach_cleanup_retry(
    projected: &mut Failure,
    retry: Option<Result<(), rea_host::fs::stable_file::CloseFailure>>,
) {
    match retry {
        Some(Ok(())) => projected.detail("cleanup_retry", Detail::Text("released".into())),
        Some(Err(error)) => {
            let state = if error.resource_released {
                "released_with_error"
            } else {
                "retained"
            };
            projected.detail(
                "cleanup_retry",
                Detail::Fields(BTreeMap::from([
                    ("state", Detail::Text(state.into())),
                    ("reason", Detail::Text(error.error.to_string())),
                ])),
            );
        }
        None => {}
    }
}

fn integrity_failure(operation: &'static str, reason: String) -> Failure {
    integrity_failure_with_path(operation, reason, None)
}

fn integrity_failure_with_path(
    operation: &'static str,
    reason: String,
    schema_path: Option<String>,
) -> Failure {
    let message = match operation {
        OPERATION => "Evidence bundle validation failed. No records were imported.".to_owned(),
        "compare_bundles" => comparison_integrity_message(&reason),
        _ => "Evidence bundle validation failed. No comparison was produced.".to_owned(),
    };
    let action = if operation == "compare_bundles" {
        message.clone()
    } else {
        "Recreate or re-export the bundle, then try again.".to_owned()
    };
    Failure::new(
        "evidence_integrity_mismatch",
        "integrity_mismatch",
        message,
        false,
        action,
        {
            let mut details = BTreeMap::from([
                ("operation", Detail::Text(operation.into())),
                (
                    "reason",
                    Detail::Text(if operation == "compare_bundles" {
                        "Evidence bundle validation failed".into()
                    } else {
                        reason.clone()
                    }),
                ),
            ]);
            if operation != "compare_bundles" {
                details.insert("validation_reason", Detail::Text(reason));
            }
            if let Some(path) = schema_path {
                details.insert("schema_path", Detail::Text(path));
            }
            details
        },
    )
}

fn bundle_validation_details(error: &EvidenceBundleError) -> (String, Option<String>) {
    let EvidenceBundleError::RecordAt { index, error } = error else {
        return (error.to_string(), None);
    };
    let field_path = match error {
        EvidenceRecordError::Shape(issues) => issues.first().and_then(|issue| {
            let fields = issue.path.iter().map(Value::to_string).collect::<Vec<_>>();
            (!fields.is_empty()).then(|| fields.join("."))
        }),
        EvidenceRecordError::SemanticIdMismatch => Some("evidence_id".to_owned()),
        _ => None,
    };
    (
        error.to_string(),
        field_path.map(|field| format!("records.{index}.{field}")),
    )
}

fn comparison_integrity_message(reason: &str) -> String {
    let Some(field) = reason
        .strip_prefix("missing field `")
        .and_then(|value| value.split('`').next())
    else {
        return format!(
            "Evidence bundle validation failed: {reason}. Recreate or re-export the bundle, then try again."
        );
    };

    let missing_fields = [
        "artifacts",
        "providers",
        "environments",
        "scenarios",
        "captures",
        "unknowns",
        "records",
    ];
    let remaining = missing_fields
        .iter()
        .position(|candidate| *candidate == field)
        .map(|index| missing_fields.len().saturating_sub(index + 1))
        .unwrap_or(0);
    let suffix = if remaining == 0 {
        String::new()
    } else {
        format!(" ({remaining} more issues)")
    };
    format!(
        "Evidence bundle does not match the bundle schema at {field}: Invalid input: expected array, received undefined{suffix}. Supply an unmodified bundle written by export_evidence_bundle or rea evidence-export."
    )
}

fn resource_failure(
    operation: &'static str,
    resource: &'static str,
    reason: String,
    limit: &'static str,
    maximum: usize,
) -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        reason.clone(),
        false,
        "Select a smaller bundle that fits the native input limit.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(operation.into())),
            ("resource", Detail::Text(resource.into())),
            ("reason", Detail::Text(reason)),
            (
                "reported_limits",
                Detail::Fields(BTreeMap::from([(limit, Detail::Count(maximum as u64))])),
            ),
        ]),
    )
}

fn execution_failure(operation: &'static str, path: &str, reason: String) -> Failure {
    let message = if operation == OPERATION {
        FAILURE_MESSAGE
    } else {
        "Evidence bundle comparison failed. Check the selected local files and try again."
    };
    Failure::new(
        "execution_failure",
        "execution_failure",
        message.into(),
        false,
        message.into(),
        BTreeMap::from([
            ("operation", Detail::Text(operation.into())),
            (
                "diagnostics",
                Detail::Fields(BTreeMap::from([
                    ("path", Detail::Text(path.into())),
                    ("reason", Detail::Text(reason)),
                ])),
            ),
        ]),
    )
}

fn cleanup_failure(operation: &'static str, resources: Vec<(String, String)>) -> Failure {
    let paths = resources.iter().map(|(path, _)| path.clone()).collect();
    let reason = resources
        .into_iter()
        .map(|(path, reason)| format!("{path}: {reason}"))
        .collect::<Vec<_>>()
        .join("; ");
    Failure::new(
        "cleanup_incomplete",
        "execution_failure",
        "Evidence bundle file cleanup could not be confirmed.".into(),
        false,
        "Retry after reviewing the local file owner; a live descriptor may still be retained."
            .into(),
        BTreeMap::from([
            ("operation", Detail::Text(operation.into())),
            ("cleanup", Detail::Text("incomplete".into())),
            ("resources", Detail::Texts(paths)),
            ("reason", Detail::Text(reason)),
        ]),
    )
}
