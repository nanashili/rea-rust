//! Retained bundle publication. The session, not the RPC future, owns failed
//! staging cleanup. A committed file remains a fact even if cleanup fails.
use crate::ledger::artifact_records::RecordSnapshot;
use rea_core::{
    cancellation::Cancellation,
    failure::{Detail, Failure},
};
use rea_host::{
    fs::caller_path,
    fs::staged_output::{self, WriteFailure, WriteIssue},
};
use serde::Serialize;
use std::{collections::BTreeMap, path::Path};

pub const OPERATION: &str = "export_evidence_bundle";
/// Constructed by the named input parser; callers cannot bypass path admission.
pub struct Input {
    pub(crate) path: String,
    pub(crate) overwrite: bool,
}
#[derive(Serialize)]
pub struct Receipt {
    path: String,
    bytes: u64,
    records: usize,
    unknowns: usize,
}
impl Receipt {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn records(&self) -> usize {
        self.records
    }
}
#[derive(Default)]
pub struct BundleExporter {
    pending: Option<(String, WriteFailure, Option<Receipt>)>,
}
impl BundleExporter {
    pub fn export(
        &mut self,
        snapshot: &RecordSnapshot,
        input: Input,
        cancellation: &Cancellation,
    ) -> Result<Receipt, Failure> {
        self.close()?;
        // Absolute validated input cannot require a current-directory lookup.
        let path = caller_path::absolute(&input.path).map_err(|e| {
            Failure::new(
                "execution_failure",
                "execution_failure",
                e.to_string(),
                true,
                "Check the selected path.".into(),
                BTreeMap::new(),
            )
        })?;
        match staged_output::publish(Path::new(&path), input.overwrite, cancellation, |out| {
            snapshot.write_canonical(out)
        }) {
            Ok(published) => Ok(Receipt {
                path,
                bytes: published.bytes,
                records: snapshot.record_count(),
                unknowns: snapshot.unknown_revision_count(),
            }),
            Err(error) => {
                let projected = project(&path, &error);
                if error.retained.is_some() {
                    let receipt = error.outcome.as_ref().ok().map(|published| Receipt {
                        path: path.clone(),
                        bytes: published.bytes,
                        records: snapshot.record_count(),
                        unknowns: snapshot.unknown_revision_count(),
                    });
                    self.pending = Some((path, error, receipt));
                }
                Err(projected)
            }
        }
    }

    /// Retry retained staging cleanup and return a receipt when publication
    /// had already committed before cleanup failed.
    pub fn retry_cleanup(&mut self) -> Result<Option<Receipt>, Failure> {
        let Some((path, error, _)) = self.pending.as_mut() else {
            return Ok(None);
        };

        if let Err(cleanup) = error.retry_cleanup() {
            error.cleanup = Some(cleanup);
            return Err(project(path, error));
        }

        let Some((_, _, receipt)) = self.pending.take() else {
            return Ok(None);
        };
        Ok(receipt)
    }

    /// Export once, retrying post-publication cleanup before reporting failure.
    pub fn export_one_shot(
        snapshot: &RecordSnapshot,
        input: Input,
        cancellation: &Cancellation,
    ) -> Result<Receipt, Failure> {
        let mut exporter = Self::default();
        match exporter.export(snapshot, input, cancellation) {
            Ok(receipt) => Ok(receipt),
            Err(mut primary) => match exporter.retry_cleanup() {
                Ok(Some(receipt)) => Ok(receipt),
                Ok(None) => Err(primary),
                Err(cleanup) => {
                    match serde_json::value::to_raw_value(&cleanup) {
                        Ok(cleanup) => {
                            primary.detail("cleanup_retry_failure", Detail::Raw(cleanup));
                        }
                        Err(encoding) => {
                            primary.detail(
                                "cleanup_retry_failure",
                                Detail::Text(format!("{cleanup:?}")),
                            );
                            primary.detail(
                                "cleanup_retry_failure_encoding",
                                Detail::Text(encoding.to_string()),
                            );
                        }
                    }
                    Err(primary)
                }
            },
        }
    }

    pub fn close(&mut self) -> Result<(), Failure> {
        self.retry_cleanup().map(|_| ())
    }
}

fn project(path: &str, error: &WriteFailure) -> Failure {
    let (reason, underlying, category, message) = match &error.outcome {
        Ok(_) => (
            "io",
            "execution_failure",
            "execution_failure",
            "The output file was published, but staging cleanup remains incomplete.",
        ),
        Err(WriteIssue::Cancelled) => (
            "cancelled",
            "cancelled",
            "cancelled",
            "Analysis was cancelled. Start it again when ready.",
        ),
        Err(WriteIssue::Exists) => (
            "exists",
            "invalid_request",
            "invalid_input",
            "Evidence file already exists. Choose another path or allow overwrite.",
        ),
        Err(WriteIssue::NotFile) => (
            "not-file",
            "invalid_request",
            "invalid_input",
            "Evidence path does not point to a regular file. Choose a file and try again.",
        ),
        Err(WriteIssue::Io(e))
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            (
                "missing",
                "invalid_request",
                "invalid_input",
                "Evidence output directory does not exist. Choose an existing directory and try again.",
            )
        }
        Err(WriteIssue::Io(_) | WriteIssue::Encoding(_)) => (
            "io",
            "execution_failure",
            "execution_failure",
            "Evidence file could not be accessed. Check file permissions and try again.",
        ),
    };
    let mut details = BTreeMap::from([
        ("operation", Detail::Text("write".into())),
        ("reason", Detail::Text(reason.into())),
        ("path", Detail::Text(path.into())),
    ]);
    if reason == "cancelled" {
        details = BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]);
        details.insert("cleanup", Detail::Text("complete".into()));
    }
    if let Ok(published) = error.outcome {
        details.insert("published", Detail::Flag(true));
        details.insert("published_path", Detail::Text(path.into()));
        details.insert("bytes", Detail::Count(published.bytes));
    }
    if let Some(cleanup) = &error.cleanup {
        details.insert("cleanup", Detail::Text("incomplete".into()));
        details.insert("cleanup_reason", Detail::Text(cleanup.to_string()));
        details.insert("execution_failure", Detail::Text(underlying.into()));
        if let Some(directory) = &error.staging_directory {
            if let Some(path) = directory.to_str() {
                details.insert("resources", Detail::Texts(vec![path.into()]));
            } else {
                // This is a byte path, not a Unicode lookup or a file URL.
                // Preserve its exact bytes rather than substituting the output.
                let hex: String = directory
                    .as_os_str()
                    .as_encoded_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                details.insert(
                    "resource_path_encoding",
                    Detail::Text("unix-bytes-hex".into()),
                );
                details.insert("resource_path_hex", Detail::Text(hex));
            }
        }
    }
    let action = if error.outcome.is_ok() {
        "Use the published file at details.published_path and resolve the reported staging cleanup failure."
    } else {
        message
    };
    Failure::new(
        if error.cleanup.is_some() {
            "cleanup_incomplete"
        } else {
            underlying
        },
        category,
        message.into(),
        true,
        action.into(),
        details,
    )
}
