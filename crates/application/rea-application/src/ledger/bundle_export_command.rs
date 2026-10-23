//! One-shot CLI workflow for validating and canonically exporting a bundle.
use crate::{
    binary::rust::Completion,
    ledger::artifact_records::ArtifactRecords,
    ledger::bundle_export::{self, BundleExporter, Input, Receipt},
    ledger::bundle_import::{self, BundleImporter},
};
use rea_core::{
    cancellation::Cancellation,
    failure::{Detail, Failure},
};
use rea_host::{fs::caller_path, fs::stable_file::FileAccess};
use std::{collections::BTreeMap, sync::Arc};

/// Validate a source bundle, retain its authenticated records, then publish a
/// canonical snapshot through the same owners used by the MCP workflow.
pub fn export_source<F: FileAccess>(
    access: Arc<F>,
    source_path: &str,
    output_path: &str,
    overwrite: bool,
    cancellation: &Cancellation,
) -> Result<Receipt, Failure> {
    let source_path = caller_path::absolute(source_path)
        .map_err(|error| path_failure(bundle_import::OPERATION, source_path, error))?;
    let records = ArtifactRecords::default();

    import_source(&records, access, &source_path, cancellation)?;

    let snapshot = records
        .snapshot()
        .map_err(|error| error.into_export_failure())?;
    let output_path = caller_path::absolute(output_path)
        .map_err(|error| path_failure(bundle_export::OPERATION, output_path, error))?;
    let input = Input {
        path: output_path,
        overwrite,
    };

    BundleExporter::export_one_shot(&snapshot, input, cancellation)
}

fn import_source<F: FileAccess>(
    records: &ArtifactRecords,
    access: Arc<F>,
    source_path: &str,
    cancellation: &Cancellation,
) -> Result<(), Failure> {
    let mut importer = BundleImporter::new(access);
    let imported = importer.import(records, source_path, cancellation, Completion::OneShot);
    let cleanup = importer.close();

    match (imported, cleanup) {
        (Ok(_), Ok(())) => Ok(()),
        (Err(primary), Ok(())) | (Ok(_), Err(primary)) => Err(primary),
        (Err(mut primary), Err(cleanup)) => {
            retain_cleanup_failure(&mut primary, cleanup);
            Err(primary)
        }
    }
}

fn retain_cleanup_failure(primary: &mut Failure, cleanup: Failure) {
    match serde_json::value::to_raw_value(&cleanup) {
        Ok(cleanup) => primary.detail("cleanup_failure", Detail::Raw(cleanup)),
        Err(encoding) => {
            primary.detail("cleanup_failure", Detail::Text(format!("{cleanup:?}")));
            primary.detail(
                "cleanup_failure_encoding",
                Detail::Text(encoding.to_string()),
            );
        }
    }
}

fn path_failure(operation: &'static str, path: &str, error: std::io::Error) -> Failure {
    Failure::new(
        "execution_failure",
        "execution_failure",
        "Evidence bundle path could not be resolved in this process.".into(),
        true,
        "Check the selected path and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(operation.into())),
            ("path", Detail::Text(path.into())),
            (
                "reason",
                Detail::Text(format!("current-directory: {}", error.kind())),
            ),
        ]),
    )
}
