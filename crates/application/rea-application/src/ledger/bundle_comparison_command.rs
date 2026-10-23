//! Read-only comparison of two caller-selected, authenticated Evidence bundles.

use crate::{binary::rust::Completion, ledger::bundle_import::BundleImporter};
use rea_core::{
    cancellation::Cancellation,
    evidence::bundle_comparison::{self, BundleComparison, BundleComparisonError},
    failure::{Detail, Failure},
};
use rea_host::{fs::caller_path, fs::stable_file::FileAccess};
use std::{collections::BTreeMap, sync::Arc};

pub const OPERATION: &str = "compare_bundles";

/// Load two caller-selected bundles and compare their authenticated contents.
pub fn compare_files<F: FileAccess>(
    access: Arc<F>,
    left_path: &str,
    right_path: &str,
    cancellation: &Cancellation,
) -> Result<BundleComparison, Failure> {
    compare_files_with_pairs(access, left_path, right_path, &[], cancellation)
}

/// Load two caller-selected bundles and compare them with explicit record pairs.
pub fn compare_files_with_pairs<F: FileAccess>(
    access: Arc<F>,
    left_path: &str,
    right_path: &str,
    pairs: &[bundle_comparison::RecordPair],
    cancellation: &Cancellation,
) -> Result<BundleComparison, Failure> {
    let left_path = absolute_path(left_path)?;
    let right_path = absolute_path(right_path)?;
    let left = load_bundle(access.clone(), &left_path, cancellation)?;
    let right = load_bundle(access, &right_path, cancellation)?;

    bundle_comparison::compare_bundles(&left, &right, pairs).map_err(comparison_failure)
}

fn load_bundle<F: FileAccess>(
    access: Arc<F>,
    path: &str,
    cancellation: &Cancellation,
) -> Result<rea_core::evidence::bundle::EvidenceBundle, Failure> {
    let mut importer = BundleImporter::new(access);
    let loaded = importer.load_with_operation(path, cancellation, Completion::OneShot, OPERATION);
    let cleanup = importer.close();

    match (loaded, cleanup) {
        (Ok(bundle), Ok(())) => Ok(bundle),
        (Err(primary), Ok(())) | (Ok(_), Err(primary)) => Err(primary),
        (Err(mut primary), Err(cleanup)) => {
            retain_cleanup_failure(&mut primary, cleanup);
            Err(primary)
        }
    }
}

fn absolute_path(path: &str) -> Result<String, Failure> {
    caller_path::absolute(path).map_err(|error| {
        Failure::new(
            "execution_failure",
            "execution_failure",
            "Evidence bundle path could not be resolved in this process.".into(),
            true,
            "Check the selected path and retry.".into(),
            BTreeMap::from([
                ("operation", Detail::Text(OPERATION.into())),
                ("path", Detail::Text(path.into())),
                (
                    "reason",
                    Detail::Text(format!("current-directory: {}", error.kind())),
                ),
            ]),
        )
    })
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

fn comparison_failure(error: BundleComparisonError) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Evidence bundle comparison input is invalid.".into(),
        false,
        "Check the comparison inputs and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(error.to_string())),
        ]),
    )
}
