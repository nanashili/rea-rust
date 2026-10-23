//! Engine archive metadata check: the JAR must contain the required bridge
//! classes, read through a bounded ZIP central-directory enumeration.
//!
//! Compatibility owner: `requireEngineArchive` in
//! `src/android/JadxConfiguration.ts`. Only metadata is read (no class
//! bodies); the central-directory allocation is bounded at 8 MiB.

use super::configuration::REQUIRED_ENGINE_CLASSES;
use super::release::{self, JADX_PROVIDER_ID};
use crate::common::errors::capability_unavailable;
use crate::common::zip::{self, ZipError};
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use serde_json::json;
use std::fs::File;

/// Bound ZIP metadata allocation during discovery (the audited 0.7.1 JAR's
/// central directory occupies 2,294,350 bytes; class bodies are not read).
const JAR_METADATA_READ_MAX_BYTES: usize = 8 * 1024 * 1024;

/// `requireEngineArchive(jar, options)`: verify the required bridge classes.
pub fn require_engine_archive(
    jar: &str,
    operation: &str,
    cancellation: &Cancellation,
) -> Result<(), AnalysisError> {
    let mut file =
        File::open(jar).map_err(|error| archive_inspection_failure(jar, &error.to_string()))?;
    let size = file
        .metadata()
        .map_err(|error| archive_inspection_failure(jar, &error.to_string()))?
        .len();
    let entries = match zip::central_directory_entries(
        &mut file,
        size,
        JAR_METADATA_READ_MAX_BYTES,
        cancellation,
    ) {
        Ok(entries) => entries,
        Err(ZipError::Cancelled(_)) => return Err(AnalysisError::cancelled(operation)),
        Err(error) => return Err(archive_inspection_failure(jar, &error.to_string())),
    };
    let mut missing: Vec<&'static str> = REQUIRED_ENGINE_CLASSES.to_vec();
    for entry in &entries {
        if !entry.directory && !entry.encrypted {
            missing.retain(|candidate| *candidate != entry.path);
        }
        if missing.is_empty() {
            return Ok(());
        }
    }
    Err(unsupported_version(jar, &missing))
}

fn unsupported_version(jar: &str, missing: &[&'static str]) -> AnalysisError {
    let joined = missing.join(", ");
    let reason = format!(
        "REA_JADX_MCP_JAR {jar} does not contain the required metadata bridge classes: {joined}. {}",
        release::jar_configuration_remediation()
    );
    capability_unavailable(
        JADX_PROVIDER_ID,
        "inspect_jadx_configuration",
        reason.clone(),
        Some(reason),
        Some(crate::common::errors::object(json!({
            "jar_path": jar,
            "phase": "jar-inspection",
            "missing_classes": missing,
            "failure_kind": "jar",
            "failure_code": "unsupported_version",
        }))),
    )
}

fn archive_inspection_failure(jar: &str, reason: &str) -> AnalysisError {
    let message = format!(
        "Cannot inspect REA_JADX_MCP_JAR {jar} as a Java archive: {reason}. {}",
        release::jar_configuration_remediation()
    );
    capability_unavailable(
        JADX_PROVIDER_ID,
        "inspect_jadx_configuration",
        message.clone(),
        Some(message),
        Some(crate::common::errors::object(json!({
            "jar_path": jar,
            "phase": "jar-inspection",
            "archive_error": reason,
            "maximum_metadata_read_bytes": JAR_METADATA_READ_MAX_BYTES,
            "failure_kind": "jar",
            "failure_code": "version_unresolved",
        }))),
    )
}
