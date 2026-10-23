//! Publish validated artifacts into the exclusively owned output directory.
//!
//! Compatibility owner: `src/javascript/recovery/WakaruPublication.ts` and the
//! `SafeOutputTree` it writes through.
//!
//! This path is only reached on the Linux execution path after a successful
//! Wakaru launch and report validation. It is unreachable on this macOS host,
//! where `resolve_wakaru_command` returns capability-unavailable first.

use serde_json::{Value, json};

use crate::javascript_recovery::command::CommandRun;
use crate::javascript_recovery::recovery_files::{
    RecoveryInputSnapshot, read_recovery_file, recovery_digest,
};
use crate::javascript_recovery::release::{
    RECOVERY_LIMITATIONS, RECOVERY_LIMITS, WAKARU_PROVIDER_ID, WAKARU_RELEASE_REVISION,
};
use crate::javascript_recovery::report::ParsedReports;
use crate::javascript_recovery::version::WakaruVersionAdmission;
use crate::javascript_recovery::{OPERATION, ParsedInput};
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_host::fs::staged_output;
use std::path::{Path, PathBuf};

/// `normalizeArtifactPath` for the slash-separated logical names Wakaru emits.
/// Wakaru module names are already NFC ASCII module paths; this preserves the
/// TS checks (no absolute, no `.`/`..`, no empty components, no trailing slash)
/// without a Unicode-normalization dependency.
pub(crate) fn normalize_artifact_path(input: &str) -> String {
    if input.contains('\0') || input.starts_with('/') || is_drive_prefixed(input) {
        return input.to_owned();
    }
    let trimmed = input.trim_end_matches('/');
    let parts: Vec<&str> = trimmed.split('/').collect();
    if trimmed.is_empty() || parts.iter().any(|part| matches!(*part, "" | "." | "..")) {
        return input.to_owned();
    }
    trimmed.to_owned()
}

fn is_drive_prefixed(input: &str) -> bool {
    let bytes = input.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// A written output file: absolute path, digest and byte count.
fn published_file(output_root: &str, relative: &str, sha256: String, bytes: u64) -> Value {
    json!({
        "path": Path::new(output_root).join(relative).to_string_lossy(),
        "sha256": sha256,
        "bytes": bytes,
    })
}

/// Write validated artifacts to the absent output directory and project the
/// complete recovery result.
pub(crate) fn publish_wakaru_artifacts(
    output_directory: &str,
    staging: &str,
    input: &ParsedInput,
    sources: &[RecoveryInputSnapshot],
    engine_command: &str,
    engine_sha256: &str,
    engine_bytes: u64,
    admitted: &WakaruVersionAdmission,
    parsed: &ParsedReports,
    execution: &CommandRun,
    cancellation: &Cancellation,
) -> Result<Value, AnalysisError> {
    std::fs::create_dir(output_directory).map_err(|cause| {
        AnalysisError::output(
            OPERATION,
            format!("Cannot create new recovery directory {output_directory}: {cause}"),
        )
    })?;

    let write = |relative: &str, bytes: &[u8]| -> Result<Value, AnalysisError> {
        let sha256 = recovery_digest(bytes);
        let destination: PathBuf = Path::new(output_directory).join(relative);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent).map_err(|cause| {
                AnalysisError::output(OPERATION, format!("Cannot stage {relative}: {cause}"))
            })?;
        }
        let owned = bytes.to_vec();
        let published = staged_output::publish(&destination, false, cancellation, |out| {
            std::io::Write::write_all(out, &owned)
        })
        .map_err(|failure| {
            let reason = failure
                .outcome
                .err()
                .map(|issue| format!("{issue:?}"))
                .unwrap_or_else(|| "publication failed".to_owned());
            AnalysisError::output(OPERATION, format!("Cannot publish {relative}: {reason}"))
        })?;
        Ok(published_file(
            output_directory,
            relative,
            sha256,
            published.bytes,
        ))
    };

    // Published source copies with exact snapshot binding.
    let mut published_sources = Vec::new();
    for source in sources {
        let snapshot = read_recovery_file(&source.snapshot_path, source.bytes)?;
        if recovery_digest(&snapshot) != source.sha256 {
            return Err(AnalysisError::output(
                OPERATION,
                format!(
                    "The input snapshot changed during recovery: {}",
                    source.path
                ),
            ));
        }
        let copy = write(&format!("inputs/{}", source.relative_path), &snapshot)?;
        published_sources.push(json!({
            "path": source.path,
            "sha256": source.sha256,
            "bytes": source.bytes,
            "snapshot_path": source.snapshot_path,
            "published_copy": copy,
        }));
    }
    let source = published_sources.first().cloned().unwrap_or(Value::Null);
    let additional_sources: Vec<Value> = published_sources.into_iter().skip(1).collect();

    // Published modules with provenance binding.
    let mut modules = Vec::new();
    for module in &parsed.report.modules {
        let artifact_bytes = read_recovery_file(
            &Path::new(staging).join(&module.filename).to_string_lossy(),
            RECOVERY_LIMITS.output_bytes,
        )?;
        let artifact = write(&format!("modules/{}", module.filename), &artifact_bytes)?;

        let map_path = Path::new(staging).join(format!("{}.map", module.filename));
        let source_map = if map_path.exists() {
            let map_bytes =
                read_recovery_file(&map_path.to_string_lossy(), RECOVERY_LIMITS.output_bytes)?;
            validate_source_map(&map_bytes, &module.filename)?;
            write(&format!("modules/{}.map", module.filename), &map_bytes)?
        } else {
            Value::Null
        };

        let provenance = parsed
            .provenance
            .modules
            .get(&module.filename)
            .ok_or_else(|| {
                AnalysisError::output(
                    OPERATION,
                    format!("Missing module provenance: {}", module.filename),
                )
            })?;
        let origin = sources
            .iter()
            .find(|source| source.snapshot_path == provenance.input)
            .ok_or_else(|| {
                AnalysisError::output(
                    OPERATION,
                    format!("Unselected module provenance input: {}", provenance.input),
                )
            })?;

        modules.push(json!({
            "reported_filename": module.filename,
            "reported_status": module.status,
            "artifact": artifact,
            "source_map": source_map,
            "provenance": {
                "reported_input": provenance.input,
                "original_path": origin.path,
                "original_sha256": origin.sha256,
                "extraction": provenance.extraction,
                "byte_ranges": ranges_value(&provenance.ranges),
                "context_byte_ranges": ranges_value(&provenance.context_ranges),
                "range_semantics": "half-open-utf8-bytes",
            },
        }));
    }

    let report = write("reports/stdout.json", execution.stdout.as_bytes())?;
    let provenance_bytes = read_recovery_file(
        &Path::new(staging).join("provenance.json").to_string_lossy(),
        RECOVERY_LIMITS.report_bytes,
    )?;
    let provenance = write("reports/provenance.json", &provenance_bytes)?;

    let admitted_version = match admitted {
        WakaruVersionAdmission::Verified { version }
        | WakaruVersionAdmission::Compatible { version, .. } => version.clone(),
        WakaruVersionAdmission::Unsupported { .. } => String::new(),
    };

    let mut limitations: Vec<String> = RECOVERY_LIMITATIONS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    if let WakaruVersionAdmission::Compatible { limitation, .. } = admitted {
        limitations.push(limitation.clone());
    }

    let warnings: Vec<Value> = parsed
        .report
        .warnings
        .iter()
        .map(|warning| {
            json!({
                "filename": warning.filename,
                "kind": warning.kind,
                "is_error": warning.is_error,
                "message": warning.message,
            })
        })
        .collect();

    let analysis_input = if modules.is_empty() {
        Value::Null
    } else {
        json!({
            "input_path": Path::new(output_directory).join("modules").to_string_lossy(),
            "format": "directory",
        })
    };

    let mut details = serde_json::Map::new();
    details.insert("source".into(), source);
    if !additional_sources.is_empty() {
        details.insert(
            "additional_sources".into(),
            Value::Array(additional_sources),
        );
    }
    details.insert(
        "engine".into(),
        json!({
            "id": WAKARU_PROVIDER_ID,
            "version": admitted_version,
            "executable": {
                "path": engine_command,
                "sha256": engine_sha256,
                "bytes": engine_bytes,
            },
            "audited_source_revision": WAKARU_RELEASE_REVISION,
            "executed_source_revision": Value::Null,
        }),
    );
    details.insert(
        "options".into(),
        json!({
            "extraction_mode": input.extraction_mode,
            "rewrite_level": input.rewrite_level,
        }),
    );
    details.insert("status".into(), Value::String(parsed.status.to_owned()));
    details.insert(
        "detected_formats".into(),
        json!(parsed.report.detected_formats),
    );
    details.insert("reported_safety".into(), json!(parsed.report.safety));
    details.insert(
        "reported_strategy".into(),
        json!(parsed.provenance.strategy),
    );
    details.insert("reported_format".into(), json!(parsed.provenance.format));
    details.insert("total".into(), json!(parsed.report.total));
    details.insert("failed".into(), json!(parsed.report.failed));
    details.insert("modules".into(), Value::Array(modules));
    details.insert("warnings".into(), Value::Array(warnings));
    details.insert("report".into(), report);
    details.insert("provenance".into(), provenance);
    details.insert("analysis_input".into(), analysis_input);
    details.insert(
        "runtime_equivalence".into(),
        Value::String("unknown".into()),
    );
    details.insert("limitations".into(), json!(limitations));

    let manifest_bytes = format!(
        "{}\n",
        serde_json::to_string_pretty(&Value::Object(details.clone())).unwrap_or_default()
    );
    let manifest = write("manifest.json", manifest_bytes.as_bytes())?;
    details.insert("manifest".into(), manifest);

    Ok(Value::Object(details))
}

fn ranges_value(ranges: &[(u64, u64)]) -> Value {
    Value::Array(
        ranges
            .iter()
            .map(|(start, end)| json!({ "start": start, "end": end }))
            .collect(),
    )
}

/// Validate a source map's representation; preserve its unverified bytes.
fn validate_source_map(bytes: &[u8], filename: &str) -> Result<(), AnalysisError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|cause| {
        AnalysisError::output(
            OPERATION,
            format!("Invalid emitted source map for {filename}: {cause}"),
        )
    })?;
    let valid = value["version"].as_i64() == Some(3)
        && value["sources"].is_array()
        && value["names"].is_array()
        && value["mappings"].is_string();
    if !valid {
        return Err(AnalysisError::output(
            OPERATION,
            format!("Invalid emitted source map for {filename}: unexpected shape"),
        ));
    }
    Ok(())
}
