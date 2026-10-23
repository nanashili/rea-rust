//! Bounded, read-only desktop application directory inspection.
//!
//! Faithful port of `scanDirectory`/`DesktopApplicationReader#inspect`
//! (`src/artifacts/DesktopApplicationReader.ts`). Traversal, no-follow
//! admission and stable reads are delegated to the host-owned
//! `rea_host::fs::stable_directory` reader; interpretation, budgets, candidate and
//! component projection and the directory snapshot digest are owned here.

use rea_core::analysis_error::{AnalysisError, ArtifactDetails, ErrorKind};
use rea_core::cancellation::Cancellation;
use rea_core::canonical_json;
use rea_host::fs::stable_directory::{
    DirectoryEntry, DirectoryEntryKind, DirectoryError, DirectoryReader,
};
use serde_json::{Value, json};
use std::path::Path;

use super::convention::desktop_path_conventions;
use super::inspection::{self, FileInspection, ReadBudget};
use super::projection;

/// 32 MiB retained-metadata representation budget (`RETAINED_METADATA_BYTES`).
const RETAINED_METADATA_BYTES: usize = 32 * 1024 * 1024;

/// Shared limitations text (`scanDirectory` `limitations`), in source order.
const BASE_LIMITATIONS: [&str; 6] = [
    "Runtime candidates and component markers do not establish loaded code, execution, or build correspondence.",
    "The directory SHA-256 commits only to retained paths, omission kinds, available filesystem metadata and read-range digests, not to every file's contents. Unread bytes are unknown.",
    "Special-entry payloads are not read. Their paths and kinds are retained; other special-entry metadata is unavailable in this report.",
    "Child symlinks are not followed. Executable section-embedded PCKs without a trailer and encrypted contents remain unexamined.",
    "This is a sequence of stable entry observations, not an atomic snapshot of the entire directory.",
    "Unity reference decoding stops after a witness in each Data/Managed directory; other assemblies' references are unexamined. Header facts remain per-file.",
];

const OPERATION: &str = "inspect_desktop_application";

/// Inspect a caller-selected directory, returning the desktop report value.
///
/// Mirrors `DesktopApplicationReader.inspect`: a single owned inspection that
/// delegates safe traversal to the host reader and translates host failures
/// through `translateArtifactFailure` semantics.
pub(crate) fn inspect(
    path: &str,
    max_entries: usize,
    max_probe_bytes: usize,
    cancellation: &Cancellation,
) -> Result<Value, AnalysisError> {
    if !Path::new(path).is_absolute() {
        // `#inspect` throws ArtifactReaderFailure("path", ...).
        return Err(artifact_failure(
            "path",
            "Expected an absolute directory path",
        ));
    }
    let reader = DirectoryReader::open(Path::new(path)).map_err(open_failure)?;
    scan_directory(&reader, path, max_entries, max_probe_bytes, cancellation)
}

/// `scanDirectory`.
fn scan_directory(
    reader: &DirectoryReader,
    path: &str,
    max_entries: usize,
    max_probe_bytes: usize,
    cancellation: &Cancellation,
) -> Result<Value, AnalysisError> {
    let root = reader.root();
    let canonical_path = root.canonical_path.to_string_lossy().into_owned();

    // `dsr_${digestCanonicalValue({canonical_path, identity:{device, inode}})}`.
    let namespace_id = format!(
        "dsr_{}",
        digest(&json!({
            "canonical_path": canonical_path,
            "identity": {
                "device": root.identity.device.to_string(),
                "inode": root.identity.file_id.to_string(),
            },
        }))?
    );

    let mut files: Vec<Value> = Vec::new();
    let omissions: Vec<Value> = Vec::new();
    let mut unity_witness_roots: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    let mut budget = ReadBudget {
        bytes: 0,
        maximum: max_probe_bytes,
        retained_bytes: 1024 + (path.len() + canonical_path.len()) * 24,
        maximum_retained_bytes: RETAINED_METADATA_BYTES,
    };

    let mut entries_examined = 0usize;
    let mut files_probed = 0usize;
    let mut symlinks = 0usize;
    let special = 0usize;
    let mut partial = false;
    let mut limitations: Vec<String> = BASE_LIMITATIONS
        .iter()
        .map(|text| (*text).to_owned())
        .collect();

    // The host reader enumerates the admitted entries up front with its own
    // no-follow traversal and `max_entries` budget.
    let enumerated = reader.entries(max_entries, cancellation);
    let entries = match enumerated {
        Ok(entries) => entries,
        Err(DirectoryError::Limit { .. }) => {
            partial = true;
            limitations.push(
                "Directory traversal reached max_entries; unvisited paths and candidate families remain unknown.".to_owned(),
            );
            Vec::new()
        }
        Err(DirectoryError::Cancelled(reason)) => {
            return Err(cancelled_failure(reason));
        }
        Err(error) => return Err(translate_reader_error(error)),
    };

    let mut scan_error: Option<AnalysisError> = None;

    'entries: for entry in &entries {
        entries_examined += 1;
        if let Err(error) = ensure_active(cancellation) {
            scan_error = Some(error);
            break;
        }
        // `reserve(1024 + (path.length + adapterKey.length) * 24)`
        let local_path = join_local_path(&canonical_path, &entry.path);
        let reservation = 1024 + (entry.path.len() + local_path.len()) * 24;
        if reservation > budget.maximum_retained_bytes - budget.retained_bytes {
            partial = true;
            limitations.push(
                "Directory metadata reached the 32 MiB representation budget; remaining entry and omission facts are unavailable.".to_owned(),
            );
            break;
        }
        budget.retained_bytes += reservation;

        let mut row = file_row(entry, &namespace_id, &local_path);

        match entry.kind {
            DirectoryEntryKind::Symlink => {
                files.push(row);
                symlinks += 1;
                continue;
            }
            DirectoryEntryKind::Directory => {
                files.push(row);
                continue;
            }
            DirectoryEntryKind::Regular => {}
        }

        let managed_root = add_path_facts(&mut row, entry);
        if !probe_selected(entry) {
            files.push(row);
            continue;
        }
        if budget.bytes >= budget.maximum {
            row["read_status"] = Value::String("unavailable".into());
            push_issue(
                &mut row,
                "Probe byte budget exhausted; bytes were not inspected.",
            );
            partial = true;
            files.push(row);
            continue;
        }

        files_probed += 1;
        let probe_issue_count = row["issues"].as_array().map(Vec::len).unwrap_or(0);
        let managed_directory = managed_root
            .as_deref()
            .filter(|managed_root| !unity_witness_roots.contains(*managed_root));

        let mut opened = match reader.open_entry(entry, cancellation) {
            Ok(file) => file,
            Err(error) => {
                if let Some(mapped) = handle_probe_error(error, &mut row, probe_issue_count) {
                    scan_error = Some(mapped);
                    files.push(row);
                    break;
                }
                partial = true;
                files.push(row);
                continue;
            }
        };

        let size = entry_declared_size(entry);
        match inspection::inspect_desktop_file(
            &mut opened,
            size,
            &mut budget,
            cancellation,
            managed_directory,
        ) {
            Ok(result) => {
                apply_inspection(&mut row, result);
                let issue_count = row["issues"].as_array().map(Vec::len).unwrap_or(0);
                row["read_status"] = Value::String(if issue_count == 0 {
                    "examined".into()
                } else {
                    "partial".into()
                });
                if let Some(managed_root) = &managed_root
                    && row_has_unity_reference(&row)
                {
                    unity_witness_roots.insert(managed_root.clone());
                }
                if issue_count > 0 {
                    partial = true;
                }
            }
            Err(failure) => {
                partial = true;
                row["read_status"] = Value::String("unavailable".into());
                push_issue(&mut row, &failure.message);
                let completed_read = false; // host reads are atomic per range; no completed-read salvage.
                if !completed_read && matches!(failure.reason, "integrity" | "io" | "cancelled") {
                    retain_only_path_facts(&mut row);
                }
                if failure.reason == "cancelled" {
                    scan_error = Some(cancelled_failure(failure.message));
                    files.push(row);
                    break 'entries;
                }
            }
        }
        files.push(row);
    }

    // `files.sort((a, b) => a.path < b.path ? -1 : ...)`.
    files.sort_by(|left, right| {
        left["path"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["path"].as_str().unwrap_or_default())
    });

    if scan_error.is_some() {
        partial = true;
        limitations.push(
            "Inspection was interrupted; only preceding stable entry observations are retained."
                .to_owned(),
        );
    }

    let coverage = json!({
        "status": if partial { "partial" } else { "complete-within-scan" },
        "entries_examined": entries_examined,
        "files_probed": files_probed,
        "bytes_read": budget.bytes,
        "symlinks_not_followed": symlinks,
        "special_entries_omitted": special,
        "limits": { "max_entries": max_entries, "max_probe_bytes": max_probe_bytes },
    });

    // `snapshot = digestCanonicalValue({root_namespace_id, files:[{file_id,bytes,ranges}], omissions:[omission_id]})`.
    let snapshot = digest(&json!({
        "root_namespace_id": namespace_id,
        "files": files.iter().map(|file| json!({
            "file_id": file["file_id"],
            "bytes": file["bytes"],
            "ranges": file["ranges"],
        })).collect::<Vec<_>>(),
        "omissions": omissions.iter().map(|omission| omission["omission_id"].clone()).collect::<Vec<_>>(),
    }))?;

    let projected = projection::project(&files);

    let report = json!({
        "root": {
            "path": path,
            "canonical_path": canonical_path,
            "identity": {
                "device": root.identity.device.to_string(),
                "inode": root.identity.file_id.to_string(),
            },
            "namespace_id": namespace_id,
            "snapshot_sha256": snapshot,
            "identity_scope": "examined-metadata-and-read-ranges",
        },
        "files": files,
        "omissions": omissions,
        "candidates": projected["candidates"],
        "components": projected["components"],
        "next_probes": projected["next_probes"],
        "coverage": coverage,
        "limitations": limitations,
    });

    Ok(report)
}

/// `fileRow(entry, rootNamespaceId)`.
fn file_row(entry: &DirectoryEntry, root_namespace_id: &str, local_path: &str) -> Value {
    let kind = kind_label(entry.kind);
    // Only regular files carry a source identity in the TypeScript reader.
    let identity = if entry.kind == DirectoryEntryKind::Regular {
        json!({
            "device": entry.identity.device.to_string(),
            "inode": entry.identity.file_id.to_string(),
            "size": entry.identity.bytes.to_string(),
            "mode": entry.mode.to_string(),
            "mtime_ns": entry.identity.modified_ns.to_string(),
            "ctime_ns": entry.identity.changed_ns.to_string(),
        })
    } else {
        Value::Null
    };

    let file_id = format!(
        "dsf_{}",
        digest(&json!({
            "root_namespace_id": root_namespace_id,
            "path": entry.path,
            "kind": kind,
            "identity": identity,
        }))
        .unwrap_or_default()
    );

    let bytes = if entry.kind == DirectoryEntryKind::Regular {
        Value::from(entry.identity.bytes)
    } else {
        Value::Null
    };

    json!({
        "file_id": file_id,
        "path": entry.path,
        "local_path": local_path,
        "kind": kind,
        "bytes": bytes,
        "identity": identity,
        "read_status": "not-selected",
        "ranges": [],
        "facts": [],
        "issues": [],
    })
}

/// `addPathFacts(row)` — path-convention facts; returns the Unity managed root.
fn add_path_facts(row: &mut Value, entry: &DirectoryEntry) -> Option<String> {
    let conventions = desktop_path_conventions(&entry.path);
    let facts = row["facts"].as_array_mut().expect("row facts array");
    if conventions.electron_archive {
        facts.push(
            json!({ "kind": "electron-asar-convention", "offset": null, "value": entry.path }),
        );
    }
    if conventions.unreal_container {
        facts.push(
            json!({ "kind": "unreal-container-convention", "offset": null, "value": entry.path }),
        );
    }
    if conventions.il2cpp_library {
        facts.push(
            json!({ "kind": "il2cpp-library-convention", "offset": null, "value": entry.path }),
        );
    }
    conventions.unity_managed_directory
}

/// `probeSelected(entry)`: the host executable marking or a probed name.
fn probe_selected(entry: &DirectoryEntry) -> bool {
    if host_executable_marking(entry) {
        return true;
    }
    let path = entry.path.to_ascii_lowercase();
    let name_tail = |suffix: &str| path.ends_with(suffix);
    name_tail(".exe")
        || name_tail(".dll")
        || name_tail(".so")
        || name_tail(".dylib")
        || name_tail(".pck")
        || name_tail(".utoc")
        || ends_with_component(&path, "global-metadata.dat")
        || ends_with_component(&path, "data.win")
}

/// `hostExecutableMarking`: POSIX hosts mark executability with any execute
/// permission bit of the entry's observed mode.
fn host_executable_marking(entry: &DirectoryEntry) -> bool {
    entry.mode & 0o111 != 0
}
/// `(?:^|\/)name$` — the path ends with `name` at a segment boundary.
fn ends_with_component(path: &str, name: &str) -> bool {
    path == name || path.ends_with(&format!("/{name}"))
}

fn join_local_path(canonical_path: &str, relative: &str) -> String {
    if canonical_path.ends_with('/') {
        format!("{canonical_path}{relative}")
    } else {
        format!("{canonical_path}/{relative}")
    }
}

fn entry_declared_size(entry: &DirectoryEntry) -> Option<u64> {
    (entry.kind == DirectoryEntryKind::Regular).then_some(entry.identity.bytes)
}

fn kind_label(kind: DirectoryEntryKind) -> &'static str {
    match kind {
        DirectoryEntryKind::Regular => "file",
        DirectoryEntryKind::Directory => "directory",
        DirectoryEntryKind::Symlink => "symlink",
    }
}

fn apply_inspection(row: &mut Value, inspection: FileInspection) {
    if let Some(facts) = row["facts"].as_array_mut() {
        facts.extend(inspection.facts);
    }
    row["ranges"] = Value::Array(inspection.ranges);
    if let Some(issues) = row["issues"].as_array_mut() {
        for issue in inspection.issues {
            issues.push(Value::String(issue));
        }
    }
}

fn push_issue(row: &mut Value, message: &str) {
    if let Some(issues) = row["issues"].as_array_mut() {
        issues.push(Value::String(message.to_owned()));
    }
}

fn row_has_unity_reference(row: &Value) -> bool {
    row["facts"].as_array().is_some_and(|facts| {
        facts
            .iter()
            .any(|fact| fact["kind"] == "unity-assembly-reference")
    })
}

/// `row.facts = row.facts.filter((fact) => fact.offset === null); row.ranges = [];`
fn retain_only_path_facts(row: &mut Value) {
    if let Some(facts) = row["facts"].as_array() {
        let retained: Vec<Value> = facts
            .iter()
            .filter(|fact| fact["offset"].is_null())
            .cloned()
            .collect();
        row["facts"] = Value::Array(retained);
    }
    row["ranges"] = Value::Array(Vec::new());
}

/// Handle a probe open/read failure, returning a fatal error to stop the scan.
fn handle_probe_error(
    error: DirectoryError,
    row: &mut Value,
    probe_issue_count: usize,
) -> Option<AnalysisError> {
    let _ = probe_issue_count;
    match error {
        DirectoryError::Cancelled(reason) => {
            row["read_status"] = Value::String("unavailable".into());
            push_issue(row, &format!("Directory inspection cancelled: {reason}"));
            retain_only_path_facts(row);
            Some(cancelled_failure(reason))
        }
        other => {
            row["read_status"] = Value::String("unavailable".into());
            push_issue(row, &other.to_string());
            if matches!(
                other,
                DirectoryError::Io { .. }
                    | DirectoryError::Changed(_)
                    | DirectoryError::Cleanup { .. }
            ) {
                retain_only_path_facts(row);
            }
            None
        }
    }
}

fn ensure_active(cancellation: &Cancellation) -> Result<(), AnalysisError> {
    match cancellation.reason() {
        None => Ok(()),
        Some(_) => Err(AnalysisError::cancelled(OPERATION)),
    }
}

fn digest(value: &Value) -> Result<String, AnalysisError> {
    canonical_json::digest(value)
        .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))
}

/// Translate an `ArtifactReaderFailure` reason into an `ArtifactOperation`
/// error (`translateArtifactFailure`).
fn artifact_failure(reason: &'static str, message: &str) -> AnalysisError {
    let mut error: AnalysisError = ErrorKind::ArtifactOperation {
        operation: OPERATION.to_owned(),
        reason: reason.to_owned(),
        artifact_details: None::<ArtifactDetails>,
        detail: Some(message.to_owned()),
    }
    .into();
    error.partial_observation = None;
    error
}

fn cancelled_failure(reason: impl Into<String>) -> AnalysisError {
    let _ = reason;
    AnalysisError::cancelled(OPERATION)
}

/// `DirectoryReader::open` failure, mapped like `translateArtifactFailure`.
fn open_failure(error: DirectoryError) -> AnalysisError {
    match error {
        DirectoryError::InvalidRoot => {
            artifact_failure("path", "Artifact root must be a directory")
        }
        DirectoryError::Cancelled(reason) => cancelled_failure(reason),
        DirectoryError::Unsupported(reason) => artifact_failure("unavailable", reason),
        other => translate_reader_error(other),
    }
}

/// Map a traversal/read failure to an `ArtifactOperation` I/O error.
fn translate_reader_error(error: DirectoryError) -> AnalysisError {
    match error {
        DirectoryError::Cancelled(reason) => cancelled_failure(reason),
        DirectoryError::InvalidRelativePath => artifact_failure("path", &error.to_string()),
        DirectoryError::Changed(_) => artifact_failure("integrity", &error.to_string()),
        DirectoryError::Unsupported(reason) => artifact_failure("unavailable", reason),
        other => artifact_failure("io", &other.to_string()),
    }
}
