//! Safe extraction of every regular artifact file into a REA-created root.
//!
//! Compatibility owners: `src/artifacts/extraction/ArtifactExtraction.ts`,
//! `src/artifacts/SafeOutputTree.ts`,
//! `src/application/artifacts/ArtifactExtractionDestination.ts`. Extraction
//! selects active regular occurrences from a fresh inventory scan, reads their
//! bytes through the same reader and writes each into a newly created,
//! exclusively owned destination (never overwriting, rejecting traversal and
//! symlink escapes). The destination is created by REA; the target is never
//! modified.
use super::asar::AsarArtifactReader;
use super::classify::is_zip_package_format;
use super::directory_reader::DirectoryArtifactReader;
use super::graph::{ArtifactInventoryResult, digest_value};
use super::reader::{
    ArtifactEntry, ArtifactReader, ArtifactTraversalOmission, ReaderFailure, RetainedReader,
    read_stable_file,
};
use super::zip_reader::ZipArtifactReader;
use crate::macos_readers::{dmg::NativeDmgArtifactReader, macho_slice::MachOSliceArtifactReader};
use crate::native_command::CommandCleanup;
use rea_core::JsString;
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_mcp::SessionResource;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// `createArtifactExtractionDestination`: a fresh temp directory chosen by REA.
pub fn create_extraction_destination() -> String {
    let unique = format!("rea-extracted-{}-{}", std::process::id(), unique_suffix());
    std::env::temp_dir()
        .join(unique)
        .to_string_lossy()
        .into_owned()
}

fn unique_suffix() -> String {
    static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);

    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let sequence = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:x}-{sequence:x}")
}

/// Whether a format has an extraction reader (`requireExtractableFormat`).
fn is_extractable(format: &str, is_directory: bool) -> bool {
    is_directory
        || format == "asar"
        || format == "dmg"
        || is_mach_o_format(format)
        || is_zip_package_format(format)
}

fn is_mach_o_format(format: &str) -> bool {
    format == "mach-o" || format == "mach-o-universal"
}

/// Run `extract_artifact` for the active target.
pub fn extract_artifact(
    input_path: &str,
    input_format: &str,
    output_root: &str,
    integrity_fail: bool,
    cancellation: &Cancellation,
) -> Result<Value, ReaderFailure> {
    if cancellation.reason().is_some() {
        return Err(ReaderFailure::new(
            "cancelled",
            "Artifact extraction cancelled",
        ));
    }
    let canonical = std::fs::canonicalize(input_path).map_err(|error| {
        ReaderFailure::new("io", format!("Could not resolve artifact path: {error}"))
    })?;
    let canonical_str = canonical.to_string_lossy().into_owned();
    let is_directory = std::fs::symlink_metadata(&canonical_str)
        .map(|metadata| metadata.is_dir())
        .map_err(|error| ReaderFailure::new("io", format!("Could not stat artifact: {error}")))?;
    if !is_extractable(input_format, is_directory) {
        // Unsupported-target is a typed caller-selection failure handled by the
        // provider boundary; surface it as a path failure here and let the
        // handler translate it. We reuse the "format" reason to signal this is
        // not an archive REA can extract.
        return Err(ReaderFailure::new(
            "format",
            format!("Artifact format has no extraction reader: {input_format}"),
        ));
    }

    // Fresh inventory scan over the same canonical root.
    let inventory = super::scan::inventory_artifact(&canonical_str, integrity_fail, cancellation)?;

    materialize_selection(
        &canonical_str,
        input_format,
        output_root,
        &inventory,
        cancellation,
    )
}

struct SelectedOccurrence {
    occurrence_id: String,
    logical_path: JsString,
    artifact_id: String,
    sha256: String,
    size: u64,
}

fn materialize_selection(
    source_path: &str,
    input_format: &str,
    output_root: &str,
    inventory: &ArtifactInventoryResult,
    cancellation: &Cancellation,
) -> Result<Value, ReaderFailure> {
    let selection = prepare_selection(inventory)?;
    let is_directory = std::fs::symlink_metadata(source_path)
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false);
    let mut reader =
        create_extraction_reader(source_path, input_format, is_directory, cancellation)?;

    let mut tree = match SafeOutputTree::create(output_root) {
        Ok(tree) => tree,
        Err(mut failure) => {
            close_reader_after_failure(&mut reader, &mut failure);
            return Err(failure);
        }
    };

    let materialized = materialize_entries(
        &mut reader,
        &mut tree,
        &selection.by_path,
        &selection.items,
        cancellation,
    )
    .map(|extracted| {
        create_extraction_result(output_root, inventory, &selection.items, &extracted)
    });

    finalize_materialization(materialized, &mut reader, tree)
}

struct SelectionPlan {
    items: Vec<SelectedOccurrence>,
    by_path: BTreeMap<JsString, usize>,
}

fn prepare_selection(inventory: &ArtifactInventoryResult) -> Result<SelectionPlan, ReaderFailure> {
    let selected: Vec<&super::graph::ArtifactOccurrence> = inventory
        .occurrences
        .iter()
        .filter(|occurrence| {
            (occurrence.entry_kind == "file" || occurrence.entry_kind == "slice")
                && occurrence.logical_path != "."
        })
        .collect();
    let regular_paths: std::collections::HashSet<JsString> = selected
        .iter()
        .map(|occurrence| occurrence.logical_path.clone())
        .collect();
    let active: Vec<&super::graph::ArtifactOccurrence> = selected
        .iter()
        .copied()
        .filter(|occurrence| {
            let mut path = occurrence.logical_path.clone();
            while let Some(slash) = path
                .units()
                .iter()
                .rposition(|unit| *unit == u16::from(b'/'))
            {
                path = path.slice_units(0..slash);
                if regular_paths.contains(&path) {
                    return false;
                }
            }
            true
        })
        .collect();

    let node_sha: BTreeMap<&str, (&str, u64)> = inventory
        .nodes
        .iter()
        .map(|node| (node.artifact_id.as_str(), (node.sha256.as_str(), node.size)))
        .collect();

    let mut items = Vec::new();
    for occurrence in active {
        validate_selected_occurrence(occurrence)?;
        let artifact_id = occurrence.artifact_id.as_ref().cloned().ok_or_else(|| {
            ReaderFailure::new(
                "format",
                format!(
                    "Selected occurrence is not an extractable regular child file: {} ({})",
                    occurrence.logical_path, occurrence.occurrence_id
                ),
            )
        })?;
        let (sha256, size) = node_sha.get(artifact_id.as_str()).ok_or_else(|| {
            ReaderFailure::new(
                "integrity",
                format!(
                    "Selected occurrence has no inventory node: {}",
                    occurrence.occurrence_id
                ),
            )
        })?;
        items.push(SelectedOccurrence {
            occurrence_id: occurrence.occurrence_id.clone(),
            logical_path: occurrence.logical_path.clone(),
            artifact_id,
            sha256: (*sha256).to_owned(),
            size: *size,
        });
    }

    let mut by_path = BTreeMap::new();
    for (index, item) in items.iter().enumerate() {
        if by_path.insert(item.logical_path.clone(), index).is_some() {
            return Err(ReaderFailure::new(
                "path",
                format!(
                    "Artifact extraction path collision: {:?}. Multiple selected occurrences share this normalized logical path, so they cannot be materialized at the same destination path. Inventory retains each occurrence.",
                    item.logical_path
                ),
            ));
        }
    }

    Ok(SelectionPlan { items, by_path })
}

fn validate_selected_occurrence(
    occurrence: &super::graph::ArtifactOccurrence,
) -> Result<(), ReaderFailure> {
    if occurrence.encrypted {
        return Err(ReaderFailure::new(
            "format",
            format!(
                "Archive entry {} is encrypted; REA does not decrypt archive entries, so the archive cannot be extracted completely",
                occurrence.logical_path
            ),
        ));
    }
    if occurrence.entry_kind == "file"
        && occurrence.artifact_id.is_none()
        && occurrence.hash_status == "unavailable"
    {
        return Err(ReaderFailure::new(
            "unavailable",
            format!(
                "ASAR unpacked companion bytes are unavailable for {}",
                occurrence.logical_path
            ),
        )
        .with_details(rea_core::analysis_error::ArtifactDetails {
            logical_path: occurrence.logical_path.to_string(),
            declared_sha256: None,
            calculated_sha256: None,
            unpacked: true,
        }));
    }
    Ok(())
}

fn finalize_materialization(
    materialized: Result<Value, ReaderFailure>,
    reader: &mut Box<dyn ArtifactReader>,
    mut tree: SafeOutputTree,
) -> Result<Value, ReaderFailure> {
    match materialized {
        Ok(result) => {
            if let Err(mut failure) = reader.close() {
                retain_reader_after_close_failure(reader, &mut failure);
                retain_output_tree_after_failure(&mut failure, tree);
                return Err(failure);
            }
            tree.commit();
            Ok(result)
        }
        Err(mut failure) => {
            close_reader_after_failure(reader, &mut failure);
            retain_output_tree_after_failure(&mut failure, tree);
            Err(failure)
        }
    }
}

fn materialize_entries(
    reader: &mut Box<dyn ArtifactReader>,
    tree: &mut SafeOutputTree,
    by_path: &BTreeMap<JsString, usize>,
    selected_items: &[SelectedOccurrence],
    cancellation: &Cancellation,
) -> Result<Vec<Value>, ReaderFailure> {
    let mut extracted = Vec::new();
    let mut remaining: std::collections::HashSet<JsString> = by_path.keys().cloned().collect();
    let mut omissions = Vec::new();
    let entries = reader.entries(cancellation, &mut omissions)?;

    for entry in &entries {
        let path = normalize(&entry.path)?;
        let Some(index) = by_path.get(&path).copied() else {
            if entry.kind == "file" || entry.kind == "slice" {
                return Err(ReaderFailure::new(
                    "integrity",
                    format!("Regular artifact entry is missing from inventory: {path}"),
                ));
            }
            continue;
        };
        if (entry.kind != "file" && entry.kind != "slice") || entry.encrypted {
            return Err(ReaderFailure::new(
                "format",
                format!("Selected artifact entry cannot be read: {}", entry.path),
            ));
        }
        let bytes = reader.open(entry, cancellation)?;
        let item = &selected_items[index];
        let filesystem_path = path.as_str().ok_or_else(|| {
            ReaderFailure::new(
                "path",
                "Artifact extraction cannot materialize a logical path containing an unpaired UTF-16 surrogate on a UTF-8 filesystem",
            )
        })?;
        let written = tree.write(filesystem_path, &bytes, &item.sha256, item.size)?;
        extracted.push(json!({
            "artifact_id": item.artifact_id,
            "relative_path": written.relative_path,
            "sha256": written.sha256,
            "bytes_written": written.bytes_written,
            "created": true,
        }));
        remaining.remove(&path);
    }

    if !remaining.is_empty() {
        let mut missing: Vec<String> = remaining.into_iter().map(|path| path.to_string()).collect();
        missing.sort();
        return Err(ReaderFailure::new(
            "integrity",
            format!(
                "Inventoried regular artifact entries were not materialized: {}",
                missing.join(", ")
            ),
        ));
    }

    extracted.sort_by(|a, b| {
        a["relative_path"]
            .as_str()
            .unwrap_or("")
            .cmp(b["relative_path"].as_str().unwrap_or(""))
    });
    Ok(extracted)
}

fn close_reader_after_failure(reader: &mut Box<dyn ArtifactReader>, failure: &mut ReaderFailure) {
    if let Err(close_failure) = reader.close() {
        retain_reader_after_close_failure(reader, failure);
        let primary = std::mem::replace(
            failure,
            ReaderFailure::new("io", "Artifact failure was replaced during cleanup"),
        );
        *failure = primary.with_cleanup_failure(close_failure);
    }
}

fn retain_reader_after_close_failure(
    reader: &mut Box<dyn ArtifactReader>,
    failure: &mut ReaderFailure,
) {
    let resource = format!("{} reader", reader.format());
    failure.retain_reader(RetainedReader::new(resource, reader_as_box(reader)));
}

fn reader_as_box(reader: &mut Box<dyn ArtifactReader>) -> Box<dyn ArtifactReader> {
    std::mem::replace(reader, Box::new(ClosedArtifactReader))
}

struct ClosedArtifactReader;

impl ArtifactReader for ClosedArtifactReader {
    fn format(&self) -> &'static str {
        "closed"
    }

    fn entries(
        &mut self,
        _cancellation: &Cancellation,
        _omissions: &mut Vec<ArtifactTraversalOmission>,
    ) -> Result<Vec<ArtifactEntry>, ReaderFailure> {
        Err(ReaderFailure::new(
            "io",
            "Artifact reader was already closed",
        ))
    }

    fn open(
        &mut self,
        _entry: &ArtifactEntry,
        _cancellation: &Cancellation,
    ) -> Result<Vec<u8>, ReaderFailure> {
        Err(ReaderFailure::new(
            "io",
            "Artifact reader was already closed",
        ))
    }

    fn close(&mut self) -> Result<(), ReaderFailure> {
        Ok(())
    }
}

fn retain_output_tree_after_failure(failure: &mut ReaderFailure, tree: SafeOutputTree) {
    let resource = tree.output_root.display().to_string();
    let owner = Arc::new(OutputTreeCleanupOwner::new(resource.clone(), tree));

    if let Err(cleanup) = owner.close() {
        let fallback_reason = cleanup.message().to_owned();
        let mut resources = cleanup
            .cleanup
            .as_ref()
            .map(|observation| observation.resources.clone())
            .unwrap_or_default();
        if resources.is_empty() {
            resources.push(resource.clone());
        }
        let reason = cleanup
            .cleanup
            .map(|observation| observation.reason)
            .unwrap_or(fallback_reason);
        append_cleanup_observation(failure, reason, resources);
        failure.retain_resource(resource, owner);
    }
}

fn append_cleanup_observation(failure: &mut ReaderFailure, reason: String, resources: Vec<String>) {
    let mut observation =
        failure
            .cleanup
            .take()
            .unwrap_or_else(|| rea_core::analysis_error::CleanupObservation {
                reason: String::new(),
                resources: Vec::new(),
            });
    if !observation.reason.is_empty() {
        observation.reason.push_str("; ");
    }
    observation.reason.push_str(&reason);
    observation.resources.extend(resources);
    observation.resources.sort();
    observation.resources.dedup();
    failure.cleanup = Some(observation);
}

fn create_extraction_reader(
    path: &str,
    input_format: &str,
    is_directory: bool,
    cancellation: &Cancellation,
) -> Result<Box<dyn ArtifactReader>, ReaderFailure> {
    if is_directory {
        return Ok(Box::new(DirectoryArtifactReader::new(path)));
    }
    if input_format == "asar" {
        let bytes = read_whole(path, cancellation)?;
        return Ok(Box::new(AsarArtifactReader::new(bytes)));
    }
    if is_zip_package_format(input_format) {
        let bytes = read_whole(path, cancellation)?;
        let zip_format: &'static str = match input_format {
            "ipa" => "ipa",
            "apk" => "apk",
            "msix" => "msix",
            "appx" => "appx",
            "hap" => "hap",
            "hsp" => "hsp",
            "app-pack" => "app-pack",
            _ => "zip",
        };
        return Ok(Box::new(ZipArtifactReader::new(zip_format, bytes)));
    }
    if input_format == "mach-o-universal" {
        return Ok(Box::new(MachOSliceArtifactReader::new(
            path,
            std::sync::Arc::new(CommandCleanup::default()),
        )));
    }
    if input_format == "dmg" {
        return Ok(Box::new(NativeDmgArtifactReader::new(
            path,
            std::sync::Arc::new(CommandCleanup::default()),
        )));
    }
    Err(ReaderFailure::new(
        "unavailable",
        "Artifact extraction requires a reader for the selected format.",
    ))
}

fn read_whole(path: &str, cancellation: &Cancellation) -> Result<Vec<u8>, ReaderFailure> {
    const MAX: usize = 2 * 1024 * 1024 * 1024;
    let snapshot = read_stable_file(path, MAX, cancellation)?;
    Ok(snapshot.bytes)
}

fn normalize(input: &JsString) -> Result<JsString, ReaderFailure> {
    rea_core::artifact_paths::normalize_artifact_js_path(input)
        .map_err(|error| ReaderFailure::new("path", error.to_string()))
}

fn create_extraction_result(
    output_root: &str,
    inventory: &ArtifactInventoryResult,
    selected: &[SelectedOccurrence],
    extracted: &[Value],
) -> Value {
    let mut selected_ids: Vec<String> = selected.iter().map(|s| s.occurrence_id.clone()).collect();
    selected_ids.sort();
    let selected_set: std::collections::HashSet<&str> =
        selected.iter().map(|s| s.occurrence_id.as_str()).collect();
    let integrity_contradictions: Vec<Value> = inventory
        .integrity_contradictions
        .iter()
        .filter(|c| selected_set.contains(c.occurrence_id.as_str()))
        .map(|c| serde_json::to_value(c).expect("contradiction serializes"))
        .collect();

    let files_sha256 = digest_value(&extracted);
    let extraction_semantic = json!({
        "source_manifest_id": inventory.manifest.manifest_id,
        "selected_occurrence_ids": selected_ids,
        "files_sha256": files_sha256,
        "output_root_alias": "$OUTPUT_ROOT",
    });
    let extraction_id = format!("aex_{}", digest_value(&extraction_semantic));
    let mut extraction_manifest = Map::new();
    extraction_manifest.insert("extraction_id".into(), Value::String(extraction_id));
    if let Value::Object(object) = extraction_semantic {
        for (key, value) in object {
            extraction_manifest.insert(key, value);
        }
    }

    let mut limitations = vec![Value::String(
        "All regular files in the active artifact were materialized; nested archive contents remain represented by their containing file.".to_owned(),
    )];
    if !integrity_contradictions.is_empty() {
        limitations.push(Value::String(format!(
            "{} extracted file(s) contradict declared integrity metadata; their bytes are observed-untrusted.",
            integrity_contradictions.len()
        )));
    }

    json!({
        "manifest": inventory.manifest,
        "extraction_manifest": Value::Object(extraction_manifest),
        "output_root": output_root,
        "artifacts": extracted,
        "containment_verified": true,
        "cleanup": { "attempted": false, "verified": true, "residual_paths": [] },
        "provenance": [],
        "integrity_contradictions": integrity_contradictions,
        "limitations": limitations,
    })
}

// --- SafeOutputTree (subset of src/artifacts/SafeOutputTree.ts) ---

struct WrittenFile {
    relative_path: String,
    sha256: String,
    bytes_written: u64,
}

struct SafeOutputTree {
    output_root: std::path::PathBuf,
    committed: bool,
    root_identity: Option<RootIdentity>,
}

/// Session-owned rollback authority for an uncommitted extraction tree.
///
/// The tree remains inside the shared owner after a failed rollback, so a
/// later session close retries the same identity-checked operation instead of
/// treating the path as a free-standing diagnostic.
struct OutputTreeCleanupOwner {
    resource: String,
    tree: Mutex<Option<SafeOutputTree>>,
}

impl OutputTreeCleanupOwner {
    fn new(resource: String, tree: SafeOutputTree) -> Self {
        Self {
            resource,
            tree: Mutex::new(Some(tree)),
        }
    }
}

impl SessionResource for OutputTreeCleanupOwner {
    fn close(&self) -> Result<(), AnalysisError> {
        let mut tree = self
            .tree
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(tree_ref) = tree.as_mut() else {
            return Ok(());
        };

        match tree_ref.cleanup() {
            Ok(()) => {
                tree.take();
                Ok(())
            }
            Err(failure) => {
                let cleanup = failure.cleanup.unwrap_or_else(|| {
                    rea_core::analysis_error::CleanupObservation {
                        reason: failure.message.clone(),
                        resources: vec![self.resource.clone()],
                    }
                });
                Err(
                    AnalysisError::artifact_operation("artifact_output_cleanup", "io")
                        .with_cleanup(cleanup.reason, cleanup.resources),
                )
            }
        }
    }
}

#[cfg(unix)]
type RootIdentity = (u64, u64);

#[cfg(not(unix))]
type RootIdentity = ();

impl SafeOutputTree {
    /// Exclusively create the destination directory. Admission never grants
    /// authority to remove an existing root.
    fn create(output_root: &str) -> Result<Self, ReaderFailure> {
        let path = Path::new(output_root);
        if !path.is_absolute() {
            return Err(ReaderFailure::new(
                "path",
                "Extraction output root must be absolute",
            ));
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| ReaderFailure::new("path", "Invalid extraction output root"))?;
        if name == "." || name == ".." {
            return Err(ReaderFailure::new("path", "Invalid extraction output root"));
        }
        let parent = path
            .parent()
            .ok_or_else(|| ReaderFailure::new("path", "Invalid extraction output root"))?;
        let canonical_parent = std::fs::canonicalize(parent).map_err(|cause| {
            ReaderFailure::new(
                "unavailable",
                format!("Extraction output parent is unavailable: {cause}"),
            )
        })?;
        let canonical_output = canonical_parent.join(name);
        create_private_dir(&canonical_output)?;
        let root_identity = match read_root_identity(&canonical_output) {
            Ok(identity) => Some(identity),
            Err(mut failure) => {
                let resource = canonical_output.display().to_string();
                let owner = Arc::new(OutputTreeCleanupOwner::new(
                    resource.clone(),
                    Self {
                        output_root: canonical_output,
                        committed: false,
                        root_identity: None,
                    },
                ));
                if let Err(cleanup) = owner.close() {
                    let fallback_reason = cleanup.message().to_owned();
                    let observation =
                        cleanup
                            .cleanup
                            .unwrap_or(rea_core::analysis_error::CleanupObservation {
                                reason: fallback_reason,
                                resources: vec![resource.clone()],
                            });
                    append_cleanup_observation(
                        &mut failure,
                        observation.reason,
                        observation.resources,
                    );
                }
                failure.retain_resource(resource, owner);
                return Err(failure);
            }
        };
        Ok(Self {
            output_root: canonical_output,
            committed: false,
            root_identity,
        })
    }

    /// Write one regular file, verifying its exact digest and byte count.
    fn write(
        &self,
        relative_path: &str,
        bytes: &[u8],
        expected_sha256: &str,
        expected_bytes: u64,
    ) -> Result<WrittenFile, ReaderFailure> {
        let path = rea_core::artifact_paths::normalize_artifact_path(relative_path)
            .map_err(|error| ReaderFailure::new("path", error.to_string()))?;
        // Build parent lineage under the created root (no symlink following).
        let mut current = self.output_root.clone();
        let parts: Vec<&str> = path.split('/').collect();
        for segment in &parts[..parts.len() - 1] {
            current = current.join(segment);
            create_dir_if_absent(&current)?;
        }
        let file_name = parts[parts.len() - 1];
        let destination = current.join(file_name);
        if bytes.len() as u64 != expected_bytes {
            return Err(ReaderFailure::new(
                "format",
                format!("Extracted byte count differs from inventory for {path}"),
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let observed = format!("{:x}", hasher.finalize());
        if observed != expected_sha256 {
            return Err(ReaderFailure::new(
                "integrity",
                format!("Extracted bytes differ from inventory digest for {path}"),
            ));
        }
        write_new_file(&destination, bytes)?;
        Ok(WrittenFile {
            relative_path: path,
            sha256: observed,
            bytes_written: bytes.len() as u64,
        })
    }

    /// Mark the tree as durably published. Cleanup is not required on success.
    fn commit(&mut self) {
        self.committed = true;
    }

    /// Remove the operation-owned tree after an uncommitted extraction error.
    ///
    /// The root was created exclusively by this operation. A replaced or
    /// symlinked root is retained and reported as cleanup uncertainty rather
    /// than following an attacker-controlled path.
    fn cleanup(&mut self) -> Result<(), ReaderFailure> {
        if self.committed {
            return Ok(());
        }
        let metadata = match std::fs::symlink_metadata(&self.output_root) {
            Ok(metadata) => metadata,
            Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(cause) => {
                return Err(ReaderFailure::new(
                    "io",
                    format!(
                        "Could not inspect extraction output root {}: {cause}",
                        self.output_root.display()
                    ),
                )
                .with_cleanup(
                    "Extraction output cleanup remains incomplete",
                    vec![self.output_root.display().to_string()],
                ));
            }
        };
        let Some(expected_identity) = self.root_identity else {
            return Err(ReaderFailure::new(
                "path",
                "Extraction output root identity is unavailable; cleanup is deferred to session retry",
            )
            .with_cleanup(
                "Extraction output cleanup cannot safely remove a root without its creation identity",
                vec![self.output_root.display().to_string()],
            ));
        };
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            if !root_identity_matches(&metadata, expected_identity) {
                return Err(ReaderFailure::new(
                    "path",
                    "Extraction output root identity changed before cleanup",
                )
                .with_cleanup(
                    "Extraction output cleanup cannot safely remove a replaced root",
                    vec![self.output_root.display().to_string()],
                ));
            }
            std::fs::remove_dir_all(&self.output_root).map_err(|cause| {
                ReaderFailure::new(
                    "io",
                    format!(
                        "Could not clean up extraction output root {}: {cause}",
                        self.output_root.display()
                    ),
                )
                .with_cleanup(
                    "Extraction output cleanup remains incomplete",
                    vec![self.output_root.display().to_string()],
                )
            })?;
            Ok(())
        } else {
            Err(
                ReaderFailure::new("path", "Extraction output root was replaced before cleanup")
                    .with_cleanup(
                        "Extraction output cleanup cannot safely remove a replaced root",
                        vec![self.output_root.display().to_string()],
                    ),
            )
        }
    }
}

fn read_root_identity(path: &Path) -> Result<RootIdentity, ReaderFailure> {
    let metadata = std::fs::symlink_metadata(path).map_err(|cause| {
        ReaderFailure::new(
            "io",
            format!("Could not inspect extraction output root: {cause}"),
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok((metadata.dev(), metadata.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Ok(())
    }
}

#[cfg(unix)]
fn root_identity_matches(metadata: &std::fs::Metadata, expected: RootIdentity) -> bool {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino()) == expected
}

#[cfg(not(unix))]
fn root_identity_matches(_metadata: &std::fs::Metadata, _expected: RootIdentity) -> bool {
    true
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> Result<(), ReaderFailure> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|cause| map_create_root(cause))
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> Result<(), ReaderFailure> {
    std::fs::create_dir(path).map_err(|cause| map_create_root(cause))
}

fn map_create_root(cause: std::io::Error) -> ReaderFailure {
    if cause.kind() == std::io::ErrorKind::AlreadyExists {
        ReaderFailure::new("path", "Extraction output root already exists")
    } else {
        ReaderFailure::new(
            "io",
            format!("Could not create extraction output root: {cause}"),
        )
    }
}

#[cfg(unix)]
fn create_dir_if_absent(path: &Path) -> Result<(), ReaderFailure> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(cause) if cause.kind() == std::io::ErrorKind::AlreadyExists => {
            if std::fs::symlink_metadata(path)
                .map(|m| m.is_dir() && !m.file_type().is_symlink())
                .unwrap_or(false)
            {
                Ok(())
            } else {
                Err(ReaderFailure::new(
                    "path",
                    "Extraction output path is not a directory",
                ))
            }
        }
        Err(cause) => Err(ReaderFailure::new(
            "io",
            format!("Could not create extraction directory: {cause}"),
        )),
    }
}

#[cfg(not(unix))]
fn create_dir_if_absent(path: &Path) -> Result<(), ReaderFailure> {
    match std::fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(cause) if cause.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(cause) => Err(ReaderFailure::new(
            "io",
            format!("Could not create extraction directory: {cause}"),
        )),
    }
}

#[cfg(unix)]
fn write_new_file(destination: &Path, bytes: &[u8]) -> Result<(), ReaderFailure> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    options.custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(destination).map_err(|cause| {
        ReaderFailure::new(
            "path",
            format!(
                "Could not exclusively create extraction path: {}: {cause}",
                destination.display()
            ),
        )
    })?;
    file.write_all(bytes).map_err(|cause| {
        ReaderFailure::new("io", format!("Could not write extraction file: {cause}"))
    })?;
    file.sync_all().map_err(|cause| {
        ReaderFailure::new("io", format!("Could not flush extraction file: {cause}"))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn asar_bytes_with_file(path: &str, payload: &[u8]) -> Vec<u8> {
        let header = serde_json::to_vec(&json!({
            "files": {
                (path): {
                    "size": payload.len(),
                    "offset": "0",
                }
            }
        }))
        .expect("fixture header serializes");
        let padded_header_bytes = (header.len() + 3) & !3;
        let header_bytes = u32::try_from(8 + padded_header_bytes).expect("small fixture header");

        let mut bytes = Vec::new();
        for extent in [
            4,
            header_bytes,
            header_bytes - 4,
            u32::try_from(header.len()).expect("small fixture JSON"),
        ] {
            bytes.extend_from_slice(&extent.to_le_bytes());
        }
        bytes.extend_from_slice(&header);
        bytes.resize(16 + padded_header_bytes, 0);
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn asar_extraction_uses_inventory_nfc_path_and_preserves_bytes() {
        let temporary_directory = tempfile::tempdir().expect("temporary directory creates");
        let archive_path = temporary_directory.path().join("sample.asar");
        std::fs::write(
            &archive_path,
            asar_bytes_with_file("e\u{301}.js", b"console.log('ok');"),
        )
        .expect("ASAR fixture writes");
        let output_root = create_extraction_destination();

        let result = extract_artifact(
            archive_path.to_str().expect("temporary path is UTF-8"),
            "asar",
            &output_root,
            false,
            &Cancellation::default(),
        )
        .expect("ASAR extraction succeeds");

        assert_eq!(result["artifacts"][0]["relative_path"], "é.js");
        assert_eq!(
            std::fs::read(Path::new(&output_root).join("é.js")).expect("extracted bytes read"),
            b"console.log('ok');"
        );
        std::fs::remove_dir_all(output_root).expect("remove extracted tree");
    }

    #[test]
    fn asar_extraction_rejects_drive_prefixed_entries() {
        let temporary_directory = tempfile::tempdir().expect("temporary directory creates");
        let archive_path = temporary_directory.path().join("sample.asar");
        std::fs::write(
            &archive_path,
            asar_bytes_with_file("C:/escape.js", b"unsafe"),
        )
        .expect("ASAR fixture writes");
        let output_root = create_extraction_destination();

        let failure = extract_artifact(
            archive_path.to_str().expect("temporary path is UTF-8"),
            "asar",
            &output_root,
            false,
            &Cancellation::default(),
        )
        .expect_err("drive-prefixed ASAR entry must be rejected");

        assert_eq!(failure.reason, "path");
        assert!(!Path::new(&output_root).exists());
    }

    #[test]
    fn uncommitted_output_tree_is_removed_after_materialization_failure() {
        let output_root = create_extraction_destination();
        let mut tree = SafeOutputTree::create(&output_root).expect("create output tree");
        assert!(Path::new(&output_root).is_dir());

        tree.cleanup().expect("cleanup output tree");

        assert!(!Path::new(&output_root).exists());
    }

    #[test]
    fn committed_output_tree_is_not_removed_by_failure_cleanup() {
        let output_root = create_extraction_destination();
        let mut tree = SafeOutputTree::create(&output_root).expect("create output tree");
        tree.commit();

        tree.cleanup().expect("committed cleanup is a no-op");

        assert!(Path::new(&output_root).is_dir());
        std::fs::remove_dir_all(output_root).expect("remove test output tree");
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_refuses_a_replaced_output_root() {
        use std::os::unix::fs::symlink;

        let output_root = create_extraction_destination();
        let replacement = format!("{output_root}-replacement");
        let mut tree = SafeOutputTree::create(&output_root).expect("create output tree");
        std::fs::remove_dir(&output_root).expect("remove original test root");
        std::fs::create_dir(&replacement).expect("create replacement directory");
        symlink(&replacement, &output_root).expect("replace root with symlink");

        let failure = tree.cleanup().expect_err("replaced root must be retained");
        assert_eq!(failure.reason, "path");
        assert!(Path::new(&output_root).exists());

        std::fs::remove_file(output_root).expect("remove test symlink");
        std::fs::remove_dir(replacement).expect("remove replacement directory");
    }

    #[cfg(unix)]
    #[test]
    fn output_tree_owner_retains_foreign_root_for_session_retry() {
        use std::os::unix::fs::symlink;

        let output_root = create_extraction_destination();
        let replacement = format!("{output_root}-replacement");
        let tree = SafeOutputTree::create(&output_root).expect("create output tree");
        std::fs::remove_dir(&output_root).expect("remove original test root");
        std::fs::create_dir(&replacement).expect("create replacement directory");
        symlink(&replacement, &output_root).expect("replace root with symlink");

        let owner = OutputTreeCleanupOwner::new(output_root.clone(), tree);
        assert!(owner.close().is_err());
        assert!(owner.close().is_err());
        assert!(Path::new(&output_root).exists());

        std::fs::remove_file(output_root).expect("remove test symlink");
        std::fs::remove_dir(replacement).expect("remove replacement directory");
    }

    #[cfg(unix)]
    #[test]
    fn output_tree_owner_retries_after_foreign_root_is_removed() {
        let output_root = create_extraction_destination();
        let original = format!("{output_root}-original");
        let replacement = format!("{output_root}-replacement");
        let tree = SafeOutputTree::create(&output_root).expect("create output tree");

        std::fs::rename(&output_root, &original).expect("move original root aside");
        std::fs::create_dir(&replacement).expect("create replacement directory");
        std::fs::rename(&replacement, &output_root).expect("install replacement root");

        let owner = OutputTreeCleanupOwner::new(output_root.clone(), tree);
        assert!(owner.close().is_err());

        std::fs::remove_dir(&output_root).expect("remove replacement root");
        std::fs::rename(&original, &output_root).expect("restore original root");

        owner.close().expect("retry original root cleanup");
        assert!(!Path::new(&output_root).exists());
    }

    #[cfg(unix)]
    #[test]
    fn materialization_failure_retains_output_owner_for_cleanup_retry() {
        let output_root = create_extraction_destination();
        let original = format!("{output_root}-original");
        let replacement = format!("{output_root}-replacement");
        let tree = SafeOutputTree::create(&output_root).expect("create output tree");

        std::fs::rename(&output_root, &original).expect("move original root aside");
        std::fs::create_dir(&replacement).expect("create replacement directory");
        std::fs::rename(&replacement, &output_root).expect("install replacement root");

        let mut failure = ReaderFailure::new("io", "materialization failed");
        retain_output_tree_after_failure(&mut failure, tree);
        assert!(failure.retry_cleanup().is_err());

        std::fs::remove_dir(&output_root).expect("remove replacement root");
        std::fs::rename(&original, &output_root).expect("restore original root");

        failure
            .retry_cleanup()
            .expect("retained output owner must retry cleanup");
        assert!(!Path::new(&output_root).exists());
    }

    struct NestedCleanupResource {
        close_count: Arc<AtomicUsize>,
    }

    impl SessionResource for NestedCleanupResource {
        fn close(&self) -> Result<(), AnalysisError> {
            self.close_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct NestedFailureReader {
        fail_once: Arc<AtomicBool>,
        resource: Arc<dyn SessionResource>,
    }

    impl ArtifactReader for NestedFailureReader {
        fn format(&self) -> &'static str {
            "nested-test"
        }

        fn entries(
            &mut self,
            _cancellation: &Cancellation,
            _omissions: &mut Vec<ArtifactTraversalOmission>,
        ) -> Result<Vec<ArtifactEntry>, ReaderFailure> {
            Ok(Vec::new())
        }

        fn open(
            &mut self,
            _entry: &ArtifactEntry,
            _cancellation: &Cancellation,
        ) -> Result<Vec<u8>, ReaderFailure> {
            Ok(Vec::new())
        }

        fn close(&mut self) -> Result<(), ReaderFailure> {
            if self.fail_once.swap(false, Ordering::SeqCst) {
                let mut failure = ReaderFailure::new("io", "nested reader close failed");
                failure.retain_resource("nested resource".to_owned(), Arc::clone(&self.resource));
                Err(failure)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn reader_close_preserves_nested_resource_for_independent_retry() {
        let close_count = Arc::new(AtomicUsize::new(0));
        let resource: Arc<dyn SessionResource> = Arc::new(NestedCleanupResource {
            close_count: Arc::clone(&close_count),
        });
        let mut reader: Box<dyn ArtifactReader> = Box::new(NestedFailureReader {
            fail_once: Arc::new(AtomicBool::new(true)),
            resource,
        });
        let mut failure = ReaderFailure::new("integrity", "materialization failed");

        close_reader_after_failure(&mut reader, &mut failure);
        failure
            .retry_cleanup()
            .expect("reader and nested cleanup should retry independently");

        assert_eq!(close_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn unresolved_output_identity_releases_only_after_path_disappears() {
        let output_root = create_extraction_destination();
        let path = Path::new(&output_root);
        std::fs::create_dir(path).expect("create unresolved test root");
        let mut tree = SafeOutputTree {
            output_root: path.to_owned(),
            committed: false,
            root_identity: None,
        };

        assert!(tree.cleanup().is_err());
        std::fs::remove_dir(path).expect("remove unresolved test root");
        tree.cleanup()
            .expect("an absent unresolved root is already cleaned up");
    }
}

#[cfg(not(unix))]
fn write_new_file(destination: &Path, bytes: &[u8]) -> Result<(), ReaderFailure> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(destination).map_err(|cause| {
        ReaderFailure::new(
            "path",
            format!(
                "Could not exclusively create extraction path: {}: {cause}",
                destination.display()
            ),
        )
    })?;
    file.write_all(bytes).map_err(|cause| {
        ReaderFailure::new("io", format!("Could not write extraction file: {cause}"))
    })?;
    file.sync_all().map_err(|cause| {
        ReaderFailure::new("io", format!("Could not flush extraction file: {cause}"))
    })?;
    Ok(())
}
