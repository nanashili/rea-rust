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
use super::reader::{ArtifactReader, ReaderFailure};
use super::zip_reader::ZipArtifactReader;
use rea_core::cancellation::Cancellation;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

/// `createArtifactExtractionDestination`: a fresh temp directory chosen by REA.
pub fn create_extraction_destination() -> String {
    let unique = format!("rea-extracted-{}-{}", std::process::id(), unique_suffix());
    std::env::temp_dir()
        .join(unique)
        .to_string_lossy()
        .into_owned()
}

fn unique_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:x}")
}

/// Whether a format has an extraction reader (`requireExtractableFormat`).
fn is_extractable(format: &str, is_directory: bool) -> bool {
    is_directory || format == "asar" || is_mach_o_format(format) || is_zip_package_format(format)
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
    logical_path: String,
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
    // selectedOccurrences: file/slice occurrences other than root.
    let selected: Vec<&super::graph::ArtifactOccurrence> = inventory
        .occurrences
        .iter()
        .filter(|occurrence| {
            (occurrence.entry_kind == "file" || occurrence.entry_kind == "slice")
                && occurrence.logical_path != "."
        })
        .collect();
    let regular_paths: std::collections::HashSet<&str> =
        selected.iter().map(|o| o.logical_path.as_str()).collect();
    // activeOccurrences: exclude members nested under a regular file.
    let active: Vec<&super::graph::ArtifactOccurrence> = selected
        .iter()
        .copied()
        .filter(|occurrence| {
            let mut path = occurrence.logical_path.as_str();
            while let Some(slash) = path.rfind('/') {
                path = &path[..slash];
                if regular_paths.contains(path) {
                    return false;
                }
            }
            true
        })
        .collect();

    // Build node lookup.
    let mut node_sha: BTreeMap<&str, (&str, u64)> = BTreeMap::new();
    for node in &inventory.nodes {
        node_sha.insert(node.artifact_id.as_str(), (node.sha256.as_str(), node.size));
    }

    let selected_ids: std::collections::HashSet<&str> =
        active.iter().map(|o| o.occurrence_id.as_str()).collect();

    let mut selected_items: Vec<SelectedOccurrence> = Vec::new();
    for occurrence in &active {
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
                logical_path: occurrence.logical_path.clone(),
                declared_sha256: None,
                calculated_sha256: None,
                unpacked: true,
            }));
        }
        let artifact_id = occurrence.artifact_id.clone().ok_or_else(|| {
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
        selected_items.push(SelectedOccurrence {
            occurrence_id: occurrence.occurrence_id.clone(),
            logical_path: occurrence.logical_path.clone(),
            artifact_id: artifact_id.clone(),
            sha256: (*sha256).to_owned(),
            size: *size,
        });
    }

    // Path-collision check.
    let mut by_path: BTreeMap<String, usize> = BTreeMap::new();
    for (index, item) in selected_items.iter().enumerate() {
        if by_path.contains_key(&item.logical_path) {
            return Err(ReaderFailure::new(
                "path",
                format!(
                    "Artifact extraction path collision: {:?}. Multiple selected occurrences share this normalized logical path; they cannot be materialized at the same destination path, even when the archive is valid. Inventory retains each occurrence.",
                    item.logical_path
                ),
            ));
        }
        by_path.insert(item.logical_path.clone(), index);
    }

    // Create reader over the source again.
    let is_directory = std::fs::symlink_metadata(source_path)
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false);
    let mut reader =
        create_extraction_reader(source_path, input_format, is_directory, cancellation)?;

    // Create the output tree.
    let tree = SafeOutputTree::create(output_root)?;

    let mut extracted: Vec<Value> = Vec::new();
    let mut remaining: std::collections::HashSet<String> = by_path.keys().cloned().collect();

    let mut omissions = Vec::new();
    let entries = reader.entries(cancellation, &mut omissions)?;
    for entry in &entries {
        let path = normalize(&entry.path)?;
        let selected_index = by_path.get(&path).copied();
        let Some(index) = selected_index else {
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
        let written = tree.write(&path, &bytes, &item.sha256, item.size)?;
        extracted.push(json!({
            "artifact_id": item.artifact_id,
            "relative_path": written.relative_path,
            "sha256": written.sha256,
            "bytes_written": written.bytes_written,
            "created": true,
        }));
        remaining.remove(&path);
    }
    let _ = selected_ids;
    if !remaining.is_empty() {
        let mut missing: Vec<String> = remaining.into_iter().collect();
        missing.sort();
        return Err(ReaderFailure::new(
            "integrity",
            format!(
                "Inventoried regular artifact entries were not materialized: {}",
                missing.join(", ")
            ),
        ));
    }
    reader.close()?;

    // Sort extracted by relative_path.
    extracted.sort_by(|a, b| {
        a["relative_path"]
            .as_str()
            .unwrap_or("")
            .cmp(b["relative_path"].as_str().unwrap_or(""))
    });

    let result = create_extraction_result(output_root, inventory, &selected_items, &extracted);
    tree.commit();
    Ok(result)
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
    // mach-o slice extraction requires the native lipo adapter, not ported.
    Err(ReaderFailure::new(
        "unavailable",
        "Mach-O slice extraction requires the native macOS adapter, which is unavailable in this build.",
    ))
}

fn read_whole(path: &str, cancellation: &Cancellation) -> Result<Vec<u8>, ReaderFailure> {
    const MAX: usize = 2 * 1024 * 1024 * 1024;
    let snapshot = rea_host::fs::stable_file::read(
        crate::common::host_files(),
        Path::new(path),
        MAX,
        cancellation,
    )
    .map_err(|_| ReaderFailure::new("io", "Could not read artifact for extraction"))?;
    Ok(snapshot.bytes)
}

fn normalize(input: &str) -> Result<String, ReaderFailure> {
    if input.contains('\0') || input.starts_with('/') {
        return Err(ReaderFailure::new(
            "path",
            format!("Artifact path is absolute or unsafe: {input:?}"),
        ));
    }
    let normalized = input.trim_end_matches('/').to_owned();
    if normalized.is_empty()
        || normalized
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(ReaderFailure::new(
            "path",
            format!("Artifact path is not normalized: {input:?}"),
        ));
    }
    Ok(normalized)
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
}

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
        Ok(Self {
            output_root: canonical_output,
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
        let path = normalize(relative_path)?;
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
    fn commit(self) {
        // The created files are the committed result; no staging to roll back.
    }
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
