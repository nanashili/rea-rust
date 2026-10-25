//! Inventory scan and artifact-graph construction.
//!
//! Compatibility owners: `src/artifacts/inventory/scanCanonical.ts`,
//! `src/artifacts/inventory/scanReader.ts`,
//! `src/artifacts/inventory/ArtifactGraphConstruction.ts`,
//! `src/artifacts/inventory/reader.ts` and `src/artifacts/ArtifactPaths.ts`.
use super::asar::AsarArtifactReader;
use super::classify::{
    self, Role, ZIP_NON_ENTRY_LIMITATION, classify_artifact_bytes, classify_artifact_content,
    classify_artifact_content_js_path, classify_artifact_js_path, classify_artifact_path,
    is_zip_package_format, zip_package_format_for_js_path, zip_package_format_for_path,
};
use super::directory_reader::DirectoryArtifactReader;
use super::graph::*;
use super::reader::{
    ArtifactEntry, ArtifactReader, ArtifactTraversalOmission, ReaderFailure, RetainedReader,
    read_stable_file,
};
use super::zip_reader::ZipArtifactReader;
use crate::macos_readers::{dmg::NativeDmgArtifactReader, macho_slice::MachOSliceArtifactReader};
use crate::native_command::CommandCleanup;
use rea_core::JsString;
use rea_core::artifact_inventory::ArtifactByteRange;
use rea_core::artifact_paths::normalize_artifact_js_path;
use rea_core::cancellation::Cancellation;
#[cfg(test)]
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(serde::Serialize)]
struct DirectoryDigestChild {
    name: JsString,
    artifact_id: Option<String>,
    entry_kind: &'static str,
}

#[derive(serde::Serialize)]
struct DirectoryDigestOccurrence {
    logical_path: JsString,
    artifact_id: Option<String>,
}

const MAX_ROOT_BYTES: usize = 2 * 1024 * 1024 * 1024;

/// A mutable occurrence during graph construction.
#[derive(Clone)]
struct MutableOccurrence {
    occurrence_id: String,
    artifact_id: Option<String>,
    parent_occurrence_id: Option<String>,
    logical_path: JsString,
    entry_kind: &'static str,
    artifact_kind: String,
    artifact_format: String,
    declared_size: Option<u64>,
    compressed_size: Option<u64>,
    executable: bool,
    encrypted: bool,
    hash_status: String,
    source_location: Option<ArtifactByteRange>,
    limitations: Vec<String>,
}

struct PendingContradiction {
    occurrence_index: usize,
    declared_sha256: String,
    observed_sha256: String,
    entry_kind: &'static str,
    unpacked: bool,
}

/// Classified-and-hashed root.
struct RootClassification {
    format: &'static str,
    sha256: Option<String>,
    size: u64,
    prefix: Vec<u8>,
    is_directory: bool,
    /// Captured root bytes for an in-memory container reader (ZIP / ASAR).
    captured: Option<Arc<[u8]>>,
}

/// Hash a byte slice and return its lowercase hex digest.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// `classifyAndHashRootForInventory` + `classifyRootFormat`.
fn classify_root(
    path: &str,
    cancellation: &Cancellation,
) -> Result<RootClassification, ReaderFailure> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| ReaderFailure::new("io", format!("Could not stat root: {error}")))?;
    if metadata.is_dir() {
        // The directory itself is not content-hashed, but its root occurrence
        // still carries the filesystem metadata size. TypeScript obtains this
        // value from `lstat`, and the occurrence participates in the graph
        // digest, so retaining zero here changes the inventory commitment for
        // every directory root.
        let directory_size = metadata.len();
        return Ok(RootClassification {
            format: "directory",
            sha256: None,
            size: directory_size,
            prefix: Vec::new(),
            is_directory: true,
            captured: None,
        });
    }
    let snapshot = read_stable_file(path, MAX_ROOT_BYTES, cancellation)?;
    let size = snapshot.bytes.len() as u64;
    let lower = path.to_lowercase();
    let prefix_len = snapshot.bytes.len().min(8192);
    let prefix = snapshot.bytes[..prefix_len].to_vec();
    let format = classify_root_format(&lower, &snapshot.bytes, size);
    let retain_source = is_zip_package_format(format) || format == "asar";
    Ok(RootClassification {
        format,
        sha256: Some(snapshot.sha256),
        size,
        prefix,
        is_directory: false,
        captured: if retain_source {
            Some(snapshot.bytes.into())
        } else {
            None
        },
    })
}

fn has_koly_trailer(bytes: &[u8], size: u64) -> bool {
    if size < 512 {
        return false;
    }
    let start = (size - 512) as usize;
    start + 4 <= bytes.len() && &bytes[start..start + 4] == b"koly"
}

fn classify_root_format(lower: &str, bytes: &[u8], size: u64) -> &'static str {
    let prefix_len = bytes.len().min(8192);
    let prefix = &bytes[..prefix_len];
    if classify::has_zip_signature(prefix) {
        return if lower.ends_with(".app") {
            "app-pack"
        } else {
            zip_package_format_for_path(lower).unwrap_or("zip")
        };
    }
    if lower.ends_with(".pkg") && prefix.len() >= 4 && &prefix[..4] == b"xar!" {
        return "pkg";
    }
    if lower.ends_with(".dmg") && has_koly_trailer(bytes, size) {
        return "dmg";
    }
    classify_artifact_content(lower, prefix, size)
        .map(|role| role.format)
        .unwrap_or("unknown")
}

/// Build a reader for a root or nested container (`createReader`).
fn create_reader(
    path: &str,
    format: &str,
    captured: Option<Arc<[u8]>>,
) -> Option<Box<dyn ArtifactReader>> {
    if is_zip_package_format(format) {
        let zip_format: &'static str = match format {
            "zip" => "zip",
            "ipa" => "ipa",
            "apk" => "apk",
            "msix" => "msix",
            "appx" => "appx",
            "hap" => "hap",
            "hsp" => "hsp",
            "app-pack" => "app-pack",
            _ => "zip",
        };
        return captured.map(|bytes| {
            Box::new(ZipArtifactReader::new(zip_format, bytes.to_vec())) as Box<dyn ArtifactReader>
        });
    }
    match format {
        "directory" => Some(Box::new(DirectoryArtifactReader::new(path))),
        "asar" => captured.map(|bytes| {
            Box::new(AsarArtifactReader::new_shared(bytes)) as Box<dyn ArtifactReader>
        }),
        "mach-o-universal" => Some(Box::new(MachOSliceArtifactReader::new(
            path,
            std::sync::Arc::new(CommandCleanup::default()),
        ))),
        "dmg" => Some(Box::new(NativeDmgArtifactReader::new(
            path,
            std::sync::Arc::new(CommandCleanup::default()),
        ))),
        _ => None,
    }
}

/// Open a JavaScript reconstruction reader after canonicalizing and checking
/// the caller-selected filesystem input. Inventory and acquisition therefore
/// share the same provider-owned path and format admission.
pub(crate) fn create_reader_for_path(
    input_path: &str,
    expected_format: &str,
    cancellation: &Cancellation,
) -> Result<(String, Option<Arc<[u8]>>, Box<dyn ArtifactReader>), ReaderFailure> {
    let canonical = std::fs::canonicalize(input_path).map_err(|error| {
        ReaderFailure::new("io", format!("Could not resolve artifact path: {error}"))
    })?;
    let canonical_str = canonical.to_str().ok_or_else(|| {
        ReaderFailure::new(
            "path",
            format!("Artifact path is not representable as UTF-8: {canonical:?}"),
        )
    })?;
    let root = classify_root(canonical_str, cancellation)?;
    let accepts_observed_format = expected_format == "auto";
    if !accepts_observed_format && root.format != expected_format {
        return Err(ReaderFailure::new(
            "format",
            format!(
                "Artifact inventory classified {canonical_str} as {}, not {expected_format}",
                root.format
            ),
        ));
    }

    if accepts_observed_format && !matches!(root.format, "directory" | "asar") {
        return Err(ReaderFailure::new(
            "format",
            format!(
                "JavaScript artifact input must be a directory or ASAR, not {}",
                root.format
            ),
        ));
    }
    let captured = root.captured.clone();
    let reader = create_reader(canonical_str, root.format, captured.clone())
        .ok_or_else(|| ReaderFailure::new("unavailable", "Artifact reader is unavailable"))?;
    Ok((canonical_str.to_owned(), captured, reader))
}

/// `inventoryCoverage`.
fn inventory_coverage(
    format: &str,
    reader_format: Option<&str>,
    traversal_status: &str,
    traversal_limitations: &[String],
) -> (ArtifactInventoryCoverage, Vec<String>) {
    if let Some(reader_format) = reader_format {
        let mut limitations = Vec::new();
        if is_zip_package_format(reader_format) {
            limitations.push(ZIP_NON_ENTRY_LIMITATION.to_owned());
        }
        limitations.extend(traversal_limitations.iter().cloned());
        return (
            ArtifactInventoryCoverage {
                scope: "container-entries".to_owned(),
                status: traversal_status.to_owned(),
            },
            limitations,
        );
    }
    if format == "dmg" || format == "pkg" {
        return (
            ArtifactInventoryCoverage {
                scope: "container-entries".to_owned(),
                status: "unknown".to_owned(),
            },
            vec![format!(
                "{} root hash is observed; child inventory requires a native macOS adapter.",
                format.to_uppercase()
            )],
        );
    }
    if format == "mach-o-universal" {
        return (
            ArtifactInventoryCoverage {
                scope: "container-entries".to_owned(),
                status: "unknown".to_owned(),
            },
            vec!["Universal Mach-O slices require the native macOS lipo adapter.".to_owned()],
        );
    }
    if is_zip_package_format(format) || format == "directory" || format == "asar" {
        return (
            ArtifactInventoryCoverage {
                scope: "container-entries".to_owned(),
                status: "unknown".to_owned(),
            },
            vec![format!("{format} child inventory reader is unavailable.")],
        );
    }
    (
        ArtifactInventoryCoverage {
            scope: "root".to_owned(),
            status: "complete".to_owned(),
        },
        vec!["Artifact has no child container entries.".to_owned()],
    )
}

// --- ArtifactPaths: normalizeArtifactPath ---

fn normalize_artifact_path(input: &str) -> Result<String, ReaderFailure> {
    let normalized = rea_core::artifact_paths::normalize_artifact_path(input)
        .map_err(|error| ReaderFailure::new("path", error.to_string()))?;
    Ok(normalized)
}

/// `createOccurrence` role assignment.
fn create_occurrence(
    entry: &ArtifactEntry,
    path: &JsString,
    duplicate_ordinal: u64,
) -> MutableOccurrence {
    let role = if entry.kind == "directory" {
        Role {
            kind: if path.to_ascii_lowercase().ends_with(".framework") {
                "framework"
            } else {
                "container"
            },
            format: "directory",
        }
    } else if container_suffix_family(path).is_none() {
        classify_artifact_js_path(path)
    } else {
        Role {
            kind: "unknown",
            format: "unknown",
        }
    };
    let source_location = match (entry.byte_offset, entry.declared_size) {
        (Some(offset), Some(length)) => Some(ArtifactByteRange { offset, length }),
        _ => None,
    };
    MutableOccurrence {
        occurrence_id: provisional_occurrence_id(path, entry.kind, duplicate_ordinal),
        artifact_id: None,
        parent_occurrence_id: None,
        logical_path: path.clone(),
        entry_kind: entry.kind,
        artifact_kind: role.kind.to_owned(),
        artifact_format: role.format.to_owned(),
        declared_size: entry.declared_size,
        compressed_size: entry.compressed_size,
        executable: entry.executable,
        encrypted: entry.encrypted,
        hash_status: if entry.encrypted {
            "unavailable".to_owned()
        } else {
            "not-hashed".to_owned()
        },
        source_location,
        limitations: entry.limitations.clone(),
    }
}

fn container_suffix_family(path: &JsString) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".asar") {
        Some("asar")
    } else {
        zip_package_format_for_js_path(&lower)
    }
}

fn note_unread_container_suffix(occurrence: &mut MutableOccurrence) {
    if occurrence.entry_kind == "directory" {
        return;
    }
    if let Some(family) = container_suffix_family(&occurrence.logical_path) {
        occurrence.limitations.push(format!(
            "The path suffix suggests {}, but these bytes were not read, so the container family is unknown.",
            family.to_uppercase()
        ));
    }
}

/// Output of scanning a reader's entries.
struct ScanOutput {
    nodes: BTreeMap<String, ArtifactNode>,
    occurrences: Vec<MutableOccurrence>,
    pending: Vec<PendingContradiction>,
    omissions: Vec<ArtifactTraversalOmission>,
    expanded_container_ids: std::collections::HashSet<String>,
}

struct ReaderFrame {
    reader: Box<dyn ArtifactReader>,
    prefix: JsString,
    entries: Vec<ArtifactEntry>,
    index: usize,
}

struct ReaderCleanupFailure {
    resource: String,
    failure: ReaderFailure,
    retained: RetainedReader,
}

struct ReaderScope {
    stack: Vec<ReaderFrame>,
    cleanup_failures: Vec<ReaderCleanupFailure>,
}

impl ReaderScope {
    fn new(root_reader: Box<dyn ArtifactReader>) -> Self {
        Self {
            stack: vec![ReaderFrame {
                reader: root_reader,
                prefix: JsString::from(""),
                entries: Vec::new(),
                index: 0,
            }],
            cleanup_failures: Vec::new(),
        }
    }

    fn resource_name(frame: &ReaderFrame) -> String {
        if frame.prefix.is_empty() {
            format!("{} reader", frame.reader.format())
        } else {
            format!("{} reader at {}", frame.reader.format(), frame.prefix)
        }
    }

    fn record_close_failure(&mut self, frame: ReaderFrame, failure: ReaderFailure) {
        let resource = Self::resource_name(&frame);
        let retained = RetainedReader::new(resource.clone(), frame.reader);
        self.cleanup_failures.push(ReaderCleanupFailure {
            resource,
            failure,
            retained,
        });
    }

    fn close_frame(&mut self, frame: ReaderFrame) -> Option<ReaderFailure> {
        let mut frame = frame;
        match frame.reader.close() {
            Ok(()) => None,
            Err(failure) => {
                let primary = failure.clone();
                self.record_close_failure(frame, failure);
                Some(primary)
            }
        }
    }

    fn close_remaining(&mut self) {
        while let Some(frame) = self.stack.pop() {
            self.close_frame(frame);
        }
    }

    fn finish(mut self, primary: Option<ReaderFailure>) -> Result<ScanOutput, ReaderFailure> {
        self.close_remaining();

        let cleanup_failures = self.cleanup_failures;
        let mut primary = match primary {
            Some(primary) => primary,
            None => match cleanup_failures.first() {
                Some(first) => first.failure.clone(),
                None => unreachable!("reader scope finished without a failure"),
            },
        };

        let (mut reasons, mut resources) = primary
            .cleanup
            .take()
            .map(|cleanup| (vec![cleanup.reason], cleanup.resources))
            .unwrap_or_else(|| (Vec::new(), Vec::new()));

        for cleanup in cleanup_failures {
            reasons.push(cleanup.failure.message.clone());
            resources.push(cleanup.resource);
            if let Some(observation) = cleanup.failure.cleanup {
                resources.extend(observation.resources);
            }
            primary.retain_reader(cleanup.retained);
        }

        if !reasons.is_empty() || !resources.is_empty() {
            resources.sort();
            resources.dedup();
            primary.cleanup = Some(rea_core::analysis_error::CleanupObservation {
                reason: reasons.join("; "),
                resources,
            });
        }

        Err(primary)
    }
}

/// `scanReader`: visit every entry across the root reader and nested ASAR
/// readers, hashing, classifying and recording contradictions.
fn scan_reader(
    root_reader: Option<Box<dyn ArtifactReader>>,
    integrity_fail: bool,
    cancellation: &Cancellation,
) -> Result<ScanOutput, ReaderFailure> {
    let mut output = ScanOutput {
        nodes: BTreeMap::new(),
        occurrences: Vec::new(),
        pending: Vec::new(),
        omissions: Vec::new(),
        expanded_container_ids: std::collections::HashSet::new(),
    };
    let Some(reader) = root_reader else {
        return Ok(output);
    };
    let mut occurrence_count_by_path: BTreeMap<JsString, u64> = BTreeMap::new();
    let mut omissions = Vec::new();
    let mut scope = ReaderScope::new(reader);
    let root_entries = match scope
        .stack
        .last_mut()
        .expect("root reader frame")
        .reader
        .entries(cancellation, &mut omissions)
    {
        Ok(entries) => entries,
        Err(failure) => return scope.finish(Some(failure)),
    };
    output.omissions.extend(omissions);
    scope.stack[0].entries = root_entries;

    loop {
        let next_entry = {
            let Some(frame) = scope.stack.last_mut() else {
                break;
            };
            if frame.index >= frame.entries.len() {
                None
            } else {
                let entry = frame.entries[frame.index].clone();
                let prefix = frame.prefix.clone();
                frame.index += 1;
                Some((entry, prefix))
            }
        };
        let Some((entry, prefix)) = next_entry else {
            let finished = scope.stack.pop().expect("frame present");
            if let Some(failure) = scope.close_frame(finished) {
                return scope.finish(Some(failure));
            }
            continue;
        };
        let candidate_path = if prefix.is_empty() {
            entry.path.clone()
        } else {
            prefix.concat_str("/").concat(&entry.path)
        };
        let logical_path = match normalize_artifact_js_path(&candidate_path) {
            Ok(path) => path,
            Err(failure) => {
                return scope.finish(Some(ReaderFailure::new("path", failure.to_string())));
            }
        };
        let entry_is_filesystem_backed = scope
            .stack
            .last()
            .expect("frame present for entry")
            .reader
            .entry_is_filesystem_backed(&entry);
        let expandable_asar = is_expandable_asar(&entry, &logical_path, entry_is_filesystem_backed);
        let duplicate_ordinal = *occurrence_count_by_path.get(&logical_path).unwrap_or(&0);
        occurrence_count_by_path.insert(logical_path.clone(), duplicate_ordinal + 1);
        let mut occurrence = create_occurrence(&entry, &logical_path, duplicate_ordinal);

        // digestArtifactEntry
        let digested = if (entry.kind == "file" || entry.kind == "slice") && !entry.encrypted {
            let frame = scope.stack.last_mut().expect("frame present for open");
            match frame.reader.open(&entry, cancellation) {
                Ok(bytes) => match digest_entry(&entry, &logical_path, bytes, integrity_fail) {
                    Ok(digested) => Some(digested),
                    Err(failure) => return scope.finish(Some(failure)),
                },
                Err(failure) => {
                    if entry.unpacked && failure.reason == "unavailable" {
                        occurrence.hash_status = "unavailable".to_owned();
                        occurrence.limitations.push(
                            "ASAR unpacked companion bytes were unavailable; no content hash or child artifact was produced.".to_owned(),
                        );
                        None
                    } else {
                        return scope.finish(Some(failure));
                    }
                }
            }
        } else {
            None
        };

        let mut nested_asar_bytes: Option<Vec<u8>> = None;
        match &digested {
            None => note_unread_container_suffix(&mut occurrence),
            Some(result) => {
                output
                    .nodes
                    .insert(result.node.artifact_id.clone(), result.node.clone());
                occurrence.artifact_id = Some(result.node.artifact_id.clone());
                occurrence.artifact_kind = result.kind.clone();
                occurrence.artifact_format = result.format.clone();
                occurrence.hash_status = if result.mismatched {
                    "mismatched".to_owned()
                } else {
                    "verified".to_owned()
                };
                if result.mismatched {
                    occurrence
                        .limitations
                        .push("Declared integrity metadata contradicts observed bytes.".to_owned());
                    output.pending.push(PendingContradiction {
                        occurrence_index: output.occurrences.len(),
                        declared_sha256: entry.declared_sha256.clone().unwrap_or_default(),
                        observed_sha256: result.node.sha256.clone(),
                        entry_kind: entry.kind,
                        unpacked: entry.unpacked,
                    });
                }
                if expandable_asar && result.format == "asar" && !result.mismatched {
                    nested_asar_bytes = result.bytes.clone();
                }
            }
        }

        let occurrence_id = occurrence.occurrence_id.clone();
        output.occurrences.push(occurrence);

        if let Some(bytes) = nested_asar_bytes {
            let nested = AsarArtifactReader::new(bytes);
            let mut nested_omissions = Vec::new();
            scope.stack.push(ReaderFrame {
                reader: Box::new(nested),
                prefix: logical_path.clone(),
                entries: Vec::new(),
                index: 0,
            });
            let nested_entries = match scope
                .stack
                .last_mut()
                .expect("nested reader frame")
                .reader
                .entries(cancellation, &mut nested_omissions)
            {
                Ok(entries) => entries,
                Err(failure) => return scope.finish(Some(failure)),
            };
            for omission in nested_omissions {
                let omission_path = match normalize_artifact_js_path(
                    &logical_path.concat_str("/").concat(&omission.path),
                ) {
                    Ok(path) => path,
                    Err(failure) => {
                        return scope.finish(Some(ReaderFailure::new("path", failure.to_string())));
                    }
                };
                output.omissions.push(ArtifactTraversalOmission {
                    path: omission_path,
                    kind: omission.kind,
                });
            }
            output.expanded_container_ids.insert(occurrence_id);
            let nested_frame = scope.stack.last_mut().expect("nested reader frame");
            nested_frame.entries = nested_entries;
        }
    }
    Ok(output)
}

struct DigestedEntry {
    node: ArtifactNode,
    mismatched: bool,
    kind: String,
    format: String,
    bytes: Option<Vec<u8>>,
}

fn digest_entry(
    entry: &ArtifactEntry,
    logical_path: &JsString,
    bytes: Vec<u8>,
    integrity_fail: bool,
) -> Result<DigestedEntry, ReaderFailure> {
    let sha256 = sha256_hex(&bytes);
    let size = bytes.len() as u64;
    let prefix_len = bytes.len().min(8192);
    let prefix = &bytes[..prefix_len];
    let mismatched = entry
        .declared_sha256
        .as_ref()
        .map(|declared| declared != &sha256)
        .unwrap_or(false);
    if mismatched
        && let Some(declared) = &entry.declared_sha256
        && integrity_fail
    {
        return Err(ReaderFailure::new(
            "integrity",
            format!("Artifact integrity metadata disagrees with content: {logical_path}"),
        )
        .with_details(rea_core::analysis_error::ArtifactDetails {
            logical_path: logical_path.to_string(),
            declared_sha256: Some(declared.clone()),
            calculated_sha256: Some(sha256.clone()),
            unpacked: entry.unpacked,
        }));
    }
    let classified = if entry.kind == "slice" {
        Role {
            kind: "universal-slice",
            format: "mach-o",
        }
    } else {
        classify_artifact_content_js_path(logical_path, prefix, size)?
    };
    let node_format = classify_artifact_bytes(prefix, size);
    Ok(DigestedEntry {
        node: create_artifact_node(&sha256, size, node_format, "embedded"),
        mismatched,
        kind: classified.kind.to_owned(),
        format: classified.format.to_owned(),
        bytes: if classified.format == "asar" {
            Some(bytes)
        } else {
            None
        },
    })
}

fn create_artifact_node(
    sha256: &str,
    size: u64,
    format: &str,
    content_state: &str,
) -> ArtifactNode {
    ArtifactNode {
        artifact_id: artifact_id_for_content(sha256),
        format: format.to_owned(),
        sha256: sha256.to_owned(),
        size,
        media_type: RequiredNullable::from_option(None),
        architecture: RequiredNullable::from_option(None),
        content_state: content_state.to_owned(),
        limitations: Vec::new(),
    }
}

/// `resolveOccurrenceParents`.
fn resolve_occurrence_parents(
    occurrences: &mut [MutableOccurrence],
    expanded_container_ids: &std::collections::HashSet<String>,
) -> (Vec<String>, std::collections::HashSet<usize>) {
    let mut by_path: BTreeMap<JsString, Vec<usize>> = BTreeMap::new();
    for (index, occurrence) in occurrences.iter().enumerate() {
        by_path
            .entry(occurrence.logical_path.clone())
            .or_default()
            .push(index);
    }
    #[derive(Default)]
    struct Node {
        children: BTreeMap<JsString, usize>,
        occurrences: Vec<usize>,
    }
    let mut nodes: Vec<Node> = vec![Node::default()];
    let mut limitations: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let paths: Vec<JsString> = by_path.keys().cloned().collect();
    for path in &paths {
        let indices = by_path.get(path).cloned().unwrap_or_default();
        let parents: Vec<usize> = indices
            .iter()
            .copied()
            .filter(|&i| {
                occurrences[i].entry_kind == "directory"
                    || expanded_container_ids.contains(&occurrences[i].occurrence_id)
            })
            .collect();
        if parents.is_empty() {
            continue;
        }
        if parents.len() > 1 {
            for &i in &parents {
                if occurrences[i].entry_kind == "directory" {
                    occurrences[i].artifact_id = None;
                    occurrences[i].hash_status = "unavailable".to_owned();
                    occurrences[i].limitations.push(
                        "This directory occurrence cannot be materialized because multiple directory entries share its logical path.".to_owned(),
                    );
                }
            }
        }
        let mut branch = 0usize;
        for segment in js_path_components(path) {
            let next = match nodes[branch].children.get(&segment) {
                Some(&child) => child,
                None => {
                    let child = nodes.len();
                    nodes.push(Node::default());
                    nodes[branch].children.insert(segment.clone(), child);
                    child
                }
            };
            branch = next;
        }
        nodes[branch].occurrences = parents;
    }
    let mut unknown_parents: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for index in 0..occurrences.len() {
        let path = occurrences[index].logical_path.clone();
        let mut branch = 0usize;
        let mut parent: Option<usize> = None;
        let mut ambiguous: Option<String> = None;
        let mut prefix = JsString::from("");
        let components = js_path_components(&path);
        for segment in components.iter().take(components.len().saturating_sub(1)) {
            let Some(&child) = nodes[branch].children.get(segment) else {
                break;
            };
            branch = child;
            prefix = if prefix.is_empty() {
                segment.clone()
            } else {
                prefix.concat_str("/").concat(segment)
            };
            let candidates = &nodes[branch].occurrences;
            if candidates.len() == 1 {
                parent = Some(candidates[0]);
                ambiguous = None;
            } else if candidates.len() > 1 {
                parent = None;
                ambiguous = Some(prefix.to_string());
            }
        }
        occurrences[index].parent_occurrence_id =
            parent.map(|p| occurrences[p].occurrence_id.clone());
        if let Some(ambiguous_path) = ambiguous {
            let limitation = format!(
                "The parent occurrence for {path:?} is unknown because multiple observed directory or container occurrences share {ambiguous_path:?}."
            );
            occurrences[index].limitations.push(limitation.clone());
            limitations.insert(limitation);
            unknown_parents.insert(index);
        }
    }
    let mut sorted: Vec<String> = limitations.into_iter().collect();
    sorted.sort_by(|a, b| compare_unicode_code_points(a, b));
    (sorted, unknown_parents)
}

/// `materializeDirectoryNodes`.
fn materialize_directory_nodes(
    occurrences: &mut [MutableOccurrence],
    nodes: &mut BTreeMap<String, ArtifactNode>,
) {
    let mut directory_indices: Vec<usize> = occurrences
        .iter()
        .enumerate()
        .filter(|(_, o)| o.entry_kind == "directory" && o.hash_status != "unavailable")
        .map(|(i, _)| i)
        .collect();
    directory_indices.sort_by(|&a, &b| {
        depth(&occurrences[b].logical_path).cmp(&depth(&occurrences[a].logical_path))
    });
    let mut children_by_parent: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, occurrence) in occurrences.iter().enumerate() {
        if let Some(parent) = &occurrence.parent_occurrence_id {
            children_by_parent
                .entry(parent.clone())
                .or_default()
                .push(index);
        }
    }
    for dir_index in directory_indices {
        let dir_id = occurrences[dir_index].occurrence_id.clone();
        let dir_path_len = occurrences[dir_index].logical_path.len();
        let children: Vec<DirectoryDigestChild> = children_by_parent
            .get(&dir_id)
            .map(|indices| {
                let mut list: Vec<(JsString, Option<String>, &'static str)> = indices
                    .iter()
                    .map(|&c| {
                        let child = &occurrences[c];
                        let name = child
                            .logical_path
                            .slice_units(dir_path_len + 1..child.logical_path.len());
                        (name, child.artifact_id.clone(), child.entry_kind)
                    })
                    .collect();
                list.sort_by(|a, b| compare_js_code_points(&a.0, &b.0));
                list.into_iter()
                    .map(|(name, artifact_id, entry_kind)| DirectoryDigestChild {
                        name,
                        artifact_id,
                        entry_kind,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let sha256 = directory_node_sha256(&children);
        let node = create_artifact_node(&sha256, 0, "directory", "virtual");
        nodes.insert(node.artifact_id.clone(), node.clone());
        occurrences[dir_index].artifact_id = Some(node.artifact_id);
        occurrences[dir_index].hash_status = "verified".to_owned();
    }
}

fn js_path_components(path: &JsString) -> Vec<JsString> {
    path.units()
        .split(|unit| *unit == u16::from(b'/'))
        .map(|component| JsString::from_utf16(component.to_vec()))
        .collect()
}

fn depth(path: &JsString) -> usize {
    path.component_count()
}

/// English (en-US) Unicode case-collision annotation (ASCII-fold grouping over
/// the full logical path, which matches `toLocaleLowerCase("en-US")` for the
/// ASCII-dominant archive names REA inventories).
fn annotate_case_collisions(occurrences: &mut [MutableOccurrence]) -> Option<String> {
    let mut by_fold: BTreeMap<JsString, Vec<JsString>> = BTreeMap::new();
    for occurrence in occurrences.iter() {
        if occurrence.logical_path.is_empty() || occurrence.logical_path == "." {
            continue;
        }
        by_fold
            .entry(occurrence.logical_path.to_ascii_lowercase())
            .or_default()
            .push(occurrence.logical_path.clone());
    }
    let mut collisions: BTreeMap<JsString, Vec<JsString>> = BTreeMap::new();
    let mut any = false;
    for spellings in by_fold.values() {
        let distinct: std::collections::BTreeSet<&JsString> = spellings.iter().collect();
        if distinct.len() > 1 {
            any = true;
            let mut sorted: Vec<JsString> = distinct.iter().map(|s| (*s).clone()).collect();
            sorted.sort_by(compare_js_code_points);
            for path in &sorted {
                let others: Vec<JsString> = sorted.iter().filter(|p| *p != path).cloned().collect();
                collisions.insert(path.clone(), others);
            }
        }
    }
    if !any {
        return None;
    }
    for occurrence in occurrences.iter_mut() {
        if let Some(others) = collisions.get(&occurrence.logical_path) {
            let other = &others[0];
            let additional = others.len() - 1;
            let others_text = if additional == 0 {
                other.to_string()
            } else {
                format!(
                    "{other} and {additional} other spelling{}",
                    if additional == 1 { "" } else { "s" }
                )
            };
            occurrence.limitations.push(format!(
                "Logical path {} collides under English (en-US) Unicode case folding with {others_text}; a case-insensitive destination cannot store both. This comparison is not a filesystem observation.",
                occurrence.logical_path
            ));
        }
    }
    Some("Logical archive names collide under English (en-US) Unicode case folding; a case-insensitive destination cannot store both spellings. This comparison is not a filesystem observation.".to_owned())
}

/// `createArtifactEdges`.
fn create_edges(
    root_artifact_id: &str,
    occurrences: &mut [MutableOccurrence],
) -> (Vec<ArtifactEdge>, Vec<String>) {
    let by_id: BTreeMap<String, usize> = occurrences
        .iter()
        .enumerate()
        .map(|(i, o)| (o.occurrence_id.clone(), i))
        .collect();
    let mut by_path: BTreeMap<JsString, Vec<usize>> = BTreeMap::new();
    for (i, o) in occurrences.iter().enumerate() {
        by_path.entry(o.logical_path.clone()).or_default().push(i);
    }
    let mut edges = Vec::new();
    let mut limitations = Vec::new();
    let mut occ_limits: Vec<(usize, String)> = Vec::new();
    for index in 0..occurrences.len() {
        let is_source_map = occurrences[index].artifact_kind == "source-map";
        let logical_path = occurrences[index].logical_path.clone();
        let source_path = if is_source_map {
            logical_path.strip_suffix(".map")
        } else {
            None
        };
        let source_candidates: Vec<usize> = source_path
            .as_ref()
            .and_then(|p| by_path.get(p).cloned())
            .unwrap_or_default();
        let mapped_source = if source_candidates.len() == 1
            && occurrences[source_candidates[0]].artifact_id.is_some()
        {
            Some(source_candidates[0])
        } else {
            None
        };
        if let Some(source_path) = &source_path {
            let unknown = if source_candidates.len() > 1 {
                Some((
                    format!(
                        "Source-map target is unknown because multiple occurrences share {source_path:?}."
                    ),
                    format!(
                        "Source-map relationships are unknown because multiple occurrences share {source_path:?}."
                    ),
                ))
            } else if source_candidates.len() == 1 && mapped_source.is_none() {
                Some((
                    format!(
                        "Source-map target identity is unknown because the matching occurrence at {source_path:?} has no content identity."
                    ),
                    format!(
                        "Source-map relationships are unknown because the matching occurrence at {source_path:?} has no content identity."
                    ),
                ))
            } else {
                None
            };
            if let Some((occurrence_limit, coverage)) = unknown {
                occ_limits.push((index, occurrence_limit));
                limitations.push(coverage);
            }
        }
        let parent_id = occurrences[index].parent_occurrence_id.clone();
        let artifact_id = occurrences[index].artifact_id.clone();
        if parent_id.is_none() || artifact_id.is_none() {
            continue;
        }
        let parent_artifact_id = mapped_source
            .and_then(|i| occurrences[i].artifact_id.clone())
            .or_else(|| {
                parent_id
                    .as_ref()
                    .and_then(|pid| by_id.get(pid))
                    .and_then(|&pi| occurrences[pi].artifact_id.clone())
            })
            .unwrap_or_else(|| root_artifact_id.to_owned());
        let entry_kind = occurrences[index].entry_kind;
        let relation = if entry_kind == "slice" {
            "slice-of"
        } else if is_source_map {
            if mapped_source.is_none() {
                "contains"
            } else {
                "maps-source"
            }
        } else {
            relation_for(&logical_path)
        };
        let occurrence_id = occurrences[index].occurrence_id.clone();
        let edge_id = artifact_edge_id(
            &parent_artifact_id,
            artifact_id.as_deref(),
            relation,
            &occurrence_id,
            &logical_path,
        );
        edges.push(ArtifactEdge {
            edge_id,
            ordinal: edges.len() as u64,
            parent_artifact_id,
            relation: relation.to_owned(),
            occurrence_id,
            producer: RequiredNullable::from_option(None),
        });
    }
    for (index, limit) in occ_limits {
        occurrences[index].limitations.push(limit);
    }
    (edges, limitations)
}

fn relation_for(path: &JsString) -> &'static str {
    if path
        .as_str()
        .map(|value| value.to_ascii_lowercase().contains(".framework/"))
        .unwrap_or(false)
    {
        "embeds"
    } else {
        "contains"
    }
}

/// `inventoryArtifact`: scan one local artifact and return the complete graph.
pub fn inventory_artifact(
    input_path: &str,
    integrity_fail: bool,
    cancellation: &Cancellation,
) -> Result<ArtifactInventoryResult, ReaderFailure> {
    let canonical = std::fs::canonicalize(input_path).map_err(|error| {
        ReaderFailure::new("io", format!("Could not resolve artifact path: {error}"))
    })?;
    let canonical_str = canonical.to_str().ok_or_else(|| {
        ReaderFailure::new(
            "io",
            "Could not resolve artifact path: canonical path is not valid UTF-8",
        )
    })?;

    let root = classify_root(canonical_str, cancellation)?;
    let reader_format_owned = root.format.to_owned();
    let reader = create_reader(canonical_str, root.format, root.captured.clone());
    let reader_format = reader.as_ref().map(|r| r.format());

    let mut scan = scan_reader(reader, integrity_fail, cancellation)?;

    let (parent_limitations, unknown_parents) =
        resolve_occurrence_parents(&mut scan.occurrences, &scan.expanded_container_ids);

    materialize_directory_nodes(&mut scan.occurrences, &mut scan.nodes);

    let root_node = build_root_node(&root, &scan.occurrences);
    scan.nodes
        .insert(root_node.artifact_id.clone(), root_node.clone());

    rekey_occurrences(&root_node.artifact_id, &mut scan.occurrences);

    let root_occurrence = build_root_occurrence(&root_node, &root, canonical_str);
    let root_occurrence_id = root_occurrence.occurrence_id.clone();

    for (index, occurrence) in scan.occurrences.iter_mut().enumerate() {
        if occurrence.parent_occurrence_id.is_none() && !unknown_parents.contains(&index) {
            occurrence.parent_occurrence_id = Some(root_occurrence_id.clone());
        }
    }
    scan.occurrences.insert(0, root_occurrence);

    let contradictions = build_contradictions(&scan.pending, &scan.occurrences, &root_node);

    let (edges, edge_limitations) = create_edges(&root_node.artifact_id, &mut scan.occurrences);

    let case_collision = annotate_case_collisions(&mut scan.occurrences);

    let mut ordered_nodes: Vec<ArtifactNode> = scan.nodes.into_values().collect();
    ordered_nodes.sort_by(|a, b| compare_unicode_code_points(&a.artifact_id, &b.artifact_id));
    scan.occurrences
        .sort_by(|a, b| compare_js_code_points(&a.logical_path, &b.logical_path));
    let mut ordered_edges = edges;
    ordered_edges.sort_by(|a, b| compare_unicode_code_points(&a.edge_id, &b.edge_id));
    for (ordinal, edge) in ordered_edges.iter_mut().enumerate() {
        edge.ordinal = ordinal as u64;
    }

    let occurrences: Vec<ArtifactOccurrence> =
        scan.occurrences.iter().map(to_public_occurrence).collect();

    let graph_sha256 = artifact_graph_digest(
        &ordered_nodes,
        &occurrences,
        &ordered_edges,
        &contradictions,
    );
    let manifest = ArtifactGraphManifest {
        manifest_id: artifact_manifest_id(&root_node.artifact_id, &graph_sha256),
        root_artifact_id: root_node.artifact_id.clone(),
        root_sha256: root_node.sha256.clone(),
        root_format: reader_format_owned.clone(),
        graph_sha256,
        node_count: ordered_nodes.len() as u64,
        occurrence_count: occurrences.len() as u64,
        edge_count: ordered_edges.len() as u64,
    };

    let mut traversal_limitations = parent_limitations;
    for omission in &scan.omissions {
        traversal_limitations.push(format!(
            "Artifact traversal omitted {} at {:?}.",
            omission.kind, omission.path
        ));
    }
    let traversal_status = if scan.omissions.is_empty() && traversal_limitations.is_empty() {
        "complete"
    } else {
        "unknown"
    };
    traversal_limitations = unique_sorted(traversal_limitations);

    let (mut coverage, scope_limitations) = inventory_coverage(
        &reader_format_owned,
        reader_format,
        traversal_status,
        &traversal_limitations,
    );
    if !edge_limitations.is_empty() {
        coverage.status = "unknown".to_owned();
    }

    let limitations = build_limitations(
        scope_limitations,
        &edge_limitations,
        &contradictions,
        case_collision,
    );

    Ok(ArtifactInventoryResult {
        manifest,
        nodes: ordered_nodes,
        occurrences,
        edges: ordered_edges,
        provenance: Vec::new(),
        integrity_contradictions: contradictions,
        coverage,
        limitations,
    })
}

fn to_public_occurrence(o: &MutableOccurrence) -> ArtifactOccurrence {
    ArtifactOccurrence {
        occurrence_id: o.occurrence_id.clone(),
        artifact_id: RequiredNullable::from_option(o.artifact_id.clone()),
        parent_occurrence_id: RequiredNullable::from_option(o.parent_occurrence_id.clone()),
        logical_path: o.logical_path.clone(),
        entry_kind: o.entry_kind.to_owned(),
        artifact_kind: o.artifact_kind.clone(),
        artifact_format: o.artifact_format.clone(),
        declared_size: RequiredNullable::from_option(o.declared_size),
        compressed_size: RequiredNullable::from_option(o.compressed_size),
        executable: o.executable,
        encrypted: o.encrypted,
        hash_status: o.hash_status.clone(),
        source_location: RequiredNullable::from_option(o.source_location.clone()),
        limitations: o.limitations.clone(),
    }
}

fn build_root_node(root: &RootClassification, occurrences: &[MutableOccurrence]) -> ArtifactNode {
    let (sha256, size, format) = match &root.sha256 {
        Some(sha256) => (
            sha256.clone(),
            root.size,
            classify_artifact_bytes(&root.prefix, root.size),
        ),
        None => {
            let mut children: Vec<DirectoryDigestOccurrence> = occurrences
                .iter()
                .map(|o| DirectoryDigestOccurrence {
                    logical_path: o.logical_path.clone(),
                    artifact_id: o.artifact_id.clone(),
                })
                .collect();
            children.sort_by(|a, b| compare_js_code_points(&a.logical_path, &b.logical_path));
            (directory_root_sha256(&children), 0, "directory")
        }
    };
    create_artifact_node(&sha256, size, format, "materialized")
}

fn build_root_occurrence(
    node: &ArtifactNode,
    root: &RootClassification,
    path: &str,
) -> MutableOccurrence {
    let format = &root.format;
    let entry_kind = if *format == "directory" {
        "directory"
    } else {
        "file"
    };
    let artifact_kind = if *format == "directory"
        || is_zip_package_format(format)
        || ["asar", "dmg", "pkg"].contains(format)
    {
        "container".to_owned()
    } else {
        artifact_role_for_root(path, format).to_owned()
    };
    MutableOccurrence {
        occurrence_id: occurrence_id_for_location(
            &node.artifact_id,
            &JsString::from("."),
            entry_kind,
            None,
        ),
        artifact_id: Some(node.artifact_id.clone()),
        parent_occurrence_id: None,
        logical_path: JsString::from("."),
        entry_kind,
        artifact_kind,
        artifact_format: (*format).to_owned(),
        declared_size: Some(root.size),
        compressed_size: None,
        executable: root_executable(path, root.is_directory),
        encrypted: false,
        hash_status: "verified".to_owned(),
        source_location: None,
        limitations: Vec::new(),
    }
}

#[cfg(unix)]
fn root_executable(path: &str, _is_directory: bool) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path)
        .map(|metadata| (metadata.mode() & 0o111) != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn root_executable(path: &str, _is_directory: bool) -> bool {
    let lower = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase());
    matches!(
        lower.as_deref(),
        Some("bat") | Some("cmd") | Some("com") | Some("exe")
    )
}

fn artifact_role_for_root(path: &str, format: &str) -> &'static str {
    let by_path = classify_artifact_path(path);
    if format == "file" || format == by_path.format {
        return by_path.kind;
    }
    if format == "unknown" {
        return "unknown";
    }
    if format == "plist" {
        return "plist";
    }
    if ["native-addon", "dynamic-library"].contains(&by_path.kind) {
        by_path.kind
    } else {
        "executable"
    }
}

fn rekey_occurrences(root_artifact_id: &str, occurrences: &mut [MutableOccurrence]) {
    let mut replacements: BTreeMap<String, String> = BTreeMap::new();
    let mut ordinal_by_path: BTreeMap<JsString, u64> = BTreeMap::new();
    for occurrence in occurrences.iter() {
        let ordinal = *ordinal_by_path.get(&occurrence.logical_path).unwrap_or(&0);
        ordinal_by_path.insert(occurrence.logical_path.clone(), ordinal + 1);
        let new_id = occurrence_id_for_location(
            root_artifact_id,
            &occurrence.logical_path,
            occurrence.entry_kind,
            if ordinal == 0 { None } else { Some(ordinal) },
        );
        replacements.insert(occurrence.occurrence_id.clone(), new_id);
    }
    for occurrence in occurrences.iter_mut() {
        if let Some(new_id) = replacements.get(&occurrence.occurrence_id) {
            occurrence.occurrence_id = new_id.clone();
        }
        if let Some(parent) = &occurrence.parent_occurrence_id
            && let Some(new_parent) = replacements.get(parent)
        {
            occurrence.parent_occurrence_id = Some(new_parent.clone());
        }
    }
}

fn build_contradictions(
    pending: &[PendingContradiction],
    occurrences: &[MutableOccurrence],
    root_node: &ArtifactNode,
) -> Vec<IntegrityContradiction> {
    let by_id: BTreeMap<String, usize> = occurrences
        .iter()
        .enumerate()
        .map(|(i, o)| (o.occurrence_id.clone(), i))
        .collect();
    pending
        .iter()
        .filter_map(|contradiction| {
            let occurrence = occurrences.get(contradiction.occurrence_index + 1)?;
            let parent_artifact_id = occurrence
                .parent_occurrence_id
                .as_ref()
                .and_then(|pid| by_id.get(pid))
                .and_then(|&pi| occurrences[pi].artifact_id.clone())
                .unwrap_or_else(|| root_node.artifact_id.clone());
            Some(IntegrityContradiction {
                contradiction_id: artifact_contradiction_id(
                    &root_node.artifact_id,
                    &occurrence.logical_path,
                    &contradiction.declared_sha256,
                    &contradiction.observed_sha256,
                ),
                occurrence_id: occurrence.occurrence_id.clone(),
                parent_artifact_id,
                logical_path: occurrence.logical_path.clone(),
                declared_sha256: contradiction.declared_sha256.clone(),
                observed_sha256: contradiction.observed_sha256.clone(),
                entry_kind: contradiction.entry_kind.to_owned(),
                unpacked: contradiction.unpacked,
                trust: "observed-untrusted".to_owned(),
                provenance: "container-integrity-metadata-versus-observed-bytes".to_owned(),
                limitations: vec![
                    "Observed bytes contradict declared integrity metadata and cannot support equivalence.".to_owned(),
                ],
            })
        })
        .collect()
}

fn build_limitations(
    scope_limitations: Vec<String>,
    edge_limitations: &[String],
    contradictions: &[IntegrityContradiction],
    case_collision: Option<String>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    out.extend(scope_limitations);
    out.extend(edge_limitations.iter().cloned());
    if let Some(case) = case_collision {
        out.push(case);
    }
    if !contradictions.is_empty() {
        out.push(format!(
            "{} integrity contradiction(s) were recorded; mismatched content is observed-untrusted.",
            contradictions.len()
        ));
    }
    out
}

/// Mirror `isExpandableAsar` using the reader-owned source classification.
fn is_expandable_asar(
    entry: &ArtifactEntry,
    logical_path: &JsString,
    entry_is_filesystem_backed: bool,
) -> bool {
    entry.kind == "file"
        && logical_path.to_ascii_lowercase().ends_with(".asar")
        && entry_is_filesystem_backed
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::sync::{Arc, Mutex};

    fn asar_bytes_with_file(path: &str, payload: &[u8]) -> Vec<u8> {
        asar_bytes_with_files(&[(path, payload)])
    }

    fn asar_bytes_with_files(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut file_tree = serde_json::Map::new();
        let mut offset = 0usize;
        for (path, payload) in files {
            let segments: Vec<&str> = path.split('/').collect();
            let (file_name, directories) = segments
                .split_last()
                .expect("ASAR fixture path has a file name");
            let mut directory = &mut file_tree;
            for segment in directories {
                let entry = directory
                    .entry((*segment).to_owned())
                    .or_insert_with(|| json!({ "files": {} }));
                directory = entry
                    .get_mut("files")
                    .and_then(serde_json::Value::as_object_mut)
                    .expect("ASAR fixture directory has files");
            }
            directory.insert(
                (*file_name).to_owned(),
                json!({
                    "size": payload.len(),
                    "offset": offset.to_string(),
                }),
            );
            offset += payload.len();
        }
        let header = serde_json::to_vec(&json!({
            "files": file_tree,
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
        for (_, payload) in files {
            bytes.extend_from_slice(payload);
        }
        bytes
    }

    #[test]
    fn inventory_normalizes_unicode_paths_before_identity() {
        let temporary_directory = tempfile::tempdir().expect("temporary directory creates");
        let archive_path = temporary_directory.path().join("sample.asar");
        let decomposed_path = "e\u{301}.js";
        fs::write(&archive_path, asar_bytes_with_file(decomposed_path, b"abc"))
            .expect("ASAR fixture writes");

        let inventory = inventory_artifact(
            archive_path.to_str().expect("temporary path is UTF-8"),
            false,
            &Cancellation::default(),
        )
        .expect("ASAR inventory succeeds");

        let file_occurrence = inventory
            .occurrences
            .iter()
            .find(|occurrence| occurrence.entry_kind == "file" && occurrence.logical_path != ".")
            .expect("inventory includes the ASAR file");
        assert_eq!(file_occurrence.logical_path, "é.js");
    }

    #[test]
    fn inventory_directory_identity_tracks_children_and_ancestors() {
        let temporary_directory = tempfile::tempdir().expect("temporary directory creates");
        let first_archive = temporary_directory.path().join("first.asar");
        let second_archive = temporary_directory.path().join("second.asar");
        let first_files = [
            ("native/deep/addon.node", b"native-v1".as_slice()),
            ("renderer/renderer.js", b"renderer".as_slice()),
            ("utility/worker.js", b"utility".as_slice()),
        ];
        let second_files = [
            ("native/deep/addon.node", b"native-v2".as_slice()),
            ("renderer/renderer.js", b"renderer".as_slice()),
            ("utility/worker.js", b"utility".as_slice()),
        ];
        fs::write(&first_archive, asar_bytes_with_files(&first_files))
            .expect("first ASAR fixture writes");
        fs::write(&second_archive, asar_bytes_with_files(&second_files))
            .expect("second ASAR fixture writes");

        let first = inventory_artifact(
            first_archive.to_str().expect("temporary path is UTF-8"),
            false,
            &Cancellation::default(),
        )
        .expect("first ASAR inventory succeeds");
        let second = inventory_artifact(
            second_archive.to_str().expect("temporary path is UTF-8"),
            false,
            &Cancellation::default(),
        )
        .expect("second ASAR inventory succeeds");

        let directory_ids = |inventory: &ArtifactInventoryResult| {
            inventory
                .occurrences
                .iter()
                .filter(|occurrence| occurrence.entry_kind == "directory")
                .map(|occurrence| {
                    (
                        occurrence.logical_path.clone(),
                        occurrence
                            .artifact_id
                            .as_ref()
                            .expect("directory has a materialized node")
                            .clone(),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        };
        let first_ids = directory_ids(&first);
        let second_ids = directory_ids(&second);

        assert_eq!(first_ids.len(), 4);
        assert_eq!(
            first_ids
                .values()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            4,
            "directories with different child names must not collapse into one node"
        );
        let native = JsString::from("native");
        let native_deep = JsString::from("native/deep");
        let renderer = JsString::from("renderer");
        let utility = JsString::from("utility");

        assert_ne!(first_ids[&native], second_ids[&native]);
        assert_ne!(first_ids[&native_deep], second_ids[&native_deep]);
        assert_eq!(first_ids[&renderer], second_ids[&renderer]);
        assert_eq!(first_ids[&utility], second_ids[&utility]);
    }

    #[test]
    fn inventory_keeps_asar_members_opaque_inside_an_asar() {
        let temporary_directory = tempfile::tempdir().expect("temporary directory creates");
        let archive_path = temporary_directory.path().join("outer.asar");
        let inner_archive = asar_bytes_with_files(&[("main.js", b"inner")]);
        fs::write(
            &archive_path,
            asar_bytes_with_files(&[("resources/inner.asar", &inner_archive)]),
        )
        .expect("nested ASAR fixture writes");

        let inventory = inventory_artifact(
            archive_path.to_str().expect("temporary path is UTF-8"),
            false,
            &Cancellation::default(),
        )
        .expect("nested ASAR inventory succeeds");

        let paths = inventory
            .occurrences
            .iter()
            .filter_map(|occurrence| occurrence.logical_path.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            paths,
            [".", "resources", "resources/inner.asar"]
                .into_iter()
                .collect()
        );
        assert_eq!(inventory.occurrences.len(), 3);
    }

    #[test]
    fn inventory_expands_asar_files_admitted_from_a_directory() {
        let temporary_directory = tempfile::tempdir().expect("temporary directory creates");
        let root = temporary_directory.path().join("bundle");
        fs::create_dir_all(root.join("resources")).expect("directory fixture creates");
        let inner_archive = asar_bytes_with_files(&[("main.js", b"inner")]);
        fs::write(root.join("resources/inner.asar"), inner_archive)
            .expect("directory ASAR fixture writes");

        let mut reader = DirectoryArtifactReader::new(root.to_str().expect("root is UTF-8"));
        let mut omissions = Vec::new();
        let entries = reader
            .entries(&Cancellation::default(), &mut omissions)
            .expect("directory entries list");
        let inner_entry = entries
            .iter()
            .find(|entry| entry.path == "resources/inner.asar")
            .expect("directory ASAR entry is listed");
        let expected_adapter_key = root
            .canonicalize()
            .expect("directory canonicalizes")
            .join("resources/inner.asar")
            .to_str()
            .expect("canonical path is UTF-8")
            .to_owned();
        assert_eq!(inner_entry.adapter_key, expected_adapter_key);

        let inventory = inventory_artifact(
            root.to_str().expect("temporary path is UTF-8"),
            false,
            &Cancellation::default(),
        )
        .expect("directory ASAR inventory succeeds");

        let paths = inventory
            .occurrences
            .iter()
            .filter_map(|occurrence| occurrence.logical_path.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert!(paths.contains("resources/inner.asar/main.js"));

        let container = inventory
            .occurrences
            .iter()
            .find(|occurrence| occurrence.logical_path == "resources/inner.asar")
            .expect("directory ASAR occurrence is present");
        let member = inventory
            .occurrences
            .iter()
            .find(|occurrence| occurrence.logical_path == "resources/inner.asar/main.js")
            .expect("expanded ASAR member is present");
        assert_eq!(
            member.parent_occurrence_id.as_ref(),
            Some(&container.occurrence_id)
        );
    }

    struct FailingReader {
        close_calls: Arc<Mutex<u32>>,
        close_failures: Arc<Mutex<u32>>,
        fail_entries: bool,
    }

    impl ArtifactReader for FailingReader {
        fn format(&self) -> &'static str {
            "test"
        }

        fn entries(
            &mut self,
            _cancellation: &Cancellation,
            _omissions: &mut Vec<ArtifactTraversalOmission>,
        ) -> Result<Vec<ArtifactEntry>, ReaderFailure> {
            if self.fail_entries {
                return Err(ReaderFailure::new("io", "entries failed"));
            }
            Ok(vec![ArtifactEntry {
                path: JsString::from("entry.js"),
                kind: "file",
                declared_size: Some(1),
                compressed_size: None,
                executable: false,
                encrypted: false,
                byte_offset: None,
                declared_sha256: None,
                unpacked: false,
                limitations: Vec::new(),
                adapter_key: JsString::from("entry.js"),
            }])
        }

        fn open(
            &mut self,
            _entry: &ArtifactEntry,
            _cancellation: &Cancellation,
        ) -> Result<Vec<u8>, ReaderFailure> {
            Err(ReaderFailure::new("io", "open failed"))
        }

        fn close(&mut self) -> Result<(), ReaderFailure> {
            *self.close_calls.lock().expect("test counter lock") += 1;
            let mut failures = self.close_failures.lock().expect("test counter lock");
            if *failures > 0 {
                *failures -= 1;
                Err(ReaderFailure::new("io", "close failed"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn traversal_failure_closes_reader_and_retains_cleanup_observation() {
        let close_calls = Arc::new(Mutex::new(0));
        let reader = FailingReader {
            close_calls: Arc::clone(&close_calls),
            close_failures: Arc::new(Mutex::new(1)),
            fail_entries: false,
        };

        let failure = match scan_reader(Some(Box::new(reader)), true, &Cancellation::default()) {
            Ok(_) => panic!("the injected open failure should be returned"),
            Err(failure) => failure,
        };

        assert_eq!(failure.message, "open failed");
        assert_eq!(*close_calls.lock().expect("test counter lock"), 1);
        let cleanup = failure.cleanup.expect("close failure should be retained");
        assert!(
            cleanup
                .resources
                .iter()
                .any(|resource| resource == "test reader")
        );
    }

    #[test]
    fn retained_reader_can_retry_cleanup_after_the_primary_failure() {
        let close_calls = Arc::new(Mutex::new(0));
        let reader = FailingReader {
            close_calls: Arc::clone(&close_calls),
            close_failures: Arc::new(Mutex::new(1)),
            fail_entries: false,
        };

        let mut failure = match scan_reader(Some(Box::new(reader)), true, &Cancellation::default())
        {
            Ok(_) => panic!("the injected open failure should be returned"),
            Err(failure) => failure,
        };

        assert_eq!(*close_calls.lock().expect("test counter lock"), 1);
        failure
            .cleanup
            .as_mut()
            .expect("initial close failure should be retained")
            .resources
            .push("independent resource".to_owned());
        let cleanup = failure
            .retry_cleanup()
            .expect_err("the independent cleanup should remain unresolved");
        assert_eq!(*close_calls.lock().expect("test counter lock"), 2);
        assert_eq!(cleanup.resources, vec!["independent resource".to_owned()]);
    }

    #[test]
    fn failed_cleanup_retry_keeps_reader_for_a_later_retry() {
        let close_calls = Arc::new(Mutex::new(0));
        let reader = FailingReader {
            close_calls: Arc::clone(&close_calls),
            close_failures: Arc::new(Mutex::new(2)),
            fail_entries: false,
        };

        let mut failure = match scan_reader(Some(Box::new(reader)), true, &Cancellation::default())
        {
            Ok(_) => panic!("the injected open failure should be returned"),
            Err(failure) => failure,
        };

        assert_eq!(*close_calls.lock().expect("test counter lock"), 1);
        assert!(failure.retry_cleanup().is_err());
        assert_eq!(*close_calls.lock().expect("test counter lock"), 2);
        assert!(failure.cleanup.is_some());

        failure
            .retry_cleanup()
            .expect("the retained reader should remain available for another retry");
        assert_eq!(*close_calls.lock().expect("test counter lock"), 3);
        assert!(failure.cleanup.is_none());
    }

    #[test]
    fn entry_enumeration_failure_closes_reader_before_returning() {
        let close_calls = Arc::new(Mutex::new(0));
        let reader = FailingReader {
            close_calls: Arc::clone(&close_calls),
            close_failures: Arc::new(Mutex::new(1)),
            fail_entries: true,
        };

        let failure = match scan_reader(Some(Box::new(reader)), true, &Cancellation::default()) {
            Ok(_) => panic!("the injected entries failure should be returned"),
            Err(failure) => failure,
        };

        assert_eq!(failure.message, "entries failed");
        assert_eq!(*close_calls.lock().expect("test counter lock"), 1);
        assert!(failure.cleanup.is_some());
    }

    #[test]
    fn cleanup_attempts_every_reader_after_a_primary_failure() {
        let root_close_calls = Arc::new(Mutex::new(0));
        let nested_close_calls = Arc::new(Mutex::new(0));
        let mut scope = ReaderScope::new(Box::new(FailingReader {
            close_calls: Arc::clone(&root_close_calls),
            close_failures: Arc::new(Mutex::new(1)),
            fail_entries: false,
        }));
        scope.stack.push(ReaderFrame {
            reader: Box::new(FailingReader {
                close_calls: Arc::clone(&nested_close_calls),
                close_failures: Arc::new(Mutex::new(1)),
                fail_entries: false,
            }),
            prefix: JsString::from("nested.asar"),
            entries: Vec::new(),
            index: 0,
        });

        let failure = match scope.finish(Some(ReaderFailure::new("io", "primary failure"))) {
            Ok(_) => panic!("the supplied primary failure should be preserved"),
            Err(failure) => failure,
        };

        assert_eq!(failure.message, "primary failure");
        assert_eq!(*root_close_calls.lock().expect("test counter lock"), 1);
        assert_eq!(*nested_close_calls.lock().expect("test counter lock"), 1);
        let resources = &failure
            .cleanup
            .expect("cleanup failures are retained")
            .resources;
        assert!(resources.iter().any(|resource| resource == "test reader"));
        assert!(
            resources
                .iter()
                .any(|resource| resource == "test reader at nested.asar")
        );
    }
}
