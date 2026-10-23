//! Inventory scan and artifact-graph construction.
//!
//! Compatibility owners: `src/artifacts/inventory/scanCanonical.ts`,
//! `src/artifacts/inventory/scanReader.ts`,
//! `src/artifacts/inventory/ArtifactGraphConstruction.ts`,
//! `src/artifacts/inventory/reader.ts` and `src/artifacts/ArtifactPaths.ts`.
use super::asar::AsarArtifactReader;
use super::classify::{
    self, Role, ZIP_NON_ENTRY_LIMITATION, classify_artifact_bytes, classify_artifact_content,
    classify_artifact_path, is_zip_package_format, zip_package_format_for_path,
};
use super::directory_reader::DirectoryArtifactReader;
use super::graph::{self, *};
use super::reader::{ArtifactEntry, ArtifactReader, ArtifactTraversalOmission, ReaderFailure};
use super::zip_reader::ZipArtifactReader;
use rea_core::cancellation::Cancellation;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const MAX_ROOT_BYTES: usize = 2 * 1024 * 1024 * 1024;

/// A mutable occurrence during graph construction.
#[derive(Clone)]
struct MutableOccurrence {
    occurrence_id: String,
    artifact_id: Option<String>,
    parent_occurrence_id: Option<String>,
    logical_path: String,
    entry_kind: &'static str,
    artifact_kind: String,
    artifact_format: String,
    declared_size: Option<u64>,
    compressed_size: Option<u64>,
    executable: bool,
    encrypted: bool,
    hash_status: String,
    source_location: Option<Value>,
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
    captured: Option<Vec<u8>>,
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
        return Ok(RootClassification {
            format: "directory",
            sha256: None,
            size: 0,
            prefix: Vec::new(),
            is_directory: true,
            captured: None,
        });
    }
    let snapshot = rea_host::fs::stable_file::read(
        crate::common::host_files(),
        std::path::Path::new(path),
        MAX_ROOT_BYTES,
        cancellation,
    )
    .map_err(|failure| translate_root_read(*failure))?;
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
            Some(snapshot.bytes)
        } else {
            None
        },
    })
}

fn translate_root_read(
    failure: rea_host::fs::stable_file::ReadFailure<crate::common::HostFiles>,
) -> ReaderFailure {
    use rea_host::fs::stable_file::ReadIssue;
    match failure.primary {
        Some(ReadIssue::Cancelled(_)) => {
            ReaderFailure::new("cancelled", "Artifact inventory cancelled")
        }
        Some(ReadIssue::InvalidPath) => {
            ReaderFailure::new("path", "Root artifact is not a regular file")
        }
        Some(ReadIssue::Changed(stage)) => {
            ReaderFailure::new("integrity", format!("Root artifact changed {stage}"))
        }
        Some(ReadIssue::Limit { maximum_bytes }) => ReaderFailure::new(
            "limit",
            format!("Root artifact exceeds {maximum_bytes} bytes"),
        ),
        Some(ReadIssue::Allocation { .. }) => {
            ReaderFailure::new("limit", "Could not allocate root artifact storage")
        }
        Some(ReadIssue::Io { error, .. }) => ReaderFailure::new("io", error.to_string()),
        Some(ReadIssue::InvalidRead) | None => {
            ReaderFailure::new("io", "Root artifact stream did not return admitted bytes")
        }
    }
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
    captured: Option<Vec<u8>>,
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
            Box::new(ZipArtifactReader::new(zip_format, bytes)) as Box<dyn ArtifactReader>
        });
    }
    match format {
        "directory" => Some(Box::new(DirectoryArtifactReader::new(path))),
        "asar" => captured
            .map(|bytes| Box::new(AsarArtifactReader::new(bytes)) as Box<dyn ArtifactReader>),
        // mach-o-universal and dmg require a native macOS adapter (lipo /
        // hdiutil) not ported here; fall through to root-only coverage exactly
        // as the TS reader factory returns undefined when unavailable.
        _ => None,
    }
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
    if input.contains('\0') || input.starts_with('/') || is_drive_prefixed(input) {
        return Err(ReaderFailure::new(
            "path",
            format!("Artifact path is absolute or unsafe: {input:?}"),
        ));
    }
    let normalized = graph::logical_path_nfc(input);
    let normalized = normalized.trim_end_matches('/').to_owned();
    let unsafe_part = normalized
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..");
    if normalized.is_empty() || unsafe_part {
        return Err(ReaderFailure::new(
            "path",
            format!("Artifact path is not normalized: {input:?}"),
        ));
    }
    Ok(normalized)
}

fn is_drive_prefixed(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// `createOccurrence` role assignment.
fn create_occurrence(
    entry: &ArtifactEntry,
    path: &str,
    duplicate_ordinal: u64,
) -> MutableOccurrence {
    let role = if entry.kind == "directory" {
        Role {
            kind: if path.to_lowercase().ends_with(".framework") {
                "framework"
            } else {
                "container"
            },
            format: "directory",
        }
    } else if container_suffix_family(path).is_none() {
        classify_artifact_path(path)
    } else {
        Role {
            kind: "unknown",
            format: "unknown",
        }
    };
    let source_location = match (entry.byte_offset, entry.declared_size) {
        (Some(offset), Some(length)) => Some(json!({ "offset": offset, "length": length })),
        _ => None,
    };
    MutableOccurrence {
        occurrence_id: provisional_occurrence_id(path, entry.kind, duplicate_ordinal),
        artifact_id: None,
        parent_occurrence_id: None,
        logical_path: path.to_owned(),
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

fn container_suffix_family(path: &str) -> Option<&'static str> {
    let lower = path.to_lowercase();
    if lower.ends_with(".asar") {
        Some("asar")
    } else {
        zip_package_format_for_path(&lower)
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
    let Some(mut reader) = root_reader else {
        return Ok(output);
    };
    let mut occurrence_count_by_path: BTreeMap<String, u64> = BTreeMap::new();
    struct Frame {
        reader: Box<dyn ArtifactReader>,
        prefix: String,
        entries: Vec<ArtifactEntry>,
        index: usize,
    }
    let mut omissions = Vec::new();
    let root_entries = reader.entries(cancellation, &mut omissions)?;
    output.omissions.extend(omissions);
    let mut stack = vec![Frame {
        reader,
        prefix: String::new(),
        entries: root_entries,
        index: 0,
    }];
    while let Some(frame) = stack.last_mut() {
        if frame.index >= frame.entries.len() {
            let mut finished = stack.pop().expect("frame present");
            finished.reader.close()?;
            continue;
        }
        let entry = frame.entries[frame.index].clone();
        frame.index += 1;
        let logical_path = normalize_artifact_path(&if frame.prefix.is_empty() {
            entry.path.clone()
        } else {
            format!("{}/{}", frame.prefix, entry.path)
        })?;
        let expandable_asar =
            entry.kind == "file" && logical_path.to_lowercase().ends_with(".asar");
        let duplicate_ordinal = *occurrence_count_by_path.get(&logical_path).unwrap_or(&0);
        occurrence_count_by_path.insert(logical_path.clone(), duplicate_ordinal + 1);
        let mut occurrence = create_occurrence(&entry, &logical_path, duplicate_ordinal);

        // digestArtifactEntry
        let digested = if (entry.kind == "file" || entry.kind == "slice") && !entry.encrypted {
            let frame = stack.last_mut().expect("frame present for open");
            match frame.reader.open(&entry, cancellation) {
                Ok(bytes) => Some(digest_entry(&entry, &logical_path, bytes, integrity_fail)?),
                Err(failure) => {
                    if entry.unpacked && failure.reason == "unavailable" {
                        occurrence.hash_status = "unavailable".to_owned();
                        occurrence.limitations.push(
                            "ASAR unpacked companion bytes were unavailable; no content hash or child artifact was produced.".to_owned(),
                        );
                        None
                    } else {
                        return Err(failure);
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
            let mut nested = AsarArtifactReader::new(bytes);
            let mut nested_omissions = Vec::new();
            let nested_entries = nested.entries(cancellation, &mut nested_omissions)?;
            for omission in nested_omissions {
                output.omissions.push(ArtifactTraversalOmission {
                    path: normalize_artifact_path(&format!("{}/{}", logical_path, omission.path))
                        .unwrap_or(omission.path),
                    kind: omission.kind,
                });
            }
            output.expanded_container_ids.insert(occurrence_id);
            stack.push(Frame {
                reader: Box::new(nested),
                prefix: logical_path,
                entries: nested_entries,
                index: 0,
            });
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
    logical_path: &str,
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
            logical_path: logical_path.to_owned(),
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
        classify_artifact_content(logical_path, prefix, size)?
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
        media_type: None,
        architecture: None,
        content_state: content_state.to_owned(),
        limitations: Vec::new(),
    }
}

/// `resolveOccurrenceParents`.
fn resolve_occurrence_parents(
    occurrences: &mut [MutableOccurrence],
    expanded_container_ids: &std::collections::HashSet<String>,
) -> (Vec<String>, std::collections::HashSet<usize>) {
    let mut by_path: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, occurrence) in occurrences.iter().enumerate() {
        by_path
            .entry(occurrence.logical_path.clone())
            .or_default()
            .push(index);
    }
    #[derive(Default)]
    struct Node {
        children: BTreeMap<String, usize>,
        occurrences: Vec<usize>,
    }
    let mut nodes: Vec<Node> = vec![Node::default()];
    let mut limitations: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let paths: Vec<String> = by_path.keys().cloned().collect();
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
        for segment in path.split('/') {
            let next = match nodes[branch].children.get(segment) {
                Some(&child) => child,
                None => {
                    let child = nodes.len();
                    nodes.push(Node::default());
                    nodes[branch].children.insert(segment.to_owned(), child);
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
        let mut prefix = String::new();
        let mut start = 0usize;
        loop {
            let Some(rel_slash) = path[start..].find('/') else {
                break;
            };
            let slash = start + rel_slash;
            let segment = &path[start..slash];
            let Some(&child) = nodes[branch].children.get(segment) else {
                break;
            };
            branch = child;
            prefix = if prefix.is_empty() {
                segment.to_owned()
            } else {
                format!("{prefix}/{segment}")
            };
            let candidates = &nodes[branch].occurrences;
            if candidates.len() == 1 {
                parent = Some(candidates[0]);
                ambiguous = None;
            } else if candidates.len() > 1 {
                parent = None;
                ambiguous = Some(prefix.clone());
            }
            start = slash + 1;
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
        let children: Vec<Value> = children_by_parent
            .get(&dir_id)
            .map(|indices| {
                let mut list: Vec<(String, Option<String>, &'static str)> = indices
                    .iter()
                    .map(|&c| {
                        let child = &occurrences[c];
                        let name = child.logical_path[dir_path_len + 1..].to_owned();
                        (name, child.artifact_id.clone(), child.entry_kind)
                    })
                    .collect();
                list.sort_by(|a, b| compare_unicode_code_points(&a.0, &b.0));
                list.into_iter()
                    .map(|(name, artifact_id, entry_kind)| {
                        json!({
                            "name": name,
                            "artifact_id": artifact_id,
                            "entry_kind": entry_kind,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let children_value = Value::Array(children);
        let sha256 = directory_node_sha256(&children_value);
        let node = create_artifact_node(&sha256, 0, "directory", "virtual");
        nodes.insert(node.artifact_id.clone(), node.clone());
        occurrences[dir_index].artifact_id = Some(node.artifact_id);
        occurrences[dir_index].hash_status = "verified".to_owned();
    }
}

fn depth(path: &str) -> usize {
    path.split('/').count()
}

/// English (en-US) Unicode case-collision annotation (ASCII-fold grouping over
/// the full logical path, which matches `toLocaleLowerCase("en-US")` for the
/// ASCII-dominant archive names REA inventories).
fn annotate_case_collisions(occurrences: &mut [MutableOccurrence]) -> Option<String> {
    let mut by_fold: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for occurrence in occurrences.iter() {
        if occurrence.logical_path.is_empty() || occurrence.logical_path == "." {
            continue;
        }
        by_fold
            .entry(occurrence.logical_path.to_lowercase())
            .or_default()
            .push(occurrence.logical_path.clone());
    }
    let mut collisions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut any = false;
    for spellings in by_fold.values() {
        let distinct: std::collections::BTreeSet<&String> = spellings.iter().collect();
        if distinct.len() > 1 {
            any = true;
            let mut sorted: Vec<String> = distinct.iter().map(|s| (*s).clone()).collect();
            sorted.sort_by(|a, b| compare_unicode_code_points(a, b));
            for path in &sorted {
                let others: Vec<String> = sorted.iter().filter(|p| *p != path).cloned().collect();
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
                other.clone()
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
    let mut by_path: BTreeMap<String, Vec<usize>> = BTreeMap::new();
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
            Some(logical_path[..logical_path.len() - ".map".len()].to_owned())
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
            producer: None,
        });
    }
    for (index, limit) in occ_limits {
        occurrences[index].limitations.push(limit);
    }
    (edges, limitations)
}

fn relation_for(path: &str) -> &'static str {
    if path.to_lowercase().contains(".framework/") {
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
    let canonical_str = canonical.to_string_lossy().into_owned();

    let root = classify_root(&canonical_str, cancellation)?;
    let reader_format_owned = root.format.to_owned();
    let reader = create_reader(&canonical_str, root.format, root.captured.clone());
    let reader_format = reader.as_ref().map(|r| r.format());

    let mut scan = scan_reader(reader, integrity_fail, cancellation)?;

    materialize_directory_nodes(&mut scan.occurrences, &mut scan.nodes);

    let root_node = build_root_node(&root, &scan.occurrences);
    scan.nodes
        .insert(root_node.artifact_id.clone(), root_node.clone());

    rekey_occurrences(&root_node.artifact_id, &mut scan.occurrences);

    let root_occurrence = build_root_occurrence(&root_node, &root, &canonical_str);
    let root_occurrence_id = root_occurrence.occurrence_id.clone();

    let (parent_limitations, unknown_parents) =
        resolve_occurrence_parents(&mut scan.occurrences, &scan.expanded_container_ids);
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
        .sort_by(|a, b| compare_unicode_code_points(&a.logical_path, &b.logical_path));
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
        artifact_id: o.artifact_id.clone(),
        parent_occurrence_id: o.parent_occurrence_id.clone(),
        logical_path: o.logical_path.clone(),
        entry_kind: o.entry_kind.to_owned(),
        artifact_kind: o.artifact_kind.clone(),
        artifact_format: o.artifact_format.clone(),
        declared_size: o.declared_size,
        compressed_size: o.compressed_size,
        executable: o.executable,
        encrypted: o.encrypted,
        hash_status: o.hash_status.clone(),
        source_location: o.source_location.clone(),
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
            let mut children: Vec<Value> = occurrences
                .iter()
                .map(|o| json!({ "logical_path": o.logical_path, "artifact_id": o.artifact_id }))
                .collect();
            children.sort_by(|a, b| {
                compare_unicode_code_points(
                    a["logical_path"].as_str().unwrap_or(""),
                    b["logical_path"].as_str().unwrap_or(""),
                )
            });
            (
                directory_root_sha256(&Value::Array(children)),
                0,
                "directory",
            )
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
        occurrence_id: occurrence_id_for_location(&node.artifact_id, ".", entry_kind, None),
        artifact_id: Some(node.artifact_id.clone()),
        parent_occurrence_id: None,
        logical_path: ".".to_owned(),
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
fn root_executable(path: &str, is_directory: bool) -> bool {
    use std::os::unix::fs::MetadataExt;
    if is_directory {
        return false;
    }
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.is_file() && (metadata.mode() & 0o111) != 0)
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
    let mut ordinal_by_path: BTreeMap<String, u64> = BTreeMap::new();
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
