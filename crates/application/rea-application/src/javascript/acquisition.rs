//! Inventory-authenticated JavaScript artifact acquisition.
//!
//! The application owns traversal policy and text decoding. A provider adapts
//! its concrete directory or archive reader to [`JavaScriptReader`]; this
//! module never opens paths or selects a reader implementation.

use super::artifact_files::{
    ExpectedContainer, ExpectedFile, InventoryLookup, JavaScriptArtifactContainer,
    JavaScriptArtifactFile, JavaScriptText, SourceSelectionError, UnanalyzedArtifactLookup,
    describe_js_path, expected_inventory, plan_source_selection,
};
use super::graph::json::{Json, Obj};
use super::semantic::value_types::JsString;
use crate::javascript::artifact_files::JavaScriptUnanalyzedArtifactFile;
use rea_core::{artifact_inventory::ArtifactInventoryResult, cancellation::Cancellation};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Metadata supplied by a provider reader for one archive or directory entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JavaScriptReaderEntry {
    pub path: String,
    pub kind: &'static str,
    pub declared_size: Option<u64>,
    pub compressed_size: Option<u64>,
    pub executable: bool,
    pub encrypted: bool,
    pub byte_offset: Option<u64>,
    pub declared_sha256: Option<String>,
    pub unpacked: bool,
    pub limitations: Vec<String>,
    pub adapter_key: String,
    pub filesystem_backed: bool,
}

/// Provider adapter used by the application acquisition workflow.
pub trait JavaScriptReader: Sized {
    type Error;

    fn format(&self) -> &'static str;
    fn entries(
        &mut self,
        cancellation: &Cancellation,
    ) -> Result<Vec<JavaScriptReaderEntry>, Self::Error>;
    fn open(
        &mut self,
        entry: &JavaScriptReaderEntry,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, Self::Error>;
    fn nested_reader(
        &mut self,
        entry: &JavaScriptReaderEntry,
        bytes: Vec<u8>,
        cancellation: &Cancellation,
    ) -> Result<Option<Self>, Self::Error>;
    fn verify_container(
        &mut self,
        _sha256: &str,
        _bytes: u64,
        _cancellation: &Cancellation,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
    fn close(&mut self) -> Result<(), Self::Error>;
    fn failure(reason: &'static str, message: String) -> Self::Error;
    fn with_cleanup(primary: Self::Error, cleanup: Self::Error) -> Self::Error;
}

/// Acquired files and retained inventory omissions for one authenticated root.
pub struct JavaScriptArtifactFileSet<'a> {
    pub files: Vec<JavaScriptArtifactFile>,
    pub unanalyzed_files: InventoryLookup<'a>,
    pub unavailable_relevant_files: Vec<JavaScriptUnanalyzedArtifactFile>,
    pub containers: Vec<JavaScriptArtifactContainer>,
    pub text_bytes_read: u64,
    pub invalid_utf8_files: u64,
    pub source_selection: Option<JavaScriptSourceSelection>,
}

/// Serialize one authenticated file using the acquisition contract.  All
/// consumers use this producer-owned representation so text values and
/// exclusion reasons cannot drift between acquisition and analysis.
pub(crate) fn canonical_file_json(file: &JavaScriptArtifactFile) -> Json {
    let kind = match file.kind {
        super::artifact_files::JavaScriptArtifactFileKind::PackageJson => "package-json",
        super::artifact_files::JavaScriptArtifactFileKind::Json => "json",
        super::artifact_files::JavaScriptArtifactFileKind::JavaScript => "javascript",
        super::artifact_files::JavaScriptArtifactFileKind::Html => "html",
        super::artifact_files::JavaScriptArtifactFileKind::SourceMap => "source-map",
        super::artifact_files::JavaScriptArtifactFileKind::NativeAddon => "native-addon",
    };
    let text = match &file.text {
        super::artifact_files::JavaScriptText::Included(source) => Obj::new()
            .with("included", true)
            .with("value", source.clone()),
        super::artifact_files::JavaScriptText::Excluded(reason) => Obj::new()
            .with("included", false)
            .with("reason", canonical_exclusion_reason(*reason)),
    };
    Obj::new()
        .with("path", JsString::from(file.path.clone()))
        .with("container_sha256", file.container_sha256.clone())
        .with("sha256", file.sha256.clone())
        .with("bytes", file.bytes as usize)
        .with("inventory_artifact_id", file.inventory_artifact_id.clone())
        .with("kind", kind)
        .with("unpacked", file.unpacked)
        .with("text", text)
        .into()
}

fn canonical_exclusion_reason(reason: super::artifact_files::TextExclusionReason) -> &'static str {
    match reason {
        super::artifact_files::TextExclusionReason::NotApplicable => "not-applicable",
        super::artifact_files::TextExclusionReason::InvalidUtf8 => "invalid-utf8",
        super::artifact_files::TextExclusionReason::OutsideAnalysisScope => {
            "outside-analysis-scope"
        }
    }
}

pub(crate) fn canonical_file_set_json(file_set: &JavaScriptArtifactFileSet<'_>) -> Json {
    let files = file_set.files.iter().map(canonical_file_json).collect();
    let unavailable = file_set
        .unavailable_relevant_files
        .iter()
        .map(|file| {
            let mut value = Obj::new()
                .with("path", file.path.clone())
                .with("container_sha256", file.container_sha256.clone())
                .with("kind", file.artifact_kind.clone());
            if let Some(sha256) = &file.sha256 {
                value.set("sha256", sha256.clone());
            }
            if let Some(bytes) = file.bytes {
                value.set("bytes", bytes as usize);
            }
            if let Some(inventory_artifact_id) = &file.inventory_artifact_id {
                value.set("inventory_artifact_id", inventory_artifact_id.clone());
            }
            value.set(
                "inventory_occurrence_id",
                file.inventory_occurrence_id.clone(),
            );
            value.set("hash_status", file.hash_status.clone());
            value.set(
                "limitations",
                Json::Array(file.limitations.iter().cloned().map(Json::from).collect()),
            );
            value.into()
        })
        .collect();
    let mut value = Obj::new()
        .with("files", Json::Array(files))
        .with("unavailable_relevant_files", Json::Array(unavailable))
        .with(
            "containers",
            Json::Array(
                file_set
                    .containers
                    .iter()
                    .map(|container| {
                        Obj::new()
                            .with("path", container.path.clone())
                            .with("sha256", container.sha256.clone())
                            .with("bytes", container.bytes as usize)
                            .with(
                                "inventory_artifact_id",
                                container.inventory_artifact_id.clone(),
                            )
                            .into()
                    })
                    .collect(),
            ),
        )
        .with("text_bytes_read", file_set.text_bytes_read as usize)
        .with("invalid_utf8_files", file_set.invalid_utf8_files as usize);
    if let Some(selection) = &file_set.source_selection {
        value.set(
            "source_selection",
            Obj::new()
                .with(
                    "requested_paths",
                    Json::Array(
                        selection
                            .requested_paths
                            .iter()
                            .cloned()
                            .map(Json::from)
                            .collect(),
                    ),
                )
                .with("unselected_files", selection.unselected_files),
        );
    }
    value.into()
}

/// Caller selection facts preserved in acquisition output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JavaScriptSourceSelection {
    pub requested_paths: Vec<String>,
    pub unselected_files: usize,
}

pub fn acquire<'a, R: JavaScriptReader>(
    reader: &mut R,
    snapshot: &'a ArtifactInventoryResult,
    cancellation: &Cancellation,
    source_paths: Option<&[String]>,
) -> Result<JavaScriptArtifactFileSet<'a>, R::Error> {
    let expected = match expected_inventory(snapshot) {
        Ok(expected) => expected,
        Err(error) => {
            return Err(close_before_traversal(
                reader,
                R::failure(
                    "integrity",
                    format!("Artifact inventory is not usable: {error:?}"),
                ),
            ));
        }
    };
    let selection = match source_paths
        .map(|paths| plan_source_selection(&expected, paths))
        .transpose()
    {
        Ok(selection) => selection,
        Err(error) => {
            return Err(close_before_traversal(
                reader,
                selection_failure::<R>(error),
            ));
        }
    };
    if reader.format() == "asar" {
        let root = snapshot
            .nodes
            .iter()
            .find(|node| node.artifact_id == snapshot.manifest.root_artifact_id)
            .ok_or_else(|| R::failure("integrity", "Root artifact node is missing".into()));
        let root = match root {
            Ok(root) => root,
            Err(error) => return Err(close_before_traversal(reader, error)),
        };
        if let Err(error) = reader.verify_container(&root.sha256, root.size, cancellation) {
            return Err(close_before_traversal(reader, error));
        }
    }

    let selected = selection.as_ref().map(|plan| {
        plan.unique_paths
            .iter()
            .enumerate()
            .map(|(index, path)| (path.clone(), index))
            .collect::<HashMap<_, _>>()
    });
    let mut state = AcquisitionState {
        expected: &expected.files,
        expected_containers: &expected.containers,
        selected: selected.clone(),
        files: Vec::new(),
        containers: Vec::new(),
        text_bytes_read: 0,
        invalid_utf8_files: 0,
    };
    visit_reader(
        reader,
        "",
        &snapshot.manifest.root_sha256,
        &mut state,
        cancellation,
    )?;

    let observed = state
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<std::collections::HashSet<_>>();
    if let Some(path) = expected
        .files
        .keys()
        .find(|path| path.as_str().is_some_and(|path| !observed.contains(path)))
    {
        return Err(R::failure(
            "integrity",
            format!(
                "Relevant artifact entry disappeared after inventory: {}",
                describe_js_path(path)
            ),
        ));
    }

    state.files.sort_by(|left, right| {
        let left_priority = selected
            .as_ref()
            .and_then(|paths| paths.get(&left.path))
            .copied()
            .unwrap_or(usize::MAX);
        let right_priority = selected
            .as_ref()
            .and_then(|paths| paths.get(&right.path))
            .copied()
            .unwrap_or(usize::MAX);
        left_priority
            .cmp(&right_priority)
            .then_with(|| left.path.chars().cmp(right.path.chars()))
    });
    state
        .containers
        .sort_by(|left, right| left.path.compare_code_points(&right.path));

    let mut lookup = InventoryLookup::new(snapshot, &state.containers);
    let mut unavailable_paths = expected.unavailable_files.iter().collect::<Vec<_>>();
    unavailable_paths.sort_by(|left, right| left.compare_code_points(right));
    let unavailable_relevant_files = unavailable_paths
        .into_iter()
        .filter_map(|path| lookup.get_exact(path))
        .collect();
    Ok(JavaScriptArtifactFileSet {
        files: state.files,
        unanalyzed_files: lookup,
        unavailable_relevant_files,
        containers: state.containers,
        text_bytes_read: state.text_bytes_read,
        invalid_utf8_files: state.invalid_utf8_files,
        source_selection: source_paths.map(|paths| JavaScriptSourceSelection {
            requested_paths: paths.to_vec(),
            unselected_files: selection
                .as_ref()
                .map(|plan| plan.unselected_files)
                .unwrap_or_default(),
        }),
    })
}

struct AcquisitionState<'a> {
    expected: &'a HashMap<JsString, ExpectedFile>,
    expected_containers: &'a HashMap<JsString, ExpectedContainer>,
    selected: Option<HashMap<String, usize>>,
    files: Vec<JavaScriptArtifactFile>,
    containers: Vec<JavaScriptArtifactContainer>,
    text_bytes_read: u64,
    invalid_utf8_files: u64,
}

fn visit_reader<R: JavaScriptReader>(
    reader: &mut R,
    prefix: &str,
    container_sha256: &str,
    state: &mut AcquisitionState<'_>,
    cancellation: &Cancellation,
) -> Result<(), R::Error> {
    let result = visit_entries(reader, prefix, container_sha256, state, cancellation);
    close_reader(reader, result)
}

fn visit_entries<R: JavaScriptReader>(
    reader: &mut R,
    prefix: &str,
    container_sha256: &str,
    state: &mut AcquisitionState<'_>,
    cancellation: &Cancellation,
) -> Result<(), R::Error> {
    for entry in reader.entries(cancellation)? {
        let raw_path = if prefix.is_empty() {
            entry.path.clone()
        } else {
            format!("{prefix}/{}", entry.path)
        };
        let path = rea_core::artifact_paths::normalize_artifact_path(&raw_path)
            .map_err(|error| R::failure("path", error.to_string()))?;
        let is_nested_asar = entry.kind == "file"
            && path.to_ascii_lowercase().ends_with(".asar")
            && entry.filesystem_backed;
        if is_nested_asar {
            acquire_nested_container(reader, &entry, path, state, cancellation)?;
            continue;
        }
        acquire_regular_file(reader, &entry, path, container_sha256, state, cancellation)?;
    }
    Ok(())
}

fn acquire_nested_container<R: JavaScriptReader>(
    reader: &mut R,
    entry: &JavaScriptReaderEntry,
    path: String,
    state: &mut AcquisitionState<'_>,
    cancellation: &Cancellation,
) -> Result<(), R::Error> {
    let container_path = JsString::from(path.clone());
    let container = state
        .expected_containers
        .get(&container_path)
        .ok_or_else(|| {
            R::failure(
                "integrity",
                format!("Nested ASAR was not present in inventory: {path}"),
            )
        })?;
    if container.hash_status == "mismatched" {
        return Ok(());
    }
    if container.hash_status == "unavailable" {
        return Err(R::failure(
            "unavailable",
            format!("Nested ASAR bytes were unavailable during inventory: {path}"),
        ));
    }
    if container.hash_status != "verified" || container.format != "asar" {
        return Ok(());
    }

    let nested_inventory = container.inventory.as_ref().ok_or_else(|| {
        R::failure(
            "integrity",
            format!("Verified nested ASAR has no inventory node: {path}"),
        )
    })?;
    let bytes = reader.open(entry, cancellation)?;
    verify_bytes::<R>(
        &bytes,
        &nested_inventory.sha256,
        nested_inventory.bytes,
        &path,
    )?;
    let mut nested = reader
        .nested_reader(entry, bytes, cancellation)?
        .ok_or_else(|| {
            R::failure(
                "unavailable",
                format!("Nested ASAR reader is unavailable: {path}"),
            )
        })?;

    state.containers.push(nested_inventory.clone());
    visit_reader(
        &mut nested,
        &path,
        &nested_inventory.sha256,
        state,
        cancellation,
    )
}

fn acquire_regular_file<R: JavaScriptReader>(
    reader: &mut R,
    entry: &JavaScriptReaderEntry,
    path: String,
    container_sha256: &str,
    state: &mut AcquisitionState<'_>,
    cancellation: &Cancellation,
) -> Result<(), R::Error> {
    let expected_path = JsString::from(path.clone());
    let Some(expected) = state.expected.get(&expected_path) else {
        return Ok(());
    };
    let bytes = reader.open(entry, cancellation)?;
    verify_bytes::<R>(&bytes, &expected.sha256, expected.bytes, &path)?;

    let selected = state
        .selected
        .as_ref()
        .is_none_or(|paths| paths.contains_key(&path));
    let text = decode_text(&bytes, expected, selected, state);
    state.files.push(JavaScriptArtifactFile {
        path,
        container_sha256: container_sha256.to_owned(),
        sha256: expected.sha256.clone(),
        bytes: expected.bytes,
        inventory_artifact_id: expected.inventory_artifact_id.clone(),
        kind: expected.kind,
        unpacked: entry.unpacked,
        text,
    });
    Ok(())
}

fn decode_text(
    bytes: &[u8],
    expected: &ExpectedFile,
    selected: bool,
    state: &mut AcquisitionState<'_>,
) -> JavaScriptText {
    if !selected {
        return JavaScriptText::Excluded(
            super::artifact_files::TextExclusionReason::OutsideAnalysisScope,
        );
    }
    if expected.kind == super::artifact_files::JavaScriptArtifactFileKind::NativeAddon {
        return JavaScriptText::Excluded(super::artifact_files::TextExclusionReason::NotApplicable);
    }

    state.text_bytes_read += bytes.len() as u64;
    match std::str::from_utf8(bytes) {
        Ok(value) => JavaScriptText::Included(JsString::from(
            if matches!(
                expected.kind,
                super::artifact_files::JavaScriptArtifactFileKind::JavaScript
                    | super::artifact_files::JavaScriptArtifactFileKind::Html
            ) {
                value.strip_prefix('\u{feff}').unwrap_or(value)
            } else {
                value
            },
        )),
        Err(_) => {
            state.invalid_utf8_files += 1;
            JavaScriptText::Excluded(super::artifact_files::TextExclusionReason::InvalidUtf8)
        }
    }
}

fn close_reader<R: JavaScriptReader>(
    reader: &mut R,
    result: Result<(), R::Error>,
) -> Result<(), R::Error> {
    match (result, reader.close()) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(R::with_cleanup(primary, cleanup)),
    }
}

fn close_before_traversal<R: JavaScriptReader>(reader: &mut R, primary: R::Error) -> R::Error {
    match reader.close() {
        Ok(()) => primary,
        Err(cleanup) => R::with_cleanup(primary, cleanup),
    }
}

fn verify_bytes<R: JavaScriptReader>(
    bytes: &[u8],
    expected_sha256: &str,
    expected_bytes: u64,
    path: &str,
) -> Result<(), R::Error> {
    let digest = Sha256::digest(bytes);
    let actual = format!("{digest:x}");
    if actual != expected_sha256 || bytes.len() as u64 != expected_bytes {
        return Err(R::failure(
            "integrity",
            format!("Artifact entry changed after inventory: {path}"),
        ));
    }
    Ok(())
}

fn selection_failure<R: JavaScriptReader>(error: SourceSelectionError) -> R::Error {
    match error {
        SourceSelectionError::UnknownPaths(paths) => R::failure(
            "path",
            format!("Unknown JavaScript artifact paths: {}", paths.len()),
        ),
        SourceSelectionError::UnavailablePath { path, .. } => R::failure(
            "unavailable",
            format!("Selected inventoried source bytes are unavailable: {path}"),
        ),
    }
}
