//! Pure JavaScript artifact-file projection and source-selection planning.
//!
//! Inventory parsing remains owned by `rea_core::artifact_inventory`. This
//! module only projects validated inventory facts; it never reads a path or
//! opens an artifact reader.

use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use super::semantic::value_types::JsString;
use rea_core::artifact_inventory::{ArtifactInventoryResult, ArtifactNode, ArtifactOccurrence};
use regex::Regex;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JavaScriptArtifactFileKind {
    PackageJson,
    Json,
    JavaScript,
    Html,
    SourceMap,
    NativeAddon,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextExclusionReason {
    NotApplicable,
    InvalidUtf8,
    OutsideAnalysisScope,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JavaScriptText {
    Included(JsString),
    Excluded(TextExclusionReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JavaScriptArtifactFile {
    pub path: String,
    pub container_sha256: String,
    pub sha256: String,
    pub bytes: u64,
    pub inventory_artifact_id: String,
    pub kind: JavaScriptArtifactFileKind,
    pub unpacked: bool,
    pub text: JavaScriptText,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JavaScriptUnanalyzedArtifactFile {
    pub path: JsString,
    pub container_sha256: String,
    pub sha256: Option<String>,
    pub bytes: Option<u64>,
    pub inventory_artifact_id: Option<String>,
    pub inventory_occurrence_id: String,
    pub kind: Option<JavaScriptArtifactFileKind>,
    pub artifact_kind: String,
    pub hash_status: String,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JavaScriptArtifactContainer {
    /// The logical path supplied by the authenticated inventory.
    ///
    /// This remains UTF-16 exact even when it cannot be represented as an
    /// operating-system path.  Readers cross that boundary explicitly.
    pub path: JsString,
    pub sha256: String,
    pub bytes: u64,
    pub inventory_artifact_id: String,
}

pub trait UnanalyzedArtifactLookup {
    fn get(&mut self, path: &str) -> Option<JavaScriptUnanalyzedArtifactFile> {
        self.get_exact(&JsString::from(path))
    }

    fn get_exact(&mut self, path: &JsString) -> Option<JavaScriptUnanalyzedArtifactFile>;

    fn has_directory(&mut self, path: &str, container_sha256: Option<&str>) -> bool;
}

#[derive(Debug)]
pub(crate) struct ExpectedInventory {
    pub(crate) files: HashMap<JsString, ExpectedFile>,
    pub(crate) containers: HashMap<JsString, ExpectedContainer>,
    pub(crate) unavailable_files: HashSet<JsString>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExpectedFile {
    pub(crate) path: JsString,
    pub(crate) sha256: String,
    pub(crate) bytes: u64,
    pub(crate) inventory_artifact_id: String,
    pub(crate) kind: JavaScriptArtifactFileKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExpectedContainer {
    pub(crate) hash_status: String,
    pub(crate) format: String,
    pub(crate) inventory: Option<JavaScriptArtifactContainer>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceSelectionPlan {
    pub(crate) requested_paths: Vec<String>,
    pub(crate) unique_paths: Vec<String>,
    pub(crate) unselected_files: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SourceSelectionError {
    UnknownPaths(Vec<IndexedPath>),
    UnavailablePath { index: usize, path: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IndexedPath {
    pub(crate) index: usize,
    pub(crate) path: String,
}

pub(crate) fn classify_relevant_path(path: &str) -> Option<JavaScriptArtifactFileKind> {
    let lower = path.to_ascii_lowercase();
    if lower == "package.json" || lower.ends_with("/package.json") {
        return Some(JavaScriptArtifactFileKind::PackageJson);
    }
    if lower.ends_with(".json") {
        return Some(JavaScriptArtifactFileKind::Json);
    }
    if is_javascript_source_path(path) {
        return Some(JavaScriptArtifactFileKind::JavaScript);
    }
    if lower.ends_with(".html") || lower.ends_with(".htm") {
        return Some(JavaScriptArtifactFileKind::Html);
    }
    if lower.ends_with(".map") {
        return Some(JavaScriptArtifactFileKind::SourceMap);
    }
    if lower.ends_with(".node") {
        return Some(JavaScriptArtifactFileKind::NativeAddon);
    }
    None
}

/// Classify an inventory path without decoding it through Rust UTF-8.
pub(crate) fn classify_relevant_js_path(path: &JsString) -> Option<JavaScriptArtifactFileKind> {
    if let Some(valid_path) = path.as_str() {
        return classify_relevant_path(valid_path);
    }

    let lower = path.to_ascii_lowercase();
    if lower == JsString::from("package.json") || lower.ends_with("/package.json") {
        return Some(JavaScriptArtifactFileKind::PackageJson);
    }
    if lower.ends_with(".json") {
        return Some(JavaScriptArtifactFileKind::Json);
    }
    if is_javascript_source_js_path(&lower) {
        return Some(JavaScriptArtifactFileKind::JavaScript);
    }
    if lower.ends_with(".html") || lower.ends_with(".htm") {
        return Some(JavaScriptArtifactFileKind::Html);
    }
    if lower.ends_with(".map") {
        return Some(JavaScriptArtifactFileKind::SourceMap);
    }
    if lower.ends_with(".node") {
        return Some(JavaScriptArtifactFileKind::NativeAddon);
    }
    None
}

pub(crate) fn describe_js_path(path: &JsString) -> String {
    path.as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| format!("UTF-16 code units {:?}", path.units()))
}

fn is_javascript_source_js_path(path: &JsString) -> bool {
    [".cjs", ".cts", ".mjs", ".mts", ".js", ".jsx", ".ts", ".tsx"]
        .iter()
        .copied()
        .any(|suffix| path.ends_with(suffix))
}

pub(crate) fn is_javascript_source_path(path: &str) -> bool {
    static SOURCE_PATH_PATTERN: OnceLock<Regex> = OnceLock::new();
    SOURCE_PATH_PATTERN
        .get_or_init(|| Regex::new(r"(?iu)\.(?:cjs|cts|mjs|mts|js|jsx|ts|tsx)$").unwrap())
        .is_match(path)
}

pub(crate) fn expected_inventory(
    snapshot: &ArtifactInventoryResult,
) -> Result<ExpectedInventory, InventoryProjectionError> {
    let nodes: HashMap<&str, &ArtifactNode> = snapshot
        .nodes
        .iter()
        .map(|node| (node.artifact_id.as_str(), node))
        .collect();
    let mut files = HashMap::new();
    let mut containers = HashMap::new();
    let mut unavailable_files = HashSet::new();

    for occurrence in &snapshot.occurrences {
        if occurrence.logical_path == JsString::from(".") {
            continue;
        }

        let nested_asar = occurrence.entry_kind == "file"
            && occurrence
                .logical_path
                .to_ascii_lowercase()
                .ends_with(".asar");
        let Some(artifact_id) = occurrence.artifact_id.as_ref() else {
            if occurrence.entry_kind == "file"
                && classify_relevant_js_path(&occurrence.logical_path).is_some()
            {
                unavailable_files.insert(occurrence.logical_path.clone());
            }
            if nested_asar {
                containers.insert(
                    occurrence.logical_path.clone(),
                    ExpectedContainer {
                        hash_status: occurrence.hash_status.clone(),
                        format: occurrence.artifact_format.clone(),
                        inventory: None,
                    },
                );
            }
            continue;
        };

        let node = nodes.get(artifact_id.as_str()).ok_or_else(|| {
            InventoryProjectionError::MissingNode(occurrence.logical_path.clone())
        })?;
        if occurrence.entry_kind != "file" {
            continue;
        }

        let container = JavaScriptArtifactContainer {
            path: occurrence.logical_path.clone(),
            sha256: node.sha256.clone(),
            bytes: node.size,
            inventory_artifact_id: node.artifact_id.clone(),
        };
        if nested_asar {
            containers.insert(
                occurrence.logical_path.clone(),
                ExpectedContainer {
                    hash_status: occurrence.hash_status.clone(),
                    format: occurrence.artifact_format.clone(),
                    inventory: Some(container),
                },
            );
        }

        let Some(kind) = classify_relevant_js_path(&occurrence.logical_path) else {
            continue;
        };
        files.insert(
            occurrence.logical_path.clone(),
            ExpectedFile {
                path: occurrence.logical_path.clone(),
                sha256: node.sha256.clone(),
                bytes: node.size,
                inventory_artifact_id: node.artifact_id.clone(),
                kind,
            },
        );
    }

    Ok(ExpectedInventory {
        files,
        containers,
        unavailable_files,
    })
}

pub(crate) fn plan_source_selection(
    inventory: &ExpectedInventory,
    requested_paths: &[String],
) -> Result<SourceSelectionPlan, SourceSelectionError> {
    let mut unique_paths = Vec::new();
    let mut seen = HashSet::new();
    let mut unknown_paths = Vec::new();
    let mut unavailable_path = None;
    for (index, path) in requested_paths.iter().enumerate() {
        let path_key = JsString::from(path.clone());
        if inventory.unavailable_files.contains(&path_key) {
            if unavailable_path.is_none() {
                unavailable_path = Some(IndexedPath {
                    index,
                    path: path.clone(),
                });
            }
            continue;
        }
        if !inventory.files.contains_key(&path_key) {
            unknown_paths.push(IndexedPath {
                index,
                path: path.clone(),
            });
            continue;
        }
        if seen.insert(path.clone()) {
            unique_paths.push(path.clone());
        }
    }

    if !unknown_paths.is_empty() {
        return Err(SourceSelectionError::UnknownPaths(unknown_paths));
    }
    if let Some(unavailable) = unavailable_path {
        return Err(SourceSelectionError::UnavailablePath {
            index: unavailable.index,
            path: unavailable.path,
        });
    }

    Ok(SourceSelectionPlan {
        requested_paths: requested_paths.to_vec(),
        unique_paths,
        unselected_files: inventory.files.len().saturating_sub(seen.len()),
    })
}

pub struct InventoryLookup<'a> {
    snapshot: &'a ArtifactInventoryResult,
    containers: Vec<JavaScriptArtifactContainer>,
    occurrence_order: Vec<usize>,
    node_order: Vec<usize>,
    container_order: Vec<usize>,
    requested: HashMap<JsString, Option<JavaScriptUnanalyzedArtifactFile>>,
    directories: HashMap<(String, Option<String>), bool>,
}

impl<'a> InventoryLookup<'a> {
    pub fn new(
        snapshot: &'a ArtifactInventoryResult,
        containers: &[JavaScriptArtifactContainer],
    ) -> Self {
        Self {
            snapshot,
            containers: containers.to_vec(),
            occurrence_order: sorted_occurrence_indices(snapshot),
            node_order: sorted_node_indices(snapshot),
            container_order: sorted_container_indices(containers),
            requested: HashMap::new(),
            directories: HashMap::new(),
        }
    }

    fn container_for_exact(&self, path: &JsString) -> String {
        let mut prefix = path.clone();
        loop {
            let Some(separator) = prefix.units().iter().rposition(|unit| *unit == b'/' as u16)
            else {
                return self.snapshot.manifest.root_sha256.clone();
            };
            prefix = prefix.slice_units(0..separator);
            if let Some(container) = self.find_container_exact(&prefix) {
                return container.sha256.clone();
            }
        }
    }

    fn find_container_exact(&self, path: &JsString) -> Option<&JavaScriptArtifactContainer> {
        let index = lower_bound_indices(&self.container_order, |index| {
            compare_code_points(&self.containers[index].path, path)
        });
        self.container_order
            .get(index)
            .filter(|index| self.containers[**index].path == path.clone())
            .map(|index| &self.containers[*index])
    }

    fn find_occurrence_exact(&self, path: &JsString) -> Option<&ArtifactOccurrence> {
        let index = lower_bound_indices(&self.occurrence_order, |index| {
            compare_code_points(&self.snapshot.occurrences[index].logical_path, path)
        });
        self.occurrence_order
            .get(index)
            .filter(|index| self.snapshot.occurrences[**index].logical_path == path.clone())
            .map(|index| &self.snapshot.occurrences[*index])
    }

    fn find_node(&self, artifact_id: &str) -> Option<&ArtifactNode> {
        let index = lower_bound_indices(&self.node_order, |index| {
            self.snapshot.nodes[index]
                .artifact_id
                .as_str()
                .cmp(artifact_id)
        });
        self.node_order
            .get(index)
            .filter(|index| self.snapshot.nodes[**index].artifact_id == artifact_id)
            .map(|index| &self.snapshot.nodes[*index])
    }
}

impl UnanalyzedArtifactLookup for InventoryLookup<'_> {
    fn get_exact(&mut self, path: &JsString) -> Option<JavaScriptUnanalyzedArtifactFile> {
        let path_key = path.clone();
        if let Some(cached) = self.requested.get(&path_key) {
            return cached.clone();
        }

        let kind = classify_relevant_js_path(path);
        let Some(occurrence) = self.find_occurrence_exact(path) else {
            self.requested.insert(path_key.clone(), None);
            return None;
        };
        let opaque = occurrence.entry_kind == "file" && kind.is_none();
        let unavailable = occurrence.entry_kind == "file"
            && occurrence.artifact_id.as_ref().is_none()
            && kind.is_some();
        if !opaque && !unavailable {
            self.requested.insert(path_key.clone(), None);
            return None;
        }

        let node = occurrence
            .artifact_id
            .as_ref()
            .and_then(|id| self.find_node(id));
        let file = JavaScriptUnanalyzedArtifactFile {
            path: path.clone(),
            container_sha256: self.container_for_exact(path),
            sha256: node.map(|item| item.sha256.clone()),
            bytes: node
                .map(|item| item.size)
                .or_else(|| occurrence.declared_size.as_ref().copied()),
            inventory_artifact_id: occurrence.artifact_id.as_ref().cloned(),
            inventory_occurrence_id: occurrence.occurrence_id.clone(),
            kind,
            artifact_kind: occurrence.artifact_kind.clone(),
            hash_status: occurrence.hash_status.clone(),
            limitations: occurrence.limitations.clone(),
        };
        self.requested.insert(path_key, Some(file.clone()));
        Some(file)
    }

    fn has_directory(&mut self, path: &str, container_sha256: Option<&str>) -> bool {
        let key = (path.to_owned(), container_sha256.map(str::to_owned));
        if let Some(present) = self.directories.get(&key) {
            return *present;
        }

        let prefix = JsString::from(format!("{path}/"));
        let start = lower_bound_indices(&self.occurrence_order, |index| {
            compare_code_points(&self.snapshot.occurrences[index].logical_path, &prefix)
        });
        let present = self.occurrence_order[start..]
            .iter()
            .take_while(|index| {
                self.snapshot.occurrences[**index]
                    .logical_path
                    .units()
                    .starts_with(prefix.units())
            })
            .any(|index| {
                let entry = &self.snapshot.occurrences[*index];
                if entry.entry_kind != "file" {
                    return false;
                }
                let relevant = classify_relevant_js_path(&entry.logical_path).is_some();
                let opaque = !relevant;
                let unavailable = entry.artifact_id.as_ref().is_none() && relevant;
                (opaque || unavailable)
                    && container_sha256.is_none_or(|expected| {
                        self.container_for_exact(&entry.logical_path) == expected
                    })
            });
        self.directories.insert(key, present);
        present
    }
}

fn sorted_occurrence_indices(snapshot: &ArtifactInventoryResult) -> Vec<usize> {
    let mut indices: Vec<_> = (0..snapshot.occurrences.len()).collect();
    indices.sort_by(|left, right| {
        compare_code_points(
            &snapshot.occurrences[*left].logical_path,
            &snapshot.occurrences[*right].logical_path,
        )
    });
    indices
}

fn sorted_node_indices(snapshot: &ArtifactInventoryResult) -> Vec<usize> {
    let mut indices: Vec<_> = (0..snapshot.nodes.len()).collect();
    indices.sort_by(|left, right| {
        snapshot.nodes[*left]
            .artifact_id
            .cmp(&snapshot.nodes[*right].artifact_id)
    });
    indices
}

fn sorted_container_indices(containers: &[JavaScriptArtifactContainer]) -> Vec<usize> {
    let mut indices: Vec<_> = (0..containers.len()).collect();
    indices.sort_by(|left, right| {
        compare_code_points(&containers[*left].path, &containers[*right].path)
    });
    indices
}

fn lower_bound_indices<F>(indices: &[usize], identity: F) -> usize
where
    F: Fn(usize) -> std::cmp::Ordering,
{
    let mut low = 0;
    let mut high = indices.len();
    while low < high {
        let middle = low + (high - low) / 2;
        if identity(indices[middle]).is_lt() {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    low
}

fn compare_code_points(left: &JsString, right: &JsString) -> std::cmp::Ordering {
    left.compare_code_points(right)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum InventoryProjectionError {
    MissingNode(JsString),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inventory() -> ExpectedInventory {
        ExpectedInventory {
            files: HashMap::from([
                (
                    "main.js".into(),
                    ExpectedFile {
                        path: "main.js".into(),
                        sha256: "a".repeat(64),
                        bytes: 3,
                        inventory_artifact_id: "art_main".into(),
                        kind: JavaScriptArtifactFileKind::JavaScript,
                    },
                ),
                (
                    "package.json".into(),
                    ExpectedFile {
                        path: "package.json".into(),
                        sha256: "b".repeat(64),
                        bytes: 2,
                        inventory_artifact_id: "art_package".into(),
                        kind: JavaScriptArtifactFileKind::PackageJson,
                    },
                ),
            ]),
            containers: HashMap::new(),
            unavailable_files: HashSet::from(["opaque.js".into()]),
        }
    }

    #[test]
    fn classifies_source_and_metadata_suffixes_case_insensitively() {
        assert_eq!(
            classify_relevant_path("src/MAIN.TSX"),
            Some(JavaScriptArtifactFileKind::JavaScript)
        );
        assert_eq!(
            classify_relevant_path("src/main.j\u{017f}"),
            Some(JavaScriptArtifactFileKind::JavaScript)
        );
        assert_eq!(
            classify_relevant_path("PACKAGE.JSON"),
            Some(JavaScriptArtifactFileKind::PackageJson)
        );
        assert_eq!(
            classify_relevant_path("assets/view.HTML"),
            Some(JavaScriptArtifactFileKind::Html)
        );
        assert_eq!(classify_relevant_path("README"), None);
    }

    #[test]
    fn source_selection_preserves_duplicate_requests_and_first_priority() {
        let plan = plan_source_selection(
            &inventory(),
            &[
                "package.json".into(),
                "main.js".into(),
                "package.json".into(),
            ],
        )
        .expect("known inventory paths are selectable");

        assert_eq!(
            plan.requested_paths,
            vec!["package.json", "main.js", "package.json"]
        );
        assert_eq!(plan.unique_paths, vec!["package.json", "main.js"]);
        assert_eq!(plan.unselected_files, 0);
    }

    #[test]
    fn source_selection_distinguishes_unknown_and_unavailable_with_original_index() {
        let unknown = plan_source_selection(&inventory(), &["missing.js".into()])
            .expect_err("unknown path must be rejected");
        assert_eq!(
            unknown,
            SourceSelectionError::UnknownPaths(vec![IndexedPath {
                index: 0,
                path: "missing.js".into(),
            }])
        );

        let unavailable = plan_source_selection(&inventory(), &["opaque.js".into()])
            .expect_err("unavailable path must retain its distinct outcome");
        assert_eq!(
            unavailable,
            SourceSelectionError::UnavailablePath {
                index: 0,
                path: "opaque.js".into()
            }
        );
    }

    #[test]
    fn source_selection_reports_all_unknowns_before_unavailable_paths() {
        let error = plan_source_selection(
            &inventory(),
            &[
                "opaque.js".into(),
                "missing-a.js".into(),
                "missing-b.js".into(),
            ],
        )
        .expect_err("invalid selections must be reported");

        assert_eq!(
            error,
            SourceSelectionError::UnknownPaths(vec![
                IndexedPath {
                    index: 1,
                    path: "missing-a.js".into(),
                },
                IndexedPath {
                    index: 2,
                    path: "missing-b.js".into(),
                },
            ])
        );
    }

    #[test]
    fn lookup_uses_nested_container_identity_with_unsorted_inventory_records() {
        let root_id = format!("art_{}", "a".repeat(64));
        let nested_id = format!("art_{}", "b".repeat(64));
        let snapshot = rea_core::artifact_inventory::parse_validated_result(serde_json::json!({
            "manifest": {
                "manifest_id": format!("agm_{}", "c".repeat(64)),
                "root_artifact_id": root_id,
                "root_sha256": "d".repeat(64),
                "root_format": "directory",
                "graph_sha256": "e".repeat(64),
                "node_count": 2,
                "occurrence_count": 3,
                "edge_count": 0
            },
            "nodes": [
                {
                    "artifact_id": nested_id,
                    "format": "file",
                    "sha256": "f".repeat(64),
                    "size": 10,
                    "media_type": null,
                    "architecture": null,
                    "content_state": "materialized",
                    "limitations": []
                },
                {
                    "artifact_id": format!("art_{}", "a".repeat(64)),
                    "format": "directory",
                    "sha256": "d".repeat(64),
                    "size": 1,
                    "media_type": null,
                    "architecture": null,
                    "content_state": "materialized",
                    "limitations": []
                }
            ],
            "occurrences": [
                {
                    "occurrence_id": format!("occ_{}", "b".repeat(64)),
                    "artifact_id": null,
                    "parent_occurrence_id": null,
                    "logical_path": "nested.asar/opaque.js",
                    "entry_kind": "file",
                    "artifact_kind": "javascript",
                    "artifact_format": "javascript-bundle",
                    "declared_size": 4,
                    "compressed_size": null,
                    "executable": false,
                    "encrypted": false,
                    "hash_status": "unavailable",
                    "source_location": null,
                    "limitations": ["bytes unavailable"]
                },
                {
                    "occurrence_id": format!("occ_{}", "a".repeat(64)),
                    "artifact_id": format!("art_{}", "b".repeat(64)),
                    "parent_occurrence_id": null,
                    "logical_path": "nested.asar",
                    "entry_kind": "file",
                    "artifact_kind": "container",
                    "artifact_format": "asar",
                    "declared_size": 10,
                    "compressed_size": null,
                    "executable": false,
                    "encrypted": false,
                    "hash_status": "verified",
                    "source_location": null,
                    "limitations": []
                },
                {
                    "occurrence_id": format!("occ_{}", "c".repeat(64)),
                    "artifact_id": format!("art_{}", "a".repeat(64)),
                    "parent_occurrence_id": null,
                    "logical_path": ".",
                    "entry_kind": "directory",
                    "artifact_kind": "container",
                    "artifact_format": "directory",
                    "declared_size": null,
                    "compressed_size": null,
                    "executable": false,
                    "encrypted": false,
                    "hash_status": "verified",
                    "source_location": null,
                    "limitations": []
                }
            ],
            "edges": [],
            "provenance": [],
            "integrity_contradictions": [],
            "coverage": {"scope": "root", "status": "complete"},
            "limitations": []
        }))
        .expect("test inventory parses");
        let inventory = expected_inventory(&snapshot).expect("inventory projects");
        let container = inventory
            .containers
            .get(&JsString::from("nested.asar"))
            .and_then(|item| item.inventory.clone())
            .expect("nested container identity");
        let containers = [container];
        let mut lookup = InventoryLookup::new(&snapshot, &containers);

        let file = lookup.get("nested.asar/opaque.js").expect("opaque file");
        assert_eq!(file.container_sha256, "f".repeat(64));
        assert!(lookup.has_directory("nested.asar", Some("f".repeat(64).as_str())));
    }
}
