//! `javascriptRuntimeStaticCandidates.ts`: static entities that can receive
//! runtime matches, and runtime-location to artifact-path translation.
use super::layers::Layer;
use super::paths::{self, relative_logical_path};
use super::runtime::{Entity, LocationKind};
use super::str_of;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};

pub struct Candidate<'a> {
    /// Index into the sorted layers.
    pub layer: usize,
    pub layer_id: &'a str,
    pub node: &'a Value,
    pub category: &'static str,
    pub paths: Vec<String>,
    /// `[posix, windows]` declarations: `(path, sourcePath)`.
    pub native_declaration_paths: [Vec<(String, Option<String>)>; 2],
    pub digests: Vec<(String, &'static str)>,
}

impl Candidate<'_> {
    pub fn node_id(&self) -> &str {
        str_of(&self.node["node_id"])
    }
    pub fn key(&self) -> String {
        format!("{}:{}", self.layer_id, self.node_id())
    }
}

#[derive(Clone)]
pub struct MappedPath {
    pub path: String,
    pub file_style: Option<&'static str>,
    pub native_relative_path: Option<String>,
    pub artifact_prefix: String,
    pub basis: &'static str,
}

/// `collectStaticRuntimeCandidates`.
pub fn collect_static_runtime_candidates(layers: &[Layer]) -> Vec<Candidate<'_>> {
    let mut candidates: Vec<Candidate<'_>> = layers
        .iter()
        .enumerate()
        .flat_map(|(index, layer)| candidates_for_layer(index, layer))
        .collect();
    candidates.sort_by(|left, right| {
        left.layer_id
            .cmp(right.layer_id)
            .then_with(|| left.node_id().cmp(right.node_id()))
    });
    candidates
}

fn candidates_for_layer(index: usize, layer: &Layer) -> Vec<Candidate<'_>> {
    let mut paths_by_node = index_static_paths(layer);
    layer
        .nodes()
        .iter()
        .filter_map(|node| {
            let category = candidate_category(node)?;
            Some(Candidate {
                layer: index,
                layer_id: &layer.layer_id,
                node,
                category,
                paths: paths_by_node
                    .remove(str_of(&node["node_id"]))
                    .unwrap_or_default(),
                native_declaration_paths: native_declaration_paths(node),
                digests: candidate_digests(node),
            })
        })
        .collect()
}

fn observations(node: &Value) -> &[Value] {
    node["observations"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
}

fn candidate_category(node: &Value) -> Option<&'static str> {
    match node["kind"].as_str()? {
        "electron-renderer" => Some("renderer"),
        "javascript-asset" => Some("javascript"),
        "javascript-module" if !is_static_source_module(node) => Some("javascript"),
        "worker" => Some("worker"),
        "service-worker" => Some("service-worker"),
        _ => None,
    }
}

fn is_static_source_module(node: &Value) -> bool {
    observations(node)
        .iter()
        .any(|observation| observation["properties"]["semantic_role"] == "source-module")
}

/// `indexStaticPaths` (also the scope's `pathsByNodeId`).
pub fn index_static_paths(layer: &Layer) -> HashMap<String, Vec<String>> {
    let nodes: HashMap<&str, &Value> = layer
        .nodes()
        .iter()
        .map(|node| (str_of(&node["node_id"]), node))
        .collect();
    let mut related: HashMap<&str, Vec<&Value>> = HashMap::new();
    for edge in layer.edges() {
        if edge["relation"] != "maps_to" {
            continue;
        }
        let Some(target) = nodes.get(str_of(&edge["target_node_id"])) else {
            continue;
        };
        related
            .entry(str_of(&edge["source_node_id"]))
            .or_default()
            .push(target);
    }
    layer
        .nodes()
        .iter()
        .map(|node| {
            let id = str_of(&node["node_id"]);
            let mut all: BTreeSet<String> = node_paths(node).into_iter().collect();
            if !uses_application_file_declaration(node) {
                for target in related.get(id).into_iter().flatten() {
                    all.extend(node_paths(target));
                }
            }
            (id.to_owned(), all.into_iter().collect())
        })
        .collect()
}

fn node_paths(node: &Value) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    if node["identity"]["strategy"] == "canonical-path" {
        paths.push(str_of(&node["identity"]["path"]).to_owned());
    }
    let owned = has_owned_artifact_path(node);
    for observation in observations(node) {
        let properties = &observation["properties"];
        let raw_application_file =
            node["kind"] == "electron-renderer" && is_raw_application_file_observation(observation);
        if let Some(path) = properties["path"].as_str() {
            paths.push(path.to_owned());
        }
        if raw_application_file {
            continue;
        }
        if let Some(path) = properties["resolved_path"].as_str() {
            paths.push(path.to_owned());
        }
        if let Some(declaration) = properties["declared_path"].as_str()
            && !owned
            && !declaration.contains('\\')
        {
            paths.push(declaration.to_owned());
        }
        let location = &observation["evidence"]["location"];
        if location["available"] == true && location["value"]["kind"] == "artifact-path" {
            paths.push(str_of(&location["value"]["path"]).to_owned());
        }
    }
    paths
        .iter()
        .filter_map(|path| relative_logical_path(path))
        .filter(|path| path != "artifact-root")
        .collect()
}

fn has_owned_artifact_path(node: &Value) -> bool {
    node["identity"]["strategy"] == "canonical-path"
        || observations(node)
            .iter()
            .any(|observation| observation["properties"]["path"].is_string())
        || observations(node).iter().any(|observation| {
            !is_raw_application_file_observation(observation)
                && observation["properties"]["resolved_path"].is_string()
        })
}

fn is_raw_application_file_observation(observation: &Value) -> bool {
    let properties = &observation["properties"];
    properties["resolution_context"] == "filesystem-expression"
        && properties["mechanism"].as_str().is_some_and(|mechanism| {
            mechanism.starts_with("call:") && mechanism.ends_with("loadFile")
        })
}

fn uses_application_file_declaration(node: &Value) -> bool {
    node["kind"] == "electron-renderer"
        && !has_owned_artifact_path(node)
        && observations(node)
            .iter()
            .any(is_raw_application_file_observation)
}

fn native_declaration_paths(node: &Value) -> [Vec<(String, Option<String>)>; 2] {
    if has_owned_artifact_path(node) {
        return [Vec::new(), Vec::new()];
    }
    let declarations: Vec<(&str, Option<String>)> = observations(node)
        .iter()
        .filter_map(|observation| {
            let properties = &observation["properties"];
            let declared = properties["declared_path"].as_str()?;
            (properties["resolution_context"] == "filesystem-expression"
                && (is_raw_application_file_observation(observation) || declared.contains('\\')))
            .then(|| (declared, native_declaration_source(observation)))
        })
        .collect();
    let normalized = |windows: bool| {
        let mut values: Vec<(String, Option<String>)> = Vec::new();
        for (path, source) in &declarations {
            if windows && (paths::win32_is_absolute(path) || paths::starts_with_drive(path)) {
                continue;
            }
            let candidate = if windows {
                path.replace('\\', "/")
            } else {
                (*path).to_owned()
            };
            if let Some(normalized) = relative_logical_path(&candidate) {
                let value = (normalized, source.clone());
                if !values.contains(&value) {
                    values.push(value);
                }
            }
        }
        values.sort_by(|left, right| {
            left.0.cmp(&right.0).then_with(|| {
                left.1
                    .as_deref()
                    .unwrap_or_default()
                    .cmp(right.1.as_deref().unwrap_or_default())
            })
        });
        values
    };
    [normalized(false), normalized(true)]
}

fn native_declaration_source(observation: &Value) -> Option<String> {
    let location = &observation["evidence"]["location"];
    if location["available"] != true {
        return None;
    }
    let source = match location["value"]["kind"].as_str() {
        Some("source-range") => location["value"]["source"].as_str(),
        Some("artifact-path") => location["value"]["path"].as_str(),
        _ => None,
    }?;
    if source == "artifact-root" {
        return None;
    }
    relative_logical_path(source)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn candidate_digests(node: &Value) -> Vec<(String, &'static str)> {
    let mut values: Vec<(String, &'static str)> = Vec::new();
    let mut push = |sha256: &str, basis: &'static str| {
        if !values
            .iter()
            .any(|(existing, existing_basis)| existing == sha256 && *existing_basis == basis)
        {
            values.push((sha256.to_owned(), basis));
        }
    };
    if node["kind"] == "javascript-asset" && node["identity"]["strategy"] == "content-digest" {
        push(str_of(&node["identity"]["sha256"]), "content-sha256");
    }
    if node["kind"] == "javascript-module" {
        for observation in observations(node) {
            if let Some(digest) = observation["properties"]["source_sha256"].as_str()
                && is_digest(digest)
            {
                push(digest, "module-source-sha256");
            }
        }
    }
    values
}

/// `mappedRuntimePaths`.
pub fn mapped_runtime_paths(layer: &Layer, entity: &Entity) -> Vec<MappedPath> {
    let (kind, value) = (&entity.location.0, entity.location.1.as_str());
    let mut paths: Vec<MappedPath> = Vec::new();
    let file_style = if *kind == LocationKind::File {
        paths::absolute_file_path_style(value)
    } else {
        None
    };
    let result = layer.result();
    if *kind == LocationKind::File
        && result["format"] == "directory"
        && let Some(path) = paths::path_below_root(str_of(&result["input_path"]), value)
    {
        paths.push(MappedPath {
            native_relative_path: Some(path.clone()),
            path,
            file_style,
            artifact_prefix: String::new(),
            basis: "artifact-path",
        });
    }
    for mapping in &layer.runtime_mappings {
        let file_root = mapping["kind"] == "file-root";
        let suffix = if file_root && *kind == LocationKind::File {
            paths::path_below_root(str_of(&mapping["root"]), value)
        } else if mapping["kind"] == "url-prefix" && *kind == LocationKind::Url {
            paths::path_below_url_prefix(str_of(&mapping["prefix"]), value)
        } else {
            None
        };
        let Some(suffix) = suffix else { continue };
        let prefix = str_of(&mapping["artifact_prefix"]);
        let Some(path) = safe_artifact_path(prefix, &suffix) else {
            continue;
        };
        paths.push(MappedPath {
            path,
            file_style,
            native_relative_path: file_root.then_some(suffix),
            artifact_prefix: normalize_artifact_prefix(prefix),
            basis: if file_root {
                "operator-file-mapping"
            } else {
                "operator-url-mapping"
            },
        });
    }
    unique_mapped_paths(paths)
}

fn unique_mapped_paths(values: Vec<MappedPath>) -> Vec<MappedPath> {
    let mut unique: Vec<MappedPath> = Vec::new();
    for value in values {
        let same = |existing: &MappedPath| {
            existing.basis == value.basis
                && existing.path == value.path
                && existing.file_style == value.file_style
                && existing.native_relative_path == value.native_relative_path
                && existing.artifact_prefix == value.artifact_prefix
        };
        if !unique.iter().any(same) {
            unique.push(value);
        }
    }
    unique.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.basis.cmp(right.basis))
            .then_with(|| {
                left.native_relative_path
                    .as_deref()
                    .unwrap_or_default()
                    .cmp(right.native_relative_path.as_deref().unwrap_or_default())
            })
            .then_with(|| left.artifact_prefix.cmp(&right.artifact_prefix))
    });
    unique
}

/// Precomputed scope for load-state decisions (`createStaticRuntimeScope`).
pub struct StaticRuntimeScope {
    pub artifact_prefixes: Vec<String>,
    pub paths_by_node_id: HashMap<String, Vec<String>>,
}

pub fn create_static_runtime_scope(layer: &Layer, entities: &[Entity]) -> StaticRuntimeScope {
    StaticRuntimeScope {
        artifact_prefixes: active_artifact_prefixes(layer, entities),
        paths_by_node_id: index_static_paths(layer),
    }
}

/// `staticNodeWithinRuntimeScope`.
pub fn static_node_within_runtime_scope(node: &Value, scope: &StaticRuntimeScope) -> bool {
    scope
        .paths_by_node_id
        .get(str_of(&node["node_id"]))
        .into_iter()
        .flatten()
        .any(|path| {
            scope
                .artifact_prefixes
                .iter()
                .any(|prefix| path_within_prefix(path, prefix))
        })
}

fn active_artifact_prefixes(layer: &Layer, entities: &[Entity]) -> Vec<String> {
    let mut prefixes = BTreeSet::new();
    let result = layer.result();
    if result["format"] == "directory"
        && entities.iter().any(|entity| {
            entity.location.0 == LocationKind::File
                && paths::path_below_root(str_of(&result["input_path"]), &entity.location.1)
                    .is_some()
        })
    {
        prefixes.insert(String::new());
    }
    for mapping in &layer.runtime_mappings {
        let exercised = entities.iter().any(|entity| {
            if mapping["kind"] == "file-root" && entity.location.0 == LocationKind::File {
                paths::path_below_root(str_of(&mapping["root"]), &entity.location.1).is_some()
            } else if mapping["kind"] == "url-prefix" && entity.location.0 == LocationKind::Url {
                paths::path_below_url_prefix(str_of(&mapping["prefix"]), &entity.location.1)
                    .is_some()
            } else {
                false
            }
        });
        if exercised {
            prefixes.insert(normalize_artifact_prefix(str_of(
                &mapping["artifact_prefix"],
            )));
        }
    }
    prefixes.into_iter().collect()
}

fn normalize_artifact_prefix(prefix: &str) -> String {
    if prefix.is_empty() {
        String::new()
    } else {
        paths::normalize_joined_logical_path(prefix)
    }
}

fn path_within_prefix(path: &str, prefix: &str) -> bool {
    prefix.is_empty() || path == prefix || path.starts_with(&format!("{prefix}/"))
}

fn safe_artifact_path(prefix: &str, suffix: &str) -> Option<String> {
    if prefix.is_empty() {
        relative_logical_path(suffix)
    } else {
        relative_logical_path(&paths::posix_join(prefix, suffix))
    }
}
