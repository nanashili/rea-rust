//! Ordered, unique-only node pairing with retained ambiguity candidates.

use super::graph::{ApplicationGraph, ApplicationNode};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MatchBasis {
    ExactContentDigest,
    ExactModuleSourceDigest,
    ExactNodeIdentity,
    SourceMapIdentity,
    StructuralFingerprint,
    SemanticKey,
}

impl MatchBasis {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExactContentDigest => "exact-content-digest",
            Self::ExactModuleSourceDigest => "exact-module-source-digest",
            Self::ExactNodeIdentity => "exact-node-identity",
            Self::SourceMapIdentity => "source-map-identity",
            Self::StructuralFingerprint => "structural-fingerprint",
            Self::SemanticKey => "semantic-key",
        }
    }

    pub fn confidence(self) -> &'static str {
        match self {
            Self::ExactContentDigest | Self::ExactModuleSourceDigest | Self::ExactNodeIdentity => {
                "exact"
            }
            Self::SourceMapIdentity => "high",
            Self::StructuralFingerprint | Self::SemanticKey => "medium",
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct NodePair {
    pub left: usize,
    pub right: usize,
    pub basis: MatchBasis,
}

#[derive(Clone, Debug)]
pub(super) struct MatchingProjection {
    pub pairs: Vec<NodePair>,
    pub unmatched_left: Vec<usize>,
    pub unmatched_right: Vec<usize>,
    pub candidates_for_left: BTreeMap<String, Vec<String>>,
    pub candidates_for_right: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Copy)]
struct MatchTier {
    basis: MatchBasis,
}

#[derive(Clone)]
struct AmbiguousGroup {
    left: Vec<usize>,
    right: Vec<usize>,
}

const TIERS: [MatchTier; 6] = [
    MatchTier {
        basis: MatchBasis::ExactContentDigest,
    },
    MatchTier {
        basis: MatchBasis::ExactModuleSourceDigest,
    },
    MatchTier {
        basis: MatchBasis::ExactNodeIdentity,
    },
    MatchTier {
        basis: MatchBasis::SourceMapIdentity,
    },
    MatchTier {
        basis: MatchBasis::StructuralFingerprint,
    },
    MatchTier {
        basis: MatchBasis::SemanticKey,
    },
];

/// Apply the TypeScript workflow's six ordered identity tiers.
pub(super) fn match_versions(
    left: &ApplicationGraph,
    right: &ApplicationGraph,
) -> Result<MatchingProjection, super::Failure> {
    let mut remaining_left = (0..left.nodes.len()).collect::<BTreeSet<_>>();
    let mut remaining_right = (0..right.nodes.len()).collect::<BTreeSet<_>>();
    let mut pairs = Vec::new();
    let mut ambiguous_groups = Vec::new();

    for tier in TIERS {
        apply_tier(
            left,
            right,
            tier,
            &mut remaining_left,
            &mut remaining_right,
            &mut pairs,
            &mut ambiguous_groups,
        )?;
    }

    pairs.sort_by(|left_pair, right_pair| {
        let left_key = format!(
            "{}\0{}",
            left.nodes[left_pair.left].node_id, right.nodes[left_pair.right].node_id
        );
        let right_key = format!(
            "{}\0{}",
            left.nodes[right_pair.left].node_id, right.nodes[right_pair.right].node_id
        );
        left_key.cmp(&right_key)
    });

    let mut candidates_for_left = BTreeMap::<String, BTreeSet<String>>::new();
    let mut candidates_for_right = BTreeMap::<String, BTreeSet<String>>::new();
    for group in ambiguous_groups {
        let surviving_left = group
            .left
            .into_iter()
            .filter(|index| remaining_left.contains(index))
            .collect::<Vec<_>>();
        let surviving_right = group
            .right
            .into_iter()
            .filter(|index| remaining_right.contains(index))
            .collect::<Vec<_>>();
        if surviving_left.is_empty() || surviving_right.is_empty() {
            continue;
        }
        record_candidates(
            &surviving_left,
            &surviving_right,
            left,
            right,
            &mut candidates_for_left,
            &mut candidates_for_right,
        );
    }

    Ok(MatchingProjection {
        pairs,
        unmatched_left: sorted_indices(left, remaining_left),
        unmatched_right: sorted_indices(right, remaining_right),
        candidates_for_left: candidates_for_left
            .into_iter()
            .map(|(node_id, candidates)| (node_id, candidates.into_iter().collect()))
            .collect(),
        candidates_for_right: candidates_for_right
            .into_iter()
            .map(|(node_id, candidates)| (node_id, candidates.into_iter().collect()))
            .collect(),
    })
}

fn apply_tier(
    left: &ApplicationGraph,
    right: &ApplicationGraph,
    tier: MatchTier,
    remaining_left: &mut BTreeSet<usize>,
    remaining_right: &mut BTreeSet<usize>,
    pairs: &mut Vec<NodePair>,
    ambiguous_groups: &mut Vec<AmbiguousGroup>,
) -> Result<(), super::Failure> {
    let left_by_key = nodes_by_key(&left.nodes, remaining_left, tier.basis)?;
    let right_by_key = nodes_by_key(&right.nodes, remaining_right, tier.basis)?;

    for (key, left_group) in left_by_key {
        let Some(right_group) = right_by_key.get(&key) else {
            continue;
        };

        if left_group.len() != 1 || right_group.len() != 1 {
            ambiguous_groups.push(AmbiguousGroup {
                left: left_group,
                right: right_group.clone(),
            });
            continue;
        }

        let left_index = left_group[0];
        let right_index = right_group[0];
        pairs.push(NodePair {
            left: left_index,
            right: right_index,
            basis: tier.basis,
        });
        remaining_left.remove(&left_index);
        remaining_right.remove(&right_index);
    }

    Ok(())
}

fn nodes_by_key(
    nodes: &[ApplicationNode],
    remaining: &BTreeSet<usize>,
    basis: MatchBasis,
) -> Result<BTreeMap<String, Vec<usize>>, super::Failure> {
    let mut grouped = BTreeMap::<String, Vec<usize>>::new();
    for index in remaining {
        let node = &nodes[*index];
        if let Some(key) = match_key(node, basis)? {
            grouped.entry(key).or_default().push(*index);
        }
    }
    Ok(grouped)
}

fn match_key(node: &ApplicationNode, basis: MatchBasis) -> Result<Option<String>, super::Failure> {
    let key = match basis {
        MatchBasis::ExactContentDigest => content_identity_key(node),
        MatchBasis::ExactModuleSourceDigest => module_source_key(node),
        MatchBasis::ExactNodeIdentity => Some(format!("node\0{}\0{}", node.kind, node.node_id)),
        MatchBasis::SourceMapIdentity => source_map_key(node)?,
        MatchBasis::StructuralFingerprint => structural_fingerprint_key(node),
        MatchBasis::SemanticKey => semantic_key(node)?,
    };
    Ok(key)
}

fn content_identity_key(node: &ApplicationNode) -> Option<String> {
    if node.identity.get("strategy").and_then(Value::as_str) != Some("content-digest") {
        return None;
    }
    let digest = node.identity.get("sha256")?.as_str()?;
    Some(format!("content\0{}\0{digest}", node.kind))
}

fn module_source_key(node: &ApplicationNode) -> Option<String> {
    if node.kind != "javascript-module" {
        return None;
    }
    let digest = unique_string_property(node, "source_sha256")?;
    Some(format!("module-source\0{}\0{digest}", node.kind))
}

fn source_map_key(node: &ApplicationNode) -> Result<Option<String>, super::Failure> {
    if node.kind != "source-module"
        || node.identity.get("strategy").and_then(Value::as_str) != Some("source-map-original")
    {
        return Ok(None);
    }
    let root = node
        .identity
        .get("source_root")
        .cloned()
        .unwrap_or(Value::Null);
    let original = node
        .identity
        .get("original_source")
        .cloned()
        .unwrap_or(Value::Null);
    let identity = serde_json::to_string(&vec![root, original])
        .map_err(|error| super::graph::invalid("matching", &error.to_string()))?;
    Ok(Some(format!("source-map\0{identity}")))
}

fn structural_fingerprint_key(node: &ApplicationNode) -> Option<String> {
    if node.kind != "javascript-module" {
        return None;
    }
    let digest = unique_string_property(node, "structural_fingerprint_sha256")?;
    let algorithm = unique_string_property(node, "structural_fingerprint_algorithm")?;
    Some(format!("structural\0{}\0{algorithm}\0{digest}", node.kind))
}

fn semantic_key(node: &ApplicationNode) -> Result<Option<String>, super::Failure> {
    if matches!(
        node.kind.as_str(),
        "javascript-module" | "javascript-chunk" | "runtime-script-instance" | "unknown"
    ) {
        return Ok(None);
    }

    let properties = first_properties(node);
    let semantic = match node.kind.as_str() {
        "endpoint" => {
            let kind = nonempty_string(properties.get("endpoint_kind"));
            let value = exact_string(properties.get("value"));
            match (kind, value) {
                (Some(kind), Some(value)) => Some(format!("{kind}\0{value}")),
                _ => None,
            }
        }
        "storage" => joined_strings(&[
            nonempty_string(properties.get("storage_kind")),
            nonempty_string(
                properties
                    .get("name")
                    .filter(|value| !value.is_null())
                    .or_else(|| properties.get("mechanism")),
            ),
        ])?,
        "ipc-channel" => {
            if properties.get("resolution").and_then(Value::as_str) == Some("dynamic") {
                None
            } else {
                exact_string(properties.get("channel")).or_else(|| first_label(node))
            }
        }
        "context-bridge-api" => first_label(node)
            .or_else(|| exact_string(properties.get("api_key")))
            .or_else(|| nonempty_string(properties.get("api_name"))),
        "native-export" => {
            let requested_members = string_list(properties.get("requested_members"));
            let namespace_access = properties
                .get("namespace_access")
                .filter(|value| value.is_boolean())
                .cloned()
                .unwrap_or(Value::Null);
            let dynamic_member_access = properties
                .get("dynamic_member_access")
                .filter(|value| value.is_boolean())
                .cloned()
                .unwrap_or(Value::Null);
            let access = serde_json::to_string(&json!([
                requested_members,
                namespace_access,
                dynamic_member_access
            ]))
            .map_err(|error| super::graph::invalid("matching", &error.to_string()))?;
            joined_strings(&[nonempty_string(properties.get("specifier")), Some(access)])?
                .or_else(|| first_label(node))
        }
        "electron-main" | "electron-preload" | "electron-renderer" | "electron-utility" => {
            joined_strings(&[
                nonempty_string(properties.get("declared_path")),
                nonempty_string(properties.get("resolved_path")),
            ])?
        }
        "package" => nonempty_string(properties.get("name")),
        _ => canonical_path(node).or_else(|| nonempty_string(properties.get("path"))),
    };

    Ok(semantic.map(|value| format!("semantic\0{}\0{value}", node.kind)))
}

fn first_properties(node: &ApplicationNode) -> &Map<String, Value> {
    node.observations
        .first()
        .map(|observation| &observation.properties)
        .expect("application node validation requires one observation")
}

fn first_label(node: &ApplicationNode) -> Option<String> {
    node.observations
        .iter()
        .find_map(|observation| observation.label.clone())
}

fn unique_string_property(node: &ApplicationNode, property_name: &str) -> Option<String> {
    let values = node
        .observations
        .iter()
        .filter_map(|observation| observation.properties.get(property_name))
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    (values.len() == 1).then(|| values.into_iter().next().unwrap_or_default().to_owned())
}

fn joined_strings(parts: &[Option<String>]) -> Result<Option<String>, super::Failure> {
    if parts.iter().any(Option::is_none) {
        return Ok(None);
    }
    let values = parts
        .iter()
        .filter_map(Clone::clone)
        .map(Value::String)
        .collect::<Vec<_>>();
    serde_json::to_string(&values)
        .map(Some)
        .map_err(|error| super::graph::invalid("matching", &error.to_string()))
}

fn nonempty_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn exact_string(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_owned)
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    let mut values = value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    values.sort();
    values
}

fn canonical_path(node: &ApplicationNode) -> Option<String> {
    if node.identity.get("strategy").and_then(Value::as_str) != Some("canonical-path") {
        return None;
    }
    node.identity
        .get("path")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

pub(super) fn content_identity(node: &ApplicationNode) -> Option<String> {
    match node.identity.get("strategy").and_then(Value::as_str) {
        Some("content-digest") => node
            .identity
            .get("sha256")
            .and_then(Value::as_str)
            .map(|digest| format!("content:{digest}")),
        _ if node.kind == "javascript-module" => unique_string_property(node, "source_sha256"),
        _ if node.kind == "source-module"
            && node.identity.get("strategy").and_then(Value::as_str)
                == Some("source-map-original") =>
        {
            node.identity
                .get("source_sha256")
                .and_then(Value::as_str)
                .map(str::to_owned)
        }
        _ => None,
    }
}

fn sorted_indices(graph: &ApplicationGraph, indices: BTreeSet<usize>) -> Vec<usize> {
    let mut indices = indices.into_iter().collect::<Vec<_>>();
    indices.sort_by(|left, right| graph.nodes[*left].node_id.cmp(&graph.nodes[*right].node_id));
    indices
}

fn record_candidates(
    left_indices: &[usize],
    right_indices: &[usize],
    left: &ApplicationGraph,
    right: &ApplicationGraph,
    candidates_for_left: &mut BTreeMap<String, BTreeSet<String>>,
    candidates_for_right: &mut BTreeMap<String, BTreeSet<String>>,
) {
    for left_index in left_indices {
        let left_id = &left.nodes[*left_index].node_id;
        let candidates = candidates_for_left.entry(left_id.clone()).or_default();
        candidates.extend(
            right_indices
                .iter()
                .map(|right_index| right.nodes[*right_index].node_id.clone()),
        );
    }
    for right_index in right_indices {
        let right_id = &right.nodes[*right_index].node_id;
        let candidates = candidates_for_right.entry(right_id.clone()).or_default();
        candidates.extend(
            left_indices
                .iter()
                .map(|left_index| left.nodes[*left_index].node_id.clone()),
        );
    }
}
