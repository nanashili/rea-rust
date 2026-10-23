//! Classification of paired and one-sided application nodes.

use super::{
    graph::{ApplicationEvidence, ApplicationGraph, ApplicationNode},
    matching::{self, MatchBasis, MatchingProjection, NodePair},
};
use rea_core::canonical_json;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

const AMBIGUOUS_MATCH_LIMITATION: &str =
    "Multiple nodes share the same permitted match key; no cross-version pair was selected.";
const INCOMPLETE_GRAPH_LIMITATION: &str = "The opposite graph is incomplete, so an unmatched node cannot be classified as added or removed.";
const INCOMPLETE_MATCH_LIMITATION: &str =
    "Incomplete graph coverage prevents a complete node-level conclusion.";
const UNRESOLVED_RELATIONSHIP_LIMITATION: &str = "Relationship target identity remains unresolved; equal node kinds do not establish cross-version alignment.";

#[derive(Clone, Debug)]
pub(super) struct ClassifiedItem {
    pub raw: Value,
    pub item_id: String,
    pub status: String,
    pub left_node_id: Option<String>,
    pub right_node_id: Option<String>,
    pub match_status: String,
    pub match_basis: String,
    pub match_confidence: String,
    pub dimensions: Vec<String>,
    pub evidence_links: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug)]
struct Relationship {
    direction: &'static str,
    relation: String,
    neighbor_id: String,
}

#[derive(Clone, Debug)]
struct RelationshipIndex {
    kind_by_id: BTreeMap<String, String>,
    adjacency: BTreeMap<String, Vec<Relationship>>,
}

#[derive(Clone, Debug)]
struct ItemContext<'a> {
    left: &'a ApplicationGraph,
    right: &'a ApplicationGraph,
    left_evidence_id: &'a str,
    right_evidence_id: &'a str,
    left_native_by_digest: BTreeMap<String, Vec<String>>,
    right_native_by_digest: BTreeMap<String, Vec<String>>,
    pair_by_left: BTreeMap<String, String>,
    pair_by_right: BTreeMap<String, String>,
    left_relationships: RelationshipIndex,
    right_relationships: RelationshipIndex,
}

#[derive(Clone, Copy, Debug)]
struct RelationshipComparison {
    different: bool,
    unresolved: bool,
}

/// Classify the comparison without converting unresolved facts into absence.
pub(super) fn classify(
    left: &ApplicationGraph,
    right: &ApplicationGraph,
    left_evidence_id: &str,
    right_evidence_id: &str,
    left_native: &[ApplicationEvidence],
    right_native: &[ApplicationEvidence],
    matching: &MatchingProjection,
) -> Result<Vec<ClassifiedItem>, super::Failure> {
    let pair_by_left = matching
        .pairs
        .iter()
        .map(|pair| {
            let left_id = &left.nodes[pair.left].node_id;
            let right_id = &right.nodes[pair.right].node_id;
            (left_id.clone(), format!("pair:{left_id}:{right_id}"))
        })
        .collect::<BTreeMap<_, _>>();
    let pair_by_right = matching
        .pairs
        .iter()
        .map(|pair| {
            let left_id = &left.nodes[pair.left].node_id;
            let right_id = &right.nodes[pair.right].node_id;
            (right_id.clone(), format!("pair:{left_id}:{right_id}"))
        })
        .collect::<BTreeMap<_, _>>();
    let context = ItemContext {
        left,
        right,
        left_evidence_id,
        right_evidence_id,
        left_native_by_digest: native_evidence_by_digest(left_native),
        right_native_by_digest: native_evidence_by_digest(right_native),
        pair_by_left,
        pair_by_right,
        left_relationships: relationship_index(left),
        right_relationships: relationship_index(right),
    };

    let mut items = Vec::with_capacity(
        matching.pairs.len() + matching.unmatched_left.len() + matching.unmatched_right.len(),
    );
    for pair in &matching.pairs {
        items.push(matched_item(pair, &context)?);
    }
    for left_index in &matching.unmatched_left {
        let node = &left.nodes[*left_index];
        let candidate_right = matching
            .candidates_for_left
            .get(&node.node_id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        items.push(left_only_item(node, candidate_right, &context)?);
    }
    for right_index in &matching.unmatched_right {
        let node = &right.nodes[*right_index];
        let candidate_left = matching
            .candidates_for_right
            .get(&node.node_id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        items.push(right_only_item(node, candidate_left, &context)?);
    }
    items.sort_by(|left, right| left.item_id.cmp(&right.item_id));
    Ok(items)
}

fn matched_item(
    pair: &NodePair,
    context: &ItemContext<'_>,
) -> Result<ClassifiedItem, super::Failure> {
    let left = &context.left.nodes[pair.left];
    let right = &context.right.nodes[pair.right];
    let relationships = compare_relationships(pair, context);
    let mut dimensions = changed_dimensions(left, right, relationships)?;
    let complete = graphs_complete(context.left, context.right);
    let observed_change = dimensions
        .iter()
        .any(|dimension| matches!(dimension.as_str(), "content" | "properties"));
    let complete_change = complete && dimensions.iter().any(|dimension| dimension != "location");
    let status = if observed_change || complete_change {
        "changed"
    } else if complete && !relationships.unresolved {
        "unchanged"
    } else {
        "unknown"
    };

    if status == "unknown" && !complete {
        dimensions.push("coverage".to_owned());
    }

    let mut limitations = match_limitations(pair.basis);
    if status == "unknown" && !complete {
        limitations.push(INCOMPLETE_MATCH_LIMITATION.to_owned());
    }
    if relationships.unresolved {
        limitations.push(UNRESOLVED_RELATIONSHIP_LIMITATION.to_owned());
    }
    build_item(
        status,
        &left.kind,
        Some(&left.node_id),
        Some(&right.node_id),
        "matched",
        pair.basis.as_str(),
        pair.basis.confidence(),
        &[],
        &[],
        dimensions,
        item_evidence_links(Some(left), Some(right), context),
        limitations,
    )
}

fn left_only_item(
    node: &ApplicationNode,
    candidate_right_node_ids: &[String],
    context: &ItemContext<'_>,
) -> Result<ClassifiedItem, super::Failure> {
    if !candidate_right_node_ids.is_empty() {
        return build_item(
            "unknown",
            &node.kind,
            Some(&node.node_id),
            None,
            "ambiguous",
            "none",
            "unknown",
            &[],
            candidate_right_node_ids,
            vec!["availability".into()],
            item_evidence_links(Some(node), None, context),
            vec![AMBIGUOUS_MATCH_LIMITATION.into()],
        );
    }

    let absence_observed = absence_claimable(&context.right.coverage);
    build_item(
        if absence_observed {
            "removed"
        } else {
            "unknown"
        },
        &node.kind,
        Some(&node.node_id),
        None,
        "unmatched",
        "none",
        "unknown",
        &[],
        &[],
        if absence_observed {
            vec!["availability".into()]
        } else {
            vec!["availability".into(), "coverage".into()]
        },
        item_evidence_links(Some(node), None, context),
        if absence_observed {
            Vec::new()
        } else {
            vec![INCOMPLETE_GRAPH_LIMITATION.into()]
        },
    )
}

fn right_only_item(
    node: &ApplicationNode,
    candidate_left_node_ids: &[String],
    context: &ItemContext<'_>,
) -> Result<ClassifiedItem, super::Failure> {
    if !candidate_left_node_ids.is_empty() {
        return build_item(
            "unknown",
            &node.kind,
            None,
            Some(&node.node_id),
            "ambiguous",
            "none",
            "unknown",
            candidate_left_node_ids,
            &[],
            vec!["availability".into()],
            item_evidence_links(None, Some(node), context),
            vec![AMBIGUOUS_MATCH_LIMITATION.into()],
        );
    }

    let absence_observed = absence_claimable(&context.left.coverage);
    build_item(
        if absence_observed { "added" } else { "unknown" },
        &node.kind,
        None,
        Some(&node.node_id),
        "unmatched",
        "none",
        "unknown",
        &[],
        &[],
        if absence_observed {
            vec!["availability".into()]
        } else {
            vec!["availability".into(), "coverage".into()]
        },
        item_evidence_links(None, Some(node), context),
        if absence_observed {
            Vec::new()
        } else {
            vec![INCOMPLETE_GRAPH_LIMITATION.into()]
        },
    )
}

fn build_item(
    status: &str,
    node_kind: &str,
    left_node_id: Option<&str>,
    right_node_id: Option<&str>,
    match_status: &str,
    match_basis: &str,
    match_confidence: &str,
    candidate_left_node_ids: &[String],
    candidate_right_node_ids: &[String],
    dimensions: Vec<String>,
    evidence_links: Vec<String>,
    limitations: Vec<String>,
) -> Result<ClassifiedItem, super::Failure> {
    let match_value = json!({
        "status": match_status,
        "basis": match_basis,
        "confidence": match_confidence,
        "candidate_left_node_ids": candidate_left_node_ids,
        "candidate_right_node_ids": candidate_right_node_ids,
    });
    let mut semantic = Map::new();
    semantic.insert("status".into(), json!(status));
    semantic.insert("node_kind".into(), json!(node_kind));
    semantic.insert("left_node_id".into(), optional_string(left_node_id));
    semantic.insert("right_node_id".into(), optional_string(right_node_id));
    semantic.insert("match".into(), match_value);
    semantic.insert("dimensions".into(), json!(dimensions));
    semantic.insert("evidence_links".into(), json!(evidence_links));
    semantic.insert("limitations".into(), json!(limitations));

    let item_id = committed_id("javc_item_", &Value::Object(semantic.clone()))?;
    let raw = item_value(semantic, &item_id);
    Ok(ClassifiedItem {
        raw,
        item_id,
        status: status.to_owned(),
        left_node_id: left_node_id.map(str::to_owned),
        right_node_id: right_node_id.map(str::to_owned),
        match_status: match_status.to_owned(),
        match_basis: match_basis.to_owned(),
        match_confidence: match_confidence.to_owned(),
        dimensions,
        evidence_links,
        limitations,
    })
}

fn item_value(mut semantic: Map<String, Value>, item_id: &str) -> Value {
    semantic.insert("item_id".into(), json!(item_id));
    Value::Object(semantic)
}

fn optional_string(value: Option<&str>) -> Value {
    value.map_or(Value::Null, |value| json!(value))
}

fn committed_id(prefix: &str, value: &Value) -> Result<String, super::Failure> {
    canonical_json::digest(value)
        .map(|digest| format!("{prefix}{digest}"))
        .map_err(|error| super::graph::invalid("items", &error.to_string()))
}

fn changed_dimensions(
    left: &ApplicationNode,
    right: &ApplicationNode,
    relationships: RelationshipComparison,
) -> Result<Vec<String>, super::Failure> {
    let mut dimensions = Vec::new();
    let left_content = matching::content_identity(left);
    let right_content = matching::content_identity(right);
    if left_content.is_some() && right_content.is_some() && left_content != right_content {
        dimensions.push("content".into());
    }

    let left_locations = locations(left)?;
    let right_locations = locations(right)?;
    if super::graph::canonical_string(&Value::Array(left_locations), "items", "locations")?
        != super::graph::canonical_string(&Value::Array(right_locations), "items", "locations")?
    {
        dimensions.push("location".into());
    }
    let left_properties = properties(left)?;
    let right_properties = properties(right)?;
    if super::graph::canonical_string(&Value::Array(left_properties), "items", "properties")?
        != super::graph::canonical_string(&Value::Array(right_properties), "items", "properties")?
    {
        dimensions.push("properties".into());
    }
    if relationships.different {
        dimensions.push("relationships".into());
    }

    Ok(dimensions)
}

fn locations(node: &ApplicationNode) -> Result<Vec<Value>, super::Failure> {
    let mut locations = node
        .observations
        .iter()
        .map(|observation| {
            let location = observation
                .evidence
                .get("location")
                .cloned()
                .unwrap_or(Value::Null);
            if location.get("available").and_then(Value::as_bool) == Some(true) {
                location.get("value").cloned().unwrap_or(Value::Null)
            } else {
                location
            }
        })
        .collect::<Vec<_>>();
    sort_values_by_canonical(&mut locations)?;
    Ok(locations)
}

fn properties(node: &ApplicationNode) -> Result<Vec<Value>, super::Failure> {
    let mut properties = node
        .observations
        .iter()
        .map(|observation| {
            json!({
                "label": observation.label,
                "properties": observation.properties,
                "source_map_reference": observation.source_map_reference,
            })
        })
        .collect::<Vec<_>>();
    sort_values_by_canonical(&mut properties)?;
    Ok(properties)
}

fn sort_values_by_canonical(values: &mut [Value]) -> Result<(), super::Failure> {
    let mut keyed = values
        .iter()
        .cloned()
        .map(|value| {
            super::graph::canonical_string(&value, "items", "comparison value")
                .map(|key| (key, value))
        })
        .collect::<Result<Vec<_>, _>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    for (target, (_, value)) in values.iter_mut().zip(keyed) {
        *target = value;
    }
    Ok(())
}

fn relationship_index(graph: &ApplicationGraph) -> RelationshipIndex {
    let kind_by_id = graph
        .nodes
        .iter()
        .map(|node| (node.node_id.clone(), node.kind.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut adjacency = BTreeMap::<String, Vec<Relationship>>::new();
    for edge in &graph.edges {
        add_relationship(
            &mut adjacency,
            &edge.source_node_id,
            Relationship {
                direction: "out",
                relation: edge.relation.clone(),
                neighbor_id: edge.target_node_id.clone(),
            },
        );
        if edge.target_node_id != edge.source_node_id {
            add_relationship(
                &mut adjacency,
                &edge.target_node_id,
                Relationship {
                    direction: "in",
                    relation: edge.relation.clone(),
                    neighbor_id: edge.source_node_id.clone(),
                },
            );
        }
    }
    RelationshipIndex {
        kind_by_id,
        adjacency,
    }
}

fn add_relationship(
    adjacency: &mut BTreeMap<String, Vec<Relationship>>,
    node_id: &str,
    relationship: Relationship,
) {
    adjacency
        .entry(node_id.to_owned())
        .or_default()
        .push(relationship);
}

fn compare_relationships(pair: &NodePair, context: &ItemContext<'_>) -> RelationshipComparison {
    let left_node = &context.left.nodes[pair.left];
    let right_node = &context.right.nodes[pair.right];
    let left = relationship_facts(left_node, true, context);
    let right = relationship_facts(right_node, false, context);
    RelationshipComparison {
        different: left.paired != right.paired || left.unpaired_shape != right.unpaired_shape,
        unresolved: left.unresolved || right.unresolved,
    }
}

#[derive(Clone, Debug)]
struct RelationshipFacts {
    paired: Vec<String>,
    unpaired_shape: Vec<String>,
    unresolved: bool,
}

fn relationship_facts(
    node: &ApplicationNode,
    is_left: bool,
    context: &ItemContext<'_>,
) -> RelationshipFacts {
    let (relationships, paired_by_id) = if is_left {
        (&context.left_relationships, &context.pair_by_left)
    } else {
        (&context.right_relationships, &context.pair_by_right)
    };
    let mut paired = Vec::new();
    let mut unpaired_shape = Vec::new();
    for relationship in relationships
        .adjacency
        .get(&node.node_id)
        .into_iter()
        .flatten()
    {
        if let Some(mapped) = paired_by_id.get(&relationship.neighbor_id) {
            paired.push(format!(
                "{}\0{}\0{}",
                relationship.direction, relationship.relation, mapped
            ));
        } else {
            let neighbor_kind = relationships
                .kind_by_id
                .get(&relationship.neighbor_id)
                .map(String::as_str)
                .unwrap_or("unknown");
            unpaired_shape.push(format!(
                "{}\0{}\0{}",
                relationship.direction, relationship.relation, neighbor_kind
            ));
        }
    }
    paired.sort();
    unpaired_shape.sort();
    RelationshipFacts {
        unresolved: !unpaired_shape.is_empty(),
        paired,
        unpaired_shape,
    }
}

fn item_evidence_links(
    left: Option<&ApplicationNode>,
    right: Option<&ApplicationNode>,
    context: &ItemContext<'_>,
) -> Vec<String> {
    let mut evidence_links = BTreeSet::from([
        context.left_evidence_id.to_owned(),
        context.right_evidence_id.to_owned(),
    ]);
    if let Some(left) = left {
        evidence_links.extend(native_links(left, &context.left_native_by_digest));
    }
    if let Some(right) = right {
        evidence_links.extend(native_links(right, &context.right_native_by_digest));
    }
    evidence_links.into_iter().collect()
}

fn native_evidence_by_digest(evidence: &[ApplicationEvidence]) -> BTreeMap<String, Vec<String>> {
    let mut by_digest = BTreeMap::<String, Vec<String>>::new();
    for observation in evidence {
        by_digest
            .entry(observation.subject_digest.clone())
            .or_default()
            .push(observation.evidence_id.clone());
    }
    by_digest
}

fn native_links(
    node: &ApplicationNode,
    evidence_by_digest: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    let Some(identity) = matching::content_identity(node) else {
        return Vec::new();
    };
    let digest = identity.strip_prefix("content:").unwrap_or(&identity);
    evidence_by_digest.get(digest).cloned().unwrap_or_default()
}

fn match_limitations(basis: MatchBasis) -> Vec<String> {
    match basis {
        MatchBasis::StructuralFingerprint => vec![
            "Structural fingerprint equality is rename-resistant inference; it is not byte identity or proof of semantic equivalence.".into(),
        ],
        MatchBasis::SourceMapIdentity => vec![
            "Source-map original names identify a candidate source lineage; changed or unavailable source content remains explicit.".into(),
        ],
        MatchBasis::SemanticKey => vec![
            "Semantic-key pairing is a deterministic inference and is never promoted to exact identity.".into(),
        ],
        _ => Vec::new(),
    }
}

fn absence_claimable(coverage: &super::graph::GraphCoverage) -> bool {
    coverage.status == "complete" && !coverage.truncated && coverage.omitted_count == Some(0)
}

fn graphs_complete(left: &ApplicationGraph, right: &ApplicationGraph) -> bool {
    absence_claimable(&left.coverage) && absence_claimable(&right.coverage)
}
