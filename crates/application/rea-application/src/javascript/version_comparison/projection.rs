//! Deterministic comparison result projection.

use super::{
    VersionSource, change_graph,
    graph::ApplicationEvidence,
    items::{self, ClassifiedItem},
    matching,
};
use rea_core::canonical_json;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) fn compare_versions(
    left: &VersionSource,
    right: &VersionSource,
    left_native: &[ApplicationEvidence],
    right_native: &[ApplicationEvidence],
) -> Result<Value, super::Failure> {
    let matching = matching::match_versions(&left.graph, &right.graph)?;
    let items = items::classify(
        &left.graph,
        &right.graph,
        &left.evidence_id,
        &right.evidence_id,
        left_native,
        right_native,
        &matching,
    )?;
    let graph = change_graph::build(
        &left.graph,
        &right.graph,
        &left.evidence_id,
        &right.evidence_id,
        &items,
    )?;
    let evidence_links = sorted_unique(
        items
            .iter()
            .flat_map(|item| item.evidence_links.iter().cloned()),
    );
    let coverage_status =
        if left.graph.coverage.status == "complete" && right.graph.coverage.status == "complete" {
            "complete-within-inputs"
        } else if left.graph.coverage.truncated || right.graph.coverage.truncated {
            "truncated"
        } else {
            "partial"
        };
    let mut limitations = vec![
        "Application comparison never uses bundler module ordinals as persistent identity and performs no fuzzy pairing.".to_owned(),
        "Exact digest equality proves byte identity only; source-map, structural-fingerprint, and semantic-key matches retain inferred confidence.".to_owned(),
        "Minified names and chunk locations are not assumed stable across versions.".to_owned(),
        "The comparison reads retained graphs and Evidence only; it does not execute either application.".to_owned(),
        "Native Evidence is linked only by exact subject digest; provider snapshot reuse remains target/provider/profile exact.".to_owned(),
    ];
    if left.graph.coverage.status != "complete" || right.graph.coverage.status != "complete" {
        limitations.push("At least one source graph is incomplete; unmatched entities on the opposite side remain unknown rather than added or removed.".to_owned());
    }
    limitations = sorted_unique(limitations);

    let semantic = json!({
        "left": {"evidence_id": left.evidence_id, "graph_id": left.graph.graph_id, "root_artifact_sha256": left.root_artifact_sha256},
        "right": {"evidence_id": right.evidence_id, "graph_id": right.graph.graph_id, "root_artifact_sha256": right.root_artifact_sha256},
        "summary": summary(&items),
        "matching": matching_summary(&items),
        "items": items.iter().map(|item| item.raw.clone()).collect::<Vec<_>>(),
        "graph": graph,
        "coverage": {
            "left_graph_status": left.graph.coverage.status,
            "right_graph_status": right.graph.coverage.status,
            "left_graph_omitted_count": left.graph.coverage.omitted_count,
            "right_graph_omitted_count": right.graph.coverage.omitted_count,
            "status": coverage_status,
        },
        "evidence_links": evidence_links,
        "limitations": limitations,
    });
    let comparison_id = format!(
        "javc_{}",
        canonical_json::digest(&semantic).map_err(|error| {
            super::graph::invalid(
                "result",
                &format!("Could not authenticate comparison: {error}"),
            )
        })?
    );
    let mut result = semantic;
    result["comparison_id"] = json!(comparison_id);
    Ok(result)
}

fn summary(items: &[ClassifiedItem]) -> Value {
    let mut counts = BTreeMap::from([
        ("unchanged", 0_u64),
        ("added", 0),
        ("removed", 0),
        ("changed", 0),
        ("unknown", 0),
    ]);
    for item in items {
        if let Some(count) = counts.get_mut(item.status.as_str()) {
            *count += 1;
        }
    }
    json!(counts)
}

fn matching_summary(items: &[ClassifiedItem]) -> Value {
    let mut counts = BTreeMap::from([
        ("exact_node_identity", 0_u64),
        ("exact_content_digest", 0),
        ("exact_module_source_digest", 0),
        ("source_map_identity", 0),
        ("structural_fingerprint", 0),
        ("semantic_key", 0),
        ("ambiguous", 0),
        ("unmatched", 0),
    ]);
    for item in items {
        let key = match item.match_status.as_str() {
            "ambiguous" => Some("ambiguous"),
            "unmatched" => Some("unmatched"),
            _ => match item.match_basis.as_str() {
                "exact-node-identity" => Some("exact_node_identity"),
                "exact-content-digest" => Some("exact_content_digest"),
                "exact-module-source-digest" => Some("exact_module_source_digest"),
                "source-map-identity" => Some("source_map_identity"),
                "structural-fingerprint" => Some("structural_fingerprint"),
                "semantic-key" => Some("semantic_key"),
                _ => None,
            },
        };
        if let Some(key) = key {
            if let Some(count) = counts.get_mut(key) {
                *count += 1;
            }
        }
    }
    json!(counts)
}

fn sorted_unique(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}
