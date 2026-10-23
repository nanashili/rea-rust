//! `reconcileRuntimeEntities` (`javascriptRuntimeReconciliationMatching.ts`).
use super::candidates::{Candidate, MappedPath, mapped_runtime_paths};
use super::captures::Capture;
use super::layers::Layer;
use super::runtime::{Entity, LocationKind};
use super::{Defect, digest, jag};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

pub struct MatchingProjection {
    pub items: Vec<Value>,
    pub edges: Vec<Value>,
}

struct Index {
    by_category_digest: HashMap<String, Vec<usize>>,
    by_layer_category_path: HashMap<String, Vec<usize>>,
    by_native_declaration_path: HashMap<String, Vec<(usize, Option<String>)>>,
}

fn category_digest_key(category: &str, digest: &str) -> String {
    format!("{category}\0{digest}")
}

fn layer_category_path_key(layer_id: &str, category: &str, path: &str) -> String {
    format!("{layer_id}\0{category}\0{path}")
}

fn index_candidates(candidates: &[Candidate<'_>]) -> Index {
    let mut index = Index {
        by_category_digest: HashMap::new(),
        by_layer_category_path: HashMap::new(),
        by_native_declaration_path: HashMap::new(),
    };
    for (position, candidate) in candidates.iter().enumerate() {
        for (sha256, _) in &candidate.digests {
            index
                .by_category_digest
                .entry(category_digest_key(candidate.category, sha256))
                .or_default()
                .push(position);
        }
        for path in &candidate.paths {
            index
                .by_layer_category_path
                .entry(layer_category_path_key(
                    candidate.layer_id,
                    candidate.category,
                    path,
                ))
                .or_default()
                .push(position);
        }
        for (style, declarations) in ["posix", "windows"]
            .iter()
            .zip(&candidate.native_declaration_paths)
        {
            for (path, source) in declarations {
                index
                    .by_native_declaration_path
                    .entry(format!(
                        "{style}\0{}",
                        layer_category_path_key(candidate.layer_id, candidate.category, path)
                    ))
                    .or_default()
                    .push((position, source.clone()));
            }
        }
    }
    index
}

struct Context<'a> {
    candidates: &'a [Candidate<'a>],
    layers: &'a [Layer],
    captures: &'a [Capture],
    index: Index,
}

struct Located {
    candidate: usize,
    mapping: MappedPath,
}

struct Unresolved {
    status: &'static str,
    basis: &'static str,
    confidence: &'static str,
    reason: &'static str,
    candidates: Vec<usize>,
}

pub fn reconcile_runtime_entities(
    entities: &[Entity],
    candidates: &[Candidate<'_>],
    layers: &[Layer],
    captures: &[Capture],
) -> Result<MatchingProjection, Defect> {
    let context = Context {
        candidates,
        layers,
        captures,
        index: index_candidates(candidates),
    };
    let mut evaluated = entities
        .iter()
        .map(|entity| reconcile_entity(&context, entity))
        .collect::<Result<Vec<_>, _>>()?;
    evaluated.sort_by(|left, right| {
        left.0["reconciliation_id"]
            .as_str()
            .unwrap_or_default()
            .cmp(right.0["reconciliation_id"].as_str().unwrap_or_default())
    });
    let edges = evaluated
        .iter()
        .filter_map(|(_, edge)| edge.clone())
        .collect();
    Ok(MatchingProjection {
        items: evaluated.into_iter().map(|(item, _)| item).collect(),
        edges,
    })
}

type Evaluated = (Value, Option<Value>);

fn reconcile_entity(context: &Context<'_>, entity: &Entity) -> Result<Evaluated, Defect> {
    if entity.location.0 == LocationKind::Unresolved {
        return unresolved(
            context,
            entity,
            Unresolved {
                status: "unknown",
                basis: "none",
                confidence: "unknown",
                reason: "runtime-location-unresolved",
                candidates: Vec::new(),
            },
        );
    }
    let locations = candidates_with_location(context, entity);
    if let Some(source) = &entity.source_sha256 {
        return reconcile_captured_source(context, entity, source, &locations);
    }
    if locations.len() == 1 {
        let located = &locations[0];
        return matched(
            context,
            entity,
            located.candidate,
            located.mapping.basis,
            "medium",
            "unique-location-match",
        );
    }
    if locations.len() > 1 {
        return unresolved(
            context,
            entity,
            Unresolved {
                status: "ambiguous",
                basis: strongest_location_basis(&locations),
                confidence: "unknown",
                reason: "ambiguous-static-candidates",
                candidates: locations.iter().map(|located| located.candidate).collect(),
            },
        );
    }
    let mapped = context
        .layers
        .iter()
        .any(|layer| !mapped_runtime_paths(layer, entity).is_empty());
    unresolved(
        context,
        entity,
        Unresolved {
            status: if mapped { "unmatched" } else { "unknown" },
            basis: "none",
            confidence: "unknown",
            reason: if mapped {
                "no-static-content-match"
            } else {
                "no-authorized-location-mapping"
            },
            candidates: Vec::new(),
        },
    )
}

fn reconcile_captured_source(
    context: &Context<'_>,
    entity: &Entity,
    source: &str,
    locations: &[Located],
) -> Result<Evaluated, Defect> {
    let content: Vec<usize> = if locations.is_empty() {
        context
            .index
            .by_category_digest
            .get(&category_digest_key(entity.static_kind, source))
            .cloned()
            .unwrap_or_default()
    } else {
        locations
            .iter()
            .map(|located| located.candidate)
            .filter(|candidate| {
                context.candidates[*candidate]
                    .digests
                    .iter()
                    .any(|(sha256, _)| sha256 == source)
            })
            .collect()
    };
    if content.len() == 1 {
        let candidate = content[0];
        let basis = if locations.is_empty() {
            context.candidates[candidate]
                .digests
                .iter()
                .find(|(sha256, _)| sha256 == source)
                .map_or("content-sha256", |(_, basis)| *basis)
        } else {
            "content-and-location"
        };
        let reason = if locations.is_empty() {
            "unique-content-match"
        } else {
            "content-and-location-match"
        };
        return matched(context, entity, candidate, basis, "high", reason);
    }
    if content.len() > 1 {
        return unresolved(
            context,
            entity,
            Unresolved {
                status: "ambiguous",
                basis: if locations.is_empty() {
                    "none"
                } else {
                    "content-and-location"
                },
                confidence: "unknown",
                reason: "ambiguous-static-candidates",
                candidates: content,
            },
        );
    }
    if !locations.is_empty() {
        let digest_unavailable = locations
            .iter()
            .any(|located| context.candidates[located.candidate].digests.is_empty());
        return unresolved(
            context,
            entity,
            Unresolved {
                status: if digest_unavailable {
                    "unknown"
                } else {
                    "unmatched"
                },
                basis: strongest_location_basis(locations),
                confidence: if digest_unavailable {
                    "unknown"
                } else {
                    "high"
                },
                reason: if digest_unavailable {
                    "static-or-runtime-coverage-incomplete"
                } else {
                    "captured-content-disagrees-with-static-location"
                },
                candidates: locations.iter().map(|located| located.candidate).collect(),
            },
        );
    }
    unresolved(
        context,
        entity,
        Unresolved {
            status: "unmatched",
            basis: "none",
            confidence: "high",
            reason: "no-static-content-match",
            candidates: Vec::new(),
        },
    )
}

fn candidates_with_location(context: &Context<'_>, entity: &Entity) -> Vec<Located> {
    let mut located: Vec<(String, Located)> = Vec::new();
    for layer in context.layers {
        for mapping in mapped_runtime_paths(layer, entity) {
            let mut found: Vec<usize> = context
                .index
                .by_layer_category_path
                .get(&layer_category_path_key(
                    &layer.layer_id,
                    entity.static_kind,
                    &mapping.path,
                ))
                .cloned()
                .unwrap_or_default();
            if let (Some(style), Some(native)) = (mapping.file_style, &mapping.native_relative_path)
            {
                let key = format!(
                    "{style}\0{}",
                    layer_category_path_key(&layer.layer_id, entity.static_kind, native)
                );
                found.extend(
                    context
                        .index
                        .by_native_declaration_path
                        .get(&key)
                        .into_iter()
                        .flatten()
                        .filter(|(_, source)| {
                            mapping.artifact_prefix.is_empty()
                                || source.as_deref().is_some_and(|source| {
                                    source.starts_with(&format!("{}/", mapping.artifact_prefix))
                                })
                        })
                        .map(|(candidate, _)| *candidate),
                );
            }
            for candidate in found {
                let key = context.candidates[candidate].key();
                if !located.iter().any(|(existing, _)| *existing == key) {
                    located.push((
                        key,
                        Located {
                            candidate,
                            mapping: mapping.clone(),
                        },
                    ));
                }
            }
        }
    }
    located.sort_by(|left, right| left.0.cmp(&right.0));
    located.into_iter().map(|(_, value)| value).collect()
}

fn strongest_location_basis(values: &[Located]) -> &'static str {
    let has = |basis: &str| values.iter().any(|located| located.mapping.basis == basis);
    if has("artifact-path") {
        "artifact-path"
    } else if has("operator-file-mapping") {
        "operator-file-mapping"
    } else {
        "operator-url-mapping"
    }
}

fn unique_candidate_references(context: &Context<'_>, candidates: &[usize]) -> Vec<Value> {
    let mut seen = HashSet::new();
    let mut items = Vec::new();
    for candidate in candidates {
        let candidate = &context.candidates[*candidate];
        if !seen.insert(candidate.key()) {
            continue;
        }
        items.push(json!({
            "static_layer_id": candidate.layer_id,
            "static_node_id": candidate.node_id(),
        }));
    }
    items
}

/// `createItem`.
#[allow(clippy::too_many_arguments)]
fn create_item(
    context: &Context<'_>,
    entity: &Entity,
    matched: Option<usize>,
    status: &str,
    basis: &str,
    confidence: &str,
    reason: &str,
    candidates: &[usize],
) -> Result<Value, Defect> {
    let references = unique_candidate_references(context, candidates);
    let (layer_id, node_id) = match matched {
        Some(candidate) => {
            let candidate = &context.candidates[candidate];
            (json!(candidate.layer_id), json!(candidate.node_id()))
        }
        None => (Value::Null, Value::Null),
    };
    let mut semantic = json!({
        "entity_kind": entity.kind,
        "runtime_evidence_id": context.captures[entity.capture].evidence_id(),
        "runtime_node_id": entity.node_id(),
        "static_layer_id": layer_id,
        "static_node_id": node_id,
        "status": status,
        "basis": basis,
        "confidence": confidence,
        "reason": reason,
        "candidate_static_count": references.len(),
        "candidate_static_nodes": references,
    });
    let id = format!("jrr_item_{}", digest(&semantic)?);
    let mut item = serde_json::Map::new();
    item.insert("reconciliation_id".into(), json!(id));
    item.extend(
        semantic
            .as_object_mut()
            .map(std::mem::take)
            .unwrap_or_default(),
    );
    Ok(Value::Object(item))
}

fn matched(
    context: &Context<'_>,
    entity: &Entity,
    candidate: usize,
    basis: &'static str,
    confidence: &'static str,
    reason: &'static str,
) -> Result<Evaluated, Defect> {
    let item = create_item(
        context,
        entity,
        Some(candidate),
        "matched",
        basis,
        confidence,
        reason,
        &[candidate],
    )?;
    let static_candidate = &context.candidates[candidate];
    let layer = &context.layers[static_candidate.layer];
    let edge = jag::create_edge(
        static_candidate.node_id(),
        entity.node_id(),
        "observed_as",
        json!({
            "reconciliation_id": item["reconciliation_id"],
            "basis": basis,
            "static_layer_id": layer.layer_id,
        }),
        &reconciliation_evidence(context, entity, layer, basis, confidence)?,
    )?;
    Ok((item, Some(edge)))
}

fn unresolved(
    context: &Context<'_>,
    entity: &Entity,
    input: Unresolved,
) -> Result<Evaluated, Defect> {
    let item = create_item(
        context,
        entity,
        None,
        input.status,
        input.basis,
        input.confidence,
        input.reason,
        &input.candidates,
    )?;
    Ok((item, None))
}

fn reconciliation_evidence(
    context: &Context<'_>,
    entity: &Entity,
    layer: &Layer,
    basis: &str,
    confidence: &str,
) -> Result<Value, Defect> {
    let observation = entity.node["observations"].get(0).ok_or(Defect)?;
    let capture = &context.captures[entity.capture];
    let artifact = match &entity.source_sha256 {
        Some(sha256) => json!({
            "available": true,
            "artifact_id": format!("art_{sha256}"),
            "sha256": sha256,
        }),
        None => json!({
            "available": false,
            "reason": "not-observed",
            "detail": "Runtime source bytes were not captured for this mapping.",
        }),
    };
    let coverage = if layer.graph()["coverage"]["status"] == "complete"
        && capture.scripts_complete_within_scope
    {
        json!({ "status": "complete", "truncated": false, "omitted_count": 0, "limits": [] })
    } else {
        json!({ "status": "partial", "truncated": false, "omitted_count": null, "limits": [] })
    };
    let first = if matches!(
        basis,
        "content-sha256" | "module-source-sha256" | "content-and-location"
    ) {
        "Equal content digests establish byte identity, not execution causality."
    } else {
        "Location correspondence is inferred from an artifact root or caller-declared mapping."
    };
    let mut ids = [
        layer.evidence_id().to_owned(),
        capture.evidence_id().to_owned(),
    ];
    ids.sort();
    Ok(json!({
        "authority": "cross-layer-reconciliation",
        "state": "inferred",
        "confidence": if confidence == "medium" { "medium" } else { "high" },
        "artifact": artifact,
        "location": observation["evidence"]["location"],
        "extractor": {
            "name": "rea-javascript-runtime-reconciliation",
            "version": "1",
            "operation": "reconcile_javascript_runtime",
            "executable_sha256": null,
        },
        "coverage": coverage,
        "limitations": [
            first,
            "Passive script parsing or target presence does not prove feature execution.",
        ],
        "evidence_ids": ids,
    }))
}
