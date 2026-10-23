//! Passive web-capture comparison and scenario-comparison dispatch.
//!
//! Compatibility owners: `src/domain/browserCaptureComparison.ts`,
//! `src/domain/webCaptureDiff.ts`, `src/domain/webCaptureDiffSchemas.ts`,
//! `src/domain/webCaptureFrameComparison.ts`, `src/application/BrowserEvidence.ts`.
//!
//! The passive branch compares two normalized `inspect_web_page` observations
//! without treating incomplete absence as proof. All structural reads operate
//! on the validated JSON so the port tracks the TS field access exactly.
use super::digest::{compare_unicode_code_points, composite_key, digest_canonical_value};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

const OPERATION: &str = "compare_web_captures";

/// Dispatch a validated comparison input and return
/// `(normalized_result, parameters, limitations)` for Evidence assembly.
pub(super) fn compare(input: &Value) -> Result<(Value, Value, Vec<String>), AnalysisError> {
    if input.get("before_scenario").is_some() || input.get("after_scenario").is_some() {
        return super::scenario::compare(input);
    }
    let before = input
        .get("before")
        .and_then(|snapshot| snapshot.get("inspection"))
        .cloned()
        .unwrap_or(Value::Null);
    let after = input
        .get("after")
        .and_then(|snapshot| snapshot.get("inspection"))
        .cloned()
        .unwrap_or(Value::Null);
    let before_webmcp = input
        .get("before")
        .and_then(|snapshot| snapshot.get("webmcp"))
        .cloned()
        .unwrap_or(Value::Null);
    let after_webmcp = input
        .get("after")
        .and_then(|snapshot| snapshot.get("webmcp"))
        .cloned()
        .unwrap_or(Value::Null);

    let result = compare_web_captures(&before, &after, &before_webmcp, &after_webmcp);

    let parameters = json!({
        "before_target_id": target_field(&before, "target_id"),
        "before_capture_ended_at": capture_window(&before, "ended_at"),
        "after_target_id": target_field(&after, "target_id"),
        "after_capture_ended_at": capture_window(&after, "ended_at"),
    });
    let limitations = super::string_array(&result, "limitations");
    Ok((result, parameters, limitations))
}

fn target_field(inspection: &Value, key: &str) -> Value {
    inspection
        .get("target")
        .and_then(|target| target.get(key))
        .cloned()
        .unwrap_or(Value::Null)
}

fn capture_window(inspection: &Value, key: &str) -> Value {
    inspection
        .get("capture_window")
        .and_then(|window| window.get(key))
        .cloned()
        .unwrap_or(Value::Null)
}

const LIMITATIONS: [&str; 4] = [
    "A changed status proves an observed difference; an unknown status means absence could not be established from capture completeness.",
    "Network comparison covers only activity observed after each CDP attachment. WebSocket connections with the same URL are compared as an unordered collection of ordered frame streams, retaining connection counts; their individual identities are not stable across captures.",
    "Accessibility roles, ignored state, text, and hierarchy are compared only when the accessibility tree was fully captured and text capture was selected and not truncated.",
    "Storage key inventories are compared only when selected and complete; usage and quota are compared only when reported. Redacted content is compared through complete SHA-256 fingerprints.",
];

/// A comparison dimension result.
pub(crate) struct Dimension {
    pub(crate) status: &'static str,
    pub(crate) changes: Vec<Change>,
    pub(crate) reason: Option<String>,
}

#[derive(Clone)]
pub(crate) struct Change {
    pub(crate) identity: String,
    pub(crate) change: &'static str,
}

impl Dimension {
    fn to_value(&self) -> Value {
        json!({
            "status": self.status,
            "total_changes": self.changes.len(),
            "changes": self.changes.iter().map(|change| json!({
                "identity": change.identity,
                "change": change.change,
            })).collect::<Vec<_>>(),
            "reason": self.reason.clone().map_or(Value::Null, Value::String),
        })
    }
}

fn compare_web_captures(
    before: &Value,
    after: &Value,
    before_webmcp: &Value,
    after_webmcp: &Value,
) -> Value {
    let dimensions = compare_dimensions(before, after, before_webmcp, after_webmcp);
    let statuses: Vec<&'static str> = dimensions.iter().map(|(_, dim)| dim.status).collect();
    let overall_status = if statuses.contains(&"changed") {
        "changed"
    } else if statuses.contains(&"unknown") {
        "unknown"
    } else {
        "unchanged"
    };
    let mut dims = Map::new();
    for (name, dim) in &dimensions {
        dims.insert((*name).to_owned(), dim.to_value());
    }
    json!({
        "overall_status": overall_status,
        "before_target": {
            "target_id": target_field(before, "target_id"),
            "url": target_field(before, "url"),
        },
        "after_target": {
            "target_id": target_field(after, "target_id"),
            "url": target_field(after, "url"),
        },
        "dimensions": Value::Object(dims),
        "limitations": LIMITATIONS.iter().map(|text| json!(text)).collect::<Vec<_>>(),
    })
}

fn compare_dimensions(
    before: &Value,
    after: &Value,
    before_webmcp: &Value,
    after_webmcp: &Value,
) -> Vec<(&'static str, Dimension)> {
    vec![
        ("dom_structure", dom_dimension(before, after)),
        (
            "scripts",
            compare_dimension(
                keyed(&scripts_projected(before), |item| {
                    item.get("script_key")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                }),
                keyed(&scripts_projected(after), |item| {
                    item.get("script_key")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                }),
                sections_complete(before, &["scripts"]) && sections_complete(after, &["scripts"]),
                "Script inventory was incomplete in at least one observation.",
                InventoryComplete::Bool(
                    sections_complete(before, &["scripts"])
                        && sections_complete(after, &["scripts"]),
                ),
            ),
        ),
        (
            "resources",
            compare_dimension(
                keyed(&array(before, "resources"), |item| {
                    item.get("resource_key")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                }),
                keyed(&array(after, "resources"), |item| {
                    item.get("resource_key")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                }),
                sections_complete(before, &["resources"])
                    && sections_complete(after, &["resources"]),
                "Resource inventory was incomplete in at least one observation.",
                InventoryComplete::Bool(
                    sections_complete(before, &["resources"])
                        && sections_complete(after, &["resources"]),
                ),
            ),
        ),
        ("network", network_dimension(before, after)),
        (
            "metadata",
            compare_aggregate(
                "metadata",
                &metadata_projection(before),
                &metadata_projection(after),
                sections_complete(before, &["metadata"]) && sections_complete(after, &["metadata"]),
                "Safe metadata capture was incomplete in at least one observation.",
            ),
        ),
        ("webmcp", webmcp_dimension(before_webmcp, after_webmcp)),
        ("accessibility", accessibility_dimension(before, after)),
        ("storage", storage_dimension(before, after)),
    ]
}

/// `inventoryComplete` is either a flat flag or a per-identity predicate.
enum InventoryComplete {
    Bool(bool),
    PerIdentity(Box<dyn Fn(&str) -> bool>),
}

fn keyed<F>(values: &[Value], identity: F) -> BTreeMap<String, String>
where
    F: Fn(&Value) -> String,
{
    let mut map = BTreeMap::new();
    for value in values {
        map.insert(identity(value), digest_canonical_value(value));
    }
    map
}

fn compare_identities(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> Vec<Change> {
    let mut changes: Vec<Change> = Vec::new();
    for (identity, fingerprint) in before {
        match after.get(identity) {
            None => changes.push(Change {
                identity: identity.clone(),
                change: "removed",
            }),
            Some(next) if next != fingerprint => changes.push(Change {
                identity: identity.clone(),
                change: "modified",
            }),
            _ => {}
        }
    }
    for identity in after.keys() {
        if !before.contains_key(identity) {
            changes.push(Change {
                identity: identity.clone(),
                change: "added",
            });
        }
    }
    changes.sort_by(|left, right| {
        compare_unicode_code_points(&left.identity, &right.identity)
            .then_with(|| compare_unicode_code_points(left.change, right.change))
    });
    changes
}

fn compare_dimension(
    before: BTreeMap<String, String>,
    after: BTreeMap<String, String>,
    complete: bool,
    reason: &str,
    inventory_complete: InventoryComplete,
) -> Dimension {
    let all: Vec<Change> = compare_identities(&before, &after)
        .into_iter()
        .filter(|change| {
            change.change == "modified"
                || match &inventory_complete {
                    InventoryComplete::Bool(flag) => *flag,
                    InventoryComplete::PerIdentity(predicate) => predicate(&change.identity),
                }
        })
        .collect();
    if !all.is_empty() {
        return Dimension {
            status: "changed",
            changes: all,
            reason: None,
        };
    }
    if complete {
        Dimension {
            status: "unchanged",
            changes: Vec::new(),
            reason: None,
        }
    } else {
        Dimension {
            status: "unknown",
            changes: Vec::new(),
            reason: Some(reason.to_owned()),
        }
    }
}

fn compare_dimension_default(
    before: BTreeMap<String, String>,
    after: BTreeMap<String, String>,
    complete: bool,
    reason: &str,
) -> Dimension {
    compare_dimension(
        before,
        after,
        complete,
        reason,
        InventoryComplete::Bool(complete),
    )
}

fn singleton(key: &str, value: String) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert(key.to_owned(), value);
    map
}

fn array(inspection: &Value, section: &str) -> Vec<Value> {
    inspection
        .get(section)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

// ---- DOM ------------------------------------------------------------------

fn dom_dimension(before: &Value, after: &Value) -> Dimension {
    let before_frames = fingerprint_frames(before.get("frames"));
    let after_frames = fingerprint_frames(after.get("frames"));
    let nodes_complete = [before, after].iter().all(|inspection| {
        sections_complete(inspection, &["dom"])
            && inspection
                .get("dom")
                .and_then(|dom| dom.get("total_nodes"))
                .and_then(Value::as_u64)
                == inspection
                    .get("dom")
                    .and_then(|dom| dom.get("nodes"))
                    .and_then(Value::as_array)
                    .map(|nodes| nodes.len() as u64)
    });
    let frames_complete = before_frames.is_some()
        && after_frames.is_some()
        && [before, after]
            .iter()
            .all(|inspection| sections_complete(inspection, &["frames"]));
    let mut changes: Vec<Change> = Vec::new();
    if nodes_complete {
        let before_nodes = before.get("dom").and_then(|dom| dom.get("nodes"));
        let after_nodes = after.get("dom").and_then(|dom| dom.get("nodes"));
        if digest_optional(before_nodes) != digest_optional(after_nodes) {
            changes.push(Change {
                identity: "document".to_owned(),
                change: "modified",
            });
        }
    }
    if frames_complete && before_frames != after_frames {
        changes.push(Change {
            identity: "frames".to_owned(),
            change: "modified",
        });
    }
    if !changes.is_empty() {
        return Dimension {
            status: "changed",
            changes,
            reason: None,
        };
    }
    if nodes_complete && frames_complete {
        Dimension {
            status: "unchanged",
            changes: Vec::new(),
            reason: None,
        }
    } else {
        Dimension {
            status: "unknown",
            changes: Vec::new(),
            reason: Some(
                "DOM or frame capture was incomplete, or frame ancestry was unresolved in at least one observation."
                    .to_owned(),
            ),
        }
    }
}

fn digest_optional(value: Option<&Value>) -> String {
    digest_canonical_value(value.unwrap_or(&Value::Null))
}

/// `fingerprintWebCaptureFrames` — compare frame forests without local IDs.
fn fingerprint_frames(frames: Option<&Value>) -> Option<String> {
    let frames = frames.and_then(Value::as_array)?;
    let mut by_id: BTreeMap<String, &Value> = BTreeMap::new();
    for frame in frames {
        let id = frame.get("frame_id").and_then(Value::as_str)?.to_owned();
        by_id.insert(id, frame);
    }
    if by_id.len() != frames.len() {
        return None;
    }
    let mut remaining: BTreeMap<String, i64> = frames
        .iter()
        .filter_map(|frame| {
            frame
                .get("frame_id")
                .and_then(Value::as_str)
                .map(|id| (id.to_owned(), 0i64))
        })
        .collect();
    for frame in frames {
        let parent = frame.get("parent_frame_id");
        if parent.map(Value::is_null).unwrap_or(true) {
            continue;
        }
        let parent_id = parent.and_then(Value::as_str)?;
        let count = remaining.get(parent_id).copied();
        match count {
            None => return None,
            Some(count) => {
                remaining.insert(parent_id.to_owned(), count + 1);
            }
        }
    }
    // Ready queue: frames with no remaining children (leaf-first).
    let mut ready: Vec<&Value> = frames
        .iter()
        .filter(|frame| {
            frame
                .get("frame_id")
                .and_then(Value::as_str)
                .and_then(|id| remaining.get(id))
                == Some(&0)
        })
        .collect();
    let mut children: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut roots: Vec<String> = Vec::new();
    let mut examined = 0usize;
    let mut index = 0usize;
    while index < ready.len() {
        let frame = ready[index];
        index += 1;
        let frame_id = frame.get("frame_id").and_then(Value::as_str)?.to_owned();
        let mut child_list = children.get(&frame_id).cloned().unwrap_or_default();
        child_list.sort();
        let fingerprint = digest_canonical_value(&json!({
            "url": frame.get("url").cloned().unwrap_or(Value::Null),
            "origin": frame.get("origin").cloned().unwrap_or(Value::Null),
            "children": child_list,
        }));
        examined += 1;
        let parent = frame.get("parent_frame_id");
        if parent.map(Value::is_null).unwrap_or(true) {
            roots.push(fingerprint);
            continue;
        }
        let parent_id = parent.and_then(Value::as_str)?.to_owned();
        children
            .entry(parent_id.clone())
            .or_default()
            .push(fingerprint);
        let count = remaining.get(&parent_id).copied().unwrap_or(0) - 1;
        remaining.insert(parent_id.clone(), count);
        if count == 0 {
            let parent_frame = *by_id.get(&parent_id)?;
            ready.push(parent_frame);
        }
    }
    if examined == frames.len() {
        roots.sort();
        Some(digest_canonical_value(&json!(roots)))
    } else {
        None
    }
}

// ---- scripts / metadata projections --------------------------------------

fn scripts_projected(inspection: &Value) -> Vec<Value> {
    inspection
        .get("scripts")
        .and_then(|scripts| scripts.get("items"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|script| {
                    json!({
                        "script_key": script.get("script_key").cloned().unwrap_or(Value::Null),
                        "url": script.get("url").cloned().unwrap_or(Value::Null),
                        "cdp_hash": script.get("cdp_hash").cloned().unwrap_or(Value::Null),
                        "length": script.get("length").cloned().unwrap_or(Value::Null),
                        "is_module": script.get("is_module").cloned().unwrap_or(Value::Null),
                        "language": script.get("language").cloned().unwrap_or(Value::Null),
                        "source_map_url": script.get("source_map_url").cloned().unwrap_or(Value::Null),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn metadata_projection(inspection: &Value) -> Value {
    let metadata = inspection.get("metadata").cloned().unwrap_or(Value::Null);
    let responses: Vec<String> = metadata
        .get("responses")
        .and_then(Value::as_array)
        .map(|items| {
            let mut digests: Vec<String> = items
                .iter()
                .map(|response| {
                    let mut object = response.as_object().cloned().unwrap_or_default();
                    object.remove("request_id");
                    digest_canonical_value(&Value::Object(object))
                })
                .collect();
            digests.sort();
            digests
        })
        .unwrap_or_default();
    let dom_urls = sorted_digests(metadata.get("dom_urls"));
    let agent_hints = sorted_digests(metadata.get("agent_hints"));
    json!({
        "responses": responses,
        "dom_urls": dom_urls,
        "agent_hints": agent_hints,
        "excluded_dom_urls": metadata.get("excluded_dom_urls").cloned().unwrap_or(Value::Null),
        "headers_allowlisted": metadata.get("headers_allowlisted").cloned().unwrap_or(Value::Null),
    })
}

fn sorted_digests(value: Option<&Value>) -> Vec<String> {
    let mut digests: Vec<String> = value
        .and_then(Value::as_array)
        .map(|items| items.iter().map(digest_canonical_value).collect())
        .unwrap_or_default();
    digests.sort();
    digests
}

// ---- metadata aggregate ---------------------------------------------------

fn compare_aggregate(
    identity: &str,
    before: &Value,
    after: &Value,
    complete: bool,
    reason: &str,
) -> Dimension {
    let before_map = if complete {
        singleton(identity, digest_canonical_value(before))
    } else {
        BTreeMap::new()
    };
    let after_map = if complete {
        singleton(identity, digest_canonical_value(after))
    } else {
        BTreeMap::new()
    };
    compare_dimension_default(before_map, after_map, complete, reason)
}

// ---- completeness ---------------------------------------------------------

fn incomplete_sections(completeness: &Value) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for key in [
        "policy_filtered_sections",
        "attach_limited_sections",
        "truncated_sections",
        "unavailable_sections",
    ] {
        if let Some(sections) = completeness.get(key).and_then(Value::as_array) {
            for section in sections {
                if let Some(name) = section.as_str() {
                    set.insert(name.to_owned());
                }
            }
        }
    }
    set
}

fn sections_complete(inspection: &Value, sections: &[&str]) -> bool {
    let completeness = inspection
        .get("completeness")
        .cloned()
        .unwrap_or(Value::Null);
    let incomplete = incomplete_sections(&completeness);
    sections
        .iter()
        .all(|section| !incomplete.contains(*section))
}

// ---- accessibility --------------------------------------------------------

struct AccessComparable {
    text: bool,
    nodes: bool,
    complete: bool,
}

fn accessibility_comparable(inspection: &Value) -> AccessComparable {
    let accessibility = inspection
        .get("accessibility")
        .cloned()
        .unwrap_or(Value::Null);
    let text_capture = accessibility
        .get("text_capture")
        .cloned()
        .unwrap_or(Value::Null);
    let text = text_capture.get("status").and_then(Value::as_str) == Some("included")
        && text_capture.get("excluded_fields").and_then(Value::as_u64) == Some(0);
    let completeness = inspection
        .get("completeness")
        .cloned()
        .unwrap_or(Value::Null);
    let exclusions: Vec<&Value> = completeness
        .get("excluded")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|item| item.get("section").and_then(Value::as_str) == Some("accessibility"))
                .collect()
        })
        .unwrap_or_default();
    let text_only_policy_filter = text_capture.get("status").and_then(Value::as_str)
        == Some("not_approved")
        && !exclusions.is_empty()
        && exclusions
            .iter()
            .all(|item| item.get("reason").and_then(Value::as_str) == Some("not_approved"));
    let not_in = |key: &str| -> bool {
        !completeness
            .get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .any(|item| item.as_str() == Some("accessibility"))
            })
            .unwrap_or(false)
    };
    let policy_filtered_has = completeness
        .get("policy_filtered_sections")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .any(|item| item.as_str() == Some("accessibility"))
        })
        .unwrap_or(false);
    let total_nodes = accessibility.get("total_nodes").and_then(Value::as_u64);
    let node_count = accessibility
        .get("nodes")
        .and_then(Value::as_array)
        .map(|nodes| nodes.len() as u64);
    let nodes = not_in("truncated_sections")
        && not_in("unavailable_sections")
        && not_in("attach_limited_sections")
        && (!policy_filtered_has || text_only_policy_filter)
        && total_nodes == node_count;
    AccessComparable {
        complete: text && nodes,
        text,
        nodes,
    }
}

fn accessibility_projection(accessibility: &Value, include_text: bool) -> Value {
    let nodes = accessibility
        .get("nodes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut node_indexes: BTreeMap<String, i64> = BTreeMap::new();
    for (index, node) in nodes.iter().enumerate() {
        if let Some(id) = node.get("node_id").and_then(Value::as_str) {
            node_indexes.insert(id.to_owned(), index as i64);
        }
    }
    let projected: Vec<Value> = nodes
        .iter()
        .map(|node| {
            let parent_index = match node.get("parent_id") {
                Some(Value::Null) | None => Value::Null,
                Some(Value::String(id)) => json!(node_indexes.get(id).copied().unwrap_or(-1)),
                Some(_) => json!(-1),
            };
            let mut object = Map::new();
            object.insert("parent_index".into(), parent_index);
            object.insert(
                "role".into(),
                node.get("role").cloned().unwrap_or(Value::Null),
            );
            object.insert(
                "ignored".into(),
                node.get("ignored").cloned().unwrap_or(Value::Null),
            );
            object.insert(
                "states".into(),
                node.get("states").cloned().unwrap_or(Value::Null),
            );
            if include_text {
                object.insert(
                    "name".into(),
                    node.get("name").cloned().unwrap_or(Value::Null),
                );
                object.insert(
                    "description".into(),
                    node.get("description").cloned().unwrap_or(Value::Null),
                );
            }
            Value::Object(object)
        })
        .collect();
    json!({
        "total_nodes": accessibility.get("total_nodes").cloned().unwrap_or(Value::Null),
        "nodes": projected,
    })
}

fn accessibility_dimension(before: &Value, after: &Value) -> Dimension {
    let before_access = accessibility_comparable(before);
    let after_access = accessibility_comparable(after);
    let text_comparable = before_access.text && after_access.text;
    let nodes_comparable = before_access.nodes && after_access.nodes;
    let reason =
        "Accessibility tree or text capture was incomplete in at least one observation.".to_owned();
    if !nodes_comparable {
        return Dimension {
            status: "unknown",
            changes: Vec::new(),
            reason: Some(reason),
        };
    }
    let before_access_value = before.get("accessibility").cloned().unwrap_or(Value::Null);
    let after_access_value = after.get("accessibility").cloned().unwrap_or(Value::Null);
    compare_dimension_default(
        singleton(
            "accessibility_tree",
            digest_canonical_value(&accessibility_projection(
                &before_access_value,
                text_comparable,
            )),
        ),
        singleton(
            "accessibility_tree",
            digest_canonical_value(&accessibility_projection(
                &after_access_value,
                text_comparable,
            )),
        ),
        before_access.complete && after_access.complete,
        &reason,
    )
}

// ---- storage --------------------------------------------------------------

fn storage_keys_comparable(inspection: &Value) -> bool {
    sections_complete(inspection, &["storage_keys"])
}

fn storage_dimension(before: &Value, after: &Value) -> Dimension {
    let keys_complete = storage_keys_comparable(before) && storage_keys_comparable(after);
    let before_storage = before.get("storage").cloned().unwrap_or(Value::Null);
    let after_storage = after.get("storage").cloned().unwrap_or(Value::Null);
    let usage_complete = !before_storage
        .get("usage_bytes")
        .map(Value::is_null)
        .unwrap_or(true)
        && !after_storage
            .get("usage_bytes")
            .map(Value::is_null)
            .unwrap_or(true)
        && !before_storage
            .get("quota_bytes")
            .map(Value::is_null)
            .unwrap_or(true)
        && !after_storage
            .get("quota_bytes")
            .map(Value::is_null)
            .unwrap_or(true);
    let comparable_fingerprints = storage_fingerprint_identities(&before_storage, &after_storage);
    let complete = storage_comparable(
        &before_storage,
        &after_storage,
        keys_complete,
        usage_complete,
    );
    compare_dimension(
        storage_map(
            &before_storage,
            keys_complete,
            usage_complete,
            &comparable_fingerprints,
        ),
        storage_map(
            &after_storage,
            keys_complete,
            usage_complete,
            &comparable_fingerprints,
        ),
        complete,
        "Storage fingerprints, inventories, usage, or quota were unavailable or truncated in at least one observation.",
        InventoryComplete::Bool(keys_complete),
    )
}

fn storage_comparable(
    before: &Value,
    after: &Value,
    keys_complete: bool,
    usage_complete: bool,
) -> bool {
    keys_complete
        && usage_complete
        && before
            .get("fingerprints_complete")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        && after
            .get("fingerprints_complete")
            .and_then(Value::as_bool)
            .unwrap_or(false)
}

fn storage_map(
    storage: &Value,
    include_keys: bool,
    include_usage: bool,
    fingerprint_identities: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let summary = {
        let mut object = Map::new();
        object.insert(
            "origin".into(),
            storage.get("origin").cloned().unwrap_or(Value::Null),
        );
        object.insert(
            "values_redacted".into(),
            storage
                .get("values_redacted")
                .cloned()
                .unwrap_or(Value::Null),
        );
        if include_usage {
            object.insert(
                "usage_bytes".into(),
                storage.get("usage_bytes").cloned().unwrap_or(Value::Null),
            );
            object.insert(
                "quota_bytes".into(),
                storage.get("quota_bytes").cloned().unwrap_or(Value::Null),
            );
        }
        Value::Object(object)
    };
    map.insert(
        "storage:summary".to_owned(),
        digest_canonical_value(&summary),
    );
    if include_keys {
        add_keys(&mut map, "local_storage", storage.get("local_storage_keys"));
        add_keys(
            &mut map,
            "session_storage",
            storage.get("session_storage_keys"),
        );
        add_keys(&mut map, "indexed_db", storage.get("indexed_db_names"));
        add_keys(&mut map, "cache", storage.get("cache_names"));
    }
    if let Some(fingerprints) = storage
        .get("content_fingerprints")
        .and_then(Value::as_array)
    {
        for fingerprint in fingerprints {
            let scope = fingerprint
                .get("scope")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let identity_sha = fingerprint
                .get("identity_sha256")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let identity = format!("{scope}:{identity_sha}");
            if !fingerprint_identities.contains(&identity) {
                continue;
            }
            map.insert(
                format!("storage:content:{identity}"),
                digest_canonical_value(
                    &fingerprint
                        .get("value_sha256")
                        .cloned()
                        .unwrap_or(Value::Null),
                ),
            );
        }
    }
    map
}

fn add_keys(map: &mut BTreeMap<String, String>, kind: &str, keys: Option<&Value>) {
    if let Some(keys) = keys.and_then(Value::as_array) {
        for key in keys {
            if let Some(key) = key.as_str() {
                map.insert(
                    format!("storage:{kind}:{key}"),
                    digest_canonical_value(&json!(key)),
                );
            }
        }
    }
}

fn storage_fingerprint_identities(before: &Value, after: &Value) -> BTreeSet<String> {
    let before_complete = complete_storage_fingerprints(before);
    let after_complete = complete_storage_fingerprints(after);
    let before_flag = before
        .get("fingerprints_complete")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let after_flag = after
        .get("fingerprints_complete")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if before_flag && after_flag {
        before_complete
            .keys()
            .chain(after_complete.keys())
            .cloned()
            .collect()
    } else {
        before_complete
            .keys()
            .filter(|identity| after_complete.contains_key(*identity))
            .cloned()
            .collect()
    }
}

fn complete_storage_fingerprints(storage: &Value) -> BTreeMap<String, Value> {
    let mut map = BTreeMap::new();
    if let Some(fingerprints) = storage
        .get("content_fingerprints")
        .and_then(Value::as_array)
    {
        for fingerprint in fingerprints {
            if fingerprint.get("complete").and_then(Value::as_bool) != Some(true) {
                continue;
            }
            let scope = fingerprint
                .get("scope")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let identity_sha = fingerprint
                .get("identity_sha256")
                .and_then(Value::as_str)
                .unwrap_or_default();
            map.insert(
                format!("{scope}:{identity_sha}"),
                fingerprint
                    .get("value_sha256")
                    .cloned()
                    .unwrap_or(Value::Null),
            );
        }
    }
    map
}

// ---- webmcp ---------------------------------------------------------------

fn webmcp_dimension(before: &Value, after: &Value) -> Dimension {
    let before_items = webmcp_items(before);
    let after_items = webmcp_items(after);
    let after_by_key: BTreeMap<String, &Value> = after_items
        .iter()
        .filter_map(|tool| {
            tool.get("tool_key")
                .and_then(Value::as_str)
                .map(|key| (key.to_owned(), tool))
        })
        .collect();
    let mut unknown_hints: BTreeSet<String> = BTreeSet::new();
    for tool in &before_items {
        let key = tool
            .get("tool_key")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if let Some(other) = after_by_key.get(key) {
            let self_missing = annotations_consequential(tool).is_none();
            let other_missing = annotations_consequential(other).is_none();
            if self_missing || other_missing {
                unknown_hints.insert(key.to_owned());
            }
        }
    }
    let project = |items: &[Value]| -> BTreeMap<String, String> {
        keyed(
            &items
                .iter()
                .map(|tool| {
                    let key = tool
                        .get("tool_key")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if !unknown_hints.contains(key) {
                        return tool.clone();
                    }
                    let mut cloned = tool.clone();
                    if let Some(annotations) =
                        cloned.get_mut("annotations").and_then(Value::as_object_mut)
                    {
                        annotations.remove("consequential");
                    }
                    cloned
                })
                .collect::<Vec<_>>(),
            |tool| {
                tool.get("tool_key")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            },
        )
    };
    let result = compare_dimension_default(
        project(&before_items),
        project(&after_items),
        webmcp_complete(before) && webmcp_complete(after),
        "WebMCP discovery was unavailable or incomplete in at least one capture.",
    );
    if result.status == "unchanged" && !unknown_hints.is_empty() {
        Dimension {
            status: "unknown",
            changes: Vec::new(),
            reason: Some(
                "Consequential annotations were not recorded or were invalid in at least one capture."
                    .to_owned(),
            ),
        }
    } else {
        result
    }
}

fn webmcp_items(discovery: &Value) -> Vec<Value> {
    discovery
        .get("tools")
        .and_then(|tools| tools.get("items"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn annotations_consequential(tool: &Value) -> Option<&Value> {
    let annotations = tool.get("annotations")?;
    let value = annotations.get("consequential")?;
    // `undefined` in TS ↔ absent key; present-with-value is Some.
    Some(value)
}

fn webmcp_complete(discovery: &Value) -> bool {
    if discovery.is_null() {
        return false;
    }
    discovery.get("status").and_then(Value::as_str) == Some("available")
        && !incomplete_sections(
            &discovery
                .get("completeness")
                .cloned()
                .unwrap_or(Value::Null),
        )
        .contains("webmcp_tools")
}

// ---- network --------------------------------------------------------------

use super::network::network_dimension;
