//! Read-only projection of decoded Interface Builder archives.
//!
//! The plist decoder owns byte parsing.  This module owns the small amount of
//! interpretation needed by callers that want object, connection, resource,
//! and hierarchy facts without depending on a particular plist implementation.
#[cfg(unix)]
pub mod bundle;
pub mod component;
pub mod keyed_archive;
pub mod nib_archive;
pub mod nib_view_hierarchy;
pub mod types;
pub mod view;
use rea_rust_analysis::plist::Report;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};

const DEFAULT_MAX_OBJECTS: usize = 4_096;
const DEFAULT_MAX_CONNECTIONS: usize = 8_192;
const DEFAULT_MAX_HIERARCHY_NODES: usize = 4_096;

#[derive(Clone, Debug, Serialize)]
pub struct ProjectionLimits {
    pub max_objects: usize,
    pub max_connections: usize,
    pub max_hierarchy_nodes: usize,
}

impl Default for ProjectionLimits {
    fn default() -> Self {
        Self {
            max_objects: DEFAULT_MAX_OBJECTS,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_hierarchy_nodes: DEFAULT_MAX_HIERARCHY_NODES,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct EvidenceRecord {
    pub archive_path: String,
    pub archive_sha256: String,
    pub description: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ObjectFact {
    pub id: String,
    pub class_name: Option<String>,
    pub label: Option<String>,
    pub attributes: BTreeMap<String, Value>,
    pub evidence: EvidenceRecord,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnectionFact {
    pub id: String,
    pub source_id: String,
    pub destination_id: Option<String>,
    pub relation: String,
    pub label: Option<String>,
    /// The serialized connection record, carried onto outlet and action nodes.
    pub attributes: Map<String, Value>,
    pub resolved: bool,
    pub evidence: EvidenceRecord,
}

#[derive(Clone, Debug, Serialize)]
pub struct HierarchyFact {
    /// `None` names the document root; otherwise the parent object id.
    pub parent_id: Option<String>,
    pub child_id: String,
    /// Display name for a child the object table does not carry.
    pub child_label: Option<String>,
    pub evidence: EvidenceRecord,
}

#[derive(Clone, Debug, Serialize)]
pub struct Coverage {
    pub objects_examined: usize,
    pub objects_omitted: usize,
    pub connections_examined: usize,
    pub connections_omitted: usize,
    pub unresolved_connections: usize,
    pub hierarchy_nodes_examined: usize,
    pub hierarchy_nodes_omitted: usize,
    pub classes_examined: usize,
    pub partial: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct InterfaceBuilderProjection {
    pub source_path: String,
    pub archive_sha256: String,
    pub objects: Vec<ObjectFact>,
    pub connections: Vec<ConnectionFact>,
    pub hierarchy: Vec<HierarchyFact>,
    pub coverage: Coverage,
    pub limitations: Vec<String>,
}

/// Project the decoded report while retaining the report's source archive path.
pub fn project_report(
    report: &Report,
    archive_sha256: &str,
    limits: ProjectionLimits,
) -> InterfaceBuilderProjection {
    project_value(
        report.source_path.clone(),
        archive_sha256,
        &report.value,
        limits,
    )
}

/// Project a JSON-compatible Interface Builder plist value.
pub fn project_value(
    source_path: String,
    archive_sha256: &str,
    value: &Value,
    limits: ProjectionLimits,
) -> InterfaceBuilderProjection {
    let evidence = |description: String| EvidenceRecord {
        archive_path: source_path.clone(),
        archive_sha256: archive_sha256.to_owned(),
        description,
    };
    let objects_value = value
        .get("com.apple.ibtool.document.objects")
        .and_then(Value::as_object);
    let mut objects = Vec::new();
    let mut object_ids = HashSet::new();
    let mut object_entries = objects_value
        .map(|objects| objects.iter().collect::<Vec<_>>())
        .unwrap_or_default();
    object_entries.sort_by(|left, right| js_key_order(left.0, right.0));
    let objects_examined = object_entries.len();
    let objects_omitted = objects_examined.saturating_sub(limits.max_objects);
    for (id, raw) in object_entries.into_iter().take(limits.max_objects) {
        let object = raw.as_object().cloned().unwrap_or_default();
        object_ids.insert(id.to_owned());
        let class_name = first_string(&object, &["customClass", "class", "isa"]);
        let label =
            first_string(&object, &["label", "title", "name"]).or_else(|| class_name.clone());
        let carried = carried_object_fields(&object, id, class_name.as_deref(), label.as_deref());
        let attributes = object
            .iter()
            .filter(|(key, _)| !carried.contains(key.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        objects.push(ObjectFact {
            id: id.to_owned(),
            class_name,
            label,
            attributes,
            evidence: evidence(format!("object {id}")),
        });
    }

    let mut connections = Vec::new();
    let mut connections_examined = 0;
    let mut connections_omitted = 0;
    let mut unresolved_connections = 0;
    if let Some(connection_map) = value
        .get("com.apple.ibtool.document.connections")
        .and_then(Value::as_object)
    {
        let mut entries = connection_map.iter().collect::<Vec<_>>();
        entries.sort_by(|left, right| js_key_order(left.0, right.0));
        for (source_id, raw_connections) in entries {
            let Some(values) = raw_connections.as_array() else {
                continue;
            };
            for (index, raw) in values.iter().enumerate() {
                connections_examined += 1;
                if connections.len() >= limits.max_connections {
                    connections_omitted += 1;
                    continue;
                }
                let connection = raw.as_object().cloned().unwrap_or_default();
                let destination_id =
                    string_or_null(&connection, &["destination-id", "destinationId"]);
                let relation = first_string(&connection, &["type", "connectionType"])
                    .unwrap_or_else(|| "unknown".to_owned());
                let id = format!("{source_id}:connection:{index}");
                let resolved = object_ids.contains(source_id)
                    && destination_id
                        .as_ref()
                        .map(|destination| object_ids.contains(destination))
                        .unwrap_or(true);
                if !resolved {
                    unresolved_connections += 1;
                }
                connections.push(ConnectionFact {
                    id,
                    source_id: source_id.to_owned(),
                    destination_id,
                    relation,
                    label: first_string(&connection, &["label", "selector", "identifier"]),
                    attributes: connection,
                    resolved,
                    evidence: evidence(format!("connection from {source_id}")),
                });
            }
        }
    }

    let roots = value
        .get("com.apple.ibtool.document.hierarchy")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let (hierarchy, hierarchy_nodes_examined, hierarchy_nodes_omitted) =
        flatten_hierarchy(roots, limits.max_hierarchy_nodes, &evidence);
    let classes_examined = value
        .get("com.apple.ibtool.document.classes")
        .and_then(Value::as_object)
        .map(|classes| classes.len())
        .unwrap_or_default();
    let partial = objects_omitted > 0 || connections_omitted > 0 || hierarchy_nodes_omitted > 0;
    let limitations = projection_limitations(partial);
    InterfaceBuilderProjection {
        source_path,
        archive_sha256: archive_sha256.to_owned(),
        objects,
        connections,
        hierarchy,
        coverage: Coverage {
            objects_examined,
            objects_omitted,
            connections_examined,
            connections_omitted,
            unresolved_connections,
            hierarchy_nodes_examined,
            hierarchy_nodes_omitted,
            classes_examined,
            partial,
        },
        limitations,
    }
}

/// Shared limitations of every Interface Builder projection.
pub(crate) fn projection_limitations(partial: bool) -> Vec<String> {
    let mut limitations = vec![
        "Interface Builder classes and fields are private serialized data; absent or unrecognized classes remain unknown.".to_owned(),
    ];
    if partial {
        limitations
            .push("Projection limits omitted one or more records; absence is unknown.".to_owned());
    }
    limitations
}

/// Flatten `{objectID, children}` hierarchy records into parent/child facts.
///
/// Returns the facts, the examined node count (bounded by the limit), and the
/// node count omitted by the limit.
pub(crate) fn flatten_hierarchy(
    roots: &[Value],
    max_hierarchy_nodes: usize,
    evidence: &dyn Fn(String) -> EvidenceRecord,
) -> (Vec<HierarchyFact>, usize, usize) {
    let mut hierarchy = Vec::new();
    let mut hierarchy_nodes_examined = 0;
    let mut hierarchy_nodes_omitted = 0;
    {
        // Process roots in document order: the stack pops LIFO, so push the
        // roots reversed (children are already pushed reversed below).
        let mut pending = roots
            .iter()
            .rev()
            .map(|root| (None::<String>, root))
            .collect::<Vec<_>>();
        while let Some((parent, raw)) = pending.pop() {
            if let Some(items) = raw.as_array() {
                for item in items.iter().rev() {
                    pending.push((parent.clone(), item));
                }
                continue;
            }
            let Some(node) = raw.as_object() else {
                continue;
            };
            let id = first_string(node, &["objectID", "object-id", "id"]).or_else(|| {
                node.get("archiveUID")
                    .filter(|uid| uid.is_number())
                    .map(Value::to_string)
            });
            // A node without identity, or one past the limit, keeps its
            // parent for its children; the walk continues so every omission
            // is counted rather than left unknown.
            let mut next_parent = parent.clone();
            if let Some(id) = id {
                hierarchy_nodes_examined += 1;
                if hierarchy_nodes_examined > max_hierarchy_nodes {
                    hierarchy_nodes_omitted += 1;
                } else {
                    let child_label = first_string(node, &["label", "name"]);
                    hierarchy.push(HierarchyFact {
                        parent_id: parent,
                        child_id: id.clone(),
                        child_label,
                        evidence: evidence(format!("hierarchy {id}")),
                    });
                    next_parent = Some(id);
                }
            }
            if let Some(children) = node.get("children") {
                pending.push((next_parent, children));
            }
        }
    }
    (
        hierarchy,
        hierarchy_nodes_examined.min(max_hierarchy_nodes),
        hierarchy_nodes_omitted,
    )
}

fn first_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        object
            .get(*key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}

fn string_or_null(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    first_string(object, keys)
}

/// Order dictionary keys as the oracle's decoded JavaScript objects iterate
/// them: canonical array-index keys ascend numerically before other keys.
/// The decoded map does not retain insertion order of other keys, so those
/// keep their lexical order.
fn js_key_order(left: &str, right: &str) -> std::cmp::Ordering {
    fn index(key: &str) -> Option<u32> {
        let value = key.parse::<u32>().ok()?;
        (value != u32::MAX && value.to_string() == key).then_some(value)
    }
    match (index(left), index(right)) {
        (Some(left), Some(right)) => left.cmp(&right),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => left.cmp(right),
    }
}

fn carried_object_fields(
    object: &Map<String, Value>,
    object_id: &str,
    class_name: Option<&str>,
    label: Option<&str>,
) -> HashSet<String> {
    let mut carried = HashSet::new();
    if object.get("customClass").and_then(Value::as_str) == class_name {
        carried.insert("customClass".to_owned());
    }
    if object.get("label").and_then(Value::as_str) == label {
        carried.insert("label".to_owned());
    }
    if object.get("objectID").and_then(Value::as_str) == Some(object_id) {
        carried.insert("objectID".to_owned());
    }
    carried
}

/// Compute a digest for callers that receive archive bytes separately.
pub fn archive_sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    let digest = digest.finalize();
    format!("{digest:x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn preserves_unknown_class_and_provenance() {
        let value = json!({
            "com.apple.ibtool.document.objects": {
                "1": { "customClass": "MysteryView", "image": "hero" },
                "2": { "customClass": "Button" }
            },
            "com.apple.ibtool.document.connections": {
                "1": [{ "type": "outlet", "destination-id": "2", "label": "button" }]
            }
        });
        let result = project_value(
            "Base.lproj/Main.nib".into(),
            "abc",
            &value,
            ProjectionLimits::default(),
        );
        assert_eq!(result.objects[0].class_name.as_deref(), Some("MysteryView"));
        assert_eq!(result.objects[0].attributes["image"], "hero");
        assert_eq!(result.connections[0].destination_id.as_deref(), Some("2"));
        assert_eq!(
            result.objects[0].evidence.archive_path,
            "Base.lproj/Main.nib"
        );
    }

    #[test]
    fn reports_bounded_omissions() {
        let value = json!({
            "com.apple.ibtool.document.objects": {"1": {}, "2": {}},
            "com.apple.ibtool.document.connections": {"1": [{"type":"outlet"}]}
        });
        let result = project_value(
            "x.nib".into(),
            "hash",
            &value,
            ProjectionLimits {
                max_objects: 1,
                max_connections: 0,
                max_hierarchy_nodes: 1,
            },
        );
        assert!(result.coverage.partial);
        assert_eq!(result.coverage.objects_omitted, 1);
        assert_eq!(result.coverage.connections_omitted, 1);
    }
}
