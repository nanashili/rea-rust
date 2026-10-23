//! Object, connection, class, and hierarchy facts for Interface Builder keyed
//! archives (NSKeyedArchiver nibs).
//!
//! Port of the oracle `parseKeyedArchive` and `keyedArchiveTable`
//! (`src/domain/apple/interfaceBuilderKeyedArchive.ts`). The property-list
//! parser owns UID identity; this module resolves only the UID edges it
//! received from that parser and emits the shared projection facts directly.
//! Object and connection attributes keep the archive's own fields: a UID
//! reference resolves to the referenced string or scalar, or to a stub naming
//! the referenced object, so cyclic object tables are never expanded.

use super::{
    ConnectionFact, Coverage, EvidenceRecord, HierarchyFact, InterfaceBuilderProjection,
    ObjectFact, ProjectionLimits, projection_limitations,
};
use rea_rust_analysis::nib::finite_number;
use rea_rust_analysis::plist::ValuePathSegment;
use serde_json::{Map, Value, json};
use std::collections::{BTreeSet, HashSet};

/// Parser-level record bounds of the oracle, applied before graph limits.
const MAX_PARSED_OBJECTS: usize = 20_000;
const MAX_PARSED_CONNECTIONS: usize = 40_000;

type ValuePath = Vec<ValuePathSegment>;

/// Project an NSKeyedArchiver object table into Interface Builder facts.
///
/// `None` means the property-list root is not a keyed archive with an object
/// table; the caller then projects the decoded value as an ibtool document.
pub fn project(
    source_path: String,
    archive_sha256: &str,
    value: &Value,
    binary_uid_paths: &[ValuePath],
    limits: &ProjectionLimits,
) -> Option<InterfaceBuilderProjection> {
    let root = value.as_object()?;
    if root.get("$archiver").and_then(Value::as_str) != Some("NSKeyedArchiver") {
        return None;
    }
    let object_table = root.get("$objects")?.as_array()?;
    let archive = ArchiveTable {
        objects: object_table,
        binary_uid_paths: binary_uid_paths.iter().cloned().collect(),
    };
    let evidence = |description: String| EvidenceRecord {
        archive_path: source_path.clone(),
        archive_sha256: archive_sha256.to_owned(),
        description,
    };

    let records = archive.records(&evidence);
    let objects_examined = records.objects.len().min(limits.max_objects);
    let objects_omitted = records.object_count - objects_examined;
    let mut objects = records.objects;
    objects.truncate(objects_examined);

    let mut connections = records.connections;
    let connections_examined = connections.len().min(limits.max_connections);
    let connections_omitted =
        records.omitted_connections + (connections.len() - connections_examined);
    connections.truncate(connections_examined);
    let object_ids = objects
        .iter()
        .map(|object| object.id.as_str())
        .collect::<HashSet<_>>();
    for connection in &mut connections {
        connection.resolved = object_ids.contains(connection.source_id.as_str())
            && connection
                .destination_id
                .as_deref()
                .is_none_or(|destination| object_ids.contains(destination));
    }

    let top = root.get("$top").and_then(Value::as_object);
    // `top.root ?? top.UITopLevelObjectsKey`
    let start = top.and_then(|top| {
        ["root", "UITopLevelObjectsKey"]
            .into_iter()
            .find_map(|name| {
                top.get(name)
                    .filter(|value| !value.is_null())
                    .map(|value| (name, value))
            })
    });
    let hierarchy = archive.hierarchy(start, limits.max_hierarchy_nodes, &evidence);
    let hierarchy_nodes_omitted = hierarchy.omitted_nodes + hierarchy.omitted_references;

    let classes_examined = object_table
        .iter()
        .filter_map(|item| item.get("$classname").and_then(non_empty_str))
        .collect::<BTreeSet<_>>()
        .len();
    let partial = objects_omitted > 0
        || connections_omitted > 0
        || records.unresolved_connections > 0
        || hierarchy_nodes_omitted > 0;
    Some(InterfaceBuilderProjection {
        source_path: source_path.clone(),
        archive_sha256: archive_sha256.to_owned(),
        objects,
        connections,
        hierarchy: hierarchy.facts,
        coverage: Coverage {
            objects_examined,
            objects_omitted,
            connections_examined,
            connections_omitted,
            unresolved_connections: records.unresolved_connections,
            hierarchy_nodes_examined: hierarchy.examined,
            hierarchy_nodes_omitted,
            classes_examined,
            partial,
        },
        limitations: projection_limitations(partial),
    })
}

struct ParsedRecords {
    objects: Vec<ObjectFact>,
    connections: Vec<ConnectionFact>,
    object_count: usize,
    omitted_connections: usize,
    unresolved_connections: usize,
}

struct HierarchyWalk {
    facts: Vec<HierarchyFact>,
    examined: usize,
    omitted_nodes: usize,
    omitted_references: usize,
}

struct ArchiveTable<'a> {
    objects: &'a [Value],
    binary_uid_paths: BTreeSet<ValuePath>,
}

impl ArchiveTable<'_> {
    /// A binary UID is a parser-owned scalar wrapper at a recorded path; an
    /// XML UID is a one-key `CF$UID` (or `UID`) dictionary with an integer.
    fn archive_uid(&self, value: &Value, path: &[ValuePathSegment]) -> Option<u64> {
        let fields = value.as_object()?;
        if self.binary_uid_paths.contains(path) {
            if fields.get("$plist_type").and_then(Value::as_str) != Some("uid") {
                return None;
            }
            let uid = fields.get("value")?;
            return uid
                .as_u64()
                .or_else(|| uid.as_str().and_then(|text| text.parse().ok()));
        }
        if fields.len() != 1 {
            return None;
        }
        fields.get("UID").or_else(|| fields.get("CF$UID"))?.as_u64()
    }

    fn target(&self, uid: u64) -> Option<(&Value, ValuePath)> {
        let index = usize::try_from(uid).ok()?;
        let target = self.objects.get(index)?;
        Some((
            target,
            vec![key("$objects"), ValuePathSegment::Index(index)],
        ))
    }

    /// The class named by an object's own `$class` reference or inline descriptor.
    fn class_name_of(&self, value: &Value, path: &[ValuePathSegment]) -> Option<String> {
        let descriptor = self.class_descriptor(value, path)?;
        descriptor
            .get("$classname")
            .and_then(non_empty_str)
            .map(str::to_owned)
    }

    fn class_descriptor<'v>(
        &'v self,
        value: &'v Value,
        path: &[ValuePathSegment],
    ) -> Option<&'v Value> {
        let reference = value.as_object()?.get("$class")?;
        match self.archive_uid(reference, &child_key(path, "$class")) {
            Some(uid) => self.target(uid).map(|(target, _)| target),
            None => Some(reference),
        }
    }

    /// The string an archived string object holds, if it is one.
    fn archived_string(&self, target: &Value, path: &[ValuePathSegment]) -> Option<String> {
        if let Some(text) = target.as_str() {
            return Some(text.to_owned());
        }
        let text = target.as_object()?.get("NS.string")?.as_str()?;
        matches!(
            self.class_name_of(target, path).as_deref(),
            Some("NSString" | "NSMutableString")
        )
        .then(|| text.to_owned())
    }

    fn text(&self, value: Option<&Value>, path: &[ValuePathSegment]) -> Option<String> {
        let value = value?;
        let text = match self.archive_uid(value, path) {
            Some(uid) => {
                let (target, target_path) = self.target(uid)?;
                self.archived_string(target, &target_path)?
            }
            None => value.as_str()?.to_owned(),
        };
        (!text.is_empty()).then_some(text)
    }

    fn authored_id(&self, item: &Value, path: &[ValuePathSegment]) -> Option<String> {
        ["objectID", "object-id"]
            .into_iter()
            .find_map(|name| self.text(item.get(name), &child_key(path, name)))
    }

    fn reference(&self, uid: u64) -> Value {
        // UID 0 is the archived nil.
        if uid == 0 {
            return Value::Null;
        }
        let Some((target, path)) = self.target(uid) else {
            return Value::Null;
        };
        match target {
            Value::Null => Value::Null,
            Value::Bool(_) | Value::Number(_) | Value::String(_) => target.clone(),
            Value::Array(_) | Value::Object(_) => {
                if let Some(text) = self.archived_string(target, &path) {
                    return Value::String(text);
                }
                let mut stub = Map::new();
                stub.insert("archiveUID".into(), json!(uid));
                if target.is_object()
                    && let Some(object_id) = self.authored_id(target, &path)
                {
                    stub.insert("objectID".into(), Value::String(object_id));
                }
                stub.insert("className".into(), self.class_name_value(target, &path));
                Value::Object(stub)
            }
        }
    }

    fn class_name_value(&self, value: &Value, path: &[ValuePathSegment]) -> Value {
        self.class_name_of(value, path)
            .map_or(Value::Null, Value::String)
    }

    /// Resolve one object's own fields, leaving references to other objects as stubs.
    fn resolve(&self, value: &Value, path: &[ValuePathSegment]) -> Value {
        if let Some(uid) = self.archive_uid(value, path) {
            return self.reference(uid);
        }
        match value {
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .enumerate()
                    .map(|(index, item)| self.resolve(item, &child_index(path, index)))
                    .collect(),
            ),
            Value::Object(fields) => Value::Object(
                fields
                    .iter()
                    .map(|(name, child)| {
                        if name == "$class" {
                            ("className".to_owned(), self.class_name_value(value, path))
                        } else {
                            (name.clone(), self.resolve(child, &child_key(path, name)))
                        }
                    })
                    .collect(),
            ),
            Value::Number(number) if number.is_f64() => {
                number.as_f64().map_or(Value::Null, finite_number)
            }
            _ => value.clone(),
        }
    }

    /// The archive field as the oracle decoder represents it, for a class
    /// reference that cannot be resolved.
    fn source_value(&self, value: &Value, path: &[ValuePathSegment]) -> Value {
        if self.binary_uid_paths.contains(path)
            && let Some(uid) = self.archive_uid(value, path)
        {
            return json!({ "UID": uid });
        }
        value.clone()
    }

    fn records(&self, evidence: &dyn Fn(String) -> EvidenceRecord) -> ParsedRecords {
        let mut records = ParsedRecords {
            objects: Vec::new(),
            connections: Vec::new(),
            object_count: 0,
            omitted_connections: 0,
            unresolved_connections: 0,
        };
        for (index, raw) in self.objects.iter().enumerate().skip(1) {
            let path = vec![key("$objects"), ValuePathSegment::Index(index)];
            let mut fields = match self.resolve(raw, &path) {
                Value::Object(fields) => fields,
                _ => Map::new(),
            };
            let class_name = fields
                .remove("className")
                .as_ref()
                .and_then(non_empty_str)
                .map(str::to_owned);
            // An archived object names its class with its own `$class`
            // reference; when that reference cannot be resolved the object is
            // still observed, with an unknown class. Scalars and class
            // descriptors are not objects.
            let class_reference = raw.as_object().and_then(|raw| raw.get("$class"));
            if class_name.is_none() && class_reference.is_none() {
                continue;
            }
            records.object_count += 1;
            if class_name.is_none()
                && let Some(reference) = class_reference
            {
                fields.insert(
                    "$class".into(),
                    self.source_value(reference, &child_key(&path, "$class")),
                );
            }
            let object_id = first_string(&fields, &["objectID", "object-id"])
                .or_else(|| fields.get("archiveUID").and_then(js_number_string))
                .unwrap_or_else(|| index.to_string());
            if records.objects.len() < MAX_PARSED_OBJECTS {
                let name = first_string(
                    &fields,
                    &["label", "title", "identifier", "accessibilityLabel"],
                )
                .or_else(|| class_name.clone())
                .unwrap_or_else(|| format!("object {index}"));
                records.objects.push(ObjectFact {
                    id: object_id.clone(),
                    class_name: class_name.clone(),
                    label: Some(name),
                    attributes: fields.clone().into_iter().collect(),
                    evidence: evidence(format!("object {object_id}")),
                });
            }
            let Some(class_name) = class_name.filter(|name| is_connection_class(name)) else {
                continue;
            };
            match connection(&class_name, &object_id, fields, evidence) {
                Some(_) if records.connections.len() >= MAX_PARSED_CONNECTIONS => {
                    records.omitted_connections += 1;
                }
                Some(connection) => records.connections.push(connection),
                // A recognized connector that cannot name its owner is an
                // unresolved connection, not an absent one.
                None => records.unresolved_connections += 1,
            }
        }
        records
    }

    /// Walk the archived hierarchy from `$top`, visiting each object once.
    ///
    /// Facts are emitted in the oracle's tree preorder; a node past the
    /// hierarchy limit is counted and its children keep its parent.
    fn hierarchy(
        &self,
        start: Option<(&str, &Value)>,
        maximum_nodes: usize,
        evidence: &dyn Fn(String) -> EvidenceRecord,
    ) -> HierarchyWalk {
        let mut walk = HierarchyWalk {
            facts: Vec::new(),
            examined: 0,
            omitted_nodes: 0,
            omitted_references: 0,
        };
        let Some((start, start_value)) = start else {
            return walk;
        };
        let mut visited = HashSet::new();
        let mut pending: Vec<(&Value, ValuePath, Option<String>)> =
            vec![(start_value, vec![key("$top"), key(start)], None)];
        while let Some((value, path, parent)) = pending.pop() {
            if let Some(uid) = self.archive_uid(value, &path) {
                // UID 0 is archived nil, not a missing hierarchy object.
                if uid == 0 {
                    continue;
                }
                let Some((target, target_path)) = self.target(uid) else {
                    walk.omitted_references += 1;
                    continue;
                };
                if !visited.insert(uid) {
                    continue;
                }
                match target {
                    Value::Array(items) => {
                        push_members(&mut pending, items, &target_path, &parent);
                    }
                    Value::Object(fields) => {
                        if self.is_archived_array(target, &target_path) {
                            if let Some(members) =
                                fields.get("NS.objects").and_then(Value::as_array)
                            {
                                let members_path = child_key(&target_path, "NS.objects");
                                push_members(&mut pending, members, &members_path, &parent);
                            }
                            continue;
                        }
                        self.append_node(
                            target,
                            target_path,
                            Some(uid),
                            parent,
                            maximum_nodes,
                            evidence,
                            &mut walk,
                            &mut pending,
                        );
                    }
                    _ => {}
                }
                continue;
            }
            match value {
                Value::Array(items) => push_members(&mut pending, items, &path, &parent),
                Value::Object(_) => self.append_node(
                    value,
                    path,
                    None,
                    parent,
                    maximum_nodes,
                    evidence,
                    &mut walk,
                    &mut pending,
                ),
                _ => {}
            }
        }
        walk.examined = walk.examined.min(maximum_nodes);
        walk
    }

    #[allow(clippy::too_many_arguments)]
    fn append_node<'v>(
        &self,
        item: &'v Value,
        path: ValuePath,
        uid: Option<u64>,
        parent: Option<String>,
        maximum_nodes: usize,
        evidence: &dyn Fn(String) -> EvidenceRecord,
        walk: &mut HierarchyWalk,
        pending: &mut Vec<(&'v Value, ValuePath, Option<String>)>,
    ) {
        let Some(fields) = item.as_object() else {
            return;
        };
        let object_id = self
            .authored_id(item, &path)
            .or_else(|| self.text(fields.get("id"), &child_key(&path, "id")))
            .or_else(|| uid.map(|uid| uid.to_string()));
        let mut child_parent = parent.clone();
        if let Some(object_id) = object_id {
            walk.examined += 1;
            if walk.examined > maximum_nodes {
                walk.omitted_nodes += 1;
            } else {
                walk.facts.push(HierarchyFact {
                    parent_id: parent,
                    child_id: object_id.clone(),
                    child_label: None,
                    evidence: evidence(format!("hierarchy {object_id}")),
                });
                child_parent = Some(object_id);
            }
        }
        for (name, child) in fields.iter().rev() {
            if is_hierarchy_key(name) {
                pending.push((child, child_key(&path, name), child_parent.clone()));
            }
        }
    }

    fn is_archived_array(&self, value: &Value, path: &[ValuePathSegment]) -> bool {
        self.class_descriptor(value, path)
            .and_then(|descriptor| descriptor.get("$classes"))
            .and_then(Value::as_array)
            .is_some_and(|names| {
                names
                    .iter()
                    .any(|name| matches!(name.as_str(), Some("NSArray" | "NSMutableArray")))
            })
    }
}

fn push_members<'v>(
    pending: &mut Vec<(&'v Value, ValuePath, Option<String>)>,
    items: &'v [Value],
    path: &[ValuePathSegment],
    parent: &Option<String>,
) {
    for (index, item) in items.iter().enumerate().rev() {
        pending.push((item, child_index(path, index), parent.clone()));
    }
}

/// Build the connection fact for a recognized connector object, or `None`
/// when the connector names no owner.
fn connection(
    class_name: &str,
    object_id: &str,
    fields: Map<String, Value>,
    evidence: &dyn Fn(String) -> EvidenceRecord,
) -> Option<ConnectionFact> {
    let control_action = class_name.to_ascii_lowercase().contains("controlconnector");
    let ui_kit = is_ui_runtime_connection(class_name);
    let (source_key, destination_key, label_key) = if ui_kit {
        ("UISource", "UIDestination", "UILabel")
    } else {
        ("NSSource", "NSDestination", "NSLabel")
    };
    let endpoint = |primary: &str, fallback: &str, owner: &str, archived_key: &str| {
        if ui_kit {
            return archived_object_reference(fields.get(archived_key));
        }
        let archived = archived_object_reference(fields.get(archived_key)).map(Value::String);
        first_object_reference(&[
            fields.get(primary),
            archived.as_ref(),
            fields.get(fallback),
            fields.get(owner),
        ])
    };
    // AppKit and UIKit archive the same endpoint roles under their own
    // class-specific field namespaces; the source is the outlet owner.
    let source = if control_action {
        endpoint("destination", "to", "target", source_key)
    } else {
        endpoint("source", "from", "owner", source_key)
    }?;
    let destination_id = if control_action {
        endpoint("source", "from", "owner", destination_key)
    } else {
        endpoint("destination", "to", "target", destination_key)
    };
    let label = if ui_kit {
        first_string(&fields, &[label_key])
    } else {
        first_string(
            &fields,
            &["label", label_key, "selector", "identifier", "action"],
        )
    };
    let id = format!("archive:{object_id}");
    Some(ConnectionFact {
        evidence: evidence(format!("connection from {source}")),
        id,
        source_id: source,
        destination_id,
        relation: if control_action {
            "action".to_owned()
        } else {
            class_name.to_owned()
        },
        label,
        attributes: fields,
        resolved: false,
    })
}

/// The node identity of a resolved archive reference: its authored object ID,
/// otherwise its archive UID, which is how the referenced object is keyed.
fn archived_object_reference(value: Option<&Value>) -> Option<String> {
    let fields = value?.as_object()?;
    let uid = fields.get("archiveUID").filter(|uid| uid.is_number())?;
    first_string(fields, &["objectID", "object-id"]).or_else(|| js_number_string(uid))
}

fn first_object_reference(values: &[Option<&Value>]) -> Option<String> {
    values.iter().flatten().find_map(|value| {
        if let Some(text) = non_empty_str(value) {
            return Some(text.to_owned());
        }
        let fields = value.as_object()?;
        first_string(fields, &["objectID", "object-id", "id", "identifier"])
            .or_else(|| fields.get("archiveUID").and_then(js_number_string))
    })
}

fn first_string(fields: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|name| fields.get(*name).and_then(non_empty_str))
        .map(str::to_owned)
}

fn non_empty_str(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| !text.is_empty())
}

/// JavaScript `String(number)` for the integral and decimal values a decoded
/// plist number can hold.
fn js_number_string(value: &Value) -> Option<String> {
    let number = value.as_number()?;
    if number.is_f64() {
        return Some(finite_number(number.as_f64()?).to_string());
    }
    Some(number.to_string())
}

fn is_connection_class(class_name: &str) -> bool {
    let lower = class_name.to_ascii_lowercase();
    [
        "outlet",
        "connection",
        "segue",
        "actionconnection",
        "controlconnector",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

/// `^UIRuntime\w*Connection$`: UIKit runtime connection classes store their
/// endpoints and labels under UI-prefixed keys.
fn is_ui_runtime_connection(class_name: &str) -> bool {
    class_name
        .strip_prefix("UIRuntime")
        .and_then(|rest| rest.strip_suffix("Connection"))
        .is_some_and(|middle| {
            middle
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}

fn is_hierarchy_key(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "subviews",
        "contentview",
        "childviewcontrollers",
        "children",
        "views",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
}

fn key(name: &str) -> ValuePathSegment {
    ValuePathSegment::Key(name.to_owned())
}

fn child_key(path: &[ValuePathSegment], name: &str) -> ValuePath {
    let mut child = path.to_vec();
    child.push(key(name));
    child
}

fn child_index(path: &[ValuePathSegment], index: usize) -> ValuePath {
    let mut child = path.to_vec();
    child.push(ValuePathSegment::Index(index));
    child
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(maximum: usize) -> ProjectionLimits {
        ProjectionLimits {
            max_objects: maximum,
            max_connections: maximum,
            max_hierarchy_nodes: maximum,
        }
    }

    fn run(archive: &Value, uid_paths: &[ValuePath], maximum: usize) -> InterfaceBuilderProjection {
        project(
            "Main.nib".into(),
            &"a".repeat(64),
            archive,
            uid_paths,
            &limits(maximum),
        )
        .expect("keyed archive projects")
    }

    #[test]
    fn projects_objects_connections_and_hierarchy_with_raw_archive_fields() {
        let projection = run(&xml_archive(), &[], 20);
        let coverage = &projection.coverage;
        assert_eq!(coverage.objects_examined, 5);
        assert_eq!(coverage.connections_examined, 2);
        assert_eq!(coverage.unresolved_connections, 1);
        assert_eq!(coverage.hierarchy_nodes_examined, 2);
        assert_eq!(coverage.classes_examined, 5);
        assert!(coverage.partial);

        let outlet = &projection.connections[0];
        assert_eq!(outlet.id, "archive:5");
        assert_eq!(outlet.source_id, "root-id");
        assert_eq!(outlet.destination_id.as_deref(), Some("child-id"));
        assert_eq!(outlet.relation, "NSNibOutletConnector");
        assert_eq!(outlet.label.as_deref(), Some("open"));
        // Connection attributes keep the archive fields with reference stubs.
        assert_eq!(
            outlet.attributes["NSSource"],
            json!({"archiveUID": 1, "objectID": "root-id", "className": "UIView"})
        );
        assert!(!outlet.attributes.contains_key("source_id"));

        let ui = &projection.connections[1];
        assert_eq!(ui.source_id, "root-id");
        assert_eq!(ui.label.as_deref(), Some("close"));

        let root = &projection.objects[0];
        assert_eq!(root.id, "root-id");
        assert_eq!(root.label.as_deref(), Some("Root"));
        // A reference to a scalar resolves to the scalar; integral reals are
        // emitted as integers.
        assert_eq!(root.attributes["count"], json!(7));
        assert_eq!(root.attributes["width"], json!(512));
        assert!(root.attributes["width"].is_i64());

        assert_eq!(projection.hierarchy[0].parent_id, None);
        assert_eq!(projection.hierarchy[0].child_id, "root-id");
        assert_eq!(
            projection.hierarchy[1].parent_id.as_deref(),
            Some("root-id")
        );
        assert_eq!(projection.hierarchy[1].child_id, "child-id");
    }

    #[test]
    fn archive_without_top_root_has_no_hierarchy() {
        let mut archive = xml_archive();
        archive["$top"] = json!({"IB.objectdata": {"CF$UID": 1}});
        let projection = run(&archive, &[], 20);
        assert!(projection.hierarchy.is_empty());
        assert_eq!(projection.coverage.hierarchy_nodes_examined, 0);
        assert_eq!(projection.coverage.hierarchy_nodes_omitted, 0);
    }

    #[test]
    fn honors_projection_bounds_and_retains_unresolved_counts() {
        let projection = run(&xml_archive(), &[], 1);
        let coverage = &projection.coverage;
        assert_eq!(coverage.objects_examined, 1);
        assert_eq!(coverage.objects_omitted, 4);
        assert_eq!(coverage.connections_examined, 1);
        assert_eq!(coverage.connections_omitted, 1);
        assert_eq!(coverage.unresolved_connections, 1);
        assert_eq!(coverage.hierarchy_nodes_examined, 1);
        assert_eq!(coverage.hierarchy_nodes_omitted, 1);
    }

    #[test]
    fn missing_hierarchy_reference_is_counted() {
        let mut archive = xml_archive();
        archive["$objects"][1]["subviews"] = json!([{"CF$UID": 99}]);
        let projection = run(&archive, &[], 20);
        assert_eq!(projection.coverage.hierarchy_nodes_examined, 1);
        assert_eq!(projection.coverage.hierarchy_nodes_omitted, 1);
    }

    #[test]
    fn binary_uid_edges_require_parser_owned_paths() {
        let archive = json!({
            "$archiver": "NSKeyedArchiver",
            "$objects": [
                "$null",
                {
                    "$class": {"$plist_type":"uid", "value":"2"},
                    "title":"Root",
                    "authored_uid_shaped_data": {"$plist_type":"uid", "value":"2"}
                },
                {"$classname":"NSView", "$classes":["NSView", "NSObject"]},
                {"$class": {"$plist_type":"uid", "value":"9"}}
            ],
            "$top": {"root":{"$plist_type":"uid", "value":"1"}}
        });
        let uid = |index: usize| {
            vec![
                key("$objects"),
                ValuePathSegment::Index(index),
                key("$class"),
            ]
        };
        let top_path = vec![key("$top"), key("root")];
        let projection = run(&archive, &[uid(1), uid(3), top_path], 20);
        let root = &projection.objects[0];
        assert_eq!(root.class_name.as_deref(), Some("NSView"));
        assert_eq!(
            root.attributes["authored_uid_shaped_data"],
            json!({"$plist_type":"uid", "value":"2"})
        );
        // An unresolvable class reference is retained as the archive UID.
        let dangling = &projection.objects[1];
        assert_eq!(dangling.class_name, None);
        assert_eq!(dangling.attributes["$class"], json!({"UID": 9}));
        assert_eq!(projection.hierarchy[0].child_id, "1");
    }

    fn xml_archive() -> Value {
        let uid = |value| json!({"CF$UID": value});
        json!({
            "$archiver":"NSKeyedArchiver",
            "$objects":[
                "$null",
                {
                    "$class":uid(2),
                    "objectID":"root-id",
                    "title":"Root",
                    "count":uid(11),
                    "width":512.0,
                    "subviews":[uid(3)]
                },
                {"$classname":"UIView", "$classes":["UIView", "NSObject"]},
                {"$class":uid(4), "objectID":"child-id", "title":"Child"},
                {"$classname":"UIButton", "$classes":["UIButton", "UIView", "NSObject"]},
                {
                    "$class":uid(6),
                    "NSSource":uid(1),
                    "NSDestination":uid(3),
                    "NSLabel":"open"
                },
                {"$classname":"NSNibOutletConnector", "$classes":["NSNibOutletConnector", "NSObject"]},
                {
                    "$class":uid(8),
                    "NSDestination":uid(1),
                    "NSLabel":"missing source"
                },
                {"$classname":"NSNibControlConnector", "$classes":["NSNibControlConnector", "NSObject"]},
                {
                    "$class":uid(10),
                    "UISource":uid(1),
                    "UIDestination":uid(3),
                    "UILabel":"close",
                    "UIEventMask":3
                },
                {"$classname":"UIRuntimeOutletConnection", "$classes":["UIRuntimeOutletConnection", "NSObject"]},
                7
            ],
            "$top":{"root":uid(1)}
        })
    }
}
