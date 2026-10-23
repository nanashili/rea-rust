//! Pure projection and reconciliation of encoded NIB view-parent relationships.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub const DEFAULT_MAX_NODES: usize = 20_000;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NibObject {
    pub id: u64,
    pub class_name: String,
    pub values: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NibHierarchyNode {
    #[serde(rename = "objectID")]
    pub object_id: String,
    pub children: Vec<NibHierarchyNode>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NibHierarchyProjection {
    pub hierarchy: Option<Vec<NibHierarchyNode>>,
    pub omitted: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NibHierarchyMerge {
    pub hierarchy: Vec<NibHierarchyNode>,
    pub omitted: usize,
}

/// Project encoded view parents; archive ownership is not inferred as a view parent.
pub fn project_nib_view_hierarchy<F>(
    objects: &[NibObject],
    retained_ids: &BTreeSet<u64>,
    mut reserve_node: F,
    max_nodes: usize,
) -> NibHierarchyProjection
where
    F: FnMut() -> bool,
{
    let collected = collect_nib_parents(objects, retained_ids);
    if collected.parents.is_empty() {
        return NibHierarchyProjection {
            hierarchy: None,
            omitted: collected.invalid,
        };
    }

    let children = child_index(&collected.parent_order, retained_ids);
    let mut roots = Vec::new();
    let mut pending = collected
        .involved_order
        .iter()
        .filter(|id| !collected.parents.contains_key(id))
        .map(|id| (*id, 0usize, Vec::new()))
        .collect::<Vec<_>>();
    let mut visited = HashSet::new();

    while let Some((id, depth, parent_path)) = pending.pop() {
        if visited.contains(&id) || depth > 128 || visited.len() >= max_nodes || !reserve_node() {
            continue;
        }

        visited.insert(id);
        let node = NibHierarchyNode {
            object_id: id.to_string(),
            children: Vec::new(),
        };
        let node_path = append_at_path(&mut roots, &parent_path, node);

        if let Some(child_ids) = children.get(&id) {
            for child in child_ids.iter().rev() {
                pending.push((*child, depth + 1, node_path.clone()));
            }
        }
    }

    NibHierarchyProjection {
        hierarchy: Some(roots),
        omitted: collected.involved_order.len() - visited.len() + collected.invalid,
    }
}

/// Merge recovered encoded hierarchy into a legacy hierarchy in place.
pub fn merge_nib_hierarchies<F>(
    legacy: &mut Vec<NibHierarchyNode>,
    recovered: &[NibHierarchyNode],
    mut reserve_node: F,
    max_nodes: usize,
) -> NibHierarchyMerge
where
    F: FnMut() -> bool,
{
    let mut existing = HashSet::new();
    let mut owners = HashMap::new();
    let mut parents = HashMap::new();
    for node in legacy.iter() {
        index_legacy(node, None, &mut existing, &mut owners, &mut parents);
    }

    let mut pending = recovered
        .iter()
        .map(|node| (node, None))
        .collect::<Vec<_>>();
    let mut omitted = 0;

    while let Some((entry, parent)) = pending.pop() {
        let id = entry.object_id.clone();
        if !existing.contains(&id) {
            if existing.len() >= max_nodes || !reserve_node() {
                omitted += 1;
                continue;
            }

            append_node(
                legacy,
                parent.as_deref(),
                NibHierarchyNode {
                    object_id: id.clone(),
                    children: Vec::new(),
                },
            );
            existing.insert(id.clone());
            owners.insert(id.clone(), parent.clone());
            if let Some(parent_id) = parent.as_ref() {
                parents.insert(id.clone(), parent_id.clone());
            }
        } else if let Some(parent_id) = parent.as_ref() {
            let owner = owners.get(&id).cloned().flatten();
            if owner.as_deref() != Some(parent_id.as_str()) {
                if owner.is_some() || would_cycle(&id, parent_id, &parents) {
                    omitted += 1;
                } else if let Some(node) = take_node(legacy, &id) {
                    append_node(legacy, Some(parent_id), node);
                    owners.insert(id.clone(), Some(parent_id.clone()));
                    parents.insert(id.clone(), parent_id.clone());
                }
            }
        }

        for child in entry.children.iter().rev() {
            pending.push((child, Some(id.clone())));
        }
    }

    NibHierarchyMerge {
        hierarchy: legacy.clone(),
        omitted,
    }
}

fn collect_nib_parents(objects: &[NibObject], retained_ids: &BTreeSet<u64>) -> CollectedParents {
    let mut parents = BTreeMap::new();
    let mut parent_order = Vec::new();
    let mut involved = BTreeSet::new();
    let mut involved_order = Vec::new();
    let mut invalid = 0;

    let mut record_involved = |id: u64| {
        if involved.insert(id) {
            involved_order.push(id);
        }
    };
    let mut record_parent = |child: u64, parent: u64| {
        if let Some(existing) = parent_order
            .iter_mut()
            .find(|(existing_child, _)| *existing_child == child)
        {
            // Match the archive decoder's Map semantics: a later encoded
            // relationship replaces the earlier parent without duplicating
            // the child in the projected index.
            existing.1 = parent;
        } else {
            parent_order.push((child, parent));
        }
        parents.insert(child, parent);
    };

    for object in objects {
        if !retained_ids.contains(&object.id) {
            continue;
        }

        let class_name = object.class_name.trim_end_matches('\0');
        let window_view = object.values.get("NSWindowView");
        if class_name == "NSWindowTemplate" && invalid_reference(window_view) {
            invalid += 1;
        }
        if class_name == "NSWindowTemplate" {
            if let Some(child) = reference(window_view) {
                record_parent(child, object.id);
                record_involved(object.id);
                record_involved(child);
            }
        }

        let superview = object.values.get("NSSuperview");
        if invalid_reference(superview) {
            invalid += 1;
        }
        if let Some(parent) = reference(superview) {
            record_parent(object.id, parent);
            record_involved(object.id);
            if retained_ids.contains(&parent) {
                record_involved(parent);
            }
        }
    }

    CollectedParents {
        parents,
        parent_order,
        involved_order,
        invalid,
    }
}

struct CollectedParents {
    parents: BTreeMap<u64, u64>,
    parent_order: Vec<(u64, u64)>,
    involved_order: Vec<u64>,
    invalid: usize,
}

fn child_index(
    parent_order: &[(u64, u64)],
    retained_ids: &BTreeSet<u64>,
) -> BTreeMap<u64, Vec<u64>> {
    let mut children = BTreeMap::new();
    for &(child, parent) in parent_order {
        if retained_ids.contains(&child) && retained_ids.contains(&parent) {
            children.entry(parent).or_insert_with(Vec::new).push(child);
        }
    }
    children
}

fn reference(value: Option<&Value>) -> Option<u64> {
    value?.as_object()?.get("$nib_object_ref")?.as_u64()
}

fn invalid_reference(value: Option<&Value>) -> bool {
    value.is_some_and(|value| !value.is_null() && reference(Some(value)).is_none())
}

fn index_legacy(
    node: &NibHierarchyNode,
    parent: Option<&str>,
    existing: &mut HashSet<String>,
    owners: &mut HashMap<String, Option<String>>,
    parents: &mut HashMap<String, String>,
) {
    if !existing.insert(node.object_id.clone()) {
        return;
    }
    owners.insert(node.object_id.clone(), parent.map(str::to_owned));
    if let Some(parent_id) = parent {
        parents.insert(node.object_id.clone(), parent_id.to_owned());
    }
    for child in &node.children {
        index_legacy(child, Some(&node.object_id), existing, owners, parents);
    }
}

fn append_node(roots: &mut Vec<NibHierarchyNode>, parent: Option<&str>, node: NibHierarchyNode) {
    match parent {
        None => roots.push(node),
        Some(parent_id) => {
            if let Some(parent_node) = find_node_mut(roots, parent_id) {
                parent_node.children.push(node);
            }
        }
    }
}

fn append_at_path(
    roots: &mut Vec<NibHierarchyNode>,
    parent_path: &[usize],
    node: NibHierarchyNode,
) -> Vec<usize> {
    if parent_path.is_empty() {
        roots.push(node);
        return vec![roots.len() - 1];
    }

    let mut current = roots;
    for &index in parent_path {
        current = &mut current[index].children;
    }
    current.push(node);

    let mut node_path = parent_path.to_vec();
    node_path.push(current.len() - 1);
    node_path
}

fn find_node_mut<'a>(
    nodes: &'a mut [NibHierarchyNode],
    object_id: &str,
) -> Option<&'a mut NibHierarchyNode> {
    for node in nodes {
        if node.object_id == object_id {
            return Some(node);
        }
        if let Some(found) = find_node_mut(&mut node.children, object_id) {
            return Some(found);
        }
    }
    None
}

fn take_node(nodes: &mut Vec<NibHierarchyNode>, object_id: &str) -> Option<NibHierarchyNode> {
    if let Some(index) = nodes.iter().position(|node| node.object_id == object_id) {
        return Some(nodes.remove(index));
    }
    for node in nodes {
        if let Some(found) = take_node(&mut node.children, object_id) {
            return Some(found);
        }
    }
    None
}

fn would_cycle(child: &str, parent: &str, parents: &HashMap<String, String>) -> bool {
    let mut seen = HashSet::new();
    let mut current = Some(parent);
    while let Some(id) = current {
        if id == child {
            return true;
        }
        if !seen.insert(id) {
            return false;
        }
        current = parents.get(id).map(String::as_str);
    }
    false
}
