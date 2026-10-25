//! Ambient identity writes and escapes.
//!
//! This pass owns the source-local coverage used to invalidate global,
//! `import.meta`, and CommonJS identities.  Identity discovery is delegated to
//! [`identity_writes`]; this module supplies the lexical origin facts and
//! retains the resulting paths in the canonical property-path index.

use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::Rc;

use crate::javascript::ast::{Field, Node, NodeKey};
use rustc_hash::FxHashMap;

use super::ast_values::{is_member, static_property_key, unwrapped};
use super::identity_writes::{
    ElectronMemberPath, IdentityPath, IdentityWriteKind, JavaScriptIntrinsicInvocation,
    collect_identity_writes_steps, electron_member_path,
};
use super::iteration_sources::{IterationSourceKind, semantic_iteration_sources};
use super::module_interop;
use super::property_paths::{PropertyPath, PropertyPathKey, semantic_array_index_units};
use super::returned_references::{
    SemanticReturnedReferenceResult, create_semantic_returned_references,
};
use super::state::{ProjectionKey, SemanticState};
use super::value_types::JsString;

/// One source write retained with its exact ambient identity.
#[derive(Clone, Debug)]
pub struct AmbientWriteEffect<'a> {
    pub path: PropertyPath,
    pub node: Node<'a>,
}

#[derive(Clone, Debug)]
struct StoredAmbientPath<'a> {
    node: Node<'a>,
    member_path: Rc<ElectronMemberPath<'a>>,
    projection: PropertyPath,
    path: Option<PropertyPath>,
}

#[derive(Clone, Debug, Default)]
struct StoredAmbientPaths<'a> {
    entries: Vec<StoredAmbientPath<'a>>,
    source_to_entry: FxHashMap<usize, usize>,
    by_first: HashMap<PropertyPathKey, Vec<usize>>,
    wildcard: Vec<usize>,
    any: Vec<usize>,
}

impl<'a> StoredAmbientPaths<'a> {
    fn add_to_index(&mut self, index: usize, path: Option<&PropertyPath>) {
        let Some(path) = path.filter(|path| !path.is_empty()) else {
            insert_sorted_index(&mut self.any, index);
            return;
        };
        match path.first() {
            Some(PropertyPathKey::Wildcard) => insert_sorted_index(&mut self.wildcard, index),
            Some(first) => {
                insert_sorted_index(self.by_first.entry(first.clone()).or_default(), index)
            }
            None => insert_sorted_index(&mut self.any, index),
        }
    }

    fn remove_from_index(&mut self, index: usize, path: Option<&PropertyPath>) {
        let bucket = match path
            .filter(|path| !path.is_empty())
            .and_then(|path| path.first())
        {
            None => &mut self.any,
            Some(PropertyPathKey::Wildcard) => &mut self.wildcard,
            Some(first) => self.by_first.entry(first.clone()).or_default(),
        };
        bucket.retain(|candidate| *candidate != index);
    }

    fn update_index(
        &mut self,
        index: usize,
        previous: Option<&PropertyPath>,
        current: Option<&PropertyPath>,
    ) {
        self.remove_from_index(index, previous);
        self.add_to_index(index, current);
    }

    fn candidate_indices(&self, path: &PropertyPath) -> StoredCandidates<'_> {
        if path.is_empty() || matches!(path.first(), Some(PropertyPathKey::Wildcard)) {
            return StoredCandidates::all(self.entries.len());
        }

        StoredCandidates::indexed(
            &self.any,
            &self.wildcard,
            self.by_first
                .get(path.first().expect("non-empty path has a first key"))
                .map_or(&[], Vec::as_slice),
        )
    }
}

fn insert_sorted_index(indices: &mut Vec<usize>, index: usize) {
    let position = indices
        .binary_search(&index)
        .unwrap_or_else(|position| position);
    indices.insert(position, index);
}

enum StoredCandidates<'a> {
    All(std::ops::Range<usize>),
    Indexed([&'a [usize]; 3]),
}

impl<'a> StoredCandidates<'a> {
    fn all(entry_count: usize) -> Self {
        Self::All(0..entry_count)
    }

    fn indexed(any: &'a [usize], wildcard: &'a [usize], matching: &'a [usize]) -> Self {
        Self::Indexed([any, wildcard, matching])
    }

    fn next(&mut self) -> Option<usize> {
        match self {
            Self::All(range) => range.next_back(),
            Self::Indexed(buckets) => {
                let (bucket_index, candidate) = buckets
                    .iter()
                    .enumerate()
                    .filter_map(|(index, bucket)| bucket.last().map(|value| (index, *value)))
                    .max_by_key(|(_, candidate)| *candidate)?;
                let bucket = &mut buckets[bucket_index];
                *bucket = &bucket[..bucket.len() - 1];
                Some(candidate)
            }
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            Self::All(range) => range.is_empty(),
            Self::Indexed(buckets) => buckets.iter().all(|bucket| bucket.is_empty()),
        }
    }
}

#[derive(Clone, Debug)]
struct PendingEscape<'a> {
    target: Node<'a>,
    browser_receiver: bool,
    projection: Option<PropertyPath>,
    capture: Node<'a>,
}

/// Immutable AST facts shared by all ambient resolver invocations in one
/// analysis. Store projections, captures, and fixpoint generations remain
/// outside this cache because they affect semantic results. Parser-assigned
/// integer keys use the same bounded-key hasher as the resolver work maps.
#[derive(Default)]
struct MemberPathCache<'a> {
    member_paths: FxHashMap<NodeKey, Rc<ElectronMemberPath<'a>>>,
}

impl<'a> MemberPathCache<'a> {
    fn member_path(&mut self, source: &'a str, node: Node<'a>) -> &ElectronMemberPath<'a> {
        let path = self
            .member_paths
            .entry(node.key())
            .or_insert_with(|| Rc::new(electron_member_path(source, node)));
        Rc::as_ref(path)
    }

    fn member_path_handle(
        &mut self,
        source: &'a str,
        node: Node<'a>,
    ) -> Rc<ElectronMemberPath<'a>> {
        self.member_paths
            .entry(node.key())
            .or_insert_with(|| Rc::new(electron_member_path(source, node)))
            .clone()
    }
}

enum PendingWork<'source, 'stores> {
    Node {
        current: Node<'source>,
        suffix: Option<PropertyPath>,
        reads_at_self: bool,
    },
    StoredEdges {
        cursor: StoredEdgeCursor<'source, 'stores>,
    },
}

struct StoredEdgeCursor<'source, 'stores> {
    path: PropertyPath,
    stored_paths: &'stores StoredAmbientPaths<'source>,
    candidates: StoredCandidates<'stores>,
}

fn stored_path_selected(
    stored_path: Option<&PropertyPath>,
    query: &PropertyPath,
    escaped_contents: bool,
) -> bool {
    let selected = stored_path.is_none_or(|stored_path| {
        stored_path.iter().enumerate().all(|(index, key)| {
            index >= query.len()
                || key == &PropertyPathKey::Wildcard
                || query[index] == PropertyPathKey::Wildcard
                || key == &query[index]
        })
    });
    let too_short =
        stored_path.is_some_and(|stored_path| query.len() < stored_path.len() && !escaped_contents);
    selected && !too_short
}

impl<'source, 'stores> StoredEdgeCursor<'source, 'stores> {
    fn take_candidate(&mut self) -> Option<usize> {
        self.candidates.next()
    }

    fn requeue_remaining(self, pending: &mut Vec<PendingWork<'source, 'stores>>) {
        if !self.candidates.is_empty() {
            pending.push(PendingWork::StoredEdges { cursor: self });
        }
    }
}

fn queue_node<'source, 'stores>(
    pending: &mut Vec<PendingWork<'source, 'stores>>,
    current: Node<'source>,
    suffix: Option<PropertyPath>,
    reads_at_self: bool,
) {
    pending.push(PendingWork::Node {
        current,
        suffix,
        reads_at_self,
    });
}

fn schedule_next_stored_edge<'source, 'stores>(
    mut cursor: StoredEdgeCursor<'source, 'stores>,
    escaped_contents: bool,
    expanded: &FxHashMap<NodeKey, Option<PropertyPath>>,
    queued: &FxHashMap<NodeKey, Vec<PropertyPath>>,
    pending: &mut Vec<PendingWork<'source, 'stores>>,
) {
    // Rejected and duplicate candidates do not change `expanded` or `queued`,
    // so consume them locally. Requeue the cursor only after materializing the
    // first useful node; this retains the previous LIFO ordering while avoiding
    // one outer scheduler turn per skipped stored edge.
    while let Some(stored_index) = cursor.take_candidate() {
        let Some(stored) = cursor.stored_paths.entries.get(stored_index) else {
            continue;
        };
        let path_len = cursor.path.len();
        if !stored_path_selected(stored.path.as_ref(), &cursor.path, escaped_contents) {
            continue;
        }

        let next = {
            let remaining = stored
                .path
                .as_ref()
                .filter(|stored_path| path_len >= stored_path.len())
                .map_or(&[][..], |stored_path| &cursor.path[stored_path.len()..]);
            let stored_member_path = stored.member_path.as_ref();
            let stored_root_key = stored_member_path.root.key();
            let duplicate = queued_stored_projection_matches(
                stored_member_path,
                expanded.get(&stored_root_key),
                queued.get(&stored_root_key),
                &stored.projection,
                remaining,
            );
            if duplicate {
                None
            } else {
                let mut next = stored.projection.clone();
                next.extend(remaining.iter().cloned());
                Some(next)
            }
        };

        let Some(next) = next else {
            continue;
        };
        let current = stored.node;
        cursor.requeue_remaining(pending);
        pending.push(PendingWork::Node {
            current,
            suffix: Some(next),
            reads_at_self: true,
        });
        return;
    }
}

fn queued_stored_projection_matches(
    member_path: &ElectronMemberPath<'_>,
    expanded: Option<&Option<PropertyPath>>,
    queued: Option<&Vec<PropertyPath>>,
    projection: &PropertyPath,
    remaining: &[PropertyPathKey],
) -> bool {
    let Some(queued) = queued else {
        return false;
    };
    let candidate_len = member_path.members.len() + projection.len() + remaining.len();
    let Some(expanded) = expanded else {
        return false;
    };
    let Some(previous) = expanded else {
        return queued.iter().any(|path| path.is_empty());
    };
    if previous.len() != candidate_len {
        // A length change widens the stored projection to unknown. Let the
        // normal resolver update `expanded` before applying its queue guard.
        return false;
    }

    let unchanged = previous.iter().enumerate().all(|(index, previous_key)| {
        if *previous_key == PropertyPathKey::Wildcard {
            return true;
        }
        if let Some(member) = member_path.members.get(index) {
            return match (member, previous_key) {
                (Some(name), PropertyPathKey::String(previous_name)) => name == previous_name,
                (None, PropertyPathKey::Wildcard) => true,
                _ => false,
            };
        }
        let projection_index = index - member_path.members.len();
        if let Some(key) = projection.get(projection_index) {
            return key == previous_key;
        }
        remaining[index - member_path.members.len() - projection.len()] == *previous_key
    });
    unchanged && queued.iter().any(|queued_path| queued_path == previous)
}

/// Collapse repeated global-object aliases while preserving dynamic segments.
pub fn canonical_ambient_path(path: &[PropertyPathKey]) -> PropertyPath {
    let Some(PropertyPathKey::String(root)) = path.first() else {
        return path.to_vec();
    };
    if root != "global" {
        return path.to_vec();
    }
    let mut result = vec![PropertyPathKey::String(root.clone())];
    let mut index = 1;
    while index < path.len()
        && matches!(&path[index], PropertyPathKey::String(name) if global_alias_key(name))
    {
        index += 1;
    }
    result.extend(path[index..].iter().cloned());

    if result.len() >= 4
        && result[2] == PropertyPathKey::String(JsString::from("prototype"))
        && result[3] == PropertyPathKey::String(JsString::from("constructor"))
    {
        result.splice(2..4, std::iter::empty());
    }

    result
}

/// Join two projections, widening only conflicting components.
pub fn join_ambient_projection(
    left: Option<&PropertyPath>,
    right: Option<&PropertyPath>,
) -> Option<PropertyPath> {
    let (Some(left), Some(right)) = (left, right) else {
        return None;
    };
    if left.len() != right.len() {
        return None;
    }
    Some(
        left.iter()
            .zip(right)
            .map(|(left, right)| {
                if left == right {
                    left.clone()
                } else {
                    PropertyPathKey::Wildcard
                }
            })
            .collect(),
    )
}

/// Convert an identity path's nullable components into the canonical path
/// representation.  Dynamic identity segments remain wildcards.
fn property_path(path: &IdentityPath) -> PropertyPath {
    path.iter()
        .map(|segment| match segment {
            Some(value) => PropertyPathKey::String(value.clone()),
            None => PropertyPathKey::Wildcard,
        })
        .collect()
}

fn pending_target_id(path: &PropertyPath) -> Option<usize> {
    let [
        PropertyPathKey::String(marker),
        PropertyPathKey::String(id),
        ..,
    ] = path.as_slice()
    else {
        return None;
    };
    (marker == "pending-target")
        .then(|| id.as_str()?.parse::<usize>().ok())
        .flatten()
}

fn retain_unique_path(result: &mut Vec<PropertyPath>, path: PropertyPath) {
    if !result.contains(&path) {
        result.push(path);
    }
}

fn global_alias(name: &str) -> bool {
    matches!(name, "globalThis" | "global" | "window" | "self")
}

fn global_alias_key(name: &JsString) -> bool {
    name == "globalThis" || name == "global" || name == "window" || name == "self"
}

fn is_import_meta<'a>(state: &SemanticState<'a>, node: Node<'a>) -> bool {
    let node = unwrapped(state.source, node);
    node.babel_type() == "MetaProperty"
        && state
            .source
            .get(node.span().start as usize..node.span().end as usize)
            == Some("import.meta")
}

fn origin_path<'a>(
    state: &SemanticState<'a>,
    node: Node<'a>,
    kind: IdentityWriteKind,
) -> Option<IdentityPath> {
    let member = electron_member_path(state.source, node);

    if matches!(
        member.root.babel_type(),
        "CallExpression" | "OptionalCallExpression"
    ) {
        let callee = member.root.field(state.source, Field::Callee)?;
        let callee = electron_member_path(state.source, callee);
        if matches!(callee.root.identifier_name(), Some("Object" | "Reflect"))
            && callee.members.len() == 1
            && callee.members[0]
                .as_ref()
                .is_some_and(|name| name == "getPrototypeOf")
            && callee
                .root
                .identifier_name()
                .is_some_and(|name| state.is_unshadowed_global(&callee.root, name))
        {
            let argument = member
                .root
                .field_list(state.source, Field::Arguments)
                .into_iter()
                .flatten()
                .next()?;
            let mut path = origin_path(state, argument, kind)?;
            path.push(Some(JsString::from("__proto__")));
            path.extend(member.members.into_iter().map(|member| member));
            return Some(path);
        }
    }

    let root = unwrapped(state.source, member.root);
    let members = member
        .members
        .into_iter()
        .map(|member| member)
        .collect::<Vec<_>>();

    if is_import_meta(state, root) {
        return Some(
            std::iter::once(Some(JsString::from("import-meta")))
                .chain(members)
                .collect(),
        );
    }

    let name = root.identifier_name()?;
    if state.is_unshadowed_global(&root, "module") && name == "module" {
        return Some(
            std::iter::once(Some(JsString::from("commonjs-module")))
                .chain(members)
                .collect(),
        );
    }
    if global_alias(name) && state.is_unshadowed_global(&root, name) {
        return Some(
            std::iter::once(Some(JsString::from("global")))
                .chain(members)
                .collect(),
        );
    }

    // A bare unshadowed global is an ambient identity.  Member writes retain
    // the member suffix, while opaque calls are represented by the global
    // root so callers can conservatively invalidate its descendants.
    if matches!(kind, IdentityWriteKind::Binding | IdentityWriteKind::Member)
        && state.is_unshadowed_global(&root, name)
    {
        return Some(
            std::iter::once(Some(JsString::from("global")))
                .chain(std::iter::once(Some(JsString::from(name))))
                .chain(members)
                .collect(),
        );
    }
    None
}

/// Resolve source-local ambient identities through aliases and projections.
/// The queue joins projections per producer node, so alias diamonds and
/// cycles terminate without enumerating every history.
pub fn resolve_ambient_paths<'source, 'state>(
    state: &'state SemanticState<'source>,
    node: Node<'source>,
    possible_writes: bool,
    projection: Option<PropertyPath>,
    capture: Option<Node<'source>>,
    escaped_contents: bool,
) -> Vec<PropertyPath> {
    let mut returned_references = create_semantic_returned_references(state);
    let mut structural_facts = MemberPathCache::default();
    resolve_ambient_paths_with_stores(
        state,
        node,
        possible_writes,
        projection,
        capture,
        escaped_contents,
        None,
        None,
        &mut returned_references,
        &mut structural_facts,
    )
}

fn resolve_ambient_paths_with_stores<'source, 'state, F>(
    state: &'state SemanticState<'source>,
    node: Node<'source>,
    possible_writes: bool,
    projection: Option<PropertyPath>,
    capture: Option<Node<'source>>,
    escaped_contents: bool,
    stores: Option<&FxHashMap<NodeKey, StoredAmbientPaths<'source>>>,
    mut local_identities: Option<&mut Vec<(Node<'source>, PropertyPath)>>,
    returned_references: &mut F,
    structural_facts: &mut MemberPathCache<'source>,
) -> Vec<PropertyPath>
where
    F: FnMut(Node<'source>) -> SemanticReturnedReferenceResult<'source>,
{
    let mut pending = vec![PendingWork::Node {
        current: node,
        suffix: projection,
        reads_at_self: false,
    }];
    // NodeKey contains parser-assigned integer IDs and a two-value role. It
    // cannot contain caller-controlled strings, so the faster integer-keyed
    // hasher is safe for these local traversal maps. Path and string maps keep
    // the standard randomized hasher.
    let mut expanded = FxHashMap::<NodeKey, Option<PropertyPath>>::default();
    // Keep the root keyed by itself and compare projections directly. Hashing
    // every property key dominated this loop for large applications, while a
    // root usually has only a few distinct projections.
    let mut queued = FxHashMap::<NodeKey, Vec<PropertyPath>>::default();
    let mut result = Vec::new();

    while let Some(work) = pending.pop() {
        let (current, suffix, reads_at_self) = match work {
            PendingWork::Node {
                current,
                suffix,
                reads_at_self,
            } => (current, suffix, reads_at_self),
            PendingWork::StoredEdges { cursor } => {
                schedule_next_stored_edge(
                    cursor,
                    escaped_contents,
                    &expanded,
                    &queued,
                    &mut pending,
                );
                continue;
            }
        };
        let member_path = structural_facts.member_path(state.source, current);
        let root = member_path.root;
        let mut path = member_path
            .members
            .iter()
            .map(|member| {
                member.as_ref().map_or(PropertyPathKey::Wildcard, |value| {
                    PropertyPathKey::String(value.clone())
                })
            })
            .collect::<PropertyPath>();
        if let Some(suffix) = suffix {
            path.extend(suffix);
        }
        let joined = match expanded.get(&root.key()) {
            None => Some(path.clone()),
            Some(Some(previous)) if previous.len() == path.len() => Some(
                previous
                    .iter()
                    .zip(&path)
                    .map(|(left, right)| {
                        if left == right {
                            left.clone()
                        } else {
                            PropertyPathKey::Wildcard
                        }
                    })
                    .collect(),
            ),
            Some(_) => None,
        };
        if expanded.contains_key(&root.key()) && !possible_writes {
            return Vec::new();
        }
        expanded.insert(root.key(), joined.clone());
        // `None` is the TS resolver's unknown projection. It still retains
        // the source identity at its root; dropping it would turn a
        // conflicting alias into an unsound absence claim.
        let path = joined.unwrap_or_default();
        let queued_paths = queued.entry(root.key()).or_default();
        if queued_paths.iter().any(|queued_path| queued_path == &path) {
            continue;
        }
        queued_paths.push(path.clone());

        if is_import_meta(state, root) {
            retain_unique_path(
                &mut result,
                canonical_ambient_path(
                    &[
                        vec![PropertyPathKey::String(JsString::from("import-meta"))],
                        path,
                    ]
                    .concat(),
                ),
            );
            continue;
        }

        if let Some(name) = root.identifier_name() {
            if name == "module" && state.is_unshadowed_global(&root, "module") {
                retain_unique_path(
                    &mut result,
                    canonical_ambient_path(
                        &[
                            vec![PropertyPathKey::String(JsString::from("commonjs-module"))],
                            path,
                        ]
                        .concat(),
                    ),
                );
                continue;
            }
            if global_alias(name) && state.is_unshadowed_global(&root, name) {
                retain_unique_path(
                    &mut result,
                    canonical_ambient_path(
                        &[
                            vec![PropertyPathKey::String(JsString::from("global"))],
                            path,
                        ]
                        .concat(),
                    ),
                );
                continue;
            }
            if state.is_unshadowed_global(&root, name) {
                retain_unique_path(
                    &mut result,
                    canonical_ambient_path(
                        &[
                            vec![
                                PropertyPathKey::String(JsString::from("global")),
                                PropertyPathKey::String(JsString::from(name)),
                            ],
                            path,
                        ]
                        .concat(),
                    ),
                );
                continue;
            }
            if let Some(binding) = state.resolve_binding(&root, name) {
                let initializers = if possible_writes {
                    let read = if reads_at_self { Some(root) } else { capture };
                    let selected = read.map(|read| {
                        state
                            .semantic_binding_at_read(&state.bindings[binding], read)
                            .binding
                    });
                    selected
                        .unwrap_or_else(|| state.bindings[binding].clone())
                        .initializers
                } else {
                    state
                        .stable_initializer(binding)
                        .into_iter()
                        .cloned()
                        .collect::<Vec<_>>()
                };
                for initializer in &initializers {
                    let mut next = initializer
                        .projection
                        .iter()
                        .map(|key| match key {
                            ProjectionKey::Name(name) => PropertyPathKey::String(name.clone()),
                            ProjectionKey::Index(index) => PropertyPathKey::Number(*index),
                            ProjectionKey::Dynamic => PropertyPathKey::Wildcard,
                        })
                        .collect::<PropertyPath>();
                    next.extend(path.clone());
                    queue_node(&mut pending, initializer.node, Some(next), true);
                }
                if !initializers.is_empty() {
                    continue;
                }
            }
        }

        if is_member(&root) {
            continue;
        }
        if possible_writes
            && root.identifier_name().is_none()
            && module_interop::is_fresh_object(state, root)
        {
            if let Some(local_identities) = local_identities.as_mut() {
                (**local_identities).push((root, path.clone()));
            }
            if let Some(stored_paths) = stores.and_then(|stores| stores.get(&root.key())) {
                let candidates = stored_paths.candidate_indices(&path);
                pending.push(PendingWork::StoredEdges {
                    cursor: StoredEdgeCursor {
                        path: path.clone(),
                        stored_paths,
                        candidates,
                    },
                });
            }
        }
        if possible_writes
            && escaped_contents
            && path.is_empty()
            && matches!(root.babel_type(), "ObjectExpression" | "ArrayExpression")
        {
            let field = if root.babel_type() == "ObjectExpression" {
                Field::Properties
            } else {
                Field::Elements
            };
            for child in root.field_list(state.source, field).into_iter().flatten() {
                let child = if child.babel_type() == "SpreadElement" {
                    child.field(state.source, Field::Argument)
                } else if child.babel_type() == "ObjectProperty" {
                    child.field(state.source, Field::Value)
                } else {
                    Some(child)
                };
                if let Some(child) = child {
                    queue_node(&mut pending, child, Some(path.clone()), reads_at_self);
                }
            }
        }
        match root.babel_type() {
            "FunctionDeclaration"
            | "FunctionExpression"
            | "ArrowFunctionExpression"
            | "ObjectMethod"
            | "ClassMethod"
            | "ClassPrivateMethod"
                if possible_writes && escaped_contents =>
            {
                for reference in returned_references(root).references {
                    let mut projected = reference.projection;
                    projected.extend(path.clone());
                    queue_node(&mut pending, reference.node, Some(projected), reads_at_self);
                }
            }
            "ConditionalExpression" | "LogicalExpression" => {
                for field in [
                    Field::Consequent,
                    Field::Alternate,
                    Field::Left,
                    Field::Right,
                ] {
                    if let Some(child) = root.field(state.source, field) {
                        queue_node(&mut pending, child, Some(path.clone()), reads_at_self);
                    }
                }
            }
            "SequenceExpression" => {
                if let Some(child) = root
                    .field_list(state.source, Field::Expressions)
                    .into_iter()
                    .flatten()
                    .last()
                {
                    queue_node(&mut pending, child, Some(path), reads_at_self);
                }
            }
            "AssignmentExpression" if possible_writes && root.operator() == Some("=") => {
                if let Some(right) = root.field(state.source, Field::Right) {
                    queue_node(&mut pending, right, Some(path), reads_at_self);
                }
            }
            "CallExpression" | "OptionalCallExpression" | "NewExpression" if possible_writes => {
                if root.babel_type() == "NewExpression"
                    && path.first().is_some_and(|key| {
                        matches!(
                            key,
                            PropertyPathKey::String(name)
                                if name == "__proto__" || name == "constructor"
                        )
                    })
                    && let Some(callee) = root.field(state.source, Field::Callee)
                {
                    queue_node(&mut pending, callee, Some(path.clone()), reads_at_self);
                }
                if root.babel_type() != "NewExpression" {
                    let intrinsic =
                        module_interop::intrinsic_path(state, root).is_some_and(|path| {
                            path.last().map(String::as_str) == Some("getPrototypeOf")
                        });
                    let direct_object_get_prototype = root
                        .field(state.source, Field::Callee)
                        .map(|callee| electron_member_path(state.source, callee))
                        .is_some_and(|callee| {
                            matches!(callee.root.identifier_name(), Some("Object" | "Reflect"))
                                && callee.members.len() == 1
                                && callee.members[0]
                                    .as_ref()
                                    .is_some_and(|name| name == "getPrototypeOf")
                                && callee.root.identifier_name().is_some_and(|name| {
                                    state.is_unshadowed_global(&callee.root, name)
                                })
                        });
                    if (intrinsic || direct_object_get_prototype)
                        && let Some(argument) = root
                            .field_list(state.source, Field::Arguments)
                            .into_iter()
                            .flatten()
                            .next()
                    {
                        let argument_path = if intrinsic || direct_object_get_prototype {
                            std::iter::once(PropertyPathKey::String(JsString::from("__proto__")))
                                .chain(path.iter().cloned())
                                .collect()
                        } else {
                            path.clone()
                        };
                        queue_node(&mut pending, argument, Some(argument_path), reads_at_self);
                    }
                }
                if let Some(callee) = root.field(state.source, Field::Callee) {
                    let mut returned = returned_references(callee).references;
                    returned.extend(direct_callable_results(state, callee));
                    for reference in returned {
                        let mut projected = reference.projection;
                        projected.extend(path.clone());
                        queue_node(&mut pending, reference.node, Some(projected), reads_at_self);
                    }
                }
            }
            "TaggedTemplateExpression" if possible_writes => {
                if let Some(tag) = root.field(state.source, Field::Callee) {
                    let mut returned = returned_references(tag).references;
                    returned.extend(direct_callable_results(state, tag));
                    for reference in returned {
                        let mut projected = reference.projection;
                        projected.extend(path.clone());
                        queue_node(&mut pending, reference.node, Some(projected), reads_at_self);
                    }
                }
            }
            "ObjectExpression" if possible_writes => {
                let key = path.first();
                for property in root
                    .field_list(state.source, Field::Properties)
                    .into_iter()
                    .flatten()
                {
                    if property.babel_type() == "SpreadElement" {
                        // Object spread copies values into a fresh object; it
                        // does not preserve the source object's identity.
                        continue;
                    }
                    if property.babel_type() != "ObjectProperty" {
                        continue;
                    }
                    let Some(value) = property.field(state.source, Field::Value) else {
                        continue;
                    };
                    if value.babel_type() == "Identifier"
                        && state
                            .resolve_binding(&value, value.identifier_name().unwrap_or_default())
                            .is_some_and(|binding| state.stable_initializer(binding).is_none())
                    {
                        // A literal captures a shorthand binding at creation.
                        // Do not link a later assignment back into that copy.
                        continue;
                    }
                    let Some(property_key) = property.field(state.source, Field::Key) else {
                        continue;
                    };
                    let static_key =
                        static_property_key(state.source, property_key, property.computed());
                    if static_key.as_ref().is_some_and(|key| key == "__proto__") {
                        // The literal's prototype is an object-internal
                        // relationship; assigning an own property on the
                        // literal does not write through to that prototype.
                        continue;
                    }
                    if key.is_none()
                        || matches!(key, Some(PropertyPathKey::Wildcard))
                        || matches!(
                            (static_key.as_ref(), key),
                            (Some(candidate), Some(PropertyPathKey::String(expected)))
                                if candidate == expected
                        )
                    {
                        let suffix = if key.is_some() && static_key.is_some() {
                            path[1..].to_vec()
                        } else {
                            path.clone()
                        };
                        queue_node(&mut pending, value, Some(suffix), reads_at_self);
                    }
                }
            }
            "ArrayExpression" if possible_writes => {
                let key = path.first();
                let elements = root
                    .field_list(state.source, Field::Elements)
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();
                for (index, element) in elements.into_iter().enumerate() {
                    if element.babel_type() == "SpreadElement" {
                        if let Some(argument) = element.field(state.source, Field::Argument) {
                            queue_node(&mut pending, argument, Some(path.clone()), reads_at_self);
                        }
                        continue;
                    }
                    let selected = match key {
                        None | Some(PropertyPathKey::Wildcard) => true,
                        Some(PropertyPathKey::Number(value)) => *value == index,
                        Some(PropertyPathKey::String(value)) => {
                            semantic_array_index_units(value) == Some(index)
                        }
                        _ => false,
                    };
                    if selected {
                        let suffix =
                            if key.is_some() && !matches!(key, Some(PropertyPathKey::Wildcard)) {
                                path[1..].to_vec()
                            } else {
                                path.clone()
                            };
                        queue_node(&mut pending, element, Some(suffix), reads_at_self);
                    }
                }
            }
            "ObjectExpression" if !possible_writes => {
                let Some(PropertyPathKey::String(key)) = path.first() else {
                    continue;
                };
                for property in root
                    .field_list(state.source, Field::Properties)
                    .into_iter()
                    .flatten()
                    .rev()
                {
                    if property.babel_type() != "ObjectProperty" {
                        continue;
                    }
                    let Some(property_key) = property.field(state.source, Field::Key) else {
                        continue;
                    };
                    if static_property_key(state.source, property_key, property.computed())
                        .is_some_and(|property_key| property_key == *key)
                    {
                        if let Some(value) = property.field(state.source, Field::Value) {
                            queue_node(
                                &mut pending,
                                value,
                                Some(path[1..].to_vec()),
                                reads_at_self,
                            );
                        }
                        break;
                    }
                }
            }
            "ArrayExpression" if !possible_writes => {
                let Some(key) = path.first() else { continue };
                let index = match key {
                    PropertyPathKey::Number(index) => *index,
                    PropertyPathKey::String(value) => {
                        let Some(index) = semantic_array_index_units(value) else {
                            continue;
                        };
                        index
                    }
                    _ => continue,
                };
                let elements = root
                    .field_list(state.source, Field::Elements)
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();
                if elements
                    .iter()
                    .any(|element| element.babel_type() == "SpreadElement")
                {
                    continue;
                }
                if let Some(element) = elements.get(index).copied() {
                    queue_node(
                        &mut pending,
                        element,
                        Some(path[1..].to_vec()),
                        reads_at_self,
                    );
                }
            }
            "SpreadElement" => {
                if let Some(argument) = root.field(state.source, Field::Argument) {
                    queue_node(&mut pending, argument, Some(path), reads_at_self);
                }
            }
            "ObjectProperty" if possible_writes => {
                if let Some(value) = root.field(state.source, Field::Value) {
                    queue_node(&mut pending, value, Some(path), reads_at_self);
                }
            }
            _ => {}
        }
    }
    result
}

fn direct_callable_results<'a>(
    state: &SemanticState<'a>,
    callee: Node<'a>,
) -> Vec<super::returned_references::SemanticReturnedReference<'a>> {
    let mut candidates = vec![unwrapped(state.source, callee)];
    if let Some(name) = callee.identifier_name()
        && let Some(binding) = state.resolve_binding(&callee, name)
    {
        candidates.extend(
            state.bindings[binding]
                .initializers
                .iter()
                .map(|initializer| initializer.node),
        );
    }

    let mut results = Vec::new();
    for candidate in candidates.into_iter().filter(|candidate| {
        matches!(
            candidate.babel_type(),
            "FunctionDeclaration"
                | "FunctionExpression"
                | "ArrowFunctionExpression"
                | "ObjectMethod"
                | "ClassMethod"
                | "ClassPrivateMethod"
        )
    }) {
        results.extend(
            state
                .callable_result_expressions(&candidate)
                .iter()
                .filter_map(|result| {
                    result.node.map(
                        |node| super::returned_references::SemanticReturnedReference {
                            node,
                            projection: if result.delegated {
                                vec![PropertyPathKey::Wildcard]
                            } else {
                                Vec::new()
                            },
                        },
                    )
                }),
        );
    }
    results
}

fn resolve_pending_write_effects<'a>(
    state: &SemanticState<'a>,
    pending_writes: Vec<(usize, Node<'a>, PropertyPath)>,
    pending_targets: &[(Node<'a>, Node<'a>)],
    stores: &FxHashMap<NodeKey, StoredAmbientPaths<'a>>,
    returned_references: &mut impl FnMut(Node<'a>) -> SemanticReturnedReferenceResult<'a>,
    structural_facts: &mut MemberPathCache<'a>,
    writes: &mut Vec<AmbientWriteEffect<'a>>,
) {
    for (target_id, node, suffix) in pending_writes {
        let Some((target, capture)) = pending_targets.get(target_id).copied() else {
            continue;
        };
        for identity in resolve_ambient_paths_with_stores(
            state,
            target,
            true,
            None,
            Some(capture),
            false,
            Some(stores),
            None,
            returned_references,
            structural_facts,
        ) {
            let mut path = identity;
            path.extend(suffix.iter().cloned());
            writes.push(AmbientWriteEffect { path, node });
        }
    }
}

fn collect_stored_escapes<'a>(
    state: &SemanticState<'a>,
    source: &'a str,
    stored_references: &[super::iteration_sources::SemanticIterationSource<'a>],
    stores: &FxHashMap<NodeKey, StoredAmbientPaths<'a>>,
    returned_references: &mut impl FnMut(Node<'a>) -> SemanticReturnedReferenceResult<'a>,
    structural_facts: &mut MemberPathCache<'a>,
    pending_escapes: &mut Vec<PendingEscape<'a>>,
) {
    for stored in stored_references {
        let Some(target) = stored.target else {
            continue;
        };
        let Some(object) = target.field(source, Field::Object) else {
            continue;
        };
        let mut local_identities = Vec::new();
        let ambient = resolve_ambient_paths_with_stores(
            state,
            object,
            true,
            None,
            Some(stored.mutation),
            false,
            Some(stores),
            Some(&mut local_identities),
            returned_references,
            structural_facts,
        );
        if local_identities.is_empty() || !ambient.is_empty() {
            pending_escapes.push(PendingEscape {
                target: stored.node,
                browser_receiver: false,
                projection: Some(stored.projection.clone()),
                capture: stored.mutation,
            });
        }
    }
}

fn publish_pending_escapes<'a>(
    state: &SemanticState<'a>,
    pending_escapes: Vec<PendingEscape<'a>>,
    stores: &FxHashMap<NodeKey, StoredAmbientPaths<'a>>,
    returned_references: &mut impl FnMut(Node<'a>) -> SemanticReturnedReferenceResult<'a>,
    structural_facts: &mut MemberPathCache<'a>,
    escapes: &mut Vec<PropertyPath>,
) {
    for pending in pending_escapes {
        let mut paths = resolve_ambient_paths_with_stores(
            state,
            pending.target,
            true,
            pending.projection,
            Some(pending.capture),
            true,
            Some(stores),
            None,
            returned_references,
            structural_facts,
        );
        if paths.is_empty() {
            paths = origin_path(state, pending.target, IdentityWriteKind::Member)
                .into_iter()
                .map(|path| property_path(&path))
                .collect();
        }
        for mut path in paths {
            if pending.browser_receiver
                && path.len() == 1
                && path[0] == PropertyPathKey::String(JsString::from("global"))
            {
                continue;
            }
            path.push(PropertyPathKey::Wildcard);
            escapes.push(path);
        }
    }
}

/// Queries observed by each stored source, retained for this fixpoint only.
/// A missing projection means that different query lengths were observed;
/// every change must then be considered. Observations only widen, so an
/// earlier dependency cannot disappear during a later source evaluation.
#[derive(Default)]
struct StoreDependents {
    queries: FxHashMap<NodeKey, FxHashMap<usize, Option<PropertyPath>>>,
}

impl StoreDependents {
    fn observe(&mut self, root: NodeKey, source_index: usize, query: &PropertyPath) {
        self.queries
            .entry(root)
            .or_default()
            .entry(source_index)
            .and_modify(|previous| {
                *previous = join_ambient_projection(previous.as_ref(), Some(query));
            })
            .or_insert_with(|| Some(query.clone()));
    }

    fn queue_affected(
        &self,
        root: NodeKey,
        change: &StoredPathChange,
        queued: &mut HashSet<usize>,
        pending: &mut VecDeque<usize>,
    ) {
        for (source_index, query) in self.queries.get(&root).into_iter().flatten() {
            let affected = query.as_ref().is_none_or(|query| change.affects(query));
            if affected && queued.insert(*source_index) {
                pending.push_back(*source_index);
            }
        }
    }
}

struct StoredPathChange {
    // Unknown stored paths are absorbing, so they never produce another
    // change. Here `None` denotes a newly inserted entry with no prior path.
    previous: Option<PropertyPath>,
    current: Option<PropertyPath>,
}

impl StoredPathChange {
    fn affects(&self, query: &PropertyPath) -> bool {
        stored_path_selected(self.current.as_ref(), query, false)
            || self
                .previous
                .as_ref()
                .is_some_and(|previous| stored_path_selected(Some(previous), query, false))
    }
}

fn record_stored_source<'a>(
    entries: &mut StoredAmbientPaths<'a>,
    source_index: usize,
    source: &super::iteration_sources::SemanticIterationSource<'a>,
    path: PropertyPath,
    source_text: &'a str,
    structural_facts: &mut MemberPathCache<'a>,
) -> Option<StoredPathChange> {
    let Some(existing_index) = entries.source_to_entry.get(&source_index).copied() else {
        let inserted_index = entries.entries.len();
        entries.entries.push(StoredAmbientPath {
            node: source.node,
            member_path: structural_facts.member_path_handle(source_text, source.node),
            projection: source.projection.clone(),
            path: Some(path.clone()),
        });
        entries.source_to_entry.insert(source_index, inserted_index);
        entries.add_to_index(inserted_index, Some(&path));
        return Some(StoredPathChange {
            previous: None,
            current: Some(path),
        });
    };

    let previous = entries.entries[existing_index].path.as_ref()?;
    let current = join_ambient_projection(Some(previous), Some(&path));
    if current.as_ref() == Some(previous) {
        return None;
    }

    let previous = previous.clone();
    entries.entries[existing_index].path = current.clone();
    entries.update_index(existing_index, Some(&previous), current.as_ref());
    Some(StoredPathChange {
        previous: Some(previous),
        current,
    })
}

fn resolve_stored_references<'a>(
    state: &SemanticState<'a>,
    stored_references: &[super::iteration_sources::SemanticIterationSource<'a>],
    returned_references: &mut impl FnMut(Node<'a>) -> SemanticReturnedReferenceResult<'a>,
    structural_facts: &mut MemberPathCache<'a>,
) -> FxHashMap<NodeKey, StoredAmbientPaths<'a>> {
    let mut stores = FxHashMap::<NodeKey, StoredAmbientPaths<'a>>::default();
    let mut dependents = StoreDependents::default();
    let mut pending_stores = VecDeque::from_iter(0..stored_references.len());
    let mut queued_stores = (0..stored_references.len()).collect::<HashSet<_>>();

    while let Some(source_index) = pending_stores.pop_front() {
        queued_stores.remove(&source_index);
        let Some(source) = stored_references.get(source_index) else {
            continue;
        };
        let Some(target) = source.target else {
            continue;
        };
        let mut identities = Vec::new();
        let _ = resolve_ambient_paths_with_stores(
            state,
            target,
            true,
            None,
            Some(source.mutation),
            false,
            Some(&stores),
            Some(&mut identities),
            returned_references,
            structural_facts,
        );

        for (node, path) in identities {
            dependents.observe(node.key(), source_index, &path);
            let entries = stores.entry(node.key()).or_default();
            let Some(change) = record_stored_source(
                entries,
                source_index,
                source,
                path,
                state.source,
                structural_facts,
            ) else {
                continue;
            };
            dependents.queue_affected(node.key(), &change, &mut queued_stores, &mut pending_stores);
        }
    }

    stores
}

/// Index ambient writes for a completed definitions state.
pub fn index_ambient_writes<'a>(state: &mut SemanticState<'a>) {
    let source = state.source;
    let program = state.program;
    let mut writes = Vec::<AmbientWriteEffect<'a>>::new();
    let mut pending_targets = Vec::<(Node<'a>, Node<'a>)>::new();
    let mut pending_writes = Vec::<(usize, Node<'a>, PropertyPath)>::new();
    let mut pending_escapes = Vec::<PendingEscape<'a>>::new();
    let mut stored_sites = HashSet::<NodeKey>::new();
    let mut stored_references = Vec::new();
    let mut escapes = Vec::<PropertyPath>::new();
    let mut assignment_escapes = Vec::<PropertyPath>::new();
    let mut returned_references = create_semantic_returned_references(state);
    let mut structural_facts = MemberPathCache::default();

    let _ = collect_identity_writes_steps(
        program,
        source,
        |node, kind, site| {
            if kind == IdentityWriteKind::Member {
                if stored_sites.insert(site.key()) {
                    for source in semantic_iteration_sources(source, site, state.parent_of(&site)) {
                        if source.kind == IterationSourceKind::ReferenceStore {
                            stored_references.push(source);
                        }
                    }
                }
                let target_id = pending_targets.len();
                pending_targets.push((node, site));
                return vec![vec![
                    Some(JsString::from("pending-target")),
                    Some(JsString::from(target_id.to_string())),
                ]];
            }
            origin_path(state, node, kind).into_iter().collect()
        },
        |node| {
            module_interop::intrinsic_path(state, node).map(|path| JavaScriptIntrinsicInvocation {
                kind: super::identity_writes::IntrinsicInvocationKind::Known,
                receiver: None,
                path,
                arguments: Some(
                    node.field_list(source, Field::Arguments)
                        .into_iter()
                        .flatten()
                        .collect(),
                ),
            })
        },
        |node| module_interop::static_string(state, node),
        |node| module_interop::is_fresh_object(state, node),
        |node, path| {
            if is_object_proto_property(source, node) {
                return;
            }
            let path = property_path(&path);
            if let Some(target_id) = pending_target_id(&path) {
                pending_writes.push((target_id, node, path[2..].to_vec()));
                return;
            }
            if node.babel_type() == "AssignmentExpression"
                && let Some(right) = node.field(source, Field::Right)
                && let Some(name) = right.identifier_name()
            {
                let mut escape = path.clone();
                escape.push(PropertyPathKey::String(JsString::from(name)));
                escape.push(PropertyPathKey::Wildcard);
                assignment_escapes.push(escape);
            }
            writes.push(AmbientWriteEffect { path, node });
        },
        |node, invocation| {
            let arguments = node
                .field_list(source, Field::Arguments)
                .into_iter()
                .flatten();
            for argument in arguments {
                let argument = unwrapped(source, argument);
                pending_escapes.push(PendingEscape {
                    target: argument,
                    browser_receiver: false,
                    projection: None,
                    capture: node,
                });
            }
            if let Some(invocation) = invocation
                && matches!(
                    invocation.path.last().map(String::as_str),
                    Some("open" | "fetch")
                )
                && let Some(receiver) = invocation.receiver
            {
                pending_escapes.push(PendingEscape {
                    target: receiver,
                    browser_receiver: true,
                    projection: None,
                    capture: node,
                });
            }
            let Some(callee) = node.field(source, Field::Callee) else {
                return;
            };
            let callee = unwrapped(source, callee);
            if let Some(object) = callee.field(source, Field::Object) {
                let is_object_or_reflect = invocation.is_some_and(|invocation| {
                    matches!(
                        invocation.path.as_slice(),
                        [_, owner, _] if owner == "Object" || owner == "Reflect"
                    )
                });
                if !is_object_or_reflect {
                    pending_escapes.push(PendingEscape {
                        target: unwrapped(source, object),
                        browser_receiver: false,
                        projection: None,
                        capture: node,
                    });
                }
            }
        },
    );

    let stores = resolve_stored_references(
        state,
        &stored_references,
        &mut returned_references,
        &mut structural_facts,
    );

    resolve_pending_write_effects(
        state,
        pending_writes,
        &pending_targets,
        &stores,
        &mut returned_references,
        &mut structural_facts,
        &mut writes,
    );

    collect_stored_escapes(
        state,
        source,
        &stored_references,
        &stores,
        &mut returned_references,
        &mut structural_facts,
        &mut pending_escapes,
    );
    publish_pending_escapes(
        state,
        pending_escapes,
        &stores,
        &mut returned_references,
        &mut structural_facts,
        &mut escapes,
    );
    drop(returned_references);

    escapes.extend(assignment_escapes);

    for effect in writes {
        state.ambient_writes.retain(&effect.path);
        state.ambient_write_effects.push(effect);
    }
    for path in escapes {
        state.ambient_escapes.retain(&path);
    }
}

fn is_object_proto_property<'a>(source: &'a str, node: Node<'a>) -> bool {
    if node.babel_type() != "ObjectProperty" {
        return false;
    }
    node.field(source, Field::Key)
        .and_then(|key| static_property_key(source, key, node.computed()))
        .is_some_and(|key| key == "__proto__")
}

/// Query whether a callee still denotes an unmodified global identity.
pub fn is_unmodified_global_reference<'a>(
    state: &SemanticState<'a>,
    callee: Node<'a>,
    name: &str,
) -> bool {
    let member = electron_member_path(state.source, callee);
    let root = unwrapped(state.source, member.root);
    let mut path = vec![PropertyPathKey::String(JsString::from("global"))];
    if member.members.is_empty() {
        path.push(PropertyPathKey::String(JsString::from(name)));
    } else {
        path.extend(member.members.iter().map(|member| {
            member.as_ref().map_or(PropertyPathKey::Wildcard, |value| {
                PropertyPathKey::String(value.clone())
            })
        }));
    }
    if state.ambient_writes.covers(&path) {
        return false;
    }

    if member.members.is_empty() {
        return state.is_unshadowed_global(&root, name);
    }
    global_alias(root.identifier_name().unwrap_or_default())
        && state.is_unshadowed_global(&root, root.identifier_name().unwrap_or_default())
        && member.members.len() == 1
        && member.members[0]
            .as_ref()
            .is_some_and(|value| value == name)
}

/// Query a complete ambient path after a caller has resolved the receiver.
/// Dynamic components are represented by [`PropertyPathKey::Wildcard`].
pub fn is_unmodified_global_path(state: &SemanticState<'_>, path: &[PropertyPathKey]) -> bool {
    !state.ambient_writes.covers(path)
}

/// Query whether `import.meta.url` is still known to be unmodified.
pub fn is_unmodified_import_meta_url<'a>(state: &SemanticState<'a>, node: Node<'a>) -> bool {
    let node = unwrapped(state.source, node);
    if !is_member_node(node) {
        return false;
    }
    let Some(property) = node.field(state.source, Field::Property) else {
        return false;
    };
    if property.identifier_name() != Some("url") {
        return false;
    }
    let Some(object) = node.field(state.source, Field::Object) else {
        return false;
    };
    if !is_import_meta(state, object) {
        return false;
    }
    !state.ambient_writes.covers(&[
        PropertyPathKey::String(JsString::from("import-meta")),
        PropertyPathKey::String(JsString::from("url")),
    ])
}

fn is_member_node(node: Node<'_>) -> bool {
    matches!(
        node.babel_type(),
        "MemberExpression" | "OptionalMemberExpression"
    )
}

#[cfg(test)]
mod tests {
    use std::ops::ControlFlow;

    use super::*;
    use crate::javascript::ast::{AstContext, AstVisitor, Node, traverse};
    use crate::javascript::parser::parse_javascript_analysis_program;
    use crate::javascript::semantic::definitions::collect_definitions;
    use crate::javascript::semantic::state::ResolutionMode;
    use oxc_allocator::Allocator;

    #[test]
    fn stored_dependencies_keep_prior_queries_and_skip_disjoint_properties() {
        let allocator = Allocator::default();
        let parsed = parse_javascript_analysis_program(&allocator, "", Some("dependencies.js"))
            .expect("parse source");
        let root = AstContext::new(parsed.program).root().key();
        let key = |name: &str| PropertyPathKey::String(JsString::from(name));
        let mut dependencies = StoreDependents::default();
        dependencies.observe(root, 0, &vec![key("foo")]);
        dependencies.observe(root, 1, &vec![key("bar")]);
        dependencies.observe(root, 2, &vec![]);
        dependencies.observe(root, 3, &vec![PropertyPathKey::Wildcard]);
        dependencies.observe(root, 4, &vec![key("foo"), key("child")]);
        dependencies.observe(root, 5, &vec![key("foo"), key("child")]);
        dependencies.observe(root, 5, &vec![key("foo")]);
        dependencies.observe(root, 6, &vec![key("foo")]);
        dependencies.observe(root, 6, &vec![key("bar")]);

        let affected_sources = |change: StoredPathChange| {
            let mut queued = HashSet::new();
            let mut pending = VecDeque::new();
            dependencies.queue_affected(root, &change, &mut queued, &mut pending);
            let mut pending = pending.into_iter().collect::<Vec<_>>();
            pending.sort_unstable();
            pending
        };
        assert_eq!(
            affected_sources(StoredPathChange {
                previous: None,
                current: Some(vec![key("foo")]),
            }),
            vec![0, 3, 4, 5, 6],
        );
        assert_eq!(
            affected_sources(StoredPathChange {
                previous: Some(vec![key("foo")]),
                current: Some(vec![PropertyPathKey::Wildcard]),
            }),
            vec![0, 1, 3, 4, 5, 6],
        );
        assert_eq!(
            affected_sources(StoredPathChange {
                previous: Some(vec![key("foo")]),
                current: None,
            }),
            vec![0, 1, 2, 3, 4, 5, 6],
        );
    }

    #[test]
    fn stored_alias_fixpoint_preserves_nested_and_dynamic_global_writes() {
        for source in [
            r#"
                const trunk = {};
                const left = {};
                const right = {};
                trunk.left = left;
                trunk.right = right;
                left.global = globalThis;
                trunk.left.global.URL = replacement;
            "#,
            r#"
                const trunk = {};
                const left = {};
                trunk[key] = left;
                left.global = globalThis;
                trunk.other.global.URL = replacement;
            "#,
        ] {
            let allocator = Allocator::default();
            let parsed = parse_javascript_analysis_program(
                &allocator,
                source,
                Some("stored-dependency-aliases.js"),
            )
            .expect("parse source");
            let ControlFlow::Continue(mut state) = collect_definitions::<()>(
                AstContext::new(parsed.program),
                ResolutionMode::Require,
                || ControlFlow::Continue(()),
            ) else {
                panic!("definition pass cancelled");
            };

            index_ambient_writes(&mut state);

            assert!(
                state.ambient_writes.covers(&[
                    PropertyPathKey::String(JsString::from("global")),
                    PropertyPathKey::String(JsString::from("URL")),
                ]),
                "nested stored aliases must retain the global URL write: {source}",
            );
        }
    }

    #[test]
    fn indexes_global_member_writes() {
        let allocator = Allocator::default();
        let parsed = parse_javascript_analysis_program(
            &allocator,
            "globalThis.URL = value;",
            Some("ambient.js"),
        )
        .expect("parse source");
        let ControlFlow::Continue(mut state) = collect_definitions::<()>(
            AstContext::new(parsed.program),
            ResolutionMode::Require,
            || ControlFlow::Continue(()),
        ) else {
            panic!("definition pass cancelled");
        };
        index_ambient_writes(&mut state);
        assert!(state.ambient_writes.covers(&[
            PropertyPathKey::String(JsString::from("global")),
            PropertyPathKey::String(JsString::from("URL")),
        ]));
    }

    #[test]
    fn escaped_fresh_object_without_stores_still_resolves_children() {
        let allocator = Allocator::default();
        let parsed = parse_javascript_analysis_program(
            &allocator,
            "const value = { first: globalThis.URL, second: window.navigator }; consume(value);",
            Some("ambient-escaped-object.js"),
        )
        .expect("parse source");
        let ControlFlow::Continue(state) = collect_definitions::<()>(
            AstContext::new(parsed.program),
            ResolutionMode::Require,
            || ControlFlow::Continue(()),
        ) else {
            panic!("definitions cancelled");
        };

        let mut object = None;
        struct ObjectFinder<'ast, 'slot> {
            object: &'slot mut Option<Node<'ast>>,
        }
        impl<'ast, 'slot> AstVisitor<'ast> for ObjectFinder<'ast, 'slot> {
            fn enter(
                &mut self,
                node: &Node<'ast>,
                _parent: Option<&Node<'ast>>,
                _ancestors: &[Node<'ast>],
            ) {
                if node.babel_type() == "ObjectExpression" {
                    *self.object = Some(*node);
                }
            }
        }
        let mut finder = ObjectFinder {
            object: &mut object,
        };
        let _ = traverse(state.program, state.source, &mut finder, || {
            ControlFlow::<()>::Continue(())
        });
        let object = object.expect("object expression");

        let paths = resolve_ambient_paths(&state, object, true, None, Some(object), true);
        assert_eq!(
            paths,
            vec![
                vec![
                    PropertyPathKey::String(JsString::from("global")),
                    PropertyPathKey::String(JsString::from("navigator")),
                ],
                vec![
                    PropertyPathKey::String(JsString::from("global")),
                    PropertyPathKey::String(JsString::from("URL")),
                ],
            ]
        );
    }

    #[test]
    fn reuses_returned_reference_resolution_across_stored_aliases() {
        let allocator = Allocator::default();
        let parsed = parse_javascript_analysis_program(
            &allocator,
            r#"
                const shared = {
                    first: globalThis.URL,
                    second: globalThis.Location,
                };
                const produced = flag ? shared.first : shared.second;
                const holder = {};
                holder.value = produced;
                const alias = holder.value;
                alias.target = value;
            "#,
            Some("returned-aliases.js"),
        )
        .expect("parse source");
        let ControlFlow::Continue(mut state) = collect_definitions::<()>(
            AstContext::new(parsed.program),
            ResolutionMode::Require,
            || ControlFlow::Continue(()),
        ) else {
            panic!("definitions cancelled");
        };

        let mut produced = None;
        struct ProducedFinder<'ast, 'slot> {
            produced: &'slot mut Option<Node<'ast>>,
        }
        impl<'ast, 'slot> AstVisitor<'ast> for ProducedFinder<'ast, 'slot> {
            fn enter(
                &mut self,
                node: &Node<'ast>,
                _parent: Option<&Node<'ast>>,
                _ancestors: &[Node<'ast>],
            ) {
                if node.babel_type() == "ConditionalExpression" {
                    *self.produced = Some(*node);
                }
            }
        }
        let mut finder = ProducedFinder {
            produced: &mut produced,
        };
        let _ = traverse(state.program, state.source, &mut finder, || {
            ControlFlow::<()>::Continue(())
        });
        let produced = produced.expect("produced conditional");
        let mut returned_references = create_semantic_returned_references(&state);
        let returned = returned_references(produced);
        assert_eq!(
            returned.precision,
            super::super::returned_references::ReturnedReferencePrecision::Widened
        );
        drop(returned_references);

        index_ambient_writes(&mut state);

        assert!(
            state.ambient_write_effects.iter().any(|effect| {
                effect.path.first() == Some(&PropertyPathKey::String(JsString::from("global")))
            }),
            "the stored alias chain should retain an ambient global write"
        );
    }

    #[test]
    fn stored_path_index_matches_full_scan_and_preserves_entry_order() {
        let allocator = Allocator::default();
        let parsed = parse_javascript_analysis_program(
            &allocator,
            "const value = {};",
            Some("stored-path-index.js"),
        )
        .expect("parse source");
        let node = AstContext::new(parsed.program).root();
        let string = |value: &str| PropertyPathKey::String(JsString::from(value));
        let entries = [
            Some(vec![string("foo"), string("child")]),
            None,
            Some(Vec::new()),
            Some(vec![PropertyPathKey::Wildcard]),
            Some(vec![string("bar")]),
        ];
        let mut index = StoredAmbientPaths::default();
        for (source_index, path) in entries.iter().cloned().enumerate() {
            index.entries.push(StoredAmbientPath {
                node,
                member_path: Rc::new(electron_member_path("const value = {};", node)),
                projection: Vec::new(),
                path,
            });
            index.source_to_entry.insert(source_index, source_index);
            let entry_path = index.entries[source_index].path.clone();
            index.add_to_index(source_index, entry_path.as_ref());
        }

        assert_eq!(index.source_to_entry.get(&3), Some(&3));
        assert_eq!(index.source_to_entry.get(&4), Some(&4));

        for query in [
            Vec::new(),
            vec![string("foo")],
            vec![string("bar")],
            vec![PropertyPathKey::Wildcard],
        ] {
            let mut indexed_candidates = index.candidate_indices(&query);
            let mut indexed = std::iter::from_fn(|| indexed_candidates.next()).collect::<Vec<_>>();
            indexed.reverse();
            let full_scan = entries
                .iter()
                .enumerate()
                .filter_map(|(source_index, stored_path)| {
                    let selected = stored_path.as_ref().is_none_or(|stored_path| {
                        stored_path.iter().enumerate().all(|(offset, key)| {
                            offset >= query.len()
                                || key == &PropertyPathKey::Wildcard
                                || query[offset] == PropertyPathKey::Wildcard
                                || key == &query[offset]
                        })
                    });
                    selected.then_some(source_index)
                })
                .collect::<Vec<_>>();
            assert_eq!(indexed, full_scan);
        }

        let previous = index.entries[4].path.clone();
        index.entries[4].path = Some(vec![string("foo")]);
        let current = index.entries[4].path.clone();
        index.update_index(4, previous.as_ref(), current.as_ref());
        let mut foo_candidates = index.candidate_indices(&vec![string("foo")]);
        assert_eq!(
            std::iter::from_fn(|| foo_candidates.next()).collect::<Vec<_>>(),
            vec![4, 3, 2, 1, 0]
        );
        let mut bar_candidates = index.candidate_indices(&vec![string("bar")]);
        assert_eq!(
            std::iter::from_fn(|| bar_candidates.next()).collect::<Vec<_>>(),
            vec![3, 2, 1]
        );
        assert_eq!(index.source_to_entry.get(&4), Some(&4));

        // Widening an earlier entry must insert it before later entries in
        // its new bucket. Appending would change the lazy merge order.
        let previous = index.entries[0].path.clone();
        index.entries[0].path = Some(vec![PropertyPathKey::Wildcard, string("child")]);
        let current = index.entries[0].path.clone();
        index.update_index(0, previous.as_ref(), current.as_ref());
        let mut bar_candidates = index.candidate_indices(&vec![string("bar")]);
        assert_eq!(
            std::iter::from_fn(|| bar_candidates.next()).collect::<Vec<_>>(),
            vec![3, 2, 1, 0]
        );
    }

    #[test]
    fn stored_projection_skip_matches_normalized_member_join() {
        let allocator = Allocator::default();
        let source = "const value = globalThis.foo[dynamic].bar;";
        let parsed =
            parse_javascript_analysis_program(&allocator, source, Some("stored-member-join.js"))
                .expect("parse source");
        let mut member = None;
        struct MemberFinder<'ast, 'slot> {
            member: &'slot mut Option<Node<'ast>>,
        }
        impl<'ast, 'slot> AstVisitor<'ast> for MemberFinder<'ast, 'slot> {
            fn enter(
                &mut self,
                node: &Node<'ast>,
                _parent: Option<&Node<'ast>>,
                _ancestors: &[Node<'ast>],
            ) {
                if self.member.is_none() && node.babel_type() == "MemberExpression" {
                    *self.member = Some(*node);
                }
            }
        }
        let mut finder = MemberFinder {
            member: &mut member,
        };
        let _ = traverse(
            AstContext::new(parsed.program).root(),
            source,
            &mut finder,
            || ControlFlow::<()>::Continue(()),
        );
        let member = member.expect("member expression");
        let member_path = electron_member_path(source, member);
        assert_eq!(member_path.root.identifier_name(), Some("globalThis"));
        assert_eq!(member_path.members.len(), 3);
        let member_prefix = member_path
            .members
            .iter()
            .map(|member| {
                member.as_ref().map_or(PropertyPathKey::Wildcard, |name| {
                    PropertyPathKey::String(name.clone())
                })
            })
            .collect::<PropertyPath>();
        let projection = vec![PropertyPathKey::String(JsString::from("projection"))];
        let remainder = vec![PropertyPathKey::String(JsString::from("tail"))];
        let mut candidate = member_prefix;
        candidate.extend(projection.iter().cloned());
        candidate.extend(remainder.iter().cloned());

        let assert_case = |previous: Option<PropertyPath>, queued: Vec<PropertyPath>| {
            let joined = join_ambient_projection(previous.as_ref(), Some(&candidate));
            let expected = joined == previous
                && queued.iter().any(|queued_path| {
                    queued_path.as_slice() == joined.as_deref().unwrap_or_default()
                });
            let actual = queued_stored_projection_matches(
                &member_path,
                Some(&previous),
                Some(&queued),
                &projection,
                &remainder,
            );
            assert_eq!(actual, expected);
        };

        assert!(!queued_stored_projection_matches(
            &member_path,
            None,
            Some(&vec![candidate.clone()]),
            &projection,
            &remainder,
        ));
        assert_case(Some(candidate.clone()), vec![candidate.clone()]);
        assert_case(Some(candidate.clone()), vec![]);
        assert_case(Some(vec![]), vec![vec![]]);
        let widened = vec![PropertyPathKey::Wildcard; candidate.len()];
        assert_case(Some(widened.clone()), vec![widened]);
        assert_case(
            Some(vec![PropertyPathKey::Wildcard; candidate.len()]),
            vec![candidate.clone()],
        );
        assert_case(Some(vec![PropertyPathKey::Wildcard; 2]), vec![vec![]]);
        assert_case(
            Some(vec![PropertyPathKey::String(JsString::from("other"))]),
            vec![],
        );
        assert_case(None, vec![vec![]]);
        assert_case(None, vec![]);
    }
}
