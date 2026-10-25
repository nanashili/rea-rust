//! Ambient identity writes and escapes.
//!
//! This pass owns the source-local coverage used to invalidate global,
//! `import.meta`, and CommonJS identities.  Identity discovery is delegated to
//! [`identity_writes`]; this module supplies the lexical origin facts and
//! retains the resulting paths in the canonical property-path index.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::javascript::ast::{Field, Node, NodeKey};

use super::ast_values::{is_member, static_property_key, unwrapped};
use super::callable_results::callable_result_expressions;
use super::identity_writes::{
    IdentityPath, IdentityWriteKind, JavaScriptIntrinsicInvocation, collect_identity_writes_steps,
    electron_member_path,
};
use super::iteration_sources::{IterationSourceKind, semantic_iteration_sources};
use super::module_interop;
use super::mutation_initializers::semantic_binding_at_read;
use super::property_paths::{PropertyPath, PropertyPathKey, semantic_array_index_units};
use super::returned_references::create_semantic_returned_references;
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
    source_index: usize,
    node: Node<'a>,
    projection: PropertyPath,
    path: Option<PropertyPath>,
}

#[derive(Clone, Debug)]
struct PendingEscape<'a> {
    target: Node<'a>,
    browser_receiver: bool,
    projection: Option<PropertyPath>,
    capture: Node<'a>,
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
    resolve_ambient_paths_with_stores(
        state,
        node,
        possible_writes,
        projection,
        capture,
        escaped_contents,
        None,
        None,
    )
}

fn resolve_ambient_paths_with_stores<'source, 'state>(
    state: &'state SemanticState<'source>,
    node: Node<'source>,
    possible_writes: bool,
    projection: Option<PropertyPath>,
    capture: Option<Node<'source>>,
    escaped_contents: bool,
    stores: Option<&HashMap<NodeKey, Vec<StoredAmbientPath<'source>>>>,
    mut local_identities: Option<&mut Vec<(Node<'source>, PropertyPath)>>,
) -> Vec<PropertyPath> {
    let mut returned_references = create_semantic_returned_references(state);
    let mut pending = vec![(node, projection, false)];
    let mut expanded = HashMap::<NodeKey, Option<PropertyPath>>::new();
    let mut queued = HashSet::<(NodeKey, String)>::new();
    let mut result = Vec::new();

    while let Some((current, suffix, reads_at_self)) = pending.pop() {
        let member_path = electron_member_path(state.source, current);
        let root = member_path.root;
        let mut path = member_path
            .members
            .into_iter()
            .map(|member| {
                member.map_or(PropertyPathKey::Wildcard, |value| {
                    PropertyPathKey::String(value)
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
        let key = serde_json::to_string(&path).expect("property path is serializable");
        if !queued.insert((root.key(), key)) {
            continue;
        }

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
                        semantic_binding_at_read(
                            &state.bindings[binding],
                            read,
                            &state.parents,
                            state.source,
                        )
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
                    pending.push((initializer.node, Some(next), true));
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
            for stored in stores
                .and_then(|stores| stores.get(&root.key()))
                .into_iter()
                .flatten()
            {
                let selected = stored.path.as_ref().is_none_or(|stored_path| {
                    stored_path.iter().enumerate().all(|(index, key)| {
                        index >= path.len()
                            || key == &PropertyPathKey::Wildcard
                            || path[index] == PropertyPathKey::Wildcard
                            || key == &path[index]
                    })
                });
                if !selected {
                    continue;
                }
                if let Some(stored_path) = stored.path.as_ref()
                    && path.len() < stored_path.len()
                    && !escaped_contents
                {
                    continue;
                }
                let mut remaining = match stored.path.as_ref() {
                    Some(stored_path) if path.len() >= stored_path.len() => {
                        path[stored_path.len()..].to_vec()
                    }
                    Some(_) => Vec::new(),
                    None => Vec::new(),
                };
                let mut next = stored.projection.clone();
                next.append(&mut remaining);
                pending.push((stored.node, Some(next), true));
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
                    pending.push((child, Some(path.clone()), reads_at_self));
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
                    pending.push((reference.node, Some(projected), reads_at_self));
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
                        pending.push((child, Some(path.clone()), reads_at_self));
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
                    pending.push((child, Some(path), reads_at_self));
                }
            }
            "AssignmentExpression" if possible_writes && root.operator() == Some("=") => {
                if let Some(right) = root.field(state.source, Field::Right) {
                    pending.push((right, Some(path), reads_at_self));
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
                    pending.push((callee, Some(path.clone()), reads_at_self));
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
                        pending.push((argument, Some(argument_path), reads_at_self));
                    }
                }
                if let Some(callee) = root.field(state.source, Field::Callee) {
                    let mut returned = returned_references(callee).references;
                    returned.extend(direct_callable_results(state, callee));
                    for reference in returned {
                        let mut projected = reference.projection;
                        projected.extend(path.clone());
                        pending.push((reference.node, Some(projected), reads_at_self));
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
                        pending.push((reference.node, Some(projected), reads_at_self));
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
                        pending.push((value, Some(suffix), reads_at_self));
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
                            pending.push((argument, Some(path.clone()), reads_at_self));
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
                        pending.push((element, Some(suffix), reads_at_self));
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
                            pending.push((value, Some(path[1..].to_vec()), reads_at_self));
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
                    pending.push((element, Some(path[1..].to_vec()), reads_at_self));
                }
            }
            "SpreadElement" => {
                if let Some(argument) = root.field(state.source, Field::Argument) {
                    pending.push((argument, Some(path), reads_at_self));
                }
            }
            "ObjectProperty" if possible_writes => {
                if let Some(value) = root.field(state.source, Field::Value) {
                    pending.push((value, Some(path), reads_at_self));
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

    candidates
        .into_iter()
        .filter(|candidate| {
            matches!(
                candidate.babel_type(),
                "FunctionDeclaration"
                    | "FunctionExpression"
                    | "ArrowFunctionExpression"
                    | "ObjectMethod"
                    | "ClassMethod"
                    | "ClassPrivateMethod"
            )
        })
        .flat_map(|candidate| callable_result_expressions(state.source, &candidate))
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
        })
        .collect()
}

fn resolve_pending_write_effects<'a>(
    state: &SemanticState<'a>,
    pending_writes: Vec<(usize, Node<'a>, PropertyPath)>,
    pending_targets: &[(Node<'a>, Node<'a>)],
    stores: &HashMap<NodeKey, Vec<StoredAmbientPath<'a>>>,
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
    stores: &HashMap<NodeKey, Vec<StoredAmbientPath<'a>>>,
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
    stores: &HashMap<NodeKey, Vec<StoredAmbientPath<'a>>>,
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

fn resolve_stored_references<'a>(
    state: &SemanticState<'a>,
    stored_references: &[super::iteration_sources::SemanticIterationSource<'a>],
) -> HashMap<NodeKey, Vec<StoredAmbientPath<'a>>> {
    let mut stores = HashMap::<NodeKey, Vec<StoredAmbientPath<'a>>>::new();
    let mut dependents = HashMap::<NodeKey, HashSet<usize>>::new();
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
        );

        for (node, path) in identities {
            dependents
                .entry(node.key())
                .or_default()
                .insert(source_index);
            let entries = stores.entry(node.key()).or_default();
            let Some(existing) = entries
                .iter_mut()
                .find(|entry| entry.source_index == source_index)
            else {
                entries.push(StoredAmbientPath {
                    source_index,
                    node: source.node,
                    projection: source.projection.clone(),
                    path: Some(path),
                });
                queue_store_dependents(
                    node.key(),
                    &dependents,
                    &mut queued_stores,
                    &mut pending_stores,
                );
                continue;
            };
            let joined = join_ambient_projection(existing.path.as_ref(), Some(&path));
            if existing.path != joined {
                existing.path = joined;
                queue_store_dependents(
                    node.key(),
                    &dependents,
                    &mut queued_stores,
                    &mut pending_stores,
                );
            }
        }
    }

    stores
}

fn queue_store_dependents(
    node: NodeKey,
    dependents: &HashMap<NodeKey, HashSet<usize>>,
    queued_stores: &mut HashSet<usize>,
    pending_stores: &mut VecDeque<usize>,
) {
    for dependent in dependents.get(&node).into_iter().flatten() {
        if queued_stores.insert(*dependent) {
            pending_stores.push_back(*dependent);
        }
    }
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

    let stores = resolve_stored_references(state, &stored_references);

    resolve_pending_write_effects(
        state,
        pending_writes,
        &pending_targets,
        &stores,
        &mut writes,
    );

    collect_stored_escapes(
        state,
        source,
        &stored_references,
        &stores,
        &mut pending_escapes,
    );
    publish_pending_escapes(state, pending_escapes, &stores, &mut escapes);

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
    use crate::javascript::ast::AstContext;
    use crate::javascript::parser::parse_javascript_analysis_program;
    use crate::javascript::semantic::definitions::collect_definitions;
    use crate::javascript::semantic::state::ResolutionMode;
    use oxc_allocator::Allocator;

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
}
