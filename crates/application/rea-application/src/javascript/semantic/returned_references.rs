//! Conservative source-local returned-reference projection.
//!
//! This is the Rust port of `javascriptSemanticReturnedReferences.ts`. It
//! computes a fixed point over binding reads and literal projections without
//! executing JavaScript or claiming runtime completeness.

use std::collections::{HashMap, HashSet};

use crate::javascript::ast::{Field, Node, NodeKey};

use super::ast_values::{is_class, is_function, static_property_key, unwrapped};
use super::property_paths::{PropertyPath, PropertyPathKey, semantic_array_index_units};
use super::state::{ProjectionKey, SemanticState};
use super::value_types::JsString;

#[derive(Clone, Debug)]
pub struct SemanticReturnedReference<'a> {
    pub node: Node<'a>,
    pub projection: PropertyPath,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnedReferencePrecision {
    Exact,
    Widened,
}

#[derive(Clone, Debug)]
pub struct SemanticReturnedReferenceResult<'a> {
    pub references: Vec<SemanticReturnedReference<'a>>,
    pub precision: ReturnedReferencePrecision,
}

#[derive(Clone, Debug)]
struct Candidate<'a> {
    node: Node<'a>,
    path: Option<PropertyPath>,
}

#[derive(Default)]
struct ObjectTargetIndex<'a> {
    property_by_name: HashMap<JsString, Node<'a>>,
    trailing_unknowns_by_property: HashMap<NodeKey, Vec<Node<'a>>>,
}

/// Create a memoized resolver for source-local references returned by a callee.
pub fn create_semantic_returned_references<'s, 'a>(
    state: &'s SemanticState<'a>,
) -> impl FnMut(Node<'a>) -> SemanticReturnedReferenceResult<'a> + 's {
    let mut results = HashMap::<NodeKey, SemanticReturnedReferenceResult<'a>>::new();
    let mut object_indexes = HashMap::<NodeKey, ObjectTargetIndex<'a>>::new();

    move |callee| {
        if let Some(existing) = results.get(&callee.key()) {
            return existing.clone();
        }
        let result = resolve_returned_references(state, callee, &mut object_indexes);
        if result.precision == ReturnedReferencePrecision::Widened {
            let range = state.context.range(&callee);
            let mut widenings = state.returned_reference_widenings.borrow_mut();
            if !widenings.contains(&range) {
                widenings.push(range);
            }
        }
        results.insert(callee.key(), result.clone());
        result
    }
}

fn resolve_returned_references<'a>(
    state: &SemanticState<'a>,
    callee: Node<'a>,
    object_indexes: &mut HashMap<NodeKey, ObjectTargetIndex<'a>>,
) -> SemanticReturnedReferenceResult<'a> {
    let mut projections = HashMap::<NodeKey, Option<PropertyPath>>::new();
    let mut queued = HashSet::<NodeKey>::new();
    let mut work = Vec::<Node<'a>>::new();
    let mut functions = Vec::<Node<'a>>::new();
    let mut function_keys = HashSet::<NodeKey>::new();
    let mut precision = ReturnedReferencePrecision::Exact;

    enqueue(
        state.source,
        callee,
        Some(Vec::new()),
        &mut projections,
        &mut queued,
        &mut work,
        &mut precision,
    );

    while let Some(node) = work.pop() {
        queued.remove(&node.key());
        let current = Candidate {
            node,
            path: projections.get(&node.key()).cloned().flatten(),
        };
        let pending = expand_candidate(
            state,
            current,
            object_indexes,
            &mut functions,
            &mut function_keys,
        );

        for candidate in pending.into_iter().rev() {
            enqueue(
                state.source,
                candidate.node,
                candidate.path,
                &mut projections,
                &mut queued,
                &mut work,
                &mut precision,
            );
        }
    }

    let mut references = Vec::new();
    for function in functions {
        for result in state.callable_result_expressions(&function).iter() {
            if let Some(node) = result.node {
                references.push(SemanticReturnedReference {
                    node,
                    projection: if result.delegated {
                        vec![PropertyPathKey::Wildcard]
                    } else {
                        Vec::new()
                    },
                });
            }
        }
    }
    SemanticReturnedReferenceResult {
        references,
        precision,
    }
}

fn expand_candidate<'a>(
    state: &SemanticState<'a>,
    current: Candidate<'a>,
    object_indexes: &mut HashMap<NodeKey, ObjectTargetIndex<'a>>,
    functions: &mut Vec<Node<'a>>,
    function_keys: &mut HashSet<NodeKey>,
) -> Vec<Candidate<'a>> {
    let node = current.node;
    let mut pending = Vec::new();

    if node.babel_type() == "Identifier" {
        if let Some(name) = node.identifier_name()
            && let Some(binding_index) = state.resolve_binding(&node, name)
        {
            let selected = state
                .semantic_binding_at_read(state.binding(binding_index), node)
                .binding;
            for initializer in selected.initializers {
                pending.push(Candidate {
                    node: initializer.node,
                    path: prepend_projection(&initializer.projection, current.path.as_ref()),
                });
            }
            for initializer in selected.reference_initializers {
                pending.push(Candidate {
                    node: initializer.node,
                    path: prepend_projection(&initializer.projection, current.path.as_ref()),
                });
            }
        }
    } else if matches!(
        node.babel_type(),
        "MemberExpression" | "OptionalMemberExpression"
    ) {
        let mut path = Vec::new();
        let mut receiver = node;
        while matches!(
            receiver.babel_type(),
            "MemberExpression" | "OptionalMemberExpression"
        ) {
            let Some(property) = receiver.field(state.source, Field::Property) else {
                path.push(PropertyPathKey::Wildcard);
                break;
            };
            path.push(member_key(state.source, receiver, property));
            let Some(object) = receiver.field(state.source, Field::Object) else {
                break;
            };
            receiver = unwrapped(state.source, object);
        }
        path.reverse();
        pending.push(Candidate {
            node: receiver,
            path: prepend_path(&path, current.path.as_ref()),
        });
    } else if matches!(
        node.babel_type(),
        "ConditionalExpression" | "LogicalExpression"
    ) {
        let (first, second) = if node.babel_type() == "ConditionalExpression" {
            (Field::Consequent, Field::Alternate)
        } else {
            (Field::Left, Field::Right)
        };
        for field in [first, second] {
            if let Some(child) = node.field(state.source, field) {
                pending.push(Candidate {
                    node: child,
                    path: current.path.clone(),
                });
            }
        }
    } else if node.babel_type() == "SequenceExpression" {
        if let Some(child) = node
            .field_list(state.source, Field::Expressions)
            .into_iter()
            .flatten()
            .last()
        {
            pending.push(Candidate {
                node: child,
                path: current.path.clone(),
            });
        }
    } else if is_function(&node) && current.path.as_ref().is_none_or(Vec::is_empty) {
        if function_keys.insert(node.key()) {
            functions.push(node);
        }
    } else if node.babel_type() == "ObjectExpression" {
        select_object_targets(state, node, current, &mut pending, object_indexes);
    } else if node.babel_type() == "ArrayExpression" {
        select_array_targets(state, node, current, &mut pending);
    } else if node.babel_type() == "NewExpression" {
        if let Some(callee) = node.field(state.source, Field::Callee) {
            pending.push(Candidate {
                node: callee,
                path: current.path.clone(),
            });
        }
    } else if is_class(&node) {
        select_class_targets(state, node, current, &mut pending);
    }

    pending
}

fn enqueue<'a>(
    source: &'a str,
    node: Node<'a>,
    path: Option<PropertyPath>,
    projections: &mut HashMap<NodeKey, Option<PropertyPath>>,
    queued: &mut HashSet<NodeKey>,
    work: &mut Vec<Node<'a>>,
    precision: &mut ReturnedReferencePrecision,
) {
    let source = unwrapped(source, node);
    let key = source.key();
    match projections.get(&key) {
        None => {
            projections.insert(key, path);
        }
        Some(previous) => {
            let joined = join_projection(previous.as_ref(), path.as_ref());
            if same_projection(previous.as_ref(), joined.as_ref()) {
                return;
            }
            projections.insert(key, joined);
            *precision = ReturnedReferencePrecision::Widened;
        }
    }
    if queued.insert(key) {
        work.push(source);
    }
}

fn join_projection(
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

fn same_projection(left: Option<&PropertyPath>, right: Option<&PropertyPath>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

fn projection_key(key: &ProjectionKey) -> PropertyPathKey {
    match key {
        ProjectionKey::Name(name) => PropertyPathKey::String(name.clone()),
        ProjectionKey::Index(index) => PropertyPathKey::Number(*index),
        ProjectionKey::Dynamic => PropertyPathKey::Wildcard,
    }
}

fn prepend_projection(
    prefix: &[ProjectionKey],
    suffix: Option<&PropertyPath>,
) -> Option<PropertyPath> {
    suffix.map(|suffix| {
        prefix
            .iter()
            .map(projection_key)
            .chain(suffix.iter().cloned())
            .collect()
    })
}

fn prepend_path(prefix: &[PropertyPathKey], suffix: Option<&PropertyPath>) -> Option<PropertyPath> {
    suffix.map(|suffix| {
        prefix
            .iter()
            .cloned()
            .chain(suffix.iter().cloned())
            .collect()
    })
}

fn member_key<'a>(source: &'a str, node: Node<'a>, property: Node<'a>) -> PropertyPathKey {
    if !node.computed() {
        return property
            .identifier_name()
            .map(|name| PropertyPathKey::String((name).into()))
            .unwrap_or(PropertyPathKey::Wildcard);
    }
    static_property_key(source, property, true)
        .map(PropertyPathKey::String)
        .unwrap_or(PropertyPathKey::Wildcard)
}

fn select_array_targets<'a>(
    state: &SemanticState<'a>,
    node: Node<'a>,
    item: Candidate<'a>,
    pending: &mut Vec<Candidate<'a>>,
) {
    let Some(path) = item.path.as_ref() else {
        for element in node
            .field_list(state.source, Field::Elements)
            .into_iter()
            .flatten()
        {
            let child = if element.babel_type() == "SpreadElement" {
                element.field(state.source, Field::Argument)
            } else {
                Some(element)
            };
            if let Some(child) = child {
                pending.push(Candidate {
                    node: child,
                    path: None,
                });
            }
        }
        return;
    };
    let (key, rest) = path
        .split_first()
        .unwrap_or((&PropertyPathKey::Wildcard, &[]));
    let index = match key {
        PropertyPathKey::Number(index) => Some(*index),
        PropertyPathKey::String(name) => semantic_array_index_units(name),
        PropertyPathKey::Wildcard | PropertyPathKey::Selection(_) => None,
    };
    let mut uncertain_offset = false;
    for (offset, element) in node
        .field_list(state.source, Field::Elements)
        .into_iter()
        .enumerate()
    {
        let Some(element) = element else {
            continue;
        };
        if element.babel_type() == "SpreadElement" {
            uncertain_offset = true;
            if let Some(argument) = element.field(state.source, Field::Argument) {
                pending.push(Candidate {
                    node: argument,
                    path: Some(
                        std::iter::once(PropertyPathKey::Wildcard)
                            .chain(rest.iter().cloned())
                            .collect(),
                    ),
                });
            }
        } else if index.is_none() || uncertain_offset || index == Some(offset) {
            pending.push(Candidate {
                node: element,
                path: Some(rest.to_vec()),
            });
        }
    }
}

fn select_object_targets<'a>(
    state: &SemanticState<'a>,
    node: Node<'a>,
    item: Candidate<'a>,
    pending: &mut Vec<Candidate<'a>>,
    indexes: &mut HashMap<NodeKey, ObjectTargetIndex<'a>>,
) {
    let (key, rest) = item.path.as_ref().map_or((None, &[][..]), |path| {
        path.split_first()
            .map_or((None, &[][..]), |(key, rest)| (Some(key), rest))
    });
    let child_path = item.path.as_ref().map(|_| rest.to_vec());
    if let Some(key) = key.filter(|key| !matches!(key, PropertyPathKey::Wildcard)) {
        let index = object_target_index(state, node, indexes);
        let name = match key {
            PropertyPathKey::String(name) => name.clone(),
            PropertyPathKey::Number(index) => JsString::from(index.to_string()),
            PropertyPathKey::Wildcard | PropertyPathKey::Selection(_) => unreachable!(),
        };
        if let Some(property) = index.property_by_name.get(&name) {
            if let Some(unknowns) = index.trailing_unknowns_by_property.get(&property.key()) {
                for unknown in unknowns {
                    let unknown_node = if unknown.babel_type() == "SpreadElement" {
                        unknown.field(state.source, Field::Argument)
                    } else {
                        unknown.field(state.source, Field::Value)
                    };
                    pending.push(Candidate {
                        node: unknown_node.unwrap_or(*unknown),
                        path: if unknown.babel_type() == "SpreadElement" {
                            item.path.clone()
                        } else {
                            child_path.clone()
                        },
                    });
                }
            }
            pending.push(Candidate {
                node: property
                    .field(state.source, Field::Value)
                    .unwrap_or(*property),
                path: child_path,
            });
            return;
        }
    }
    let mut replaced = false;
    for property in node
        .field_list(state.source, Field::Properties)
        .into_iter()
        .flatten()
        .rev()
    {
        if replaced {
            break;
        }
        if property.babel_type() == "SpreadElement" {
            if let Some(argument) = property.field(state.source, Field::Argument) {
                pending.push(Candidate {
                    node: argument,
                    path: item.path.clone(),
                });
            }
            continue;
        }
        let name = property
            .field(state.source, Field::Key)
            .and_then(|key| static_property_key(state.source, key, property.computed()));
        if let Some(key) = key
            && !matches!(key, PropertyPathKey::Wildcard)
            && name
                .as_ref()
                .is_some_and(|name| !object_key_matches(Some(name), key))
        {
            continue;
        }
        pending.push(Candidate {
            node: property
                .field(state.source, Field::Value)
                .unwrap_or(property),
            path: child_path.clone(),
        });
        if let Some(key) = key.filter(|key| !matches!(key, PropertyPathKey::Wildcard)) {
            replaced = name
                .as_ref()
                .is_some_and(|name| object_key_matches(Some(name), key));
        }
    }
}

fn object_target_index<'a, 'i>(
    state: &SemanticState<'a>,
    node: Node<'a>,
    indexes: &'i mut HashMap<NodeKey, ObjectTargetIndex<'a>>,
) -> &'i ObjectTargetIndex<'a> {
    if !indexes.contains_key(&node.key()) {
        let mut index = ObjectTargetIndex::<'a>::default();
        let mut trailing = Vec::new();
        for property in node
            .field_list(state.source, Field::Properties)
            .into_iter()
            .flatten()
            .rev()
        {
            if property.babel_type() == "SpreadElement" {
                trailing.push(property);
                continue;
            }
            let Some(key) = property
                .field(state.source, Field::Key)
                .and_then(|key| static_property_key(state.source, key, property.computed()))
            else {
                trailing.push(property);
                continue;
            };
            let key = key;
            if index.property_by_name.contains_key(&key) {
                continue;
            }
            index.property_by_name.insert(key, property);
            if !trailing.is_empty() {
                index
                    .trailing_unknowns_by_property
                    .insert(property.key(), trailing.clone());
            }
        }
        indexes.insert(node.key(), index);
    }
    indexes
        .get(&node.key())
        .expect("inserted object target index")
}

fn select_class_targets<'a>(
    state: &SemanticState<'a>,
    node: Node<'a>,
    item: Candidate<'a>,
    pending: &mut Vec<Candidate<'a>>,
) {
    let (key, rest) = item.path.as_ref().map_or((None, &[][..]), |path| {
        path.split_first()
            .map_or((None, &[][..]), |(key, rest)| (Some(key), rest))
    });
    let members = node
        .field(state.source, Field::Body)
        .into_iter()
        .flat_map(|body| {
            body.field_list(state.source, Field::Body)
                .into_iter()
                .flatten()
        });
    for member in members {
        let path_is_unknown = item.path.is_none();
        let path_is_empty = item.path.as_ref().is_some_and(Vec::is_empty);
        let member_name = member
            .field(state.source, Field::Key)
            .and_then(|key| static_property_key(state.source, key, member.computed()));
        let matches_key = path_is_unknown
            || (path_is_empty && member.declaration_kind() == Some("constructor"))
            || matches!(key, Some(PropertyPathKey::Wildcard))
            || member_name
                .as_ref()
                .is_some_and(|name| key.is_some_and(|key| object_key_matches(Some(name), key)));
        if !matches_key {
            continue;
        }
        if member.babel_type() == "ClassProperty" {
            if !path_is_unknown && key.is_none() {
                continue;
            }
            if let Some(value) = member.field(state.source, Field::Value) {
                pending.push(Candidate {
                    node: value,
                    path: item.path.as_ref().map(|_| rest.to_vec()),
                });
            }
        } else if member.babel_type() == "ClassMethod" {
            pending.push(Candidate {
                node: member,
                path: item.path.as_ref().map(|_| rest.to_vec()),
            });
        }
    }
    if let Some(super_class) = node.field(state.source, Field::SuperClass) {
        pending.push(Candidate {
            node: super_class,
            path: item.path,
        });
    }
}

fn object_key_matches(name: Option<&JsString>, key: &PropertyPathKey) -> bool {
    match (name, key) {
        (Some(name), PropertyPathKey::String(expected)) => name == expected,
        (Some(name), PropertyPathKey::Number(index)) => *name == JsString::from(index.to_string()),
        (_, PropertyPathKey::Wildcard | PropertyPathKey::Selection(_)) => true,
        _ => false,
    }
}
