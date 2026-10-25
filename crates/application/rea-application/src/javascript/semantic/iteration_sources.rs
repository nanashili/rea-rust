//! Iterator receivers and reference stores derived from binding patterns.
//!
//! This is the Rust counterpart of `javascriptSemanticIterationSources.ts`.
//! The function is syntax-only: it records source nodes and projections, but
//! never evaluates a receiver or claims that a dynamic property is known.

use crate::javascript::ast::{Field, Node};

use super::ast_values::{
    is_function, object_pattern_keys, property_key_of, runtime_function_parameters,
};
use super::property_paths::{PropertyPath, PropertyPathKey, PropertySelection};

#[derive(Clone, Debug)]
pub struct IterationSourceValue<'a> {
    pub node: Node<'a>,
    pub projection: PropertyPath,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IterationSourceKind {
    Iteration,
    ReferenceStore,
}

#[derive(Clone, Debug)]
pub struct SemanticIterationSource<'a> {
    pub kind: IterationSourceKind,
    pub node: Node<'a>,
    pub projection: PropertyPath,
    pub mutation: Node<'a>,
    pub target: Option<Node<'a>>,
    pub fallback_sources: Vec<IterationSourceValue<'a>>,
    pub required_sources: Vec<IterationSourceValue<'a>>,
}

#[derive(Clone, Debug)]
struct PatternSource<'a> {
    value: IterationSourceValue<'a>,
    rest_start_index: Option<usize>,
}

#[derive(Clone, Debug, Default)]
struct SourceGuards<'a> {
    fallback_sources: Vec<IterationSourceValue<'a>>,
    required_sources: Vec<IterationSourceValue<'a>>,
}

fn add<'a>(
    sources: &mut Vec<SemanticIterationSource<'a>>,
    source: &PatternSource<'a>,
    mutation: Node<'a>,
    guards: &SourceGuards<'a>,
    kind: IterationSourceKind,
    target: Option<Node<'a>>,
) {
    let mut value = source.value.clone();
    if source.rest_start_index.is_some() && kind == IterationSourceKind::ReferenceStore {
        value
            .projection
            .push(PropertyPathKey::Selection(PropertySelection {
                excluded_keys: Vec::new(),
                start_index: source.rest_start_index,
            }));
    }
    sources.push(SemanticIterationSource {
        kind,
        node: value.node,
        projection: value.projection,
        mutation,
        target,
        fallback_sources: guards.fallback_sources.clone(),
        required_sources: guards.required_sources.clone(),
    });
}

fn project<'a>(
    source: Option<&PatternSource<'a>>,
    key: Option<PropertyPathKey>,
) -> Option<PatternSource<'a>> {
    let source = source?;
    let mut value = source.value.clone();
    value
        .projection
        .push(key.unwrap_or(PropertyPathKey::Wildcard));
    if let Some(start) = source.rest_start_index {
        if let Some(PropertyPathKey::Number(index)) = value.projection.last_mut() {
            *index = start.checked_add(*index).unwrap_or(*index);
        }
    }
    Some(PatternSource {
        value,
        rest_start_index: source.rest_start_index,
    })
}

fn static_pattern_key<'a>(source: &'a str, property: Node<'a>) -> Option<PropertyPathKey> {
    property_key_of(source, &property).map(PropertyPathKey::String)
}

/// Describe iterator receivers and property reference stores without evaluation.
pub fn semantic_iteration_sources<'a>(
    source_text: &'a str,
    node: Node<'a>,
    parent: Option<Node<'a>>,
) -> Vec<SemanticIterationSource<'a>> {
    let mut sources = Vec::new();
    let mutation = node;
    let empty = SourceGuards::default();
    let initial = |node: Node<'a>| PatternSource {
        value: IterationSourceValue {
            node,
            projection: Vec::new(),
        },
        rest_start_index: None,
    };

    match node.babel_type() {
        "VariableDeclarator" => {
            if let (Some(pattern), Some(init)) = (
                node.field(source_text, Field::Id),
                node.field(source_text, Field::Init),
            ) {
                let source = initial(init);
                visit_with_source(
                    source_text,
                    &mut sources,
                    pattern,
                    Some(&source),
                    mutation,
                    &empty,
                );
            }
        }
        "AssignmentExpression" => {
            if matches!(
                node.operator(),
                Some("=") | Some("||=") | Some("&&=") | Some("??=")
            ) {
                if let (Some(left), Some(right)) = (
                    node.field(source_text, Field::Left),
                    node.field(source_text, Field::Right),
                ) {
                    let source = initial(right);
                    visit_with_source(
                        source_text,
                        &mut sources,
                        left,
                        Some(&source),
                        mutation,
                        &empty,
                    );
                }
            }
        }
        "ForOfStatement" => {
            if let (Some(left), Some(right)) = (
                node.field(source_text, Field::Left),
                node.field(source_text, Field::Right),
            ) {
                let receiver = initial(right);
                add(
                    &mut sources,
                    &receiver,
                    mutation,
                    &empty,
                    IterationSourceKind::Iteration,
                    None,
                );
                let element = PatternSource {
                    value: IterationSourceValue {
                        node: right,
                        projection: vec![PropertyPathKey::Wildcard],
                    },
                    rest_start_index: None,
                };
                if left.babel_type() == "VariableDeclaration" {
                    for declaration in left
                        .field_list(source_text, Field::Declarations)
                        .into_iter()
                        .flatten()
                    {
                        if let Some(id) = declaration.field(source_text, Field::Id) {
                            visit_with_source(
                                source_text,
                                &mut sources,
                                id,
                                Some(&element),
                                mutation,
                                &empty,
                            );
                        }
                    }
                } else {
                    visit_with_source(
                        source_text,
                        &mut sources,
                        left,
                        Some(&element),
                        mutation,
                        &empty,
                    );
                }
            }
        }
        "SpreadElement"
            if parent.is_some_and(|parent| parent.babel_type() == "ArrayExpression") =>
        {
            if let Some(argument) = node.field(source_text, Field::Argument) {
                let source = initial(argument);
                add(
                    &mut sources,
                    &source,
                    mutation,
                    &empty,
                    IterationSourceKind::Iteration,
                    None,
                );
            }
        }
        "YieldExpression" if node.delegate() => {
            if let Some(argument) = node.field(source_text, Field::Argument) {
                let source = initial(argument);
                add(
                    &mut sources,
                    &source,
                    mutation,
                    &empty,
                    IterationSourceKind::Iteration,
                    None,
                );
            }
        }
        _ if is_function(&node) => {
            for parameter in runtime_function_parameters(source_text, &node) {
                visit_with_source(source_text, &mut sources, parameter, None, mutation, &empty);
            }
        }
        _ => {}
    }
    sources
}

fn visit_with_source<'a>(
    source_text: &'a str,
    sources: &mut Vec<SemanticIterationSource<'a>>,
    pattern: Node<'a>,
    source: Option<&PatternSource<'a>>,
    mutation: Node<'a>,
    guards: &SourceGuards<'a>,
) {
    // The recursive visitor is intentionally kept parameterized by source text
    // so no node is reparsed or interpreted by this semantic layer.
    visit_impl(source_text, sources, pattern, source, mutation, guards)
}

fn visit_impl<'a>(
    source_text: &'a str,
    sources: &mut Vec<SemanticIterationSource<'a>>,
    pattern: Node<'a>,
    source: Option<&PatternSource<'a>>,
    mutation: Node<'a>,
    guards: &SourceGuards<'a>,
) {
    // Implementation is filled by the source-aware pattern walk below.
    match pattern.babel_type() {
        "MemberExpression" => {
            if let Some(source) = source {
                add(
                    sources,
                    source,
                    mutation,
                    guards,
                    IterationSourceKind::ReferenceStore,
                    Some(pattern),
                );
            }
        }
        "TSParameterProperty" => {
            if let Some(parameter) = pattern.field(source_text, Field::Parameter) {
                visit_impl(source_text, sources, parameter, source, mutation, guards);
            }
        }
        "AssignmentPattern" => {
            let Some(left) = pattern.field(source_text, Field::Left) else {
                return;
            };
            let mut required = guards.clone();
            if let Some(source) = source {
                required.required_sources.push(source.value.clone());
            }
            visit_impl(source_text, sources, left, source, mutation, &required);
            let mut fallback = guards.clone();
            if let Some(source) = source {
                fallback.fallback_sources.push(source.value.clone());
            }
            if let Some(right) = pattern.field(source_text, Field::Right) {
                let default_source = PatternSource {
                    value: IterationSourceValue {
                        node: right,
                        projection: Vec::new(),
                    },
                    rest_start_index: None,
                };
                visit_impl(
                    source_text,
                    sources,
                    left,
                    Some(&default_source),
                    mutation,
                    &fallback,
                );
            }
        }
        "ObjectPattern" => {
            for property in pattern
                .field_list(source_text, Field::Properties)
                .into_iter()
                .flatten()
            {
                if property.babel_type() == "RestElement" {
                    let Some(argument) = property.field(source_text, Field::Argument) else {
                        continue;
                    };
                    let Some(source) = source else {
                        visit_impl(source_text, sources, argument, None, mutation, guards);
                        continue;
                    };
                    let mut value = source.value.clone();
                    let mut excluded = object_pattern_keys(source_text, &pattern)
                        .into_iter()
                        .collect::<Vec<_>>();
                    excluded.sort_by(|a, b| a.compare_code_points(b));
                    excluded.dedup();
                    value
                        .projection
                        .push(PropertyPathKey::Selection(PropertySelection {
                            excluded_keys: excluded,
                            start_index: None,
                        }));
                    let rest = PatternSource {
                        value,
                        rest_start_index: None,
                    };
                    visit_impl(
                        source_text,
                        sources,
                        argument,
                        Some(&rest),
                        mutation,
                        guards,
                    );
                } else {
                    let target = property
                        .field(source_text, Field::Value)
                        .unwrap_or(property);
                    let projected = source.map(|source| {
                        project(
                            Some(source),
                            Some(
                                static_pattern_key(source_text, property)
                                    .unwrap_or(PropertyPathKey::Wildcard),
                            ),
                        )
                        .expect("projecting an existing pattern source")
                    });
                    visit_impl(
                        source_text,
                        sources,
                        target,
                        projected.as_ref(),
                        mutation,
                        guards,
                    );
                }
            }
        }
        "ArrayPattern" => {
            if let Some(source) = source {
                if source.rest_start_index.is_none() {
                    add(
                        sources,
                        source,
                        mutation,
                        guards,
                        IterationSourceKind::Iteration,
                        None,
                    );
                }
            }
            for (index, element) in pattern
                .field_list(source_text, Field::Elements)
                .into_iter()
                .enumerate()
            {
                let Some(element) = element else {
                    continue;
                };
                if element.babel_type() == "RestElement" {
                    let Some(argument) = element.field(source_text, Field::Argument) else {
                        continue;
                    };
                    let rest = source.map(|source| PatternSource {
                        value: source.value.clone(),
                        rest_start_index: Some(source.rest_start_index.unwrap_or(0) + index),
                    });
                    visit_impl(
                        source_text,
                        sources,
                        argument,
                        rest.as_ref(),
                        mutation,
                        guards,
                    );
                } else {
                    let projected = source.and_then(|source| {
                        project(Some(source), Some(PropertyPathKey::Number(index)))
                    });
                    visit_impl(
                        source_text,
                        sources,
                        element,
                        projected.as_ref(),
                        mutation,
                        guards,
                    );
                }
            }
        }
        "RestElement" => {
            if let Some(argument) = pattern.field(source_text, Field::Argument) {
                visit_impl(source_text, sources, argument, None, mutation, guards);
            }
        }
        _ => {}
    }
}
