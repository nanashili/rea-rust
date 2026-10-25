//! Source-local object and class slot interpretation.
//!
//! The query engine owns retry and identity.  This module owns only the
//! source order rules for object literals and class members.

use crate::javascript::ast::{Field, Node};

use super::ast_values::{static_property_key, unwrapped};
use super::getter_queries::{GetterInvocation, SemanticGetterQuery, SemanticObjectReference};
use super::getter_results::{GetterResultResolvers, expand_semantic_getter_result};
use super::property_paths::{PropertyPath, PropertyPathKey};
use super::state::SemanticState;
use super::value_types::JsString;

#[derive(Clone, Copy)]
pub(crate) enum ClassLookupKind {
    Instance,
    Static,
    Prototype,
}

#[derive(Clone, Copy)]
pub(crate) struct ClassPropertyLookup<'a> {
    pub owner: Node<'a>,
    pub receiver: Option<Node<'a>>,
    pub kind: ClassLookupKind,
    pub fields_only: bool,
    pub initialized_before: Option<Node<'a>>,
}

struct Resolvers<'state, 'ast> {
    state: &'state SemanticState<'ast>,
}

impl<'state, 'ast> GetterResultResolvers<'ast> for Resolvers<'state, 'ast> {
    fn private_receiver(
        &mut self,
        query: &mut SemanticGetterQuery<'_, 'ast>,
        receiver: Node<'ast>,
        owner: Node<'ast>,
        path: &[PropertyPathKey],
        _is_static: bool,
    ) -> bool {
        let Some(private_name) = path.first().and_then(|key| match key {
            PropertyPathKey::String(name) => Some(name),
            _ => None,
        }) else {
            return false;
        };
        let Some(body) = owner.field(self.state.source, Field::Body) else {
            return false;
        };
        let remaining = path.iter().skip(1).cloned().collect::<PropertyPath>();
        let mut found = false;
        for member in body
            .field_list(self.state.source, Field::Body)
            .into_iter()
            .flatten()
        {
            if member.babel_type() != "ClassPrivateProperty"
                || (member.is_static() && receiver.key() != owner.key())
            {
                continue;
            }
            let key = member.field(self.state.source, Field::Key);
            if key
                .and_then(|key| key.field(self.state.source, Field::Id))
                .and_then(|key| key.identifier_name())
                .is_none_or(|actual| private_name != actual)
            {
                continue;
            }
            if let Some(value) = member.field(self.state.source, Field::Value) {
                query.retain(
                    SemanticObjectReference {
                        node: value,
                        path: remaining.clone(),
                        escapes: false,
                        widened_getter_result: false,
                        owner_initializer: None,
                    },
                    false,
                );
                found = true;
            }
        }
        found
    }

    fn class_references(
        &mut self,
        query: &mut SemanticGetterQuery<'_, 'ast>,
        lookup: ClassPropertyLookup<'ast>,
        path: PropertyPath,
        escapes: bool,
    ) {
        let Some(key) = path.first().cloned() else {
            return;
        };
        let key_name = match key {
            PropertyPathKey::String(value) => Some(value),
            PropertyPathKey::Number(value) => Some(JsString::from(value.to_string())),
            _ => None,
        };
        let remaining = path.into_iter().skip(1).collect::<PropertyPath>();
        let mut pending = vec![lookup.owner];
        let mut cursor = 0;
        let mut seen = std::collections::HashSet::new();
        while let Some(current) = pending.get(cursor).copied() {
            cursor += 1;
            if !seen.insert(current.key()) {
                continue;
            }
            let Some(body) = current.field(self.state.source, Field::Body) else {
                continue;
            };
            let mut data_or_method_seen = false;
            let mut getter_seen = false;
            for member in body
                .field_list(self.state.source, Field::Body)
                .into_iter()
                .flatten()
            {
                let is_static = member.is_static();
                if lookup.initialized_before.is_some_and(|before| {
                    self.state.context.start(&member) >= self.state.context.start(&before)
                }) {
                    continue;
                }
                if !matches!(lookup.kind, ClassLookupKind::Static) && is_static {
                    continue;
                }
                if matches!(lookup.kind, ClassLookupKind::Static) && !is_static {
                    continue;
                }
                let member_key = member
                    .field(self.state.source, Field::Key)
                    .and_then(|node| {
                        static_property_key(self.state.source, node, member.computed())
                    });
                if key_name.as_ref().is_some_and(|expected| {
                    member_key.as_ref().is_none_or(|actual| expected != actual)
                }) {
                    continue;
                }
                match member.babel_type() {
                    "ClassProperty" | "ClassAccessorProperty" => {
                        if is_static
                            && lookup.receiver.map(|receiver| receiver.key()) != Some(current.key())
                        {
                            continue;
                        }
                        if data_or_method_seen {
                            continue;
                        }
                        data_or_method_seen = true;
                        if let Some(value) = member.field(self.state.source, Field::Value) {
                            query.retain(
                                SemanticObjectReference {
                                    node: value,
                                    path: remaining.clone(),
                                    escapes: false,
                                    widened_getter_result: false,
                                    owner_initializer: None,
                                },
                                escapes,
                            );
                        }
                    }
                    "ClassMethod" if member.declaration_kind() == Some("get") => {
                        if lookup.fields_only {
                            continue;
                        }
                        if data_or_method_seen || getter_seen {
                            continue;
                        }
                        getter_seen = true;
                        query.schedule(
                            GetterInvocation {
                                getter: member,
                                owner: current,
                                receiver: lookup.receiver,
                            },
                            remaining.clone(),
                            escapes,
                        );
                    }
                    "ClassMethod" => data_or_method_seen = true,
                    _ => {}
                }
            }

            if !data_or_method_seen && !getter_seen {
                if let Some(base) = current.field(self.state.source, Field::SuperClass) {
                    pending.extend(semantic_class_candidates(self.state, base));
                }
            }
        }
    }

    fn object_references(
        &mut self,
        query: &mut SemanticGetterQuery<'_, 'ast>,
        object: Node<'ast>,
        path: PropertyPath,
        escapes: bool,
    ) -> Vec<SemanticObjectReference<'ast>> {
        object_property_references(self.state, object, path, Some((query, escapes)))
    }
}

/// Resolve one object literal property, including getter scheduling.
pub fn semantic_object_property_references<'state, 'ast>(
    state: &'state SemanticState<'ast>,
    object: Node<'ast>,
    path: PropertyPath,
) -> Vec<SemanticObjectReference<'ast>> {
    let mut query = SemanticGetterQuery::new(state);
    let resolvers = std::cell::RefCell::new(Resolvers { state });
    query.run(
        |query| {
            let refs =
                object_property_references(state, object, path.clone(), Some((query, false)));
            for reference in refs {
                query.retain(reference, false);
            }
        },
        |job, query| expand_semantic_getter_result(state, job, query, &mut *resolvers.borrow_mut()),
    )
}

/// Resolve one class property through fields and getters.
pub fn semantic_class_property_references<'state, 'ast>(
    state: &'state SemanticState<'ast>,
    owner: Node<'ast>,
    receiver: Node<'ast>,
    path: PropertyPath,
) -> Vec<SemanticObjectReference<'ast>> {
    let mut query = SemanticGetterQuery::new(state);
    let resolvers = std::cell::RefCell::new(Resolvers { state });
    query.run(
        |query| {
            resolvers.borrow_mut().class_references(
                query,
                ClassPropertyLookup {
                    owner,
                    receiver: Some(receiver),
                    kind: ClassLookupKind::Prototype,
                    fields_only: false,
                    initialized_before: None,
                },
                path.clone(),
                false,
            )
        },
        |job, query| expand_semantic_getter_result(state, job, query, &mut *resolvers.borrow_mut()),
    )
}

fn object_property_references<'state, 'ast>(
    state: &'state SemanticState<'ast>,
    object: Node<'ast>,
    path: PropertyPath,
    mut query: Option<(&mut SemanticGetterQuery<'_, 'ast>, bool)>,
) -> Vec<SemanticObjectReference<'ast>> {
    let key = path.first();
    let remaining = path.iter().skip(1).cloned().collect::<PropertyPath>();
    let mut output = Vec::new();
    let members = object
        .field_list(state.source, Field::Properties)
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let mut overwritten = std::collections::HashSet::<JsString>::new();
    for member in members.into_iter().rev() {
        if member.babel_type() == "SpreadElement" {
            let argument = member.field(state.source, Field::Argument);
            if let Some(argument) = argument {
                let selection = match key {
                    Some(PropertyPathKey::Selection(selection)) => {
                        let mut excluded = selection.excluded_keys.clone();
                        excluded.extend(overwritten.iter().cloned());
                        excluded.sort();
                        excluded.dedup();
                        PropertyPathKey::Selection(super::property_paths::PropertySelection {
                            excluded_keys: excluded,
                            start_index: selection.start_index,
                        })
                    }
                    Some(PropertyPathKey::String(name)) if overwritten.contains(name) => continue,
                    Some(value) => value.clone(),
                    None => PropertyPathKey::Wildcard,
                };
                output.push(SemanticObjectReference {
                    node: argument,
                    path: [selection].into_iter().chain(remaining.clone()).collect(),
                    escapes: false,
                    widened_getter_result: false,
                    owner_initializer: None,
                });
            }
            continue;
        }
        let member_key = member
            .field(state.source, Field::Key)
            .and_then(|node| static_property_key(state.source, node, member.computed()));
        let matches = key.map_or(true, |key| match key {
            PropertyPathKey::String(value) => member_key.as_ref().is_some_and(|name| name == value),
            PropertyPathKey::Number(value) => member_key
                .as_ref()
                .is_some_and(|name| name == &JsString::from(value.to_string())),
            _ => true,
        });
        if !matches {
            continue;
        }
        if let Some(name) = member_key {
            if overwritten.contains(&name) {
                continue;
            }
            overwritten.insert(name);
        }
        if member.babel_type() == "ObjectMethod" && member.declaration_kind() == Some("get") {
            if let Some((getter_query, escapes)) = query.as_mut() {
                getter_query.schedule(
                    GetterInvocation {
                        getter: member,
                        owner: object,
                        receiver: Some(object),
                    },
                    remaining.clone(),
                    *escapes,
                );
            }
            continue;
        }
        if let Some(value) = member.field(state.source, Field::Value) {
            output.push(SemanticObjectReference {
                node: value,
                path: remaining.clone(),
                escapes: false,
                widened_getter_result: false,
                owner_initializer: None,
            });
        }
    }
    output
}

/// Follow class candidates through the syntactic superclass expression.
pub fn semantic_class_candidates<'state, 'ast>(
    state: &'state SemanticState<'ast>,
    root: Node<'ast>,
) -> Vec<Node<'ast>> {
    let mut pending = vec![unwrapped(state.source, root)];
    let mut seen = std::collections::HashSet::new();
    let mut classes = Vec::new();
    let mut cursor = 0;
    while let Some(node) = pending.get(cursor).copied() {
        cursor += 1;
        let node = unwrapped(state.source, node);
        if !seen.insert(node.key()) {
            continue;
        }
        match node.babel_type() {
            "ClassDeclaration" | "ClassExpression" => classes.push(node),
            "Identifier" | "IdentifierReference" => {
                if let Some(name) = node.identifier_name() {
                    if let Some(index) = state.resolve_binding(&node, name) {
                        let binding = state.binding(index);
                        pending.extend(binding.initializers.iter().map(|value| value.node));
                    }
                }
            }
            "ConditionalExpression" | "LogicalExpression" => {
                pending.extend(
                    [
                        node.field(state.source, Field::Consequent),
                        node.field(state.source, Field::Alternate),
                        node.field(state.source, Field::Left),
                        node.field(state.source, Field::Right),
                    ]
                    .into_iter()
                    .flatten(),
                );
            }
            "SequenceExpression" => {
                pending.extend(
                    node.field_list(state.source, Field::Expressions)
                        .into_iter()
                        .flatten()
                        .last(),
                );
            }
            _ => {}
        }
    }
    classes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::javascript::ast::{AstContext, AstVisitor, traverse};
    use crate::javascript::parser::parse_javascript_analysis_program;
    use crate::javascript::semantic::definitions::collect_definitions;
    use crate::javascript::semantic::state::ResolutionMode;
    use oxc_allocator::Allocator;
    use std::ops::ControlFlow;

    struct Nodes<'a>(Vec<Node<'a>>);
    impl<'a> AstVisitor<'a> for Nodes<'a> {
        fn enter(&mut self, node: &Node<'a>, _: Option<&Node<'a>>, _: &[Node<'a>]) {
            self.0.push(*node);
        }
    }

    fn state<'a>(
        allocator: &'a Allocator,
        source: &'a str,
    ) -> (
        crate::javascript::semantic::state::SemanticState<'a>,
        Vec<Node<'a>>,
    ) {
        let parsed =
            parse_javascript_analysis_program(allocator, source, Some("object.js")).expect("parse");
        let context = AstContext::new(parsed.program);
        let state = match collect_definitions(context, ResolutionMode::Import, || {
            ControlFlow::<()>::Continue(())
        }) {
            ControlFlow::Continue(state) => state,
            ControlFlow::Break(()) => panic!("definition collection cancelled"),
        };
        let mut nodes = Nodes(Vec::new());
        assert!(matches!(
            traverse(state.program, source, &mut nodes, || {
                ControlFlow::<()>::Continue(())
            }),
            ControlFlow::Continue(())
        ));
        (state, nodes.0)
    }

    #[test]
    fn object_getter_and_later_data_property_preserve_source_slot_rules() {
        let allocator = Allocator::default();
        let source = "const value = { get child() { return { leaf: 1 }; }, leaf: 2 };";
        let (state, nodes) = state(&allocator, source);
        let object = nodes
            .into_iter()
            .find(|node| node.babel_type() == "ObjectExpression")
            .expect("object");
        let references = semantic_object_property_references(
            &state,
            object,
            vec![PropertyPathKey::String("child".into())],
        );
        assert_eq!(references.len(), 1);
        assert_eq!(references[0].node.babel_type(), "ObjectExpression");
    }

    #[test]
    fn class_lookup_falls_through_to_superclass_when_child_has_no_descriptor() {
        let allocator = Allocator::default();
        let source =
            "class Base { get child() { return { leaf: 1 }; } } class Child extends Base {}";
        let (state, nodes) = state(&allocator, source);
        let classes = nodes
            .into_iter()
            .filter(|node| node.babel_type() == "ClassDeclaration")
            .collect::<Vec<_>>();
        let references = semantic_class_property_references(
            &state,
            classes[1],
            classes[1],
            vec![PropertyPathKey::String("child".into())],
        );
        assert_eq!(references.len(), 1);
        assert_eq!(references[0].node.babel_type(), "ObjectExpression");
    }
}
