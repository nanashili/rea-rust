//! Interpretation of one getter result.
//!
//! Scheduling is deliberately kept in [`getter_queries`].  This module only
//! follows source syntax and asks the owner of class/object slots to resolve
//! a receiver.  That split is important: a getter result must not invent a
//! runtime value when a slot owner cannot establish one.

use crate::javascript::ast::{Field, Node};

use super::ast_values::{static_property_key, unwrapped};
use super::getter_queries::{GetterQueryJob, SemanticGetterQuery, SemanticObjectReference};
use super::object_references::ClassPropertyLookup;
use super::property_paths::{PropertyPath, PropertyPathKey};
use super::state::SemanticState;

/// Owner supplied interpretation of receiver and class reads.
pub(crate) trait GetterResultResolvers<'a> {
    fn class_references(
        &mut self,
        query: &mut SemanticGetterQuery<'_, 'a>,
        lookup: ClassPropertyLookup<'a>,
        key: PropertyPath,
        escapes: bool,
    );

    fn object_references(
        &mut self,
        query: &mut SemanticGetterQuery<'_, 'a>,
        object: Node<'a>,
        path: PropertyPath,
        escapes: bool,
    ) -> Vec<SemanticObjectReference<'a>>;

    fn private_receiver(
        &mut self,
        _query: &mut SemanticGetterQuery<'_, 'a>,
        _receiver: Node<'a>,
        _owner: Node<'a>,
        _path: &[PropertyPathKey],
        _is_static: bool,
    ) -> bool {
        false
    }
}

/// Expand a scheduled getter result using the supplied slot owners.
pub(crate) fn expand_semantic_getter_result<'state, 'ast, R: GetterResultResolvers<'ast>>(
    state: &'state SemanticState<'ast>,
    job: &GetterQueryJob<'ast>,
    query: &mut SemanticGetterQuery<'state, 'ast>,
    resolvers: &mut R,
) {
    let mut walker = GetterResultWalker {
        state,
        job,
        query,
        resolvers,
        seen: std::collections::HashSet::new(),
    };
    let getter = job.invocation.getter;
    let results = super::callable_results::callable_result_expressions(state.source, &getter);
    for result in results {
        if let Some(value) = result.node {
            walker.visit(value, job.path.clone(), job.escapes || result.delegated);
        }
    }
}

struct GetterResultWalker<'state, 'ast, 'q, R> {
    state: &'state SemanticState<'ast>,
    job: &'q GetterQueryJob<'ast>,
    query: &'q mut SemanticGetterQuery<'state, 'ast>,
    resolvers: &'q mut R,
    seen: std::collections::HashSet<String>,
}

impl<'state, 'ast, 'q, R: GetterResultResolvers<'ast>> GetterResultWalker<'state, 'ast, 'q, R> {
    fn retain(&mut self, node: Node<'ast>, path: PropertyPath, escapes: bool) {
        self.query.retain(
            SemanticObjectReference {
                node,
                path,
                escapes,
                widened_getter_result: false,
                owner_initializer: None,
            },
            escapes,
        );
    }

    fn visit(&mut self, input: Node<'ast>, path: PropertyPath, escapes: bool) {
        let node = unwrapped(self.state.source, input);
        let identity = format!("{:?}:{:?}:{}", node.key(), path, escapes);
        if !self.seen.insert(identity) {
            self.retain(node, Vec::new(), true);
            return;
        }

        match node.babel_type() {
            "Identifier" | "IdentifierReference" => self.identifier(node, path, escapes),
            "ThisExpression" => self.this_value(path, escapes),
            "MemberExpression" | "OptionalMemberExpression" => self.member(node, path, escapes),
            "ConditionalExpression" => {
                for field in [Field::Consequent, Field::Alternate] {
                    if let Some(child) = node.field(self.state.source, field) {
                        self.visit(child, path.clone(), escapes);
                    }
                }
            }
            "LogicalExpression" => {
                for field in [Field::Left, Field::Right] {
                    if let Some(child) = node.field(self.state.source, field) {
                        self.visit(child, path.clone(), escapes);
                    }
                }
            }
            "SequenceExpression" => {
                if let Some(child) = node
                    .field_list(self.state.source, Field::Expressions)
                    .into_iter()
                    .flatten()
                    .last()
                {
                    self.visit(child, path, escapes);
                }
            }
            "AssignmentExpression" => {
                if let Some(right) = node.field(self.state.source, Field::Right) {
                    self.visit(right, path, escapes);
                }
            }
            "NewExpression" => {
                if let Some(callee) = node.field(self.state.source, Field::Callee) {
                    self.visit(callee, path, escapes);
                }
            }
            "FunctionDeclaration"
            | "FunctionExpression"
            | "ArrowFunctionExpression"
            | "ObjectMethod"
            | "ClassMethod" => self.retain(node, path, escapes),
            _ => self.retain(node, path, escapes),
        }
    }

    fn identifier(&mut self, node: Node<'ast>, path: PropertyPath, escapes: bool) {
        let Some(name) = node.identifier_name() else {
            self.retain(node, path, escapes);
            return;
        };
        let Some(index) = self.state.resolve_binding(&node, name) else {
            self.retain(node, path, escapes);
            return;
        };
        let binding = self.state.binding(index);
        let mut initializers = Vec::new();
        initializers.extend(binding.initializers.iter().map(|value| value.node));
        initializers.extend(
            binding
                .reference_initializers
                .iter()
                .map(|value| value.node),
        );
        if initializers.is_empty() {
            self.retain(node, path, escapes);
            return;
        }
        for initializer in initializers {
            self.visit(initializer, path.clone(), escapes);
        }
    }

    fn member(&mut self, node: Node<'ast>, path: PropertyPath, escapes: bool) {
        let Some(object) = node.field(self.state.source, Field::Object) else {
            self.retain(node, path, escapes);
            return;
        };
        let receiver = unwrapped(self.state.source, object);
        if let Some(property) = node.field(self.state.source, Field::Property) {
            if property.babel_type() == "PrivateName" {
                if let Some(name) = property
                    .field(self.state.source, Field::Id)
                    .and_then(|id| id.identifier_name())
                {
                    let mut selected = vec![PropertyPathKey::String((name).into())];
                    selected.extend(path.clone());
                    if self.resolvers.private_receiver(
                        self.query,
                        receiver,
                        self.job.invocation.owner,
                        &selected,
                        false,
                    ) {
                        return;
                    }
                }
            }
        }
        let key = node
            .field(self.state.source, Field::Property)
            .and_then(|property| static_property_key(self.state.source, property, node.computed()))
            .map_or(PropertyPathKey::Wildcard, |key| {
                PropertyPathKey::String(key)
            });
        let mut selected = vec![key];
        selected.extend(path);
        match receiver.babel_type() {
            "Super" => {
                if let Some(owner) = self
                    .job
                    .invocation
                    .owner
                    .field(self.state.source, Field::SuperClass)
                {
                    self.resolvers.class_references(
                        self.query,
                        ClassPropertyLookup {
                            owner: unwrapped(self.state.source, owner),
                            receiver: Some(unwrapped(self.state.source, owner)),
                            kind: super::object_references::ClassLookupKind::Prototype,
                            fields_only: false,
                            initialized_before: None,
                        },
                        selected,
                        escapes,
                    );
                }
            }
            "ObjectExpression" => {
                for reference in self
                    .resolvers
                    .object_references(self.query, receiver, selected, escapes)
                {
                    self.query.retain(reference, escapes);
                }
            }
            "ClassDeclaration" | "ClassExpression" => self.resolvers.class_references(
                self.query,
                ClassPropertyLookup {
                    owner: receiver,
                    receiver: Some(receiver),
                    kind: super::object_references::ClassLookupKind::Static,
                    fields_only: false,
                    initialized_before: None,
                },
                selected,
                escapes,
            ),
            _ => self.retain(receiver, selected, escapes),
        }
    }

    fn this_value(&mut self, path: PropertyPath, escapes: bool) {
        let receiver = self.job.invocation.receiver();
        if receiver.babel_type() == "ObjectExpression" {
            for reference in self
                .resolvers
                .object_references(self.query, receiver, path, escapes)
            {
                self.query.retain(reference, escapes);
            }
        } else {
            self.resolvers.class_references(
                self.query,
                ClassPropertyLookup {
                    owner: self.job.invocation.owner,
                    receiver: Some(receiver),
                    kind: super::object_references::ClassLookupKind::Instance,
                    fields_only: false,
                    initialized_before: None,
                },
                path,
                escapes,
            );
        }
    }
}
