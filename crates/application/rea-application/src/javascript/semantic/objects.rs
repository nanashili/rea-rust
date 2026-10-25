//! Static property operations from `javascriptSemanticObjects.ts`.
//!
//! A member chain contributes one operation for its complete path. Dynamic
//! keys retain an unknown path, and binding lookups retain unresolved identity.
//! This collector records syntax and lexical facts without evaluating a target.

use std::collections::HashSet;
use std::ops::ControlFlow;

use crate::javascript::ast::{AstVisitor, Field, Node, NodeMap, traverse};
use crate::javascript::contracts::semantic_ir::{
    SemanticObjectOperation, SemanticObjectOperationKind, SemanticOperationResolution,
};
use crate::javascript::static_analysis::helpers::range;

use super::ast_values::{
    is_member, static_property_key, unwrapped, write_site_reads_first, write_site_target,
    write_targets,
};
use super::callable_stack::SemanticCallableStack;
use super::projection::SemanticCallable;
use super::state::SemanticState;
use super::value_types::JsString;

struct ObjectIdentity {
    binding_id: Option<String>,
    path: Option<Vec<JsString>>,
}

struct ObjectCollector<'s, 'a> {
    state: &'s SemanticState<'a>,
    callable_ids: HashSet<&'s str>,
    callable_stack: SemanticCallableStack<String>,
    write_targets: NodeMap<Node<'a>>,
    output: Vec<SemanticObjectOperation>,
}

/// Recover property reads, writes, object spreads, and destructuring operations.
pub fn collect_semantic_objects<'s, 'a>(
    state: &'s SemanticState<'a>,
    callables: &'s [SemanticCallable],
) -> Vec<SemanticObjectOperation> {
    let mut collector = ObjectCollector {
        state,
        callable_ids: callables
            .iter()
            .map(|callable| callable.callable_id.as_str())
            .collect(),
        callable_stack: SemanticCallableStack::default(),
        write_targets: NodeMap::new(),
        output: Vec::new(),
    };

    let _ = traverse(state.program, state.source, &mut collector, || {
        ControlFlow::<()>::Continue(())
    });
    collector.output
}

impl<'a> AstVisitor<'a> for ObjectCollector<'_, 'a> {
    fn enter(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>, _ancestors: &[Node<'a>]) {
        let callable_ids = &self.callable_ids;
        self.callable_stack
            .enter(&self.state.context, node, parent, |id| {
                callable_ids.contains(id).then(|| id.to_owned())
            });

        self.index_write_targets(node);

        if is_member(node) {
            self.collect_member(*node, parent);
        } else if node.babel_type() == "SpreadElement"
            && parent.is_some_and(|parent| parent.babel_type() == "ObjectExpression")
        {
            let identity = self.expression_identity(node.field(self.state.source, Field::Argument));
            self.add_operation(*node, SemanticObjectOperationKind::Spread, identity, None);
        } else if node.babel_type() == "VariableDeclarator"
            && let Some(pattern) = node.field(self.state.source, Field::Id)
            && is_destructuring_pattern(pattern)
        {
            self.collect_destructuring(pattern, node.field(self.state.source, Field::Init));
        } else if node.babel_type() == "AssignmentExpression"
            && node.operator() == Some("=")
            && let Some(pattern) = node.field(self.state.source, Field::Left)
            && is_destructuring_pattern(pattern)
        {
            self.collect_destructuring(pattern, node.field(self.state.source, Field::Right));
        }
    }

    fn exit(&mut self, node: &Node<'a>, _parent: Option<&Node<'a>>) {
        self.callable_stack.exit(&self.state.context, node);
    }
}

impl<'a> ObjectCollector<'_, 'a> {
    fn index_write_targets(&mut self, site: &Node<'a>) {
        let Some(target) = write_site_target(self.state.source, site) else {
            return;
        };

        for leaf in write_targets(self.state.source, target) {
            if leaf.babel_type() != "Identifier" {
                self.write_targets.insert(leaf.key(), *site);
            }
        }
    }

    fn collect_member(&mut self, node: Node<'a>, parent: Option<&Node<'a>>) {
        if parent.is_some_and(|parent| {
            is_member(parent)
                && parent
                    .field(self.state.source, Field::Object)
                    .map(|object| object.key())
                    == Some(node.key())
        }) {
            return;
        }

        let identity = self.expression_identity(Some(node));
        let write_site = self.write_targets.remove(&node.key());
        if write_site.as_ref().is_some_and(write_site_reads_first) {
            self.add_operation(
                node,
                SemanticObjectOperationKind::Read,
                ObjectIdentity {
                    binding_id: identity.binding_id.clone(),
                    path: identity.path.clone(),
                },
                None,
            );
        }

        let kind = if write_site.is_some() {
            SemanticObjectOperationKind::Write
        } else {
            SemanticObjectOperationKind::Read
        };
        self.add_operation(node, kind, identity, None);
    }

    fn collect_destructuring(&mut self, root: Node<'a>, initializer: Option<Node<'a>>) {
        let source = self.expression_identity(initializer);
        let mut pending = vec![(root, Vec::<JsString>::new())];

        while let Some((next, path)) = pending.pop() {
            let occurrence = unwrapped(self.state.source, next);
            let pattern = if occurrence.babel_type() == "AssignmentPattern" {
                let Some(left) = occurrence.field(self.state.source, Field::Left) else {
                    continue;
                };
                unwrapped(self.state.source, left)
            } else {
                occurrence
            };

            match pattern.babel_type() {
                "ObjectPattern" => self.queue_object_slots(pattern, &path, &mut pending),
                "ArrayPattern" => self.queue_array_slots(pattern, &path, &mut pending),
                "Identifier" => {
                    let target_binding_id = self.binding_id(pattern);
                    let identity = ObjectIdentity {
                        binding_id: source.binding_id.clone(),
                        path: source
                            .path
                            .as_ref()
                            .map(|prefix| prefix.iter().chain(&path).cloned().collect()),
                    };
                    self.add_operation(
                        occurrence,
                        SemanticObjectOperationKind::Destructure,
                        identity,
                        target_binding_id,
                    );
                }
                _ => {}
            }
        }
    }

    fn queue_object_slots(
        &self,
        pattern: Node<'a>,
        path: &[JsString],
        pending: &mut Vec<(Node<'a>, Vec<JsString>)>,
    ) {
        for property in pattern
            .field_list(self.state.source, Field::Properties)
            .into_iter()
            .rev()
            .flatten()
        {
            if property.babel_type() != "ObjectProperty" {
                continue;
            }
            let Some(key) = property.field(self.state.source, Field::Key) else {
                continue;
            };
            let Some(name) = static_property_key(self.state.source, key, property.computed())
            else {
                continue;
            };
            let Some(value) = property.field(self.state.source, Field::Value) else {
                continue;
            };
            let mut projected = path.to_vec();
            projected.push(name);
            pending.push((value, projected));
        }
    }

    fn queue_array_slots(
        &self,
        pattern: Node<'a>,
        path: &[JsString],
        pending: &mut Vec<(Node<'a>, Vec<JsString>)>,
    ) {
        for (index, element) in pattern
            .field_list(self.state.source, Field::Elements)
            .into_iter()
            .enumerate()
            .rev()
        {
            if let Some(element) = element
                && element.babel_type() != "RestElement"
            {
                let mut projected = path.to_vec();
                projected.push(index.to_string().into());
                pending.push((element, projected));
            }
        }
    }

    fn expression_identity(&self, node: Option<Node<'a>>) -> ObjectIdentity {
        let mut path = Vec::new();
        let mut current = node;
        let mut static_path = true;

        while let Some(node) = current {
            let node = unwrapped(self.state.source, node);
            if !is_member(&node) {
                current = Some(node);
                break;
            }

            let name = node
                .field(self.state.source, Field::Property)
                .and_then(|property| {
                    static_property_key(self.state.source, property, node.computed())
                });
            if let Some(name) = name {
                path.push(name);
            } else {
                static_path = false;
            }
            current = node.field(self.state.source, Field::Object);
        }

        path.reverse();
        ObjectIdentity {
            binding_id: current.and_then(|node| self.binding_id(node)),
            path: static_path.then_some(path),
        }
    }

    fn binding_id(&self, node: Node<'a>) -> Option<String> {
        let name = node.identifier_name()?;
        let binding = self.state.resolve_binding(&node, name)?;
        Some(self.state.binding(binding).binding_id.clone())
    }

    fn add_operation(
        &mut self,
        node: Node<'a>,
        kind: SemanticObjectOperationKind,
        identity: ObjectIdentity,
        target_binding_id: Option<String>,
    ) {
        let resolution = if identity.binding_id.is_none()
            || identity.path.is_none()
            || (kind == SemanticObjectOperationKind::Destructure && target_binding_id.is_none())
        {
            SemanticOperationResolution::Partial
        } else {
            SemanticOperationResolution::Complete
        };

        self.output.push(SemanticObjectOperation {
            object_operation_id: format!(
                "object:{}:{}:{}",
                kind.as_str(),
                self.state.context.start(&node),
                self.state.context.end(&node)
            ),
            kind,
            location: range(&self.state.context, &node),
            owner_callable_id: self.callable_stack.current().cloned(),
            object_binding_id: identity.binding_id,
            target_binding_id,
            property_path: identity.path,
            resolution,
        });
    }
}

fn is_destructuring_pattern(node: Node<'_>) -> bool {
    matches!(node.babel_type(), "ObjectPattern" | "ArrayPattern")
}

#[cfg(test)]
mod tests;
