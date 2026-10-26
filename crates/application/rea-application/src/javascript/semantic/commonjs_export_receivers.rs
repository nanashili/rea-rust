//! CommonJS export receiver identity and definition-site facts.
//!
//! This is the source-order port of `javascriptCommonJsExportReceivers.ts`.
//! Identity writes and ambient call effects remain separate collaborators: the
//! caller supplies the already-indexed public call writes by `NodeKey`.

use std::collections::HashMap;

use crate::javascript::ast::{Field, Node, NodeKey, NodeSet, traverse};

use super::ast_values::{is_member, static_property_key, unwrapped, write_targets};
use super::globals::is_unmodified_global_reference;
use super::state::SemanticState;
use super::value_types::JsString;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommonJsExportReceiverEffect {
    Connected,
    Detached,
    Uncertain,
}

#[derive(Clone, Debug)]
pub struct CommonJsDefinedExport<'a> {
    pub exported_name: JsString,
    pub receiver: Node<'a>,
    pub descriptor: Node<'a>,
}

fn is_commonjs_module_exports<'a>(state: &SemanticState<'a>, node: Node<'a>) -> bool {
    if !is_member(&node) {
        return false;
    }
    let Some(object) = node.field(state.source, Field::Object) else {
        return false;
    };
    state.is_unshadowed_global(&object, "module")
        && node
            .field(state.source, Field::Property)
            .and_then(|property| static_property_key(state.source, property, node.computed()))
            .is_some_and(|key| key == "exports")
}

/// Return the CommonJS export name represented by a member write.
pub fn commonjs_export_name<'a>(state: &SemanticState<'a>, node: Node<'a>) -> Option<JsString> {
    if !is_member(&node) {
        return None;
    }
    let object = node.field(state.source, Field::Object)?;
    let key = node
        .field(state.source, Field::Property)
        .and_then(|property| static_property_key(state.source, property, node.computed()));
    if state.is_unshadowed_global(&object, "exports") || is_commonjs_module_exports(state, object) {
        return Some(key.unwrap_or_else(|| JsString::from("*")));
    }
    is_commonjs_module_exports(state, node).then(|| JsString::from("default"))
}

fn is_unmodified_define_property<'a>(state: &SemanticState<'a>, callee: Node<'a>) -> bool {
    if !is_member(&callee) {
        return false;
    }
    let Some(object) = callee.field(state.source, Field::Object) else {
        return false;
    };
    state.is_unshadowed_global(&object, "Object")
        && callee
            .field(state.source, Field::Property)
            .and_then(|property| static_property_key(state.source, property, callee.computed()))
            .is_some_and(|key| key == "defineProperty")
        && is_unmodified_global_reference(state, &object, "Object")
}

/// Decode `Object.defineProperty(exports, key, descriptor)` export sites.
pub fn commonjs_defined_export<'a>(
    state: &SemanticState<'a>,
    node: Node<'a>,
) -> Option<CommonJsDefinedExport<'a>> {
    if node.babel_type() != "CallExpression" {
        return None;
    }
    let arguments = node
        .field_list(state.source, Field::Arguments)
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let [target, key, descriptor] = arguments.as_slice() else {
        return None;
    };
    if [target, key, descriptor]
        .into_iter()
        .any(|argument| argument.babel_type() == "SpreadElement")
    {
        return None;
    }
    let receiver = unwrapped(state.source, *target);
    if !(state.is_unshadowed_global(&receiver, "exports")
        || is_commonjs_module_exports(state, receiver))
        || !is_unmodified_define_property(state, node.field(state.source, Field::Callee)?)
    {
        return None;
    }
    Some(CommonJsDefinedExport {
        exported_name: static_property_key(state.source, *key, true)
            .unwrap_or_else(|| JsString::from("*")),
        receiver,
        descriptor: *descriptor,
    })
}

type Identity<'a> = Option<Node<'a>>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Execution {
    Ordered,
    Conditional,
    Deferred,
}

fn has_destructuring_evaluation_order(source: &str, node: Node<'_>) -> bool {
    let pattern = match node.babel_type() {
        "AssignmentExpression" => node
            .field(source, Field::Left)
            .map(|left| unwrapped(source, left)),
        "VariableDeclarator" => node.field(source, Field::Id),
        _ => None,
    };
    pattern.is_some_and(|pattern| matches!(pattern.babel_type(), "ObjectPattern" | "ArrayPattern"))
}

struct ReceiverIndexer<'s, 'a> {
    state: &'s SemanticState<'a>,
    public_identity: Identity<'a>,
    exports_identity: Identity<'a>,
    module_intact: bool,
    deferred_replacement: bool,
    fresh: NodeSet,
    values: HashMap<NodeKey, Identity<'a>>,
    captures: HashMap<NodeKey, Identity<'a>>,
    public_call_writes: &'s NodeSet,
    execution: Vec<Execution>,
}

impl<'s, 'a> ReceiverIndexer<'s, 'a> {
    fn value_of(&self, node: Node<'a>) -> Identity<'a> {
        let value = unwrapped(self.state.source, node);
        self.values
            .get(&value.key())
            .copied()
            .unwrap_or(Some(value))
    }

    fn write(&mut self, target: Node<'a>, identity: Identity<'a>, mode: Execution) {
        let target = unwrapped(self.state.source, target);
        let possible_public_write = is_member(&target)
            && target
                .field(self.state.source, Field::Object)
                .is_some_and(|object| self.state.is_unshadowed_global(&object, "module"))
            && target
                .field(self.state.source, Field::Property)
                .and_then(|property| {
                    static_property_key(self.state.source, property, target.computed())
                })
                .is_none();
        let public_write = is_commonjs_module_exports(self.state, target) || possible_public_write;
        let exports_write = self.state.is_unshadowed_global(&target, "exports");
        let module_write = self.state.is_unshadowed_global(&target, "module");
        if !(public_write || exports_write || module_write) {
            return;
        }
        if mode == Execution::Deferred {
            self.deferred_replacement = true;
            return;
        }
        let selected = (mode == Execution::Ordered && !possible_public_write)
            .then_some(identity)
            .flatten();
        if module_write {
            self.module_intact = false;
        }
        if public_write || module_write {
            self.public_identity = if self.module_intact { selected } else { None };
        }
        if exports_write {
            self.exports_identity = selected;
        }
    }

    fn enter(&mut self, node: Node<'a>, parent: Option<Node<'a>>) {
        let outer = self.execution.last().copied().unwrap_or(Execution::Ordered);
        let deferred = outer == Execution::Deferred
            || matches!(
                node.babel_type(),
                "FunctionDeclaration"
                    | "FunctionExpression"
                    | "ArrowFunctionExpression"
                    | "ClassDeclaration"
                    | "ClassExpression"
            );
        let conditional = outer == Execution::Conditional
            || has_destructuring_evaluation_order(self.state.source, node)
            || matches!(
                node.babel_type(),
                "IfStatement"
                    | "SwitchStatement"
                    | "ForStatement"
                    | "ForInStatement"
                    | "ForOfStatement"
                    | "WhileStatement"
                    | "DoWhileStatement"
                    | "TryStatement"
                    | "ObjectPattern"
                    | "ArrayPattern"
            )
            || parent.is_some_and(|parent| {
                (parent.babel_type() == "LogicalExpression"
                    && parent
                        .field(self.state.source, Field::Right)
                        .is_some_and(|right| right.key() == node.key()))
                    || (parent.babel_type() == "AssignmentPattern"
                        && parent
                            .field(self.state.source, Field::Right)
                            .is_some_and(|right| right.key() == node.key()))
                    || (parent.babel_type() == "AssignmentExpression"
                        && ["&&=", "||=", "??="].contains(&parent.operator().unwrap_or(""))
                        && parent
                            .field(self.state.source, Field::Right)
                            .is_some_and(|right| right.key() == node.key()))
                    || parent.babel_type() == "OptionalCallExpression"
                    || (parent.babel_type() == "OptionalMemberExpression"
                        && parent
                            .field(self.state.source, Field::Property)
                            .is_some_and(|property| property.key() == node.key()))
                    || (parent.babel_type() == "ConditionalExpression"
                        && parent
                            .field(self.state.source, Field::Test)
                            .is_none_or(|test| test.key() != node.key()))
            });
        self.execution.push(if deferred {
            Execution::Deferred
        } else if conditional {
            Execution::Conditional
        } else {
            Execution::Ordered
        });

        if node.babel_type() == "AssignmentExpression"
            && commonjs_export_name(
                self.state,
                node.field(self.state.source, Field::Left).unwrap_or(node),
            )
            .is_some()
            && !is_commonjs_module_exports(
                self.state,
                unwrapped(
                    self.state.source,
                    node.field(self.state.source, Field::Left).unwrap_or(node),
                ),
            )
        {
            let receiver = node.field(self.state.source, Field::Left).and_then(|left| {
                let left = unwrapped(self.state.source, left);
                is_member(&left)
                    .then(|| left.field(self.state.source, Field::Object))
                    .flatten()
            });
            let mode = *self.execution.last().expect("execution pushed");
            let captured = if mode != Execution::Ordered {
                None
            } else if receiver
                .is_some_and(|receiver| self.state.is_unshadowed_global(&receiver, "exports"))
            {
                self.exports_identity
            } else {
                self.public_identity
            };
            self.captures.insert(node.key(), captured);
        }
        if let Some(defined) = commonjs_defined_export(self.state, node) {
            let mode = *self.execution.last().expect("execution pushed");
            let captured = if mode != Execution::Ordered {
                None
            } else if self
                .state
                .is_unshadowed_global(&defined.receiver, "exports")
            {
                self.exports_identity
            } else {
                self.public_identity
            };
            self.captures.insert(node.key(), captured);
        }
    }

    fn exit(&mut self, node: Node<'a>) {
        let mode = self.execution.pop().unwrap_or(Execution::Conditional);
        if self.public_call_writes.contains(&node.key()) {
            if mode == Execution::Deferred {
                self.deferred_replacement = true;
            } else {
                self.public_identity = None;
            }
        }
        match node.babel_type() {
            "AssignmentExpression" => {
                let left = node
                    .field(self.state.source, Field::Left)
                    .map(|left| unwrapped(self.state.source, left));
                let identity = if node.operator() == Some("=")
                    && left.is_some_and(|left| {
                        matches!(
                            left.babel_type(),
                            "Identifier" | "MemberExpression" | "OptionalMemberExpression"
                        )
                    }) {
                    node.field(self.state.source, Field::Right)
                        .and_then(|right| self.value_of(right))
                } else {
                    None
                };
                if let Some(left) = left {
                    for target in write_targets(self.state.source, left) {
                        self.write(target, identity, mode);
                    }
                }
                self.values.insert(node.key(), identity);
            }
            "VariableDeclarator" => {
                if let Some(init) = node.field(self.state.source, Field::Init) {
                    for target in write_targets(
                        self.state.source,
                        node.field(self.state.source, Field::Id).unwrap_or(node),
                    ) {
                        self.write(
                            target,
                            (node
                                .field(self.state.source, Field::Id)
                                .is_some_and(|id| id.babel_type() == "Identifier"))
                            .then(|| self.value_of(init))
                            .flatten(),
                            mode,
                        );
                    }
                }
            }
            "ForOfStatement" | "ForInStatement" => {
                if node
                    .field(self.state.source, Field::Left)
                    .is_some_and(|left| left.babel_type() != "VariableDeclaration")
                {
                    if let Some(left) = node.field(self.state.source, Field::Left) {
                        for target in write_targets(self.state.source, left) {
                            self.write(target, None, mode);
                        }
                    }
                }
            }
            "UpdateExpression" | "UnaryExpression" => {
                if node.babel_type() == "UpdateExpression" || node.operator() == Some("delete") {
                    if let Some(argument) = node.field(self.state.source, Field::Argument) {
                        self.write(argument, None, mode);
                    }
                }
            }
            _ if self.state.is_unshadowed_global(&node, "exports") => {
                self.values.insert(node.key(), self.exports_identity);
            }
            _ if is_commonjs_module_exports(self.state, node) => {
                self.values.insert(node.key(), self.public_identity);
            }
            "ObjectExpression"
            | "ArrayExpression"
            | "FunctionExpression"
            | "ArrowFunctionExpression"
            | "ClassExpression" => {
                self.values.insert(node.key(), Some(node));
                self.fresh.insert(node.key());
            }
            "SequenceExpression" => {
                let identity = node
                    .field_list(self.state.source, Field::Expressions)
                    .into_iter()
                    .flatten()
                    .last()
                    .and_then(|last| self.value_of(last));
                self.values.insert(node.key(), identity);
            }
            _ => {}
        }
    }

    fn finish(self) -> HashMap<NodeKey, CommonJsExportReceiverEffect> {
        self.captures
            .into_iter()
            .map(|(key, receiver)| {
                let effect = if self.deferred_replacement
                    || receiver.is_none()
                    || self.public_identity.is_none()
                {
                    CommonJsExportReceiverEffect::Uncertain
                } else if receiver
                    .zip(self.public_identity)
                    .is_some_and(|(receiver, identity)| receiver.key() == identity.key())
                {
                    CommonJsExportReceiverEffect::Connected
                } else if receiver.is_some_and(|receiver| self.fresh.contains(&receiver.key()))
                    && self
                        .public_identity
                        .is_some_and(|identity| self.fresh.contains(&identity.key()))
                {
                    CommonJsExportReceiverEffect::Detached
                } else {
                    CommonJsExportReceiverEffect::Uncertain
                };
                (key, effect)
            })
            .collect()
    }
}

/// Index export receiver effects after definitions and ambient call writes exist.
pub fn index_commonjs_export_receivers<'a>(
    state: &SemanticState<'a>,
    public_call_writes: &NodeSet,
) -> HashMap<NodeKey, CommonJsExportReceiverEffect> {
    let initial = state.program;
    let mut indexer = ReceiverIndexer {
        state,
        public_identity: Some(initial),
        exports_identity: Some(initial),
        module_intact: true,
        deferred_replacement: false,
        fresh: NodeSet::from([initial.key()]),
        values: HashMap::new(),
        captures: HashMap::new(),
        public_call_writes,
        execution: Vec::new(),
    };
    struct Visitor<'i, 's, 'a> {
        indexer: &'i mut ReceiverIndexer<'s, 'a>,
    }
    impl<'i, 's, 'a> crate::javascript::ast::AstVisitor<'a> for Visitor<'i, 's, 'a> {
        fn enter(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>, _ancestors: &[Node<'a>]) {
            self.indexer.enter(*node, parent.copied());
        }
        fn exit(&mut self, node: &Node<'a>, _parent: Option<&Node<'a>>) {
            self.indexer.exit(*node);
        }
    }
    {
        let mut visitor = Visitor {
            indexer: &mut indexer,
        };
        let _ = traverse(state.program, state.source, &mut visitor, || {
            std::ops::ControlFlow::<()>::Continue(())
        });
    }
    indexer.finish()
}
