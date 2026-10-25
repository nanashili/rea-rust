//! Source-owned Promise/task operation recovery.
//!
//! This is intentionally kept separate from the graph projection.  The pass
//! records only explicit syntax and lexical facts; callers decide when to
//! serialize the resulting operations.

use std::collections::{HashMap, HashSet};

use crate::javascript::ast::{AstVisitor, Field, Node, NodeKey, traverse};
use crate::javascript::contracts::semantic_ir::SemanticPromiseOperation;
use crate::javascript::contracts::static_analysis::SourceRange as ContractSourceRange;
use crate::javascript::parser::SourceRange;

use super::ast_values::{static_property_name, unwrapped};
use super::callable_stack::SemanticCallableStack;
use super::data_effect_helpers::{
    assigned_semantic_result_bindings, data_effect_member_callee, scalar_assigned_result_binding,
};
use super::projection::{SemanticCallable, callable_id_for_node};
use super::state::SemanticState;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PromiseKind {
    Constructor,
    Static,
    Chain,
    Aggregate,
    AwaitedExpression,
}

impl PromiseKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Constructor => "constructor",
            Self::Static => "static",
            Self::Chain => "chain",
            Self::Aggregate => "aggregate",
            Self::AwaitedExpression => "awaited-expression",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PromiseMethod {
    New,
    Resolve,
    Reject,
    Then,
    Catch,
    Finally,
    All,
    AllSettled,
    Await,
}

impl PromiseMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Resolve => "resolve",
            Self::Reject => "reject",
            Self::Then => "then",
            Self::Catch => "catch",
            Self::Finally => "finally",
            Self::All => "all",
            Self::AllSettled => "allSettled",
            Self::Await => "await",
        }
    }
}

struct Candidate<'a> {
    node: Node<'a>,
    kind: PromiseKind,
    method: PromiseMethod,
    promise_id: String,
    owner_callable_id: Option<String>,
    ancestors: Vec<Node<'a>>,
}

/// Recover explicit construction, chaining, aggregation, and await syntax.
///
/// `return_sites` is supplied by the return-site owner so this pass does not
/// reconstruct return values or silently invent return identities.
pub fn collect_semantic_promises<'a>(
    state: &SemanticState<'a>,
    callables: &[SemanticCallable],
    return_sites: &HashMap<String, HashMap<String, String>>,
) -> Vec<SemanticPromiseOperation> {
    let candidates = collect_candidates(state, callables);
    let by_node: HashMap<NodeKey, usize> = candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| (candidate.node.key(), index))
        .collect();

    candidates
        .iter()
        .map(|candidate| {
            let ownership =
                promise_ownership(candidate, &candidates, &by_node, state, return_sites);
            let sources = promise_sources(candidate, &candidates, &by_node, state);
            let mut source_ids = sources.ids;
            source_ids.sort();
            source_ids.dedup();
            SemanticPromiseOperation {
                promise_id: candidate.promise_id.clone(),
                kind: candidate.kind.as_str().to_owned(),
                method: candidate.method.as_str().to_owned(),
                location: contract_range(state.context.range(&candidate.node)),
                owner_callable_id: candidate.owner_callable_id.clone(),
                ownership: ownership.0.to_owned(),
                owner_binding_id: ownership.1,
                return_site_id: ownership.2,
                source_promise_ids: source_ids,
                source_resolution: sources.status.to_owned(),
            }
        })
        .collect()
}

fn collect_candidates<'a>(
    state: &SemanticState<'a>,
    callables: &[SemanticCallable],
) -> Vec<Candidate<'a>> {
    let admitted: HashSet<String> = callables.iter().map(|c| c.callable_id.clone()).collect();
    struct Visitor<'a, 's> {
        state: &'s SemanticState<'a>,
        admitted: &'s HashSet<String>,
        stack: SemanticCallableStack<String>,
        ancestors: Vec<Node<'a>>,
        output: Vec<Candidate<'a>>,
    }
    impl<'a, 's> AstVisitor<'a> for Visitor<'a, 's> {
        fn enter(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>, _ancestors: &[Node<'a>]) {
            self.stack.enter(&self.state.context, node, parent, |id| {
                self.admitted.contains(id).then(|| id.to_owned())
            });
            if let Some((kind, method)) = candidate_details(*node, self.state) {
                self.output.push(Candidate {
                    node: *node,
                    kind,
                    method,
                    promise_id: format!(
                        "promise:{}:{}:{}",
                        kind.as_str(),
                        self.state.context.start(node),
                        self.state.context.end(node)
                    ),
                    owner_callable_id: self.stack.current().cloned(),
                    ancestors: self.ancestors.clone(),
                });
            }
            self.ancestors.push(*node);
        }
        fn exit(&mut self, node: &Node<'a>, _parent: Option<&Node<'a>>) {
            self.ancestors.pop();
            self.stack.exit(&self.state.context, node);
        }
    }
    let mut visitor = Visitor {
        state,
        admitted: &admitted,
        stack: SemanticCallableStack::default(),
        ancestors: Vec::new(),
        output: Vec::new(),
    };
    let _ = traverse(state.program, state.source, &mut visitor, || {
        std::ops::ControlFlow::<()>::Continue(())
    });
    visitor.output
}

fn candidate_details<'a>(
    node: Node<'a>,
    state: &SemanticState<'a>,
) -> Option<(PromiseKind, PromiseMethod)> {
    if node.babel_type() == "NewExpression"
        && node
            .field(state.source, Field::Callee)
            .is_some_and(|callee| {
                callee.identifier_name() == Some("Promise")
                    && state.resolve_binding(&callee, "Promise").is_none()
                    && !state.resolution_blocked(&callee, "Promise")
            })
    {
        return Some((PromiseKind::Constructor, PromiseMethod::New));
    }
    if matches!(
        node.babel_type(),
        "CallExpression" | "OptionalCallExpression"
    ) {
        let member = data_effect_member_callee(node, state.source)?;
        let method = static_property_name(
            state.source,
            member.field(state.source, Field::Property)?,
            member.computed(),
        )
        .try_to_string()
        .ok()?;
        if member
            .field(state.source, Field::Object)
            .is_some_and(|object| {
                object.identifier_name() == Some("Promise")
                    && state.resolve_binding(&object, "Promise").is_none()
                    && !state.resolution_blocked(&object, "Promise")
            })
        {
            return match method.as_str() {
                "all" => Some((PromiseKind::Aggregate, PromiseMethod::All)),
                "allSettled" => Some((PromiseKind::Aggregate, PromiseMethod::AllSettled)),
                "resolve" => Some((PromiseKind::Static, PromiseMethod::Resolve)),
                "reject" => Some((PromiseKind::Static, PromiseMethod::Reject)),
                _ => None,
            };
        }
        return match method.as_str() {
            "then" => Some((PromiseKind::Chain, PromiseMethod::Then)),
            "catch" => Some((PromiseKind::Chain, PromiseMethod::Catch)),
            "finally" => Some((PromiseKind::Chain, PromiseMethod::Finally)),
            _ => None,
        };
    }
    if node.babel_type() == "AwaitExpression"
        && node
            .field(state.source, Field::Argument)
            .is_some_and(|argument| {
                candidate_details(unwrapped(state.source, argument), state).is_none()
            })
    {
        return Some((PromiseKind::AwaitedExpression, PromiseMethod::Await));
    }
    None
}

fn promise_ownership<'a>(
    candidate: &Candidate<'a>,
    candidates: &[Candidate<'a>],
    by_node: &HashMap<NodeKey, usize>,
    state: &SemanticState<'a>,
    return_sites: &HashMap<String, HashMap<String, String>>,
) -> (&'static str, Option<String>, Option<String>) {
    if candidate.kind == PromiseKind::AwaitedExpression {
        return ("awaited", None, None);
    }
    for ancestor in candidate.ancestors.iter().rev() {
        if ancestor.babel_type() == "AwaitExpression" {
            if ancestor
                .field(state.source, Field::Argument)
                .is_some_and(|argument| {
                    unwrapped(state.source, argument).key() == candidate.node.key()
                })
            {
                return ("awaited", None, None);
            }
            break;
        }
        let outer_index = by_node.get(&ancestor.key()).copied().or_else(|| {
            candidates
                .iter()
                .position(|candidate| same_expression_node(state, *ancestor, candidate.node))
        });
        if let Some(index) = outer_index {
            let outer = &candidates[index];
            if outer.owner_callable_id == candidate.owner_callable_id
                && outer_consumes(outer, candidate, state)
            {
                return (
                    if outer.kind == PromiseKind::Chain {
                        "chained"
                    } else {
                        "aggregated"
                    },
                    None,
                    None,
                );
            }
        } else if matches!(
            ancestor.babel_type(),
            "CallExpression" | "OptionalCallExpression" | "NewExpression"
        ) {
            break;
        }
        if let Some(binding) =
            assigned_binding(ancestor, candidate.node, state, &candidate.ancestors)
        {
            return ("assigned", Some(binding), None);
        }
        if ancestor.babel_type() == "ReturnStatement" {
            let Some(argument) = ancestor.field(state.source, Field::Argument) else {
                break;
            };
            if unwrapped(state.source, argument).key() != candidate.node.key() {
                break;
            }
            let callable = candidate.owner_callable_id.clone();
            let return_id = callable.as_ref().and_then(|id| {
                let key = return_site_key(&state.context.range(ancestor));
                return_sites
                    .get(id)
                    .and_then(|sites| sites.get(&key))
                    .cloned()
            });
            return ("returned", None, return_id);
        }
        if ancestor.babel_type() == "ExpressionStatement" {
            return if ancestor
                .field(state.source, Field::Expression)
                .is_some_and(|expression| {
                    unwrapped(state.source, expression).key() == candidate.node.key()
                }) {
                ("detached", None, None)
            } else {
                break;
            };
        }
        if let Some(callable) = callable_id_for_node(&state.context, ancestor) {
            if Some(callable) != candidate.owner_callable_id {
                continue;
            }
            if ancestor.babel_type() == "ArrowFunctionExpression"
                && ancestor
                    .field(state.source, Field::Body)
                    .is_some_and(|body| unwrapped(state.source, body).key() == candidate.node.key())
            {
                let return_id = candidate.owner_callable_id.as_ref().and_then(|id| {
                    let key = return_site_key(
                        &state
                            .context
                            .range(&ancestor.field(state.source, Field::Body).unwrap()),
                    );
                    return_sites
                        .get(id)
                        .and_then(|sites| sites.get(&key))
                        .cloned()
                });
                return ("returned", None, return_id);
            }
            break;
        }
    }
    ("unknown", None, None)
}

fn assigned_binding<'a>(
    ancestor: &Node<'a>,
    candidate: Node<'a>,
    state: &SemanticState<'a>,
    ancestors: &[Node<'a>],
) -> Option<String> {
    if !matches!(
        ancestor.babel_type(),
        "VariableDeclarator" | "AssignmentExpression"
    ) {
        return None;
    }
    let source = if ancestor.babel_type() == "VariableDeclarator" {
        ancestor.field(state.source, Field::Init)
    } else {
        ancestor.field(state.source, Field::Right)
    }?;
    if unwrapped(state.source, source).key() != candidate.key() {
        return None;
    }
    scalar_assigned_result_binding(&assigned_semantic_result_bindings(
        candidate, ancestors, state,
    ))
    .map(str::to_owned)
}

fn outer_consumes<'a>(
    outer: &Candidate<'a>,
    candidate: &Candidate<'a>,
    state: &SemanticState<'a>,
) -> bool {
    if outer.kind == PromiseKind::Chain {
        return data_effect_member_callee(outer.node, state.source)
            .and_then(|member| member.field(state.source, Field::Object))
            .is_some_and(|object| same_expression_node(state, object, candidate.node));
    }
    if outer.kind == PromiseKind::Aggregate {
        let Some(argument) = outer
            .node
            .field_list(state.source, Field::Arguments)
            .into_iter()
            .next()
            .flatten()
        else {
            return false;
        };
        return argument.babel_type() == "ArrayExpression"
            && argument
                .field_list(state.source, Field::Elements)
                .into_iter()
                .flatten()
                .filter(|element| element.babel_type() != "SpreadElement")
                .any(|element| same_expression_node(state, element, candidate.node));
    }
    false
}

fn same_expression_node<'a>(state: &SemanticState<'a>, left: Node<'a>, right: Node<'a>) -> bool {
    let left = unwrapped(state.source, left);
    let right = unwrapped(state.source, right);
    left.key() == right.key()
        || (left.babel_type() == right.babel_type()
            && state.context.start(&left) == state.context.start(&right)
            && state.context.end(&left) == state.context.end(&right))
}

struct Resolution {
    ids: Vec<String>,
    status: &'static str,
}

fn promise_sources<'a>(
    candidate: &Candidate<'a>,
    candidates: &[Candidate<'a>],
    by_node: &HashMap<NodeKey, usize>,
    state: &SemanticState<'a>,
) -> Resolution {
    match candidate.kind {
        PromiseKind::Chain => data_effect_member_callee(candidate.node, state.source)
            .and_then(|member| member.field(state.source, Field::Object))
            .map(|object| {
                resolve_expression(
                    object,
                    candidate,
                    candidates,
                    by_node,
                    state,
                    &mut HashSet::new(),
                )
            })
            .unwrap_or_else(unresolved),
        PromiseKind::Aggregate => {
            let Some(input) = candidate
                .node
                .field_list(state.source, Field::Arguments)
                .into_iter()
                .next()
                .flatten()
            else {
                return unresolved();
            };
            if input.babel_type() != "ArrayExpression" {
                return unresolved();
            }
            let values = input
                .field_list(state.source, Field::Elements)
                .into_iter()
                .map(|element| match element {
                    None => complete(),
                    Some(element) if element.babel_type() == "SpreadElement" => unresolved(),
                    Some(element) if obviously_non_promise(element) => complete(),
                    Some(element) => resolve_expression(
                        element,
                        candidate,
                        candidates,
                        by_node,
                        state,
                        &mut HashSet::new(),
                    ),
                })
                .collect::<Vec<_>>();
            combine(values)
        }
        PromiseKind::AwaitedExpression => candidate
            .node
            .field(state.source, Field::Argument)
            .map(|argument| {
                resolve_expression(
                    argument,
                    candidate,
                    candidates,
                    by_node,
                    state,
                    &mut HashSet::new(),
                )
            })
            .unwrap_or_else(unresolved),
        _ => complete(),
    }
}

fn resolve_expression<'a>(
    raw: Node<'a>,
    current: &Candidate<'a>,
    candidates: &[Candidate<'a>],
    by_node: &HashMap<NodeKey, usize>,
    state: &SemanticState<'a>,
    seen: &mut HashSet<String>,
) -> Resolution {
    let node = unwrapped(state.source, raw);
    if let Some(index) = by_node.get(&node.key()).copied() {
        if candidates[index].promise_id != current.promise_id {
            return Resolution {
                ids: vec![candidates[index].promise_id.clone()],
                status: "complete",
            };
        }
    }
    let Some(name) = node.identifier_name() else {
        return unresolved();
    };
    let Some(binding_index) = state.resolve_binding(&node, name) else {
        return unresolved();
    };
    let binding = state.binding(binding_index);
    if binding.mutable
        || binding.initializers.len() != 1
        || !seen.insert(binding.binding_id.clone())
    {
        return unresolved();
    }
    let Some(initializer) = binding.initializers.first() else {
        return unresolved();
    };
    if !initializer.projection.is_empty() {
        return unresolved();
    }
    resolve_expression(initializer.node, current, candidates, by_node, state, seen)
}

fn combine(values: Vec<Resolution>) -> Resolution {
    let has_unresolved = values.iter().any(|v| v.status == "unresolved");
    let has_complete = values.iter().any(|v| v.status == "complete");
    let status = if has_unresolved {
        if has_complete {
            "partial"
        } else {
            "unresolved"
        }
    } else if values.iter().any(|v| v.status == "partial") {
        "partial"
    } else {
        "complete"
    };
    Resolution {
        ids: values.into_iter().flat_map(|v| v.ids).collect(),
        status,
    }
}

fn complete() -> Resolution {
    Resolution {
        ids: Vec::new(),
        status: "complete",
    }
}
fn unresolved() -> Resolution {
    Resolution {
        ids: Vec::new(),
        status: "unresolved",
    }
}

fn obviously_non_promise(node: Node<'_>) -> bool {
    matches!(
        node.babel_type(),
        "StringLiteral"
            | "NumericLiteral"
            | "BooleanLiteral"
            | "NullLiteral"
            | "BigIntLiteral"
            | "RegExpLiteral"
            | "TemplateLiteral"
            | "ObjectExpression"
            | "FunctionExpression"
            | "ArrowFunctionExpression"
            | "ClassExpression"
            | "ClassDeclaration"
            | "FunctionDeclaration"
    )
}

fn return_site_key(location: &SourceRange) -> String {
    format!(
        "{}:{}:{}:{}",
        location.start.line, location.start.column, location.end.line, location.end.column
    )
}

fn contract_range(location: SourceRange) -> ContractSourceRange {
    ContractSourceRange {
        start: crate::javascript::contracts::static_analysis::SourcePoint {
            line: location.start.line,
            column: location.start.column,
        },
        end: crate::javascript::contracts::static_analysis::SourcePoint {
            line: location.end.line,
            column: location.end.column,
        },
    }
}
