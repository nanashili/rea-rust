//! Demand and lexical activation boundaries for symbolic Electron reads.

use std::collections::HashSet;
use std::rc::Rc;

use crate::javascript::ast::{AstContext, Field, Node, NodeKey};
use crate::javascript::semantic::ast_values::{is_class, is_function};
use crate::javascript::semantic::control_flow::{
    LogicalOperator, definite_exit, symbolic_logical_right, symbolic_truth,
};
use crate::javascript::semantic::state::SemanticState;
use crate::javascript::semantic::symbolic_bindings::SymbolicBindings;
use crate::javascript::semantic::symbolic_values::{
    SymbolicEnvironment, SymbolicFunction, SymbolicKind, SymbolicValue, symbolic_variants,
};

type Environment<'a> = Rc<SymbolicEnvironment<'a>>;

pub(super) fn collect_symbolic_read_uncertainty<'a>(
    context: &AstContext<'a>,
    nodes: &[Node<'a>],
    state: &SemanticState<'a>,
) -> bool {
    let mut collector = SymbolicReads {
        context,
        resolver: SymbolicBindings::new(state),
        active_functions: HashSet::new(),
        remaining_visits: 1_000_000,
    };
    let environment = SymbolicEnvironment::empty();

    for call in nodes.iter().copied().filter(is_call) {
        let Some(callee) = call.field(state.source, Field::Callee) else {
            continue;
        };
        let string_seed = call
            .field_list(state.source, Field::Arguments)
            .into_iter()
            .next()
            .flatten()
            .is_some_and(|node| node.babel_type() == "StringLiteral");

        if string_seed {
            if collector.seed_reachable(call, &environment) {
                collector.call(call, &environment);
            }
        } else {
            // The isolated-world seed probe demands the callee even when
            // the call cannot become a path entry.
            collector.resolver.evaluate(callee, &environment);
        }
    }

    collector.resolver.unresolved || collector.resolver.truncated || collector.remaining_visits == 0
}

struct SymbolicReads<'state, 'a> {
    context: &'state AstContext<'a>,
    resolver: SymbolicBindings<'state, 'a>,
    active_functions: HashSet<NodeKey>,
    remaining_visits: usize,
}

impl<'state, 'a> SymbolicReads<'state, 'a> {
    fn seed_reachable(&mut self, node: Node<'a>, environment: &Environment<'a>) -> bool {
        let mut child = node;
        while let Some(parent) = self.resolver.state.parent_of(&child) {
            if is_function(&parent) {
                break;
            }
            match parent.babel_type() {
                "IfStatement" | "ConditionalExpression" => {
                    let test = parent.field(self.context.source(), Field::Test);
                    if test.is_some_and(|test| test.key() != child.key()) {
                        let truth = test.and_then(|test| {
                            symbolic_truth(&self.resolver.evaluate(test, environment))
                        });
                        let consequent = parent
                            .field(self.context.source(), Field::Consequent)
                            .is_some_and(|branch| branch.key() == child.key());
                        if truth.is_some_and(|truth| truth != consequent) {
                            return false;
                        }
                    }
                }
                "LogicalExpression" => {
                    if parent
                        .field(self.context.source(), Field::Right)
                        .is_some_and(|right| right.key() == child.key())
                        && self.logical_right(parent, environment) == Some(false)
                    {
                        return false;
                    }
                }
                "BlockStatement" => {
                    for statement in parent
                        .field_list(self.context.source(), Field::Body)
                        .into_iter()
                        .flatten()
                    {
                        if statement.key() == child.key() {
                            break;
                        }
                        if self.exits(statement, environment) {
                            return false;
                        }
                    }
                }
                _ => {}
            }
            child = parent;
        }
        true
    }

    fn call(&mut self, call: Node<'a>, environment: &Environment<'a>) {
        let Some(callee) = call.field(self.context.source(), Field::Callee) else {
            return;
        };
        let value = self.resolver.evaluate(callee, environment);
        let arguments = self.resolver.arguments(call, environment);
        for variant in symbolic_variants(&value) {
            if let SymbolicKind::Function(function) = &variant.kind {
                self.function_body(function, call, arguments.clone(), environment);
            }
        }
    }

    fn function_body(
        &mut self,
        function: &SymbolicFunction<'a>,
        invocation: Node<'a>,
        arguments: Vec<SymbolicValue<'a>>,
        caller: &Environment<'a>,
    ) {
        if super::babel::function_flags(&function.node).is_some_and(|(_, generator)| generator) {
            return;
        }
        if self.active_functions.len() >= 128 {
            self.remaining_visits = 0;
            return;
        }
        if !self.active_functions.insert(function.node.key()) {
            return;
        }

        if let Some(body) = function.node.field(self.context.source(), Field::Body) {
            let environment =
                self.resolver
                    .bind(function, arguments, invocation, Some(caller.clone()));
            self.walk(body, &environment);
        }

        self.active_functions.remove(&function.node.key());
    }

    fn walk(&mut self, node: Node<'a>, environment: &Environment<'a>) {
        if self.remaining_visits == 0 {
            return;
        }
        self.remaining_visits -= 1;
        if is_function(&node) || is_class(&node) {
            return;
        }

        match node.babel_type() {
            "BlockStatement" => self.walk_block(node, environment),
            "IfStatement" | "ConditionalExpression" => self.walk_conditional(node, environment),
            "LogicalExpression" => self.walk_logical(node, environment),
            _ => {
                if is_call(&node) {
                    self.call(node, environment);
                }
                for child in self.context.children(&node) {
                    self.walk(child, environment);
                }
            }
        }
    }

    fn walk_block(&mut self, block: Node<'a>, environment: &Environment<'a>) {
        for statement in block
            .field_list(self.context.source(), Field::Body)
            .into_iter()
            .flatten()
        {
            self.walk(statement, environment);
            if self.exits(statement, environment) {
                break;
            }
        }
    }

    fn exits(&mut self, statement: Node<'a>, environment: &Environment<'a>) -> bool {
        if definite_exit(self.context.source(), Some(statement)) {
            return true;
        }
        if statement.babel_type() != "IfStatement" {
            return false;
        }
        let truth = statement
            .field(self.context.source(), Field::Test)
            .and_then(|test| symbolic_truth(&self.resolver.evaluate(test, environment)));
        truth.is_some_and(|truth| {
            definite_exit(
                self.context.source(),
                statement.field(
                    self.context.source(),
                    if truth {
                        Field::Consequent
                    } else {
                        Field::Alternate
                    },
                ),
            )
        })
    }

    fn walk_conditional(&mut self, node: Node<'a>, environment: &Environment<'a>) {
        let selected = node
            .field(self.context.source(), Field::Test)
            .and_then(|test| symbolic_truth(&self.resolver.evaluate(test, environment)));
        if selected != Some(false)
            && let Some(consequent) = node.field(self.context.source(), Field::Consequent)
        {
            self.walk(consequent, environment);
        }
        if selected != Some(true)
            && let Some(alternate) = node.field(self.context.source(), Field::Alternate)
        {
            self.walk(alternate, environment);
        }
    }

    fn logical_right(&mut self, node: Node<'a>, environment: &Environment<'a>) -> Option<bool> {
        let operator = match node.operator()? {
            "&&" => LogicalOperator::And,
            "||" => LogicalOperator::Or,
            "??" => LogicalOperator::Nullish,
            _ => return None,
        };
        let left = node.field(self.context.source(), Field::Left)?;
        symbolic_logical_right(operator, &self.resolver.evaluate(left, environment))
    }

    fn walk_logical(&mut self, node: Node<'a>, environment: &Environment<'a>) {
        if let Some(left) = node.field(self.context.source(), Field::Left) {
            self.walk(left, environment);
        }
        if self.logical_right(node, environment) != Some(false)
            && let Some(right) = node.field(self.context.source(), Field::Right)
        {
            self.walk(right, environment);
        }
    }
}

fn is_call(node: &Node<'_>) -> bool {
    matches!(
        node.babel_type(),
        "CallExpression" | "OptionalCallExpression"
    )
}
