//! Port of `javascriptSemanticCallableResults.ts`.

use crate::javascript::ast::{Field, Node};

use super::ast_values::{is_class, is_function};

/// `SemanticCallableResultExpression.kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallableResultKind {
    Return,
    Yield,
}

/// One direct return or yield, excluding every nested callable.
#[derive(Clone, Copy, Debug)]
pub struct CallableResultExpression<'a> {
    /// The returned/yielded expression; `None` for a bare `return`/`yield`.
    pub node: Option<Node<'a>>,
    pub site: Node<'a>,
    pub kind: CallableResultKind,
    pub delegated: bool,
}

/// `semanticCallableResultExpressions`: direct result syntax in source
/// (pre-order) order, without evaluating the callable.
pub fn callable_result_expressions<'a>(
    source: &'a str,
    callable: &Node<'a>,
) -> Vec<CallableResultExpression<'a>> {
    if callable.babel_type() == "ArrowFunctionExpression"
        && let Some(body) = callable.field(source, Field::Body)
        && body.babel_type() != "BlockStatement"
    {
        return vec![CallableResultExpression {
            node: Some(body),
            site: body,
            kind: CallableResultKind::Return,
            delegated: false,
        }];
    }
    if !is_function(callable) {
        return Vec::new();
    }
    let Some(body) = callable.field(source, Field::Body) else {
        return Vec::new();
    };
    let mut output = Vec::new();
    let mut pending: Vec<Node<'a>> = body.children(source);
    pending.reverse();
    while let Some(node) = pending.pop() {
        if is_function(&node) || is_class(&node) {
            continue;
        }
        match node.babel_type() {
            "ReturnStatement" => output.push(CallableResultExpression {
                node: node.field(source, Field::Argument),
                site: node,
                kind: CallableResultKind::Return,
                delegated: false,
            }),
            "YieldExpression" => output.push(CallableResultExpression {
                node: node.field(source, Field::Argument),
                site: node,
                kind: CallableResultKind::Yield,
                delegated: node.delegate(),
            }),
            _ => {}
        }
        let mut children = node.children(source);
        children.reverse();
        pending.extend(children);
    }
    output
}
