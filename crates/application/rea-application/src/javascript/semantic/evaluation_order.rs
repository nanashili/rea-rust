//! Port of `javascriptSemanticEvaluationOrder.ts`.

use crate::javascript::ast::{Field, Node};

use super::ast_values::{
    ExactLiteral, read_exact_literal, static_property_key, unwrap_expression, unwrapped,
};

/// `JavaScriptSemanticIterationCardinality`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IterationCardinality {
    Empty,
    Nonempty,
    Unknown,
}

/// `semanticIterationCardinality`: exact source-only cardinality for literal
/// loop heads. `prototype_may_affect_enumeration` is `None` for TS `undefined`.
pub fn iteration_cardinality<'a>(
    source: &'a str,
    looped: &Node<'a>,
    prototype_may_affect_enumeration: Option<bool>,
) -> IterationCardinality {
    use IterationCardinality as C;
    let Some(right) = looped.field(source, Field::Right) else {
        return C::Unknown;
    };
    let iterable = unwrapped(source, right);
    let literal = read_exact_literal(source, iterable);
    let prototype_known_inert = prototype_may_affect_enumeration == Some(false);
    if looped.babel_type() == "ForOfStatement" {
        if !prototype_known_inert {
            return C::Unknown;
        }
        if iterable.babel_type() == "ArrayExpression" {
            let elements = iterable.field_list(source, Field::Elements);
            if elements.is_empty() {
                return C::Empty;
            }
            if elements.iter().any(|element| match element {
                None => true,
                Some(element) => element.babel_type() != "SpreadElement",
            }) {
                return C::Nonempty;
            }
            return C::Unknown;
        }
        if let Some(ExactLiteral::String(text)) = literal {
            return if text.is_empty() {
                C::Empty
            } else {
                C::Nonempty
            };
        }
        return C::Unknown;
    }
    if iterable.babel_type() == "ObjectExpression" {
        let mut prototype: Option<Node<'a>> = None;
        for property in iterable
            .field_list(source, Field::Properties)
            .into_iter()
            .flatten()
        {
            if property.babel_type() == "SpreadElement" {
                return C::Unknown;
            }
            let key = property
                .field(source, Field::Key)
                .and_then(|key| static_property_key(source, key, property.computed()));
            if property.babel_type() == "ObjectProperty"
                && !property.computed()
                && !property.shorthand()
                && key.as_ref().is_some_and(|key| key == "__proto__")
            {
                prototype = property
                    .field(source, Field::Value)
                    .map(|value| unwrapped(source, value));
                continue;
            }
            if key.is_none() {
                return C::Unknown;
            }
            return C::Nonempty;
        }
        if prototype.is_some_and(|p| p.babel_type() == "NullLiteral") {
            return C::Empty;
        }
        if prototype.is_some_and(|p| read_exact_literal(source, p).is_none()) {
            return C::Unknown;
        }
        return if prototype_known_inert {
            C::Empty
        } else {
            C::Unknown
        };
    }
    match literal {
        Some(ExactLiteral::Null) => C::Empty,
        Some(ExactLiteral::String(text)) if !text.is_empty() => C::Nonempty,
        Some(_) if prototype_known_inert => C::Empty,
        _ => C::Unknown,
    }
}

/// `delayedInstanceFieldValue`: instance values run on construction; their
/// computed keys run at definition.
pub fn delayed_instance_field_value<'a>(
    source: &'a str,
    parent: Option<&Node<'a>>,
    child: Option<&Node<'a>>,
) -> bool {
    let Some(parent) = parent else { return false };
    matches!(
        parent.babel_type(),
        "ClassProperty" | "ClassPrivateProperty" | "ClassAccessorProperty"
    ) && !parent.is_static()
        && child.is_some_and(|child| is_field(source, parent, Field::Value, child))
}

fn is_field<'a>(source: &'a str, parent: &Node<'a>, field: Field, child: &Node<'a>) -> bool {
    parent
        .field(source, field)
        .is_some_and(|value| value.key() == child.key())
}

/// `semanticBranchMayBeSkipped`: shared branch facts for binding writes and
/// their possible execution positions.
pub fn branch_may_be_skipped<'a>(source: &'a str, parent: &Node<'a>, child: &Node<'a>) -> bool {
    use Field as F;
    if delayed_instance_field_value(source, Some(parent), Some(child)) {
        return true;
    }
    let is = |field| is_field(source, parent, field, child);
    match parent.babel_type() {
        "IfStatement" => is(F::Consequent) || is(F::Alternate),
        "SwitchCase" => true,
        "TryStatement" => is(F::Block) || is(F::Handler),
        "ForStatement" => is(F::Body) || is(F::Update),
        "WhileStatement" => is(F::Body),
        "DoWhileStatement" => is(F::Test),
        "ForInStatement" | "ForOfStatement" => is(F::Left) || is(F::Body),
        "LogicalExpression" | "AssignmentPattern" => is(F::Right),
        "AssignmentExpression" => {
            matches!(parent.operator(), Some("&&=" | "||=" | "??=")) && is(F::Right)
        }
        "ConditionalExpression" => is(F::Consequent) || is(F::Alternate),
        "OptionalCallExpression" | "CallExpression" => {
            parent
                .field_list(source, F::Arguments)
                .into_iter()
                .flatten()
                .any(|argument| argument.key() == child.key())
                && ((parent.babel_type() == "OptionalCallExpression" && parent.optional())
                    || parent
                        .field(source, F::Callee)
                        .is_some_and(|callee| optional_chain_may_short_circuit(source, callee)))
        }
        "OptionalMemberExpression" => {
            parent.computed()
                && is(F::Property)
                && (parent.optional()
                    || parent
                        .field(source, F::Object)
                        .is_some_and(|object| optional_chain_may_short_circuit(source, object)))
        }
        _ => false,
    }
}

/// Parentheses terminate optional-chain short-circuiting: `(foo?.bar)(arg)`
/// evaluates `arg` before attempting the call.
fn optional_chain_may_short_circuit<'a>(source: &'a str, expression: Node<'a>) -> bool {
    let mut current = expression;
    loop {
        if current.parenthesized() {
            return false;
        }
        let inner = unwrap_expression(source, current, true).node;
        if inner.key() != current.key() {
            current = inner;
            continue;
        }
        let next = match current.babel_type() {
            "OptionalMemberExpression" => {
                if current.optional() {
                    return true;
                }
                current.field(source, Field::Object)
            }
            "MemberExpression" => current.field(source, Field::Object),
            "OptionalCallExpression" => {
                if current.optional() {
                    return true;
                }
                current.field(source, Field::Callee)
            }
            "CallExpression" => current.field(source, Field::Callee),
            _ => return false,
        };
        match next {
            Some(next) => current = next,
            None => return false,
        }
    }
}
