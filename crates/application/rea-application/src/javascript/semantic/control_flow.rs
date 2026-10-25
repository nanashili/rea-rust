//! Port of `javascriptSymbolicControlFlow.ts`.
//!
//! `symbolicLogicalRight` (and the `symbolicTruth` it uses) read the
//! `SymbolicValue` algebra through [`SymbolicTruthView`], which the symbolic
//! evaluator package implements for its value type.

use crate::javascript::ast::{Field, Node};

/// Recursion bound of `symbolicDefiniteExit`.
const DEFINITE_EXIT_DEPTH_LIMIT: usize = 128;

/// `symbolicDefiniteExit`: only definite synchronous exits; unsupported
/// control flow stays `false`.
pub fn definite_exit<'a>(source: &'a str, node: Option<Node<'a>>) -> bool {
    definite_exit_at(source, node, 0)
}

fn definite_exit_at<'a>(source: &'a str, node: Option<Node<'a>>, depth: usize) -> bool {
    let Some(node) = node else { return false };
    if depth >= DEFINITE_EXIT_DEPTH_LIMIT {
        return false;
    }
    match node.babel_type() {
        "ReturnStatement" | "ThrowStatement" => true,
        "BlockStatement" => node
            .field_list(source, Field::Body)
            .into_iter()
            .any(|child| definite_exit_at(source, child, depth + 1)),
        "IfStatement" => {
            definite_exit_at(source, node.field(source, Field::Consequent), depth + 1)
                && definite_exit_at(source, node.field(source, Field::Alternate), depth + 1)
        }
        _ => false,
    }
}

/// The parts of a `SymbolicValue` (`javascriptSymbolicValues.ts`) that
/// `symbolicTruth` and `symbolicLogicalRight` read. The value algebra itself
/// (environments, origins, conditions) belongs to the symbolic evaluator
/// package; it implements [`SymbolicTruthView`] instead of this module
/// re-deriving its representation.
#[derive(Clone, Copy, Debug)]
pub enum SymbolicShape<'v, V> {
    /// `kind: "literal"`: whether the value is `null`/`undefined`, and
    /// JavaScript `Boolean(value)`.
    Literal { nullish: bool, truthy: bool },
    /// `kind: "namespace"`.
    Namespace { runtime_value_unknown: bool },
    /// `kind: "union"`.
    Union(&'v [V]),
    /// `function`, `object`, `array`, `record`, `loader`, `promise`,
    /// `iterator`: always truthy and never nullish.
    Object,
    /// `unknown`, `external`.
    Opaque,
}

/// A symbolic value as seen by the truth predicates.
pub trait SymbolicTruthView: Sized {
    fn shape(&self) -> SymbolicShape<'_, Self>;
}

/// `symbolicTruth`: `None` is TS `undefined` (unknown).
pub fn symbolic_truth<V: SymbolicTruthView>(value: &V) -> Option<bool> {
    match value.shape() {
        SymbolicShape::Namespace {
            runtime_value_unknown: true,
        } => None,
        SymbolicShape::Union(values) => unanimous(values.iter().map(symbolic_truth)),
        SymbolicShape::Literal { truthy, .. } => Some(truthy),
        SymbolicShape::Namespace { .. } | SymbolicShape::Object => Some(true),
        SymbolicShape::Opaque => None,
    }
}

/// `LogicalExpression["operator"]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogicalOperator {
    And,
    Or,
    Nullish,
}

/// `symbolicLogicalRight`: whether short-circuit evaluation reaches the
/// right operand; unknown stays `None`.
pub fn symbolic_logical_right<V: SymbolicTruthView>(
    operator: LogicalOperator,
    left: &V,
) -> Option<bool> {
    match left.shape() {
        SymbolicShape::Namespace {
            runtime_value_unknown: true,
        } => return None,
        SymbolicShape::Union(values) => {
            return unanimous(values.iter().map(|v| symbolic_logical_right(operator, v)));
        }
        _ => {}
    }
    if operator == LogicalOperator::Nullish {
        return match left.shape() {
            SymbolicShape::Literal { nullish, .. } => Some(nullish),
            SymbolicShape::Namespace { .. } | SymbolicShape::Object => Some(false),
            _ => None,
        };
    }
    symbolic_truth(left).map(|truth| {
        if operator == LogicalOperator::And {
            truth
        } else {
            !truth
        }
    })
}

/// The shared choice of a non-empty list, `None` when empty or mixed.
fn unanimous(mut choices: impl Iterator<Item = Option<bool>>) -> Option<bool> {
    let first = choices.next()?;
    choices
        .all(|choice| choice == first)
        .then_some(first)
        .flatten()
}
