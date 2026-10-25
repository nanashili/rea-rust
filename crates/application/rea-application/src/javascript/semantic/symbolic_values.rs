//! Symbolic JavaScript values and their provenance leaves.
//!
//! This is the Rust counterpart of `javascriptSymbolicValues.ts`.  Values are
//! immutable reference-counted nodes: the reference identity is deliberately
//! observable by [`symbolic_union`], just as JavaScript's `Set` observes object
//! identity rather than structural equality.

use std::rc::Rc;

use super::control_flow::{SymbolicShape, SymbolicTruthView};
use super::value_types::JsString;
use crate::javascript::ast::Node;

/// A symbolic value with identity-preserving sharing.
pub type SymbolicValue<'a> = Rc<SymbolicValueData<'a>>;

/// Insertion-preserving counterpart of JavaScript's `ReadonlyMap`.
#[derive(Clone, Debug, Default)]
pub struct SymbolicMap<'a> {
    entries: Vec<(String, SymbolicValue<'a>)>,
}

impl<'a> SymbolicMap<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<SymbolicValue<'a>> {
        self.entries
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
    }

    pub fn insert(&mut self, key: impl Into<String>, value: SymbolicValue<'a>) {
        let key = key.into();
        if let Some((_, existing)) = self.entries.iter_mut().find(|(name, _)| name == &key) {
            *existing = value;
            return;
        }
        self.entries.push((key, value));
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &SymbolicValue<'a>)> {
        self.entries
            .iter()
            .map(|(name, value)| (name.as_str(), value))
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(name, _)| name.as_str())
    }
}

impl<'a> From<Vec<(String, SymbolicValue<'a>)>> for SymbolicMap<'a> {
    fn from(entries: Vec<(String, SymbolicValue<'a>)>) -> Self {
        let mut map = Self::new();
        for (key, value) in entries {
            map.insert(key, value);
        }
        map
    }
}

/// A lexical substitution environment, never a JavaScript execution context.
#[derive(Clone, Debug)]
pub struct SymbolicEnvironment<'a> {
    /// Values directly bound in this environment.
    pub values: SymbolicMap<'a>,
    /// Lexical parent environment.
    pub parent: Option<Rc<SymbolicEnvironment<'a>>>,
    /// Stable activation identity shared by completed views.
    pub activation: Rc<Activation>,
    /// Known synchronous caller, distinct from lexical capture.
    pub caller: Option<Rc<SymbolicEnvironment<'a>>>,
    /// Source point where the function is symbolically executed.
    pub point: Option<Node<'a>>,
    /// Lexical function scope for point-sensitive initializer checks.
    pub scope_id: Option<String>,
    /// Function activation captured by this environment.
    pub scope_node: Option<Node<'a>>,
    /// Completion boundary proven for this captured activation.
    pub completed_at: Option<Node<'a>>,
    /// Shared completion facts remain unchanged through this later exit.
    pub common_through: Option<Node<'a>>,
}

/// Identity token for a symbolic activation.
#[derive(Debug, Default)]
pub struct Activation;

impl<'a> SymbolicEnvironment<'a> {
    /// Construct an empty lexical environment with a fresh activation.
    pub fn empty() -> Rc<Self> {
        Self::with_activation(Rc::new(Activation))
    }

    /// Construct an environment that shares an existing activation.
    pub fn with_activation(activation: Rc<Activation>) -> Rc<Self> {
        Rc::new(Self {
            values: SymbolicMap::new(),
            parent: None,
            activation,
            caller: None,
            point: None,
            scope_id: None,
            scope_node: None,
            completed_at: None,
            common_through: None,
        })
    }

    /// Return the value in this environment or one of its lexical parents.
    pub fn lookup(&self, name: &str) -> Option<SymbolicValue<'a>> {
        self.values.get(name).or_else(|| {
            self.parent
                .as_deref()
                .and_then(|parent| parent.lookup(name))
        })
    }
}

/// Selection predicate attached to a symbolic value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionPolarity {
    Positive,
    Negative,
    Nullish,
    NotNullish,
}

/// A symbolic selection condition.
#[derive(Clone, Copy, Debug)]
pub struct SymbolicCondition<'a> {
    /// AST node whose branch selected the value.
    pub node: Node<'a>,
    /// How the branch tested the value.
    pub positive: ConditionPolarity,
}

/// Metadata shared by every symbolic value kind.
#[derive(Clone, Debug, Default)]
pub struct SymbolicMetadata<'a> {
    /// Predicates required for this value to be selected.
    pub conditions: Option<Vec<SymbolicCondition<'a>>>,
    /// A control-flow join prevented a sound predicate from being retained.
    pub condition_unresolved: bool,
}

/// JavaScript primitive values represented by the symbolic evaluator.
#[derive(Clone, Debug, PartialEq)]
pub enum LiteralValue {
    /// JavaScript `undefined` (kept distinct from `null`).
    Undefined,
    /// JavaScript `null` (kept distinct from `undefined`).
    Null,
    String(JsString),
    Number(f64),
    Boolean(bool),
}

/// A symbolic function value.
#[derive(Clone, Debug)]
pub struct SymbolicFunction<'a> {
    /// Function AST node.
    pub node: Node<'a>,
    /// Lexical environment captured by the function.
    pub environment: Rc<SymbolicEnvironment<'a>>,
    /// Source origins contributing to this function value.
    pub origins: Vec<Node<'a>>,
    /// Return statement completing its activation, when known.
    pub return_point: Option<Node<'a>>,
}

/// The non-metadata portion of a symbolic value.
#[derive(Clone, Debug)]
pub enum SymbolicKind<'a> {
    /// Unknown value with a human-readable reason.
    Unknown { reason: String },
    /// JavaScript primitive.
    Literal { value: LiteralValue },
    /// External path provenance.
    External { path: Vec<String> },
    /// Object expression and its lexical environment.
    Object {
        node: Node<'a>,
        environment: Rc<SymbolicEnvironment<'a>>,
    },
    /// Namespace identity, optionally with unknown runtime value.
    Namespace {
        binding_id: String,
        environment: Rc<SymbolicEnvironment<'a>>,
        runtime_value_unknown: bool,
    },
    /// CommonJS/ESM loader namespace.
    Loader { modules: SymbolicMap<'a> },
    /// Array elements.
    Array { values: Vec<SymbolicValue<'a>> },
    /// String-keyed record.
    Record { values: SymbolicMap<'a> },
    /// Identity-preserving union of alternatives.
    Union { values: Vec<SymbolicValue<'a>> },
    /// Iterator result source.
    Iterator,
    /// Promise result source.
    Promise {
        value: SymbolicValue<'a>,
        return_point: Option<Node<'a>>,
    },
    /// Captured function.
    Function(SymbolicFunction<'a>),
}

/// A symbolic value node.
#[derive(Clone, Debug)]
pub struct SymbolicValueData<'a> {
    /// Value kind and provenance payload.
    pub kind: SymbolicKind<'a>,
    /// Selection metadata.
    pub metadata: SymbolicMetadata<'a>,
}

/// Construct an unknown symbolic value.
pub fn symbolic_unknown<'a>(reason: impl Into<String>) -> SymbolicValue<'a> {
    value(SymbolicKind::Unknown {
        reason: reason.into(),
    })
}

/// Construct a literal symbolic value.
pub fn symbolic_literal<'a>(literal: LiteralValue) -> SymbolicValue<'a> {
    value(SymbolicKind::Literal { value: literal })
}

/// Construct an external provenance path.
pub fn symbolic_external<'a>(
    path: impl IntoIterator<Item = impl Into<String>>,
) -> SymbolicValue<'a> {
    value(SymbolicKind::External {
        path: path.into_iter().map(Into::into).collect(),
    })
}

/// Construct an object-expression value.
pub fn symbolic_object<'a>(
    node: Node<'a>,
    environment: Rc<SymbolicEnvironment<'a>>,
) -> SymbolicValue<'a> {
    value(SymbolicKind::Object { node, environment })
}

/// Construct a namespace value.
pub fn symbolic_namespace<'a>(
    binding_id: impl Into<String>,
    environment: Rc<SymbolicEnvironment<'a>>,
    runtime_value_unknown: bool,
) -> SymbolicValue<'a> {
    value(SymbolicKind::Namespace {
        binding_id: binding_id.into(),
        environment,
        runtime_value_unknown,
    })
}

/// Construct a loader namespace while retaining module insertion order.
pub fn symbolic_loader<'a>(modules: impl Into<SymbolicMap<'a>>) -> SymbolicValue<'a> {
    value(SymbolicKind::Loader {
        modules: modules.into(),
    })
}

/// Construct an array value.
pub fn symbolic_array<'a>(values: Vec<SymbolicValue<'a>>) -> SymbolicValue<'a> {
    value(SymbolicKind::Array { values })
}

/// Construct a record value while retaining property insertion order.
pub fn symbolic_record<'a>(values: impl Into<SymbolicMap<'a>>) -> SymbolicValue<'a> {
    value(SymbolicKind::Record {
        values: values.into(),
    })
}

/// Construct an iterator value.
pub fn symbolic_iterator<'a>() -> SymbolicValue<'a> {
    value(SymbolicKind::Iterator)
}

/// Construct a promise value.
pub fn symbolic_promise<'a>(
    resolved: SymbolicValue<'a>,
    return_point: Option<Node<'a>>,
) -> SymbolicValue<'a> {
    value(SymbolicKind::Promise {
        value: resolved,
        return_point,
    })
}

/// Construct a captured function value.
pub fn symbolic_function<'a>(function: SymbolicFunction<'a>) -> SymbolicValue<'a> {
    value(SymbolicKind::Function(function))
}

fn value<'a>(kind: SymbolicKind<'a>) -> SymbolicValue<'a> {
    Rc::new(SymbolicValueData {
        kind,
        metadata: SymbolicMetadata::default(),
    })
}

/// Return union alternatives, or a one-element slice for a non-union value.
pub fn symbolic_variants<'a>(value: &SymbolicValue<'a>) -> Vec<SymbolicValue<'a>> {
    match &value.kind {
        SymbolicKind::Union { values } => values.clone(),
        _ => vec![value.clone()],
    }
}

/// Flatten and identity-deduplicate alternatives, preserving first-seen order.
pub fn symbolic_union<'a>(
    values: impl IntoIterator<Item = SymbolicValue<'a>>,
) -> SymbolicValue<'a> {
    let mut unique = Vec::new();
    for candidate in values
        .into_iter()
        .flat_map(|value| symbolic_variants(&value))
    {
        if unique
            .iter()
            .any(|existing| Rc::ptr_eq(existing, &candidate))
        {
            continue;
        }
        unique.push(candidate);
    }
    match unique.as_slice() {
        [only] => only.clone(),
        _ => value(SymbolicKind::Union { values: unique }),
    }
}

/// Attach one selection condition, preserving union representation and identity
/// semantics for each variant.
pub fn symbolic_condition<'a>(
    value: &SymbolicValue<'a>,
    condition: SymbolicCondition<'a>,
) -> SymbolicValue<'a> {
    match &value.kind {
        SymbolicKind::Union { values } => symbolic_union(
            values
                .iter()
                .map(|variant| symbolic_condition(variant, condition)),
        ),
        _ => Rc::new(SymbolicValueData {
            kind: value.kind.clone(),
            metadata: SymbolicMetadata {
                conditions: Some(
                    value
                        .metadata
                        .conditions
                        .as_deref()
                        .unwrap_or_default()
                        .iter()
                        .copied()
                        .chain([condition])
                        .collect(),
                ),
                condition_unresolved: value.metadata.condition_unresolved,
            },
        }),
    }
}

/// Mark selection predicates unresolved while retaining the value kind.
pub fn symbolic_conditions_unresolved<'a>(value: &SymbolicValue<'a>) -> SymbolicValue<'a> {
    match &value.kind {
        SymbolicKind::Union { values } => {
            symbolic_union(values.iter().map(symbolic_conditions_unresolved))
        }
        _ => Rc::new(SymbolicValueData {
            kind: value.kind.clone(),
            metadata: SymbolicMetadata {
                conditions: value.metadata.conditions.clone(),
                condition_unresolved: true,
            },
        }),
    }
}

impl<'a> SymbolicTruthView for SymbolicValue<'a> {
    fn shape(&self) -> SymbolicShape<'_, Self> {
        match &self.kind {
            SymbolicKind::Literal { value } => SymbolicShape::Literal {
                nullish: matches!(value, LiteralValue::Null | LiteralValue::Undefined),
                truthy: literal_truth(value),
            },
            SymbolicKind::Namespace {
                runtime_value_unknown,
                ..
            } => SymbolicShape::Namespace {
                runtime_value_unknown: *runtime_value_unknown,
            },
            SymbolicKind::Union { values } => SymbolicShape::Union(values),
            SymbolicKind::Function(_)
            | SymbolicKind::Object { .. }
            | SymbolicKind::Loader { .. }
            | SymbolicKind::Array { .. }
            | SymbolicKind::Record { .. }
            | SymbolicKind::Iterator
            | SymbolicKind::Promise { .. } => SymbolicShape::Object,
            SymbolicKind::Unknown { .. } | SymbolicKind::External { .. } => SymbolicShape::Opaque,
        }
    }
}

fn literal_truth(value: &LiteralValue) -> bool {
    match value {
        LiteralValue::Undefined | LiteralValue::Null => false,
        LiteralValue::Boolean(value) => *value,
        LiteralValue::Number(value) => *value != 0.0 && !value.is_nan(),
        LiteralValue::String(value) => !value.is_empty(),
    }
}

/// Compare value identity, matching JavaScript `===` for symbolic references.
pub fn same_symbolic_value<'a>(left: &SymbolicValue<'a>, right: &SymbolicValue<'a>) -> bool {
    Rc::ptr_eq(left, right)
}

/// Find a string-keyed entry in a loader or record.
pub fn symbolic_property<'a>(value: &SymbolicValue<'a>, key: &str) -> Option<SymbolicValue<'a>> {
    let entries = match &value.kind {
        SymbolicKind::Loader { modules } => modules,
        SymbolicKind::Record { values } => values,
        _ => return None,
    };
    entries.get(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn union_deduplicates_identity_but_not_equal_literals() {
        let first = symbolic_literal(LiteralValue::String(JsString::from("same")));
        let second = symbolic_literal(LiteralValue::String(JsString::from("same")));
        let joined = symbolic_union([first.clone(), first.clone(), second.clone()]);
        let SymbolicKind::Union { values } = &joined.kind else {
            panic!("distinct references must remain distinct alternatives")
        };
        assert_eq!(values.len(), 2);
        assert!(same_symbolic_value(&values[0], &first));
        assert!(same_symbolic_value(&values[1], &second));
    }

    #[test]
    fn null_and_undefined_are_distinct_and_falsy() {
        let null = symbolic_literal(LiteralValue::Null);
        let undefined = symbolic_literal(LiteralValue::Undefined);
        assert_eq!(
            super::super::control_flow::symbolic_truth(&null),
            Some(false)
        );
        assert_eq!(
            super::super::control_flow::symbolic_truth(&undefined),
            Some(false)
        );
        assert!(!same_symbolic_value(&null, &undefined));
    }
}
