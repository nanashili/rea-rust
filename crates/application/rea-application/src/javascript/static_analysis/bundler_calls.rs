//! References emitted by bundler runtime helpers.
//!
//! Webpack factories and Vite's `__vite__mapDeps` helper are ordinary calls in
//! the parsed source, but their arguments describe chunks rather than module
//! specifiers.  Keeping this classification separate from the general call
//! inspector makes the factory binding proof and the Vite table proof
//! explicit.

use std::collections::{BTreeSet, HashSet};
use std::ops::ControlFlow;

use crate::javascript::ast::{AstVisitor, Field, Node, traverse};
use crate::javascript::contracts::static_analysis::{ReferenceKind, StaticReference};
use crate::javascript::semantic::ambient_writes::is_unmodified_global_reference;
use crate::javascript::semantic::ast_values::{
    ExactLiteral, read_exact_literal, static_property_key, unwrapped,
};
use crate::javascript::semantic::state::SemanticState;
use crate::javascript::semantic::value_types::JsString;

use super::babel::same;
use super::bundler::{RequireLoaderFact, factory_loader_member_at};
use super::helpers::{argument_value, callee_name, range, source_slice};

/// Collect Webpack factory `.e` chunk references and Vite preload references.
///
/// The returned references are deliberately independent of the general call
/// collector so callers can merge them once, after bundler factories have
/// populated their proven binding IDs.
pub fn collect_runtime_references<'a>(
    state: &SemanticState<'a>,
    nodes: &[Node<'a>],
    factory_binding_ids: &BTreeSet<String>,
) -> Vec<StaticReference> {
    let ids: HashSet<String> = factory_binding_ids.iter().cloned().collect();
    let semantics = crate::javascript::semantic::module_interop::StateFacts::new(state);
    let mut references = collect_factory_require_references(state, nodes, &ids, &semantics);
    references.extend(collect_factory_chunk_references(
        state, nodes, &ids, &semantics,
    ));
    references.extend(collect_vite_preload_references(state, nodes));
    references.sort_by_key(|reference| {
        (
            reference.location.start.line,
            reference.location.start.column,
            reference.location.end.line,
            reference.location.end.column,
        )
    });
    references
}

fn collect_factory_require_references<'a>(
    state: &SemanticState<'a>,
    nodes: &[Node<'a>],
    factory_binding_ids: &HashSet<String>,
    semantics: &dyn super::semantics::StaticSemantics<'a>,
) -> Vec<StaticReference> {
    let source = state.source;
    nodes
        .iter()
        .copied()
        .filter(|node| {
            matches!(
                node.babel_type(),
                "CallExpression" | "OptionalCallExpression" | "NewExpression"
            )
        })
        .filter_map(|node| {
            let callee = node.field(source, Field::Callee)?;
            let (member, argument_index) = if callee.babel_type() == "Identifier" {
                (None, 0)
            } else {
                (Some("bind"), 1)
            };
            let fact =
                factory_loader_member_at(source, &node, semantics, factory_binding_ids, member)?;
            let argument = node
                .field_list(source, Field::Arguments)
                .get(argument_index)
                .copied()
                .flatten();
            let (specifier, expression) = match fact {
                RequireLoaderFact::FactoryLoader => {
                    let specifier = exact_literal_value(source, argument);
                    let expression = specifier
                        .is_none()
                        .then(|| JsString::from(source_slice(&state.context, &node)));
                    (specifier, expression)
                }
                RequireLoaderFact::Unknown => (
                    None,
                    Some(JsString::from(source_slice(&state.context, &node))),
                ),
            };
            Some(StaticReference {
                module_key: None,
                location: range(&state.context, &node),
                kind: ReferenceKind::Require,
                specifier,
                expression,
                module_runtime: None,
            })
        })
        .collect()
}

fn collect_factory_chunk_references<'a>(
    state: &SemanticState<'a>,
    nodes: &[Node<'a>],
    factory_binding_ids: &HashSet<String>,
    semantics: &dyn super::semantics::StaticSemantics<'a>,
) -> Vec<StaticReference> {
    let source = state.source;
    nodes
        .iter()
        .copied()
        .filter(|node| {
            matches!(
                node.babel_type(),
                "CallExpression" | "OptionalCallExpression" | "NewExpression"
            )
        })
        .filter_map(|node| {
            let fact =
                factory_loader_member_at(source, &node, semantics, factory_binding_ids, Some("e"))?;
            let args = node.field_list(source, Field::Arguments);
            let first = args.first().copied().flatten();
            let (specifier, expression) = match fact {
                RequireLoaderFact::FactoryLoader => {
                    let specifier = chunk_specifier(source, first);
                    let expression = specifier
                        .is_none()
                        .then(|| JsString::from(source_slice(&state.context, &node)));
                    (specifier, expression)
                }
                RequireLoaderFact::Unknown => (
                    None,
                    Some(JsString::from(source_slice(&state.context, &node))),
                ),
            };
            Some(StaticReference {
                module_key: None,
                location: range(&state.context, &node),
                kind: ReferenceKind::DynamicImport,
                specifier,
                expression,
                module_runtime: None,
            })
        })
        .collect()
}

fn collect_vite_preload_references<'a>(
    state: &SemanticState<'a>,
    nodes: &[Node<'a>],
) -> Vec<StaticReference> {
    let Some(table) = index_vite_map_deps(state) else {
        return Vec::new();
    };
    let source = state.source;
    nodes
        .iter()
        .copied()
        .filter(|node| {
            matches!(
                node.babel_type(),
                "CallExpression" | "OptionalCallExpression"
            )
        })
        .filter(|node| {
            node.field(source, Field::Callee)
                .is_some_and(|callee| callee_name(&state.context, callee) == "__vite__mapDeps")
        })
        .flat_map(|node| {
            let args = node.field_list(source, Field::Arguments);
            let Some(indexes) = args.first().copied().flatten() else {
                return Vec::new();
            };
            if indexes.babel_type() != "ArrayExpression"
                || !args.iter().skip(1).all(|argument| {
                    argument
                        .as_ref()
                        .is_none_or(|argument| is_explicit_default(state, argument))
                })
            {
                return indexes
                    .field_list(source, Field::Elements)
                    .into_iter()
                    .map(|_| unknown_reference(state, node))
                    .collect();
            }
            indexes
                .field_list(source, Field::Elements)
                .into_iter()
                .map(|element| {
                    let value = element
                        .and_then(|element| element.numeric_value())
                        .filter(|value| value.is_finite() && *value >= 0.0 && value.fract() == 0.0)
                        .and_then(|value| usize::try_from(value as u64).ok())
                        .and_then(|index| table.get(index).cloned().flatten());
                    match value {
                        Some(specifier) => StaticReference {
                            module_key: None,
                            location: range(&state.context, &node),
                            kind: ReferenceKind::DynamicImport,
                            specifier: Some(specifier),
                            expression: None,
                            module_runtime: None,
                        },
                        None => unknown_reference(state, node),
                    }
                })
                .collect()
        })
        .collect()
}

fn unknown_reference<'a>(state: &SemanticState<'a>, node: Node<'a>) -> StaticReference {
    StaticReference {
        module_key: None,
        location: range(&state.context, &node),
        kind: ReferenceKind::DynamicImport,
        specifier: None,
        expression: Some(JsString::from(source_slice(&state.context, &node))),
        module_runtime: None,
    }
}

fn is_explicit_default<'a>(state: &SemanticState<'a>, node: &Node<'a>) -> bool {
    let value = unwrapped(state.source, *node);
    if value.babel_type() == "UnaryExpression" && value.operator() == Some("void") {
        return true;
    }
    value.babel_type() == "Identifier"
        && value.identifier_name() == Some("undefined")
        && is_unmodified_global_reference(state, value, "undefined")
}

/// Recover the dependency table assigned to Vite's canonical map helper.
pub fn index_vite_map_deps<'a>(state: &SemanticState<'a>) -> Option<Vec<Option<JsString>>> {
    let source = state.source;
    let mut helpers = Vec::new();
    struct Find<'a> {
        source: &'a str,
        helpers: Vec<Node<'a>>,
    }
    impl<'a> AstVisitor<'a> for Find<'a> {
        fn enter(&mut self, node: &Node<'a>, _: Option<&Node<'a>>, _: &[Node<'a>]) {
            if node.babel_type() == "FunctionDeclaration"
                && node
                    .field(self.source, Field::Id)
                    .and_then(|id| id.identifier_name())
                    == Some("__vite__mapDeps")
            {
                self.helpers.push(*node);
            } else if node.babel_type() == "VariableDeclarator"
                && node
                    .field(self.source, Field::Id)
                    .and_then(|id| id.identifier_name())
                    == Some("__vite__mapDeps")
                && node.field(self.source, Field::Init).is_some_and(|init| {
                    matches!(
                        init.babel_type(),
                        "FunctionExpression" | "ArrowFunctionExpression"
                    )
                })
            {
                if let Some(init) = node.field(self.source, Field::Init) {
                    self.helpers.push(init);
                }
            }
        }
    }
    let mut finder = Find { source, helpers };
    let _: ControlFlow<()> = traverse(state.context.root(), source, &mut finder, || {
        ControlFlow::Continue(())
    });
    helpers = finder.helpers;
    if helpers.len() != 1 {
        return None;
    }
    let helper = helpers[0];
    let params = helper.field_list(source, Field::Params);
    let map = params.get(1).copied().flatten()?;
    let map = if map.babel_type() == "AssignmentPattern" {
        map.field(source, Field::Left)?
    } else {
        map
    };
    let map_name = map.identifier_name()?;
    let mut table: Option<Vec<Option<JsString>>> = None;
    let mut assignment_count = 0_usize;
    struct Assignment<'a> {
        source: &'a str,
        helper: Node<'a>,
        map_name: &'a str,
        table: &'a mut Option<Vec<Option<JsString>>>,
        count: &'a mut usize,
    }
    impl<'a> AstVisitor<'a> for Assignment<'_> {
        fn enter(&mut self, node: &Node<'a>, _: Option<&Node<'a>>, ancestors: &[Node<'a>]) {
            if ancestors.iter().any(|ancestor| {
                !same(ancestor, &self.helper)
                    && matches!(
                        ancestor.babel_type(),
                        "FunctionDeclaration" | "FunctionExpression" | "ArrowFunctionExpression"
                    )
            }) || node.babel_type() != "AssignmentExpression"
            {
                return;
            }
            let Some(left) = node.field(self.source, Field::Left) else {
                return;
            };
            let Some(object) = left.field(self.source, Field::Object) else {
                return;
            };
            let Some(property) = left.field(self.source, Field::Property) else {
                return;
            };
            if object.identifier_name() != Some(self.map_name)
                || static_property_key(self.source, property, left.computed())
                    .and_then(|key| key.try_to_string().ok())
                    .as_deref()
                    != Some("f")
            {
                return;
            }
            let Some(right) = node.field(self.source, Field::Right) else {
                return;
            };
            if right.babel_type() != "ArrayExpression" {
                return;
            }
            *self.count += 1;
            *self.table = Some(
                right
                    .field_list(self.source, Field::Elements)
                    .into_iter()
                    .map(|element| exact_literal_value(self.source, element))
                    .collect(),
            );
        }
    }
    let mut assignment = Assignment {
        source,
        helper,
        map_name,
        table: &mut table,
        count: &mut assignment_count,
    };
    let _: ControlFlow<()> = traverse(
        helper,
        source,
        &mut assignment,
        || ControlFlow::Continue(()),
    );
    let Some(table) = table else {
        return None;
    };
    if assignment_count != 1 {
        return Some(Vec::new());
    }
    if !vite_helper_is_stable(state, helper) {
        return Some(table.into_iter().map(|_| None).collect());
    }
    Some(table)
}

fn exact_literal_value<'a>(source: &'a str, node: Option<Node<'a>>) -> Option<JsString> {
    let node = node?;

    match read_exact_literal(source, node) {
        Some(ExactLiteral::String(value)) => Some(value),
        Some(ExactLiteral::Number(_)) => {
            Some(JsString::from(argument_value(source, Some(node))?.as_ref()))
        }
        _ => None,
    }
}

fn chunk_specifier<'a>(source: &'a str, node: Option<Node<'a>>) -> Option<JsString> {
    Some(JsString::from("chunk:").concat(&exact_literal_value(source, node)?))
}

fn vite_helper_is_stable<'a>(state: &SemanticState<'a>, helper: Node<'a>) -> bool {
    struct Uses<'a> {
        source: &'a str,
        helper: Node<'a>,
        escaped: bool,
    }
    impl<'a> AstVisitor<'a> for Uses<'a> {
        fn enter(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>, ancestors: &[Node<'a>]) {
            if self.escaped || node.babel_type() != "Identifier" {
                return;
            }
            if ancestors
                .iter()
                .any(|ancestor| same(ancestor, &self.helper))
            {
                return;
            }
            if node.identifier_name() != Some("__vite__mapDeps") {
                return;
            }
            if same(node, &self.helper) {
                return;
            }
            let Some(parent) = parent else {
                self.escaped = true;
                return;
            };
            let declaration = (parent.babel_type() == "FunctionDeclaration"
                && parent
                    .field(self.source, Field::Id)
                    .is_some_and(|id| same(&id, node)))
                || (parent.babel_type() == "VariableDeclarator"
                    && parent
                        .field(self.source, Field::Id)
                        .is_some_and(|id| same(&id, node)));
            let call = matches!(
                parent.babel_type(),
                "CallExpression" | "OptionalCallExpression"
            ) && parent
                .field(self.source, Field::Callee)
                .is_some_and(|callee| same(&callee, node));
            if !declaration && !call {
                self.escaped = true;
            }
        }
    }
    let mut uses = Uses {
        source: state.source,
        helper,
        escaped: false,
    };
    let _: ControlFlow<()> = traverse(state.context.root(), state.source, &mut uses, || {
        ControlFlow::Continue(())
    });
    !uses.escaped
}
