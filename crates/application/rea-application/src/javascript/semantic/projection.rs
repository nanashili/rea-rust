//! Stage-2 semantic projection: callable identities and lexical references.
//!
//! This module only projects facts owned by [`SemanticState`].  It deliberately
//! leaves value/provenance evaluation and module-require origin resolution to
//! their owning packages.

use std::collections::HashSet;

use crate::javascript::ast::{AstContext, AstVisitor, Field, Node, traverse};
use crate::javascript::contracts::semantic_ir::{SemanticBinding, SemanticDefinition};
use crate::javascript::graph::json::compare_code_points;
use crate::javascript::parser::SourceRange;

use super::reference_role::{ReferenceRole, semantic_reference_role};
use super::state::{BindingLookup, SemanticState};
use super::value_types::JsString;
use super::values::{evaluate_semantic_binding, evaluate_semantic_provenance};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticCallable {
    pub callable_id: String,
    pub kind: String,
    pub name: Option<JsString>,
    pub container_scope_id: String,
    pub body_scope_id: Option<String>,
    pub location: SourceRange,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticReference {
    pub name: String,
    pub role: ReferenceRole,
    pub location: SourceRange,
    pub binding_id: Option<String>,
    pub resolution: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticScopeProjection {
    pub scope_id: String,
    pub parent_scope_id: Option<String>,
    pub kind: String,
    pub location: SourceRange,
    pub bindings_complete: bool,
    pub binding_ids: Vec<String>,
}

/// Return the stable callable identity used by the semantic projection.
pub fn callable_id_for_node(context: &AstContext<'_>, node: &Node<'_>) -> Option<String> {
    let kind = match node.babel_type() {
        "ClassMethod" | "ClassPrivateMethod" | "ObjectMethod" => "method",
        _ if super::ast_values::is_function(node) => "function",
        _ if super::ast_values::is_class(node) => "class",
        _ => return None,
    };

    Some(format!(
        "callable:{kind}:{}:{}",
        context.start(node),
        context.end(node)
    ))
}

struct Collector<'s, 'a> {
    state: &'s SemanticState<'a>,
    callables: Vec<SemanticCallable>,
    references: Vec<SemanticReference>,
    seen_references: HashSet<(u32, ReferenceRole, String)>,
}

/// Collect callable and reference projections in Babel traversal order.
pub fn collect_semantic_projection<'a>(
    state: &SemanticState<'a>,
) -> (Vec<SemanticCallable>, Vec<SemanticReference>) {
    let mut collector = Collector {
        state,
        callables: Vec::new(),
        references: Vec::new(),
        seen_references: HashSet::new(),
    };
    let _ = traverse(state.program, state.source, &mut collector, || {
        std::ops::ControlFlow::<()>::Continue(())
    });
    (collector.callables, collector.references)
}

/// Freeze scope records while retaining the state's insertion order.
pub fn immutable_scopes(state: &SemanticState<'_>) -> Vec<SemanticScopeProjection> {
    state
        .scopes
        .iter()
        .map(|scope| {
            let mut binding_ids = scope
                .bindings
                .values()
                .map(|index| state.binding(*index).binding_id.clone())
                .collect::<Vec<_>>();
            binding_ids.sort_by(|left, right| compare_code_points(left, right));

            SemanticScopeProjection {
                scope_id: scope.scope_id.clone(),
                parent_scope_id: scope.parent_scope_id.clone(),
                kind: scope.kind.as_str().to_owned(),
                location: scope.location,
                bindings_complete: scope.bindings_complete,
                binding_ids,
            }
        })
        .collect()
}

/// Evaluate values and provenance before freezing bindings into the public IR.
pub fn immutable_bindings(state: &SemanticState<'_>) -> Vec<SemanticBinding> {
    let mut bindings = state
        .bindings_by_id
        .values()
        .map(|index| {
            let binding = state.binding(*index);
            SemanticBinding {
                binding_id: binding.binding_id.clone(),
                scope_id: binding.scope_id.clone(),
                name: binding.name.clone().into(),
                kind: binding.kind.as_str().to_owned(),
                mutable: binding.mutable,
                definitions: binding
                    .definitions
                    .iter()
                    .map(|definition| SemanticDefinition {
                        kind: definition.kind.as_str().to_owned(),
                        location: definition.location.into(),
                    })
                    .collect(),
                value: evaluate_semantic_binding(binding, state),
                provenance: evaluate_semantic_provenance(binding, state),
            }
        })
        .collect::<Vec<_>>();
    bindings.sort_by(|left, right| compare_code_points(&left.binding_id, &right.binding_id));
    bindings
}

impl<'a> AstVisitor<'a> for Collector<'_, 'a> {
    fn enter(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>, ancestors: &[Node<'a>]) {
        if let Some(callable) = project_callable(self.state, node, parent) {
            self.callables.push(callable);
        }
        let Some(parent) = parent else { return };
        let Some(name) = node.identifier_name() else {
            return;
        };
        let Some(role) = semantic_reference_role(self.state.source, node, parent, ancestors) else {
            return;
        };
        if role == ReferenceRole::Write
            && let Some(site) =
                super::ast_values::wrapped_write_site(self.state.source, node, parent, ancestors)
            && super::ast_values::write_site_reads_first(&site)
        {
            self.push_reference(node, name, ReferenceRole::Read);
        }
        self.push_reference(node, name, role);
    }
}

impl<'a> Collector<'_, 'a> {
    fn push_reference(&mut self, node: &Node<'a>, name: &str, role: ReferenceRole) {
        let lookup = self.state.lookup_at(node, name);
        let binding_id = match lookup {
            BindingLookup::Binding(index) => Some(self.state.binding(index).binding_id.clone()),
            _ => None,
        };
        let resolution = match lookup {
            BindingLookup::Binding(_) => "resolved",
            BindingLookup::UncertainBinding(_) | BindingLookup::Unknown => "unknown",
            BindingLookup::Ambient => "unbound",
            BindingLookup::UncertainAmbient | BindingLookup::Captured => "unknown",
        };
        let key = (self.state.context.start(node), role, name.to_owned());
        if !self.seen_references.insert(key) {
            return;
        }
        self.references.push(SemanticReference {
            name: name.to_owned(),
            role,
            location: self.state.context.range(node),
            binding_id,
            resolution,
        });
    }
}

fn project_callable<'a>(
    state: &SemanticState<'a>,
    node: &Node<'a>,
    parent: Option<&Node<'a>>,
) -> Option<SemanticCallable> {
    let (kind, name) = match node.babel_type() {
        "ClassMethod" | "ClassPrivateMethod" | "ObjectMethod" => (
            "method",
            method_name(state.source, node, state.context.start(node)),
        ),
        _ty if super::ast_values::is_function(node) => {
            ("function", function_name(state.source, node, parent))
        }
        _ty if super::ast_values::is_class(node) => {
            ("class", function_name(state.source, node, parent))
        }
        _ => return None,
    };
    let container_scope = parent
        .and_then(|parent| state.scope_for_node(parent))
        .or_else(|| state.scope_for_node(node))?;
    let body_scope_id = state
        .scope_for_node(node)
        .map(|index| state.scope(index))
        .filter(|scope| scope.bindings_complete)
        .map(|scope| scope.scope_id.clone());
    Some(SemanticCallable {
        callable_id: callable_id_for_node(&state.context, node)?,
        kind: kind.to_owned(),
        name,
        container_scope_id: state.scope(container_scope).scope_id.clone(),
        body_scope_id,
        location: state.context.range(node),
    })
}

fn function_name<'a>(
    source: &'a str,
    node: &Node<'a>,
    parent: Option<&Node<'a>>,
) -> Option<JsString> {
    node.field(source, Field::Id)
        .and_then(|id| id.identifier_name())
        .map(JsString::from)
        .or_else(|| {
            parent
                .filter(|p| p.babel_type() == "VariableDeclarator")
                .and_then(|p| p.field(source, Field::Id))
                .and_then(|id| id.identifier_name())
                .map(JsString::from)
        })
}

fn method_name<'a>(source: &'a str, node: &Node<'a>, node_start: u32) -> Option<JsString> {
    let key = node.field(source, Field::Key)?;
    if key.babel_type() == "PrivateName" {
        return key
            .field(source, Field::Id)
            .and_then(|id| id.identifier_name())
            .map(|name| format!("#{name}").into());
    }
    if !node.computed() {
        return key
            .identifier_name()
            .map(JsString::from)
            .or_else(|| key.string_value_units().map(JsString::from_utf16));
    }
    super::ast_values::static_property_key(source, key, true)
        .or_else(|| Some(format!("[computed@{node_start}]").into()))
}
