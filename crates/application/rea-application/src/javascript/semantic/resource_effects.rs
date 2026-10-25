//! Source-local resource acquisition and release operations.
//!
//! This is the Rust owner of `javascriptSemanticResources.ts`.  Acquisition
//! matching is delegated to the shared data-effect provenance matcher; this
//! pass only owns the resource-specific linkage and release proof.

use std::collections::{HashMap, HashSet};

use crate::javascript::ast::{Field, Node};
use crate::javascript::contracts::semantic_ir::SemanticResourceOperation;
use crate::javascript::static_analysis::helpers::range;

use super::ambient_writes::is_unmodified_global_reference;
use super::ast_values::{static_property_key, unwrapped};
use super::data_effect_helpers::{
    assigned_semantic_result_bindings, builtin_data_effect_method, data_effect_member_callee,
    scalar_assigned_result_binding, traverse_data_effects,
};
use super::projection::SemanticCallable;
use super::state::{BindingState, SemanticState};

const RESOURCE_SPECIFIERS: [&str; 4] = ["fs", "fs/promises", "net", "tls"];

struct ResourceCandidate<'a> {
    node: Node<'a>,
    method: String,
    owner_callable_id: Option<String>,
    result_binding_id: Option<String>,
}

/// Recover built-in acquisition calls and local handle releases in source order.
pub fn collect_semantic_resources<'a>(
    program: Node<'a>,
    state: &SemanticState<'a>,
    callables: &[SemanticCallable],
) -> Vec<SemanticResourceOperation> {
    let callable_ids: HashSet<String> = callables
        .iter()
        .map(|callable| callable.callable_id.clone())
        .collect();
    let mut acquisitions = Vec::new();
    let mut context = super::data_effect_helpers::DataEffectTraversalContext {
        state,
        callable_ids: &callable_ids,
        callable_stack: Vec::new(),
        ancestors: Vec::new(),
    };
    traverse_data_effects(program, &mut context, |node, _parent, ancestors, owner| {
        if !matches!(
            node.babel_type(),
            "CallExpression" | "OptionalCallExpression"
        ) {
            return;
        }
        let Some(method) = acquisition_method(node, state) else {
            return;
        };
        let result_binding_id = scalar_assigned_result_binding(&assigned_semantic_result_bindings(
            node, ancestors, state,
        ))
        .map(str::to_owned);
        acquisitions.push(ResourceCandidate {
            node,
            method,
            owner_callable_id: owner.map(str::to_owned),
            result_binding_id,
        });
    });

    let mut output = acquisitions
        .iter()
        .map(|candidate| SemanticResourceOperation {
            resource_id: acquisition_id(candidate, state),
            kind: "acquire".to_owned(),
            method: candidate.method.clone(),
            location: range(&state.context, &candidate.node),
            owner_callable_id: candidate.owner_callable_id.clone(),
            result_binding_id: candidate.result_binding_id.clone(),
            linked_resource_ids: Vec::new(),
            resolution: "complete".to_owned(),
        })
        .collect::<Vec<_>>();

    let mut by_binding: HashMap<&str, Vec<&ResourceCandidate<'a>>> = HashMap::new();
    for candidate in &acquisitions {
        if let Some(binding) = candidate.result_binding_id.as_deref() {
            by_binding.entry(binding).or_default().push(candidate);
        }
    }

    let mut release_context = super::data_effect_helpers::DataEffectTraversalContext {
        state,
        callable_ids: &callable_ids,
        callable_stack: Vec::new(),
        ancestors: Vec::new(),
    };
    traverse_data_effects(
        program,
        &mut release_context,
        |node, _parent, _ancestors, owner| {
            if !matches!(
                node.babel_type(),
                "CallExpression" | "OptionalCallExpression"
            ) {
                return;
            }
            let Some(member) = data_effect_member_callee(node, state.source) else {
                return;
            };
            let Some(object) = member.field(state.source, Field::Object) else {
                return;
            };
            if object.babel_type() != "Identifier" {
                return;
            }
            let Some(method) = member
                .field(state.source, Field::Property)
                .and_then(|property| static_property_key(state.source, property, member.computed()))
                .and_then(release_method_name)
            else {
                return;
            };
            let Some(name) = object.identifier_name() else {
                return;
            };
            let Some(binding_index) = state.resolve_binding(&object, name) else {
                return;
            };
            let binding = state.binding(binding_index);
            let Some(linked) = by_binding.get(binding.binding_id.as_str()) else {
                return;
            };
            let complete = linked.len() == 1 && holds_only_acquisitions(binding, linked, state);
            let mut linked_resource_ids = linked
                .iter()
                .map(|candidate| acquisition_id(candidate, state))
                .collect::<Vec<_>>();
            linked_resource_ids.sort();
            output.push(SemanticResourceOperation {
                resource_id: format!(
                    "resource:release:{}:{}",
                    state.context.start(&node),
                    state.context.end(&node)
                ),
                kind: "release".to_owned(),
                method,
                location: range(&state.context, &node),
                owner_callable_id: owner.map(str::to_owned),
                result_binding_id: Some(binding.binding_id.clone()),
                linked_resource_ids,
                resolution: if complete { "complete" } else { "partial" }.to_owned(),
            });
        },
    );
    output
}

fn release_method_name(value: super::value_types::JsString) -> Option<String> {
    let method = if value == "close" {
        "close"
    } else if value == "destroy" {
        "destroy"
    } else if value == "end" {
        "end"
    } else {
        return None;
    };
    Some(method.to_owned())
}

fn acquisition_method<'a>(node: Node<'a>, state: &SemanticState<'a>) -> Option<String> {
    let callee = node.field(state.source, Field::Callee)?;
    let method = builtin_data_effect_method(callee, state, &RESOURCE_SPECIFIERS)?;
    let allowed = match method.as_str() {
        "open" | "openSync" | "createReadStream" | "createWriteStream" => true,
        "connect" | "createConnection" => true,
        _ => false,
    };
    allowed.then_some(method)
}

fn acquisition_id(candidate: &ResourceCandidate<'_>, state: &SemanticState<'_>) -> String {
    format!(
        "resource:acquire:{}:{}",
        state.context.start(&candidate.node),
        state.context.end(&candidate.node)
    )
}

fn holds_only_acquisitions<'a>(
    binding: &BindingState<'a>,
    linked: &[&ResourceCandidate<'a>],
    state: &SemanticState<'a>,
) -> bool {
    binding
        .initializers
        .iter()
        .map(|initializer| (initializer.node, !initializer.projection.is_empty()))
        .chain(
            binding
                .reference_initializers
                .iter()
                .map(|initializer| (initializer.node, !initializer.projection.is_empty())),
        )
        .all(|(initializer, projected)| {
            if projected {
                return false;
            }
            let mut value = unwrapped(state.source, initializer);
            if value.babel_type() == "AwaitExpression"
                && let Some(argument) = value.field(state.source, Field::Argument)
            {
                value = unwrapped(state.source, argument);
            }
            is_nullish_placeholder(value, state)
                || linked
                    .iter()
                    .any(|candidate| candidate.node.key() == value.key())
        })
}

fn is_nullish_placeholder<'a>(node: Node<'a>, state: &SemanticState<'a>) -> bool {
    node.babel_type() == "NullLiteral"
        || (node.babel_type() == "UnaryExpression" && node.operator() == Some("void"))
        || is_unmodified_global_reference(state, node, "undefined")
}
