//! Source-local configuration, request, and boundary effects.
//!
//! This module is the Rust owner of `javascriptSemanticDataEffects.ts`.  It
//! deliberately keeps the collector syntax-driven: builtin recognition is
//! delegated to `data_effect_helpers`, while the operation records retain the
//! source location, caller, binding, and uncertainty selected by the caller.

use std::collections::{HashMap, HashSet};

use crate::javascript::ast::{Field, Node};
use crate::javascript::contracts::semantic_ir::{
    SemanticBoundaryOperation, SemanticCallable, SemanticConfigurationOperation,
    SemanticProjectedResultBinding, SemanticProjectionPathSegment, SemanticRequestField,
    SemanticRequestOperation,
};
use crate::javascript::semantic::ast_values::{
    read_exact_literal, static_property_key, static_property_name, unwrapped,
};
use crate::javascript::semantic::data_effect_helpers::{
    DataEffectTraversalContext, ProjectionKey, ProjectionResolution,
    assigned_semantic_result_bindings, builtin_data_effect_method, data_effect_argument_binding_id,
    data_effect_literal_string, data_effect_member_callee, is_semantic_process_object,
    traverse_data_effects,
};
use crate::javascript::semantic::state::SemanticState;
use crate::javascript::semantic::value_types::{JsString, Primitive};
use crate::javascript::static_analysis::helpers::range as contract_range;

/// The three collections produced by the source analysis pass.
#[derive(Clone, Debug, Default)]
pub struct DataEffectAnalysis {
    pub configuration_operations: Vec<SemanticConfigurationOperation>,
    pub request_operations: Vec<SemanticRequestOperation>,
    pub boundary_operations: Vec<SemanticBoundaryOperation>,
}

/// Collect all data effects in Babel visitor order.
pub fn collect_semantic_data_effects<'a>(
    program: Node<'a>,
    state: &SemanticState<'a>,
    callables: &[SemanticCallable],
) -> DataEffectAnalysis {
    let callable_ids: HashSet<String> = callables
        .iter()
        .map(|item| item.callable_id.clone())
        .collect();
    let mut context = DataEffectTraversalContext {
        state,
        callable_ids: &callable_ids,
        callable_stack: Vec::new(),
        ancestors: Vec::new(),
    };
    let mut configurations = Vec::new();
    let mut requests = Vec::new();
    let mut boundaries = Vec::new();
    traverse_data_effects(program, &mut context, |node, _parent, ancestors, owner| {
        if let Some(operation) = configuration_operation(node, ancestors, owner, state) {
            configurations.push(operation);
        }
        if let Some(operation) = request_operation(node, ancestors, owner, state) {
            requests.push(operation);
        }
        if let Some(operation) = boundary_operation(node, ancestors, owner, state) {
            boundaries.push(operation);
        }
    });

    let defaults = collect_defaults(program, state, &callable_ids);
    let response_consumers = collect_response_consumers(program, state, &callable_ids, &requests);
    DataEffectAnalysis {
        configuration_operations: configurations.into_iter().chain(defaults).collect(),
        request_operations: requests.into_iter().chain(response_consumers).collect(),
        boundary_operations: boundaries,
    }
}

fn owner_binding<'a>(
    node: Node<'a>,
    ancestors: &[Node<'a>],
    state: &SemanticState<'a>,
) -> Option<String> {
    let projected = assigned_semantic_result_bindings(node, ancestors, state);
    (projected.len() == 1 && projected[0].projection_path.is_empty())
        .then(|| projected[0].binding_id.clone())
}

fn projection_bindings<'a>(
    node: Node<'a>,
    ancestors: &[Node<'a>],
    state: &SemanticState<'a>,
) -> Vec<SemanticProjectedResultBinding> {
    assigned_semantic_result_bindings(node, ancestors, state)
        .into_iter()
        .filter(|item| !item.projection_path.is_empty())
        .map(|item| SemanticProjectedResultBinding {
            binding_id: item.binding_id,
            projection_path: item
                .projection_path
                .into_iter()
                .map(projection_segment)
                .collect(),
            resolution: match item.resolution {
                ProjectionResolution::Complete => "complete",
                ProjectionResolution::Partial => "partial",
            }
            .to_owned(),
        })
        .collect()
}

fn projection_segment(key: ProjectionKey) -> SemanticProjectionPathSegment {
    match key {
        ProjectionKey::Name(value) => SemanticProjectionPathSegment::String(value),
        ProjectionKey::Index(value) => SemanticProjectionPathSegment::Number(value as f64),
        ProjectionKey::Dynamic => SemanticProjectionPathSegment::Null,
    }
}

fn configuration_operation<'a>(
    node: Node<'a>,
    ancestors: &[Node<'a>],
    owner: Option<&str>,
    state: &SemanticState<'a>,
) -> Option<SemanticConfigurationOperation> {
    let (kind, key, resolution) = configuration_details(node, state)?;
    Some(SemanticConfigurationOperation {
        config_id: format!(
            "config:{kind}:{}:{}",
            state.context.start(&node),
            state.context.end(&node)
        ),
        kind: kind.to_owned(),
        location: contract_range(&state.context, &node),
        owner_callable_id: owner.map(str::to_owned),
        result_binding_id: owner_binding(node, ancestors, state),
        key,
        source_config_id: None,
        value: Primitive::Null,
        value_resource_limit: None,
        resolution: resolution.to_owned(),
    })
}

fn configuration_details<'a>(
    node: Node<'a>,
    state: &SemanticState<'a>,
) -> Option<(&'static str, Option<JsString>, &'static str)> {
    if matches!(
        node.babel_type(),
        "MemberExpression" | "OptionalMemberExpression"
    ) {
        if let Some(object) = node.field(state.source, Field::Object) {
            if matches!(
                object.babel_type(),
                "MemberExpression" | "OptionalMemberExpression"
            ) {
                let family = object
                    .field(state.source, Field::Property)
                    .map(|p| static_property_name(state.source, p, object.computed()))
                    .filter(|p| p == "env" || p == "argv");
                if let Some(family) = family.and_then(|family| family.try_to_string().ok()) {
                    let key = node
                        .field(state.source, Field::Property)
                        .and_then(|p| static_property_key(state.source, p, node.computed()));
                    let valid_argv = family != "argv"
                        || key.as_ref().is_none_or(|key| {
                            key.try_to_string()
                                .ok()
                                .is_some_and(|key| array_index_key(&key))
                        });
                    if valid_argv
                        && object
                            .field(state.source, Field::Object)
                            .is_some_and(|process| {
                                process_object_matches(process, state, &family, key.as_ref())
                            })
                    {
                        return Some((
                            if family == "env" {
                                "environment"
                            } else {
                                "argv"
                            },
                            key.clone(),
                            if key.is_some() { "complete" } else { "partial" },
                        ));
                    }
                }
            }
        }
    }
    if matches!(
        node.babel_type(),
        "CallExpression" | "OptionalCallExpression"
    ) {
        let method = node
            .field(state.source, Field::Callee)
            .and_then(|callee| builtin_data_effect_method(callee, state, &["fs", "node:fs"]));
        if matches!(method.as_deref(), Some("readFile" | "readFileSync")) {
            let key = node
                .field_list(state.source, Field::Arguments)
                .into_iter()
                .flatten()
                .next()
                .and_then(|argument| data_effect_literal_string(Some(argument), state.source));
            return Some((
                "file",
                key.clone(),
                if key.is_some() { "complete" } else { "partial" },
            ));
        }
    }
    None
}

fn array_index_key(key: &str) -> bool {
    key.parse::<u64>()
        .ok()
        .is_some_and(|value| value < (1u64 << 32) - 1 && (value == 0 || !key.starts_with('0')))
}

fn process_object_matches<'a>(
    process: Node<'a>,
    state: &SemanticState<'a>,
    family: &str,
    key: Option<&JsString>,
) -> bool {
    let Some(key) = key else {
        return is_semantic_process_object(process, state, family, None);
    };
    let Ok(key) = key.try_to_string() else {
        return false;
    };
    is_semantic_process_object(process, state, family, Some(&key))
}

fn collect_defaults<'a>(
    program: Node<'a>,
    state: &SemanticState<'a>,
    callables: &HashSet<String>,
) -> Vec<SemanticConfigurationOperation> {
    let mut context = DataEffectTraversalContext {
        state,
        callable_ids: callables,
        callable_stack: Vec::new(),
        ancestors: Vec::new(),
    };
    let mut configurations = HashMap::new();
    traverse_data_effects(
        program,
        &mut context,
        |node, _parent, _ancestors, _owner| {
            if let Some((kind, key, resolution)) = configuration_details(node, state) {
                configurations.insert(
                    unwrapped(state.source, node).key(),
                    (
                        kind.to_owned(),
                        key,
                        resolution.to_owned(),
                        format!(
                            "config:{kind}:{}:{}",
                            state.context.start(&node),
                            state.context.end(&node)
                        ),
                    ),
                );
            }
        },
    );

    let mut context = DataEffectTraversalContext {
        state,
        callable_ids: callables,
        callable_stack: Vec::new(),
        ancestors: Vec::new(),
    };
    let mut output = Vec::new();
    traverse_data_effects(program, &mut context, |node, _parent, ancestors, owner| {
        if !matches!(node.babel_type(), "LogicalExpression") {
            return;
        }
        let Some(operator) = node.operator() else {
            return;
        };
        if operator != "??" && operator != "||" {
            return;
        }
        let Some(left) = node.field(state.source, Field::Left) else {
            return;
        };
        let source_key = unwrapped(state.source, left).key();
        let Some((kind, key, _resolution, source_id)) = configurations.get(&source_key) else {
            return;
        };
        let literal = node
            .field(state.source, Field::Right)
            .and_then(|right| read_exact_literal(state.source, right));
        let value = literal.map(primitive_value);
        output.push(SemanticConfigurationOperation {
            config_id: format!(
                "config:default:{}:{}",
                state.context.start(&node),
                state.context.end(&node)
            ),
            kind: "default".to_owned(),
            location: node
                .field(state.source, Field::Right)
                .map(|right| contract_range(&state.context, &right))
                .unwrap_or_else(|| contract_range(&state.context, &node)),
            owner_callable_id: owner.map(str::to_owned),
            result_binding_id: owner_binding(node, ancestors, state),
            key: key.clone(),
            source_config_id: Some(source_id.clone()),
            value: value.clone().unwrap_or(Primitive::Null),
            value_resource_limit: None,
            resolution: if value.is_some() {
                "complete"
            } else {
                "partial"
            }
            .to_owned(),
        });
        let _ = kind;
    });
    output
}

fn primitive_value(literal: crate::javascript::semantic::ast_values::ExactLiteral) -> Primitive {
    match literal {
        crate::javascript::semantic::ast_values::ExactLiteral::String(value) => {
            Primitive::String(value)
        }
        crate::javascript::semantic::ast_values::ExactLiteral::Number(value) => {
            Primitive::Number(value)
        }
        crate::javascript::semantic::ast_values::ExactLiteral::Boolean(value) => {
            Primitive::Boolean(value)
        }
        crate::javascript::semantic::ast_values::ExactLiteral::Null => Primitive::Null,
    }
}

fn request_operation<'a>(
    node: Node<'a>,
    ancestors: &[Node<'a>],
    owner: Option<&str>,
    state: &SemanticState<'a>,
) -> Option<SemanticRequestOperation> {
    if !matches!(
        node.babel_type(),
        "CallExpression" | "OptionalCallExpression" | "NewExpression"
    ) {
        return None;
    }
    let callee = node.field(state.source, Field::Callee)?;
    let method = request_method(callee, node.babel_type() == "NewExpression", state)?;
    let arguments = node
        .field_list(state.source, Field::Arguments)
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let endpoint = arguments
        .first()
        .and_then(|argument| {
            (!matches!(argument.babel_type(), "ObjectExpression"))
                .then(|| data_effect_literal_string(Some(*argument), state.source))
                .flatten()
        })
        .and_then(|endpoint| endpoint.try_to_string().ok());
    Some(SemanticRequestOperation {
        request_id: format!(
            "request:{}:{}",
            state.context.start(&node),
            state.context.end(&node)
        ),
        kind: "request".to_owned(),
        method: method.to_owned(),
        location: contract_range(&state.context, &node),
        owner_callable_id: owner.map(str::to_owned),
        result_binding_id: owner_binding(node, ancestors, state),
        projected_result_bindings: projection_bindings(node, ancestors, state),
        linked_request_ids: Vec::new(),
        endpoint: endpoint.clone(),
        fields: request_fields(&arguments, &method, state),
        resolution: if endpoint.is_some() {
            "complete"
        } else {
            "partial"
        }
        .to_owned(),
    })
}

fn request_method<'a>(callee: Node<'a>, is_new: bool, state: &SemanticState<'a>) -> Option<String> {
    if let Some(name) = callee.identifier_name() {
        if !is_new && name == "fetch" && state.is_unshadowed_global(&callee, name) {
            return Some("fetch".to_owned());
        }
        if is_new && name == "WebSocket" && state.is_unshadowed_global(&callee, name) {
            return Some("WebSocket".to_owned());
        }
    }
    builtin_data_effect_method(callee, state, &["http", "https", "node:http", "node:https"])
        .filter(|name| name == "request" || name == "get")
}

fn request_fields<'a>(
    arguments: &[Node<'a>],
    method: &str,
    state: &SemanticState<'a>,
) -> Vec<SemanticRequestField> {
    let candidate = if matches!(method, "fetch" | "WebSocket") {
        arguments.get(1).copied()
    } else {
        arguments
            .first()
            .copied()
            .filter(|node| node.babel_type() == "ObjectExpression")
            .or_else(|| arguments.get(1).copied())
    };
    let Some(candidate) = candidate.filter(|node| node.babel_type() == "ObjectExpression") else {
        return Vec::new();
    };
    candidate
        .field_list(state.source, Field::Properties)
        .into_iter()
        .flatten()
        .filter(|property| property.babel_type() == "ObjectProperty")
        .filter_map(|property| {
            let key = property
                .field(state.source, Field::Key)
                .and_then(|key| static_property_key(state.source, key, property.computed()))?;
            let source_binding_id = property
                .field(state.source, Field::Value)
                .and_then(|value| {
                    let name = value.identifier_name()?;
                    state.resolve_binding(&value, name)
                })
                .map(|index| state.binding(index).binding_id.clone());
            Some(SemanticRequestField {
                name: key,
                source_binding_id,
            })
        })
        .collect()
}

fn boundary_operation<'a>(
    node: Node<'a>,
    ancestors: &[Node<'a>],
    owner: Option<&str>,
    state: &SemanticState<'a>,
) -> Option<SemanticBoundaryOperation> {
    if !matches!(
        node.babel_type(),
        "CallExpression" | "OptionalCallExpression"
    ) {
        return None;
    }
    let callee = node.field(state.source, Field::Callee)?;
    let (kind, method, resolution) = boundary_details(callee, state)?;
    let argument = node
        .field_list(state.source, Field::Arguments)
        .into_iter()
        .flatten()
        .next();
    Some(SemanticBoundaryOperation {
        boundary_id: format!(
            "boundary:{kind}:{}:{}",
            state.context.start(&node),
            state.context.end(&node)
        ),
        kind: kind.to_owned(),
        method: method.to_owned(),
        location: contract_range(&state.context, &node),
        owner_callable_id: owner.map(str::to_owned),
        source_binding_id: data_effect_argument_binding_id(argument, state),
        result_binding_id: owner_binding(node, ancestors, state),
        resolution: resolution.to_owned(),
    })
}

fn boundary_details<'a>(
    callee: Node<'a>,
    state: &SemanticState<'a>,
) -> Option<(&'static str, String, &'static str)> {
    if let Some(name) = callee.identifier_name() {
        if ["String", "Number", "Boolean", "parseInt", "parseFloat"].contains(&name)
            && state.is_unshadowed_global(&callee, name)
        {
            return Some(("coerce", name.to_owned(), "complete"));
        }
    }
    let member = (matches!(
        callee.babel_type(),
        "MemberExpression" | "OptionalMemberExpression"
    ))
    .then_some(callee)?;
    let method = member
        .field(state.source, Field::Property)
        .map(|property| static_property_name(state.source, property, member.computed()))
        .and_then(|method| method.try_to_string().ok())?;
    let object = member.field(state.source, Field::Object)?;
    if method == "parse"
        && object.identifier_name() == Some("JSON")
        && state.is_unshadowed_global(&object, "JSON")
    {
        return Some(("parse", "JSON.parse".to_owned(), "complete"));
    }
    if method == "parse" || method == "safeParse" {
        return Some(("parse", method, "partial"));
    }
    if ["validate", "assert", "is"].contains(&method.as_str()) {
        return Some(("validate", method, "partial"));
    }
    None
}

fn collect_response_consumers<'a>(
    program: Node<'a>,
    state: &SemanticState<'a>,
    callables: &HashSet<String>,
    requests: &[SemanticRequestOperation],
) -> Vec<SemanticRequestOperation> {
    let mut by_binding: HashMap<String, Vec<&SemanticRequestOperation>> = HashMap::new();
    for request in requests {
        if let Some(id) = &request.result_binding_id {
            by_binding.entry(id.clone()).or_default().push(request);
        }
        for projection in &request.projected_result_bindings {
            by_binding
                .entry(projection.binding_id.clone())
                .or_default()
                .push(request);
        }
    }
    let mut context = DataEffectTraversalContext {
        state,
        callable_ids: callables,
        callable_stack: Vec::new(),
        ancestors: Vec::new(),
    };
    let mut output = Vec::new();
    traverse_data_effects(program, &mut context, |node, _parent, ancestors, owner| {
        if !matches!(
            node.babel_type(),
            "CallExpression" | "OptionalCallExpression"
        ) {
            return;
        }
        let Some(member) = data_effect_member_callee(node, state.source) else {
            return;
        };
        let Some(object) = member
            .field(state.source, Field::Object)
            .filter(|object| object.identifier_name().is_some())
        else {
            return;
        };
        let method = member
            .field(state.source, Field::Property)
            .and_then(|property| {
                static_property_name(state.source, property, member.computed())
                    .try_to_string()
                    .ok()
            });
        if !matches!(method.as_deref(), Some("json" | "text" | "arrayBuffer")) {
            return;
        }
        let Some(name) = object.identifier_name() else {
            return;
        };
        let Some(index) = state.resolve_binding(&object, name) else {
            return;
        };
        let id = state.binding(index).binding_id.clone();
        let linked = by_binding.get(&id).cloned().unwrap_or_default();
        if linked.is_empty() {
            return;
        }
        let unique = (linked.len() == 1
            && !linked[0]
                .projected_result_bindings
                .iter()
                .any(|item| item.binding_id == id))
        .then_some(linked[0]);
        let endpoint = unique.and_then(|item| item.endpoint.clone());
        let retains_incoming_request = sole_write_reaches_read(object, state);
        let mut linked_request_ids = linked
            .iter()
            .map(|item| item.request_id.clone())
            .collect::<Vec<_>>();
        linked_request_ids.sort();
        output.push(SemanticRequestOperation {
            request_id: format!(
                "response:{}:{}",
                state.context.start(&node),
                state.context.end(&node)
            ),
            kind: "response-consumer".to_owned(),
            method: method.unwrap_or_default(),
            location: contract_range(&state.context, &node),
            owner_callable_id: owner.map(str::to_owned),
            result_binding_id: owner_binding(node, ancestors, state),
            projected_result_bindings: projection_bindings(node, ancestors, state),
            linked_request_ids,
            endpoint: retains_incoming_request.then_some(endpoint).flatten(),
            fields: Vec::new(),
            resolution: if unique.is_some() {
                "complete"
            } else {
                "partial"
            }
            .to_owned(),
        });
    });
    output
}

fn sole_write_reaches_read<'a>(read: Node<'a>, state: &SemanticState<'a>) -> bool {
    let Some(name) = read.identifier_name() else {
        return false;
    };
    let Some(binding_index) = state.resolve_binding(&read, name) else {
        return false;
    };
    let binding = state.binding(binding_index);
    binding.initializers.len() == 1
        && (state.stable_initializer(binding_index).is_some()
            || state
                .semantic_binding_at_read(binding, read)
                .has_definite_initializer)
}
