//! Static `node:child_process` creation and interaction facts.
//!
//! This pass mirrors `javascriptSemanticChildProcesses.ts`.  It only records
//! source evidence; it never launches a process or attempts to execute the
//! analyzed program.

use std::collections::{HashMap, HashSet};

use crate::javascript::ast::{Field, Node};
use crate::javascript::contracts::semantic_ir::{
    SemanticCallable, SemanticChildProcessInteraction, SemanticChildProcessSpawn,
    SemanticProjectedResultBinding, SemanticProjectionPathSegment,
};
use crate::javascript::semantic::ast_values::{
    is_nullish_syntax, static_object_property, static_property_key, unwrapped,
};
use crate::javascript::semantic::data_effect_helpers::{
    DataEffectTraversalContext, ProjectionKey, ProjectionResolution,
    assigned_semantic_result_bindings, builtin_data_effect_method, data_effect_literal_string,
    data_effect_member_callee, scalar_assigned_result_binding, traverse_data_effects,
};
use crate::javascript::semantic::mutation_initializers::BindingReadStatus;
use crate::javascript::semantic::state::SemanticState;
use crate::javascript::semantic::value_types::JsString;
use crate::javascript::static_analysis::helpers::range;

const METHODS: [&str; 4] = ["spawn", "exec", "execFile", "fork"];
const LISTENER_METHODS: [&str; 3] = ["on", "once", "addListener"];

#[derive(Clone, Debug, Default)]
pub struct ChildProcessAnalysis {
    pub child_process_spawns: Vec<SemanticChildProcessSpawn>,
    pub child_process_interactions: Vec<SemanticChildProcessInteraction>,
}

#[derive(Clone, Debug)]
struct SpawnCandidate<'a> {
    node: Node<'a>,
    method: &'static str,
    owner: Option<String>,
    result_binding: Option<String>,
    projections:
        Vec<crate::javascript::semantic::data_effect_helpers::SemanticProjectedBinding<'a>>,
}

/// Collect child-process facts in source traversal order.
pub fn collect_semantic_child_processes<'a>(
    program: Node<'a>,
    state: &SemanticState<'a>,
    callables: &[SemanticCallable],
) -> ChildProcessAnalysis {
    let callable_ids: HashSet<String> = callables.iter().map(|c| c.callable_id.clone()).collect();
    let mut context = DataEffectTraversalContext {
        state,
        callable_ids: &callable_ids,
        callable_stack: Vec::new(),
        ancestors: Vec::new(),
    };
    let mut candidates = Vec::new();
    traverse_data_effects(program, &mut context, |node, _parent, ancestors, owner| {
        let Some(method) = child_process_method(node, state) else {
            return;
        };
        let assigned = assigned_semantic_result_bindings(node, ancestors, state);
        let projections: Vec<_> = assigned
            .iter()
            .filter(|binding| !binding.projection_path.is_empty())
            .cloned()
            .collect();
        candidates.push(SpawnCandidate {
            node,
            method,
            owner: owner.map(str::to_owned),
            result_binding: scalar_assigned_result_binding(&assigned).map(str::to_owned),
            projections,
        });
    });

    let spawns = candidates
        .iter()
        .map(|candidate| spawn_record(candidate, state))
        .collect::<Vec<_>>();
    let child_process_interactions = collect_interactions(program, state, callables, &candidates);
    ChildProcessAnalysis {
        child_process_spawns: spawns,
        child_process_interactions,
    }
}

fn child_process_method<'a>(node: Node<'a>, state: &SemanticState<'a>) -> Option<&'static str> {
    if !matches!(
        node.babel_type(),
        "CallExpression" | "OptionalCallExpression"
    ) {
        return None;
    }
    let callee = node.field(state.source, Field::Callee)?;
    let method =
        builtin_data_effect_method(callee, state, &["child_process", "node:child_process"])?;
    METHODS
        .iter()
        .cloned()
        .find(|candidate| *candidate == method)
}

fn spawn_record<'a>(
    candidate: &SpawnCandidate<'a>,
    state: &SemanticState<'a>,
) -> SemanticChildProcessSpawn {
    let (options, argv_count) = spawn_arguments(candidate.node, candidate.method, state);
    let command = data_effect_literal_string(
        candidate
            .node
            .field_list(state.source, Field::Arguments)
            .into_iter()
            .flatten()
            .next(),
        state.source,
    );
    let options = options.map(|node| unwrapped(state.source, node));
    let environment_supplied = object_has_property(options, state, "env");
    let stdio_mode = stdio_mode(options, candidate.method, state);
    let resolution = if command.is_some() {
        "complete"
    } else {
        "partial"
    };
    SemanticChildProcessSpawn {
        process_id: format!(
            "child:spawn:{}:{}",
            state.context.start(&candidate.node),
            state.context.end(&candidate.node)
        ),
        method: candidate.method.to_owned(),
        location: range(&state.context, &candidate.node),
        owner_callable_id: candidate.owner.clone(),
        result_binding_id: candidate.result_binding.clone(),
        projected_result_bindings: candidate
            .projections
            .iter()
            .map(projected_binding)
            .collect(),
        command,
        argv_count,
        environment_supplied,
        stdio_mode,
        resolution: resolution.to_owned(),
    }
}

fn projected_binding(
    binding: &crate::javascript::semantic::data_effect_helpers::SemanticProjectedBinding<'_>,
) -> SemanticProjectedResultBinding {
    SemanticProjectedResultBinding {
        binding_id: binding.binding_id.clone(),
        projection_path: binding
            .projection_path
            .iter()
            .map(projection_segment)
            .collect(),
        resolution: match binding.resolution {
            ProjectionResolution::Complete => "complete",
            ProjectionResolution::Partial => "partial",
        }
        .to_owned(),
    }
}

fn projection_segment(key: &ProjectionKey) -> SemanticProjectionPathSegment {
    match key {
        ProjectionKey::Name(value) => SemanticProjectionPathSegment::String(value.clone()),
        ProjectionKey::Index(value) => SemanticProjectionPathSegment::Number(*value as f64),
        ProjectionKey::Dynamic => SemanticProjectionPathSegment::Null,
    }
}

fn spawn_arguments<'a>(
    node: Node<'a>,
    method: &str,
    state: &SemanticState<'a>,
) -> (Option<Node<'a>>, Option<usize>) {
    let args: Vec<_> = node
        .field_list(state.source, Field::Arguments)
        .into_iter()
        .flatten()
        .collect();
    let second: Option<Node<'a>> = args
        .get(1)
        .copied()
        .map(|node| unwrapped(state.source, node));
    let third: Option<Node<'a>> = args
        .get(2)
        .copied()
        .map(|node| unwrapped(state.source, node));
    let argv =
        method != "exec" && second.is_some_and(|node| node.babel_type() == "ArrayExpression");
    let options = if method == "exec" || second.is_none() {
        second
    } else if argv || second.is_some_and(|node| is_nullish_syntax(state.source, node)) {
        third
    } else {
        second
    };
    let argv_count = second
        .filter(|node| node.babel_type() == "ArrayExpression")
        .and_then(|array| {
            let elements = array.field_list(state.source, Field::Elements);
            (!elements
                .iter()
                .flatten()
                .any(|node| node.babel_type() == "SpreadElement"))
            .then_some(elements.len())
        });
    (options, argv_count)
}

fn object_has_property(object: Option<Node<'_>>, state: &SemanticState<'_>, name: &str) -> bool {
    let Some(object) = object else {
        return false;
    };
    if object.babel_type() != "ObjectExpression" {
        return false;
    }
    object
        .field_list(state.source, Field::Properties)
        .into_iter()
        .flatten()
        .filter(|property| property.babel_type() != "SpreadElement")
        .any(|property| {
            property
                .field(state.source, Field::Key)
                .and_then(|key| static_property_key(state.source, key, property.computed()))
                .is_some_and(|key| key == name)
        })
}

fn stdio_mode(options: Option<Node<'_>>, method: &str, state: &SemanticState<'_>) -> String {
    let Some(options) = options else {
        return "default".to_owned();
    };
    let options = unwrapped(state.source, options);
    if is_nullish_syntax(state.source, options)
        || ((method == "exec" || method == "execFile") && is_callback(options, state))
    {
        return "default".to_owned();
    }
    let lookup = static_object_property(state.source, Some(options), "stdio", None);
    let crate::javascript::semantic::ast_values::StaticObjectProperty::Explicit(property) = lookup
    else {
        return match lookup {
            crate::javascript::semantic::ast_values::StaticObjectProperty::Missing => {
                "default".to_owned()
            }
            _ => "dynamic".to_owned(),
        };
    };
    let Some(value) = property
        .field(state.source, Field::Value)
        .map(|node| unwrapped(state.source, node))
    else {
        return "dynamic".to_owned();
    };
    if is_nullish_syntax(state.source, value) {
        return "default".to_owned();
    }
    if value.babel_type() == "StringLiteral" {
        return value.string_value().unwrap_or_default().to_owned();
    }
    if value.babel_type() == "ArrayExpression" {
        return "array".to_owned();
    }
    "dynamic".to_owned()
}

fn is_callback(node: Node<'_>, _state: &SemanticState<'_>) -> bool {
    matches!(
        node.babel_type(),
        "FunctionDeclaration"
            | "FunctionExpression"
            | "ArrowFunctionExpression"
            | "ObjectMethod"
            | "ClassMethod"
            | "ClassPrivateMethod"
    )
}

fn collect_interactions<'a>(
    program: Node<'a>,
    state: &SemanticState<'a>,
    callables: &[SemanticCallable],
    candidates: &[SpawnCandidate<'a>],
) -> Vec<SemanticChildProcessInteraction> {
    let callable_ids: HashSet<String> = callables.iter().map(|c| c.callable_id.clone()).collect();
    let mut by_node = HashMap::new();
    let mut by_binding: HashMap<String, Vec<SpawnCandidate<'a>>> = HashMap::new();
    for candidate in candidates {
        by_node.insert(candidate.node.key(), candidate.clone());
        if let Some(id) = candidate.result_binding.as_ref() {
            by_binding
                .entry(id.clone())
                .or_default()
                .push(candidate.clone());
        }
        for projection in &candidate.projections {
            by_binding
                .entry(projection.binding_id.clone())
                .or_default()
                .push(candidate.clone());
        }
    }
    let mut context = DataEffectTraversalContext {
        state,
        callable_ids: &callable_ids,
        callable_stack: Vec::new(),
        ancestors: Vec::new(),
    };
    let mut output = Vec::new();
    traverse_data_effects(program, &mut context, |node, _parent, _ancestors, owner| {
        let Some(member) = data_effect_member_callee(node, state.source) else {
            return;
        };
        let Some(method) = member
            .field(state.source, Field::Property)
            .and_then(|property| static_property_key(state.source, property, member.computed()))
        else {
            return;
        };
        let method_name = method
            .try_to_string()
            .expect("admitted child-process method names are ASCII");
        let args: Vec<_> = node
            .field_list(state.source, Field::Arguments)
            .into_iter()
            .flatten()
            .collect();
        let (kind, event) = if method == "kill" {
            ("signal", None)
        } else if LISTENER_METHODS
            .iter()
            .any(|candidate| method == *candidate)
            && data_effect_literal_string(args.first().copied(), state.source)
                .is_some_and(|event| event == "exit" || event == "error")
        {
            (
                "listener",
                data_effect_literal_string(args.first().copied(), state.source),
            )
        } else {
            return;
        };
        let object = member
            .field(state.source, Field::Object)
            .map(|node| unwrapped(state.source, node));
        let (linked, complete) = resolve_candidates(object, state, &by_node, &by_binding);
        if linked.is_empty() {
            return;
        }
        let binding_id = object
            .as_ref()
            .and_then(|object| {
                object
                    .identifier_name()
                    .and_then(|name| state.resolve_binding(object, name))
            })
            .map(|index| state.binding(index).binding_id.clone());
        let mut linked_process_ids = linked
            .into_iter()
            .map(|candidate| {
                format!(
                    "child:spawn:{}:{}",
                    state.context.start(&candidate.node),
                    state.context.end(&candidate.node)
                )
            })
            .collect::<Vec<_>>();
        linked_process_ids.sort_by(|left, right| {
            left.chars()
                .map(u32::from)
                .cmp(right.chars().map(u32::from))
        });
        let signal_name = (kind == "signal")
            .then(|| signal_name(&args, state))
            .flatten();
        output.push(SemanticChildProcessInteraction {
            interaction_id: format!(
                "child:{kind}:{}:{}",
                state.context.start(&node),
                state.context.end(&node)
            ),
            kind: kind.to_owned(),
            method: method_name,
            location: range(&state.context, &node),
            owner_callable_id: owner.map(str::to_owned),
            process_binding_id: binding_id,
            linked_process_ids,
            event_name: event,
            signal_name,
            listener_location: (kind == "listener")
                .then(|| args.get(1).copied())
                .flatten()
                .map(|node| range(&state.context, &node)),
            resolution: if complete { "complete" } else { "partial" }.to_owned(),
        });
    });
    output
}

fn signal_name<'a>(args: &[Node<'a>], state: &SemanticState<'a>) -> Option<JsString> {
    let signal = args.first().copied();
    if signal.is_none()
        || signal.is_some_and(|node| {
            let node = unwrapped(state.source, node);
            (node.babel_type() == "UnaryExpression" && node.operator() == Some("void"))
                || (node.identifier_name() == Some("undefined")
                    && state.is_unshadowed_global(&node, "undefined"))
        })
    {
        return Some(JsString::from("SIGTERM"));
    }
    data_effect_literal_string(signal, state.source)
}

fn resolve_candidates<'a>(
    node: Option<Node<'a>>,
    state: &SemanticState<'a>,
    by_node: &HashMap<crate::javascript::ast::NodeKey, SpawnCandidate<'a>>,
    by_binding: &HashMap<String, Vec<SpawnCandidate<'a>>>,
) -> (Vec<SpawnCandidate<'a>>, bool) {
    let Some(node) = node else {
        return (Vec::new(), false);
    };
    let mut pending = vec![node];
    let mut visited = HashSet::new();
    let mut linked = HashSet::new();
    let mut fallback = HashSet::new();
    let mut complete = true;
    while let Some(current) = pending.pop() {
        let current = unwrapped(state.source, current);
        if !visited.insert(current.key()) {
            complete = false;
            continue;
        }
        if current.babel_type() == "AwaitExpression" {
            if let Some(argument) = current.field(state.source, Field::Argument) {
                pending.push(argument);
            }
            continue;
        }
        if let Some(candidate) = by_node.get(&current.key()) {
            linked.insert(candidate.node.key());
            continue;
        }
        let Some(name) = current.identifier_name() else {
            complete = false;
            continue;
        };
        let Some(index) = state.resolve_binding(&current, name) else {
            complete = false;
            continue;
        };
        let binding = state.binding(index);
        for candidate in by_binding.get(&binding.binding_id).into_iter().flatten() {
            fallback.insert(candidate.node.key());
        }
        let snapshot = state.semantic_binding_at_read(binding, current);
        let selected = snapshot.binding;
        let mut initializers = selected.initializers.clone();
        initializers.extend(selected.reference_initializers.iter().map(|reference| {
            crate::javascript::semantic::state::Initializer {
                record_id: 0,
                node: reference.node,
                projection: reference.projection.clone(),
                entry_body: None,
            }
        }));
        if initializers.len() != 1
            || !selected.reference_initializers.is_empty()
            || snapshot.status != BindingReadStatus::Ordered
        {
            complete = false;
        }
        for initializer in initializers {
            if initializer.projection.is_empty() {
                pending.push(initializer.node);
            } else {
                complete = false;
            }
        }
    }
    if !complete {
        linked.extend(fallback);
    }
    let values = by_node
        .values()
        .filter(|candidate| linked.contains(&candidate.node.key()))
        .cloned()
        .collect::<Vec<_>>();
    let is_complete = complete && values.len() == 1;
    (values, is_complete)
}
