//! Event-emitter and timer effects from `javascriptSemanticAsyncEffects.ts`.
//!
//! This pass is intentionally source driven.  It records candidates without
//! inventing runtime registrations, while binding and source-order helpers
//! retain the uncertainty that the TypeScript owner exposes.

use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::javascript::ast::{Field, Node};
use crate::javascript::contracts::semantic_ir::{
    SemanticCallable, SemanticEventOperation, SemanticProjectedResultBinding,
    SemanticProjectionPathSegment, SemanticTimerOperation,
};
use crate::javascript::semantic::ast_values::{static_property_name, unwrapped};
use crate::javascript::semantic::data_effect_helpers::{
    DataEffectTraversalContext, ProjectionKey, ProjectionResolution,
    assigned_semantic_result_bindings, builtin_data_effect_method, data_effect_literal_string,
    data_effect_member_callee,
};
use crate::javascript::semantic::mutation_initializers::BindingReadStatus;
use crate::javascript::semantic::state::SemanticState;
use crate::javascript::semantic::value_types::JsString;
use crate::javascript::static_analysis::helpers::range;

const EVENT_REGISTER_METHODS: &[&str] = &[
    "on",
    "once",
    "addListener",
    "prependListener",
    "prependOnceListener",
];
const EVENT_REMOVE_METHODS: &[&str] = &["off", "removeListener", "removeAllListeners"];
const TIMER_SCHEDULE_METHODS: &[&str] = &["setTimeout", "setInterval", "setImmediate"];
const TIMER_CANCEL_METHODS: &[&str] = &["clearTimeout", "clearInterval", "clearImmediate"];

#[derive(Clone, Debug, Default, Serialize)]
pub struct AsyncEffectAnalysis {
    pub event_operations: Vec<SemanticEventOperation>,
    pub timer_operations: Vec<SemanticTimerOperation>,
}

#[derive(Clone, Debug)]
struct TimerCandidate<'a> {
    node: Node<'a>,
    method: String,
    kind: &'static str,
    owner_callable_id: Option<String>,
    handle_binding_id: Option<String>,
    projected_result_bindings: Vec<SemanticProjectedResultBinding>,
    handle_read: Option<HandleRead<'a>>,
}

#[derive(Clone, Debug)]
struct HandleRead<'a> {
    origins: Vec<Node<'a>>,
    complete: bool,
}

/// Collect explicit EventEmitter-style and Node timer candidates.
pub fn collect_semantic_async_effects<'a>(
    program: Node<'a>,
    state: &SemanticState<'a>,
    callables: &[SemanticCallable],
) -> AsyncEffectAnalysis {
    let callable_ids: HashSet<String> = callables
        .iter()
        .map(|item| item.callable_id.clone())
        .collect();
    let mut events = Vec::new();
    let mut candidates = Vec::new();
    let mut context = DataEffectTraversalContext {
        state,
        callable_ids: &callable_ids,
        callable_stack: Vec::new(),
        ancestors: Vec::new(),
    };
    super::data_effect_helpers::traverse_data_effects(
        program,
        &mut context,
        |node, _parent, ancestors, owner| {
            if matches!(
                node.babel_type(),
                "CallExpression" | "OptionalCallExpression"
            ) {
                if let Some(event) = collect_event(node, owner.map(str::to_owned), state) {
                    events.push(event);
                }
                if let Some(timer) = collect_timer(node, owner.map(str::to_owned), state, ancestors)
                {
                    candidates.push(timer);
                }
            }
        },
    );
    let timer_operations = resolve_timers(candidates, state);
    AsyncEffectAnalysis {
        event_operations: events,
        timer_operations,
    }
}

fn collect_event<'a>(
    node: Node<'a>,
    owner: Option<String>,
    state: &SemanticState<'a>,
) -> Option<SemanticEventOperation> {
    let member = data_effect_member_callee(node, state.source)?;
    let method = static_property_name(
        state.source,
        member.field(state.source, Field::Property)?,
        member.computed(),
    )
    .try_to_string()
    .ok()?;
    if !EVENT_REGISTER_METHODS
        .iter()
        .chain(EVENT_REMOVE_METHODS)
        .chain(["emit"].iter())
        .any(|candidate| *candidate == method)
    {
        return None;
    }
    let kind = if EVENT_REGISTER_METHODS
        .iter()
        .any(|candidate| *candidate == method)
    {
        "register"
    } else if EVENT_REMOVE_METHODS
        .iter()
        .any(|candidate| *candidate == method)
    {
        "remove"
    } else {
        "dispatch"
    };
    let event_name = node
        .field_list(state.source, Field::Arguments)
        .into_iter()
        .flatten()
        .next()
        .and_then(|arg| data_effect_literal_string(Some(arg), state.source))
        .map(JsString::from);
    let listener = if EVENT_REGISTER_METHODS
        .iter()
        .chain(["off", "removeListener"].iter())
        .any(|candidate| *candidate == method)
    {
        node.field_list(state.source, Field::Arguments)
            .into_iter()
            .flatten()
            .nth(1)
    } else {
        None
    };
    let object = member.field(state.source, Field::Object)?;
    let (emitter_key, emitter_binding_id, complete) = emitter_identity(object, state);
    Some(SemanticEventOperation {
        event_id: format!(
            "event:{kind}:{}:{}",
            state.context.start(&node),
            state.context.end(&node)
        ),
        kind: kind.to_owned(),
        method,
        location: range(&state.context, &node),
        owner_callable_id: owner,
        emitter_key,
        emitter_binding_id,
        event_name: event_name.clone(),
        listener_binding_id: listener
            .and_then(|item| {
                item.identifier_name()
                    .and_then(|name| state.resolve_binding(&item, name))
            })
            .map(|index| state.binding(index).binding_id.clone()),
        listener_location: listener.map(|item| range(&state.context, &item)),
        resolution: if event_name.is_none() {
            "unresolved".to_owned()
        } else if complete {
            "complete".to_owned()
        } else {
            "partial".to_owned()
        },
    })
}

fn emitter_identity<'a>(
    node: Node<'a>,
    state: &SemanticState<'a>,
) -> (JsString, Option<String>, bool) {
    if node.babel_type() == "ThisExpression" {
        return (JsString::from("this"), None, true);
    }
    if let Some(name) = node.identifier_name() {
        if let Some(index) = state.resolve_binding(&node, name) {
            return (
                JsString::from(format!("binding:{}", state.binding(index).binding_id)),
                Some(state.binding(index).binding_id.clone()),
                true,
            );
        }
        return (
            JsString::from(format!("global:{name}")),
            None,
            !state.resolution_blocked(&node, name),
        );
    }
    (
        JsString::from(format!(
            "expression:{}:{}",
            state.context.start(&node),
            state.context.end(&node)
        )),
        None,
        false,
    )
}

fn collect_timer<'a>(
    node: Node<'a>,
    owner: Option<String>,
    state: &SemanticState<'a>,
    ancestors: &[Node<'a>],
) -> Option<TimerCandidate<'a>> {
    let callee = node.field(state.source, Field::Callee)?;
    let method = timer_method(callee, state)?;
    let kind = if TIMER_SCHEDULE_METHODS
        .iter()
        .any(|candidate| *candidate == method)
    {
        "schedule"
    } else {
        "cancel"
    };
    let projected = assigned_semantic_result_bindings(node, ancestors, state);
    let projected_result_bindings = if kind == "schedule" {
        projected
            .iter()
            .filter(|item| !item.projection_path.is_empty())
            .map(projected_binding)
            .collect()
    } else {
        Vec::new()
    };
    let handle_binding_id = if kind == "schedule" {
        (projected.len() == 1 && projected[0].projection_path.is_empty())
            .then(|| projected[0].binding_id.clone())
    } else {
        node.field_list(state.source, Field::Arguments)
            .into_iter()
            .flatten()
            .next()
            .and_then(|arg| {
                arg.identifier_name()
                    .and_then(|name| state.resolve_binding(&arg, name))
            })
            .map(|index| state.binding(index).binding_id.clone())
    };
    let handle_read = if kind == "cancel" {
        node.field_list(state.source, Field::Arguments)
            .into_iter()
            .flatten()
            .next()
            .filter(|arg| arg.identifier_name().is_some())
            .and_then(|arg| {
                let name = arg.identifier_name()?;
                let index = state.resolve_binding(&arg, name)?;
                let binding = state.binding(index);
                let snapshot = state.semantic_binding_at_read(binding, arg);
                let stable = !binding.mutable
                    && binding.initializers.len() == 1
                    && binding.reference_initializers.is_empty();
                let origins = snapshot
                    .binding
                    .initializers
                    .iter()
                    .map(|item| item.node)
                    .chain(
                        snapshot
                            .binding
                            .reference_initializers
                            .iter()
                            .map(|item| item.node),
                    )
                    .collect();
                Some(HandleRead {
                    origins,
                    complete: snapshot.status == BindingReadStatus::Ordered || stable,
                })
            })
    } else {
        None
    };
    Some(TimerCandidate {
        node,
        method,
        kind,
        owner_callable_id: owner,
        handle_binding_id,
        projected_result_bindings,
        handle_read,
    })
}

fn timer_method<'a>(callee: Node<'a>, state: &SemanticState<'a>) -> Option<String> {
    let callee = unwrapped(state.source, callee);
    if let Some(name) = callee.identifier_name() {
        if state.resolve_binding(&callee, name).is_none() {
            let method = admitted_timer_method(name)?;
            return (!state.resolution_blocked(&callee, name)).then_some(method.to_owned());
        }
    }
    builtin_data_effect_method(callee, state, &["timers", "node:timers"])
        .filter(|method| admitted_timer_method(method).is_some())
}

fn admitted_timer_method(value: &str) -> Option<&'static str> {
    TIMER_SCHEDULE_METHODS
        .iter()
        .chain(TIMER_CANCEL_METHODS)
        .copied()
        .find(|candidate| *candidate == value)
}

fn projected_binding(
    item: &crate::javascript::semantic::data_effect_helpers::SemanticProjectedBinding<'_>,
) -> SemanticProjectedResultBinding {
    SemanticProjectedResultBinding {
        binding_id: item.binding_id.clone(),
        projection_path: item
            .projection_path
            .iter()
            .map(|key| match key {
                ProjectionKey::Name(value) => {
                    SemanticProjectionPathSegment::String(JsString::from(value.clone()))
                }
                ProjectionKey::Index(value) => SemanticProjectionPathSegment::Number(*value as f64),
                ProjectionKey::Dynamic => SemanticProjectionPathSegment::Null,
            })
            .collect(),
        resolution: match item.resolution {
            ProjectionResolution::Complete => "complete",
            ProjectionResolution::Partial => "partial",
        }
        .to_owned(),
    }
}

fn resolve_timers<'a>(
    candidates: Vec<TimerCandidate<'a>>,
    state: &SemanticState<'a>,
) -> Vec<SemanticTimerOperation> {
    let schedules: HashMap<_, _> = candidates
        .iter()
        .filter(|item| item.kind == "schedule")
        .map(|item| (item.node.key(), item))
        .collect();
    candidates
        .iter()
        .map(|candidate| {
            let linked: Vec<&TimerCandidate<'a>> = candidate
                .handle_read
                .as_ref()
                .map(|read| {
                    read.origins
                        .iter()
                        .filter_map(|origin| schedules.get(&origin.key()).copied())
                        .collect()
                })
                .unwrap_or_default();
            let incomplete = candidate
                .handle_read
                .as_ref()
                .is_some_and(|read| read.origins.len() != linked.len());
            let resolution = if candidate.kind == "schedule" {
                "complete"
            } else if linked.len() == 1
                && candidate
                    .handle_read
                    .as_ref()
                    .is_some_and(|read| read.complete)
                && !incomplete
                && !linked[0]
                    .projected_result_bindings
                    .iter()
                    .any(|item| Some(&item.binding_id) == candidate.handle_binding_id.as_ref())
            {
                "complete"
            } else if !linked.is_empty() {
                "partial"
            } else {
                "unresolved"
            };
            let delay = if candidate.kind == "schedule" && candidate.method != "setImmediate" {
                node_numeric_argument(candidate.node, state)
            } else {
                None
            };
            SemanticTimerOperation {
                timer_id: format!(
                    "timer:{}:{}:{}",
                    candidate.kind,
                    state.context.start(&candidate.node),
                    state.context.end(&candidate.node)
                ),
                kind: candidate.kind.to_owned(),
                method: candidate.method.clone(),
                location: range(&state.context, &candidate.node),
                owner_callable_id: candidate.owner_callable_id.clone(),
                handle_binding_id: candidate.handle_binding_id.clone(),
                projected_result_bindings: candidate.projected_result_bindings.clone(),
                linked_timer_id: linked.first().map(|item| {
                    format!(
                        "timer:{}:{}:{}",
                        item.kind,
                        state.context.start(&item.node),
                        state.context.end(&item.node)
                    )
                }),
                delay_milliseconds: delay,
                resolution: resolution.to_owned(),
            }
        })
        .collect()
}

fn node_numeric_argument(node: Node<'_>, state: &SemanticState<'_>) -> Option<f64> {
    node.field_list(state.source, Field::Arguments)
        .into_iter()
        .flatten()
        .nth(1)
        .and_then(|item| item.numeric_value())
}
