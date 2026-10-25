//! Internal composition of the JavaScript semantic producers.
//!
//! This is deliberately an application-internal seam.  It owns phase ordering
//! and cancellation checkpoints, while each semantic module remains the owner
//! of the facts it produces.  Public CLI/MCP admission stays in the interface
//! crates until the complete producer pipeline has parity evidence.

use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;

use oxc_allocator::Allocator;

use crate::javascript::ast::{AstContext, NodeSet};
use crate::javascript::contracts::semantic_ir::{
    SemanticCallable as ContractCallable, SemanticIr, SemanticReference,
};
use crate::javascript::parser::{RawDiagnostic, parse_javascript_analysis_program};

use super::ambient_writes::index_ambient_writes;
use super::async_effects::collect_semantic_async_effects;
use super::calls::collect_semantic_calls;
use super::child_processes::collect_semantic_child_processes;
use super::commonjs_export_receivers::index_commonjs_export_receivers;
use super::data_effects::collect_semantic_data_effects;
use super::definitions::collect_definitions;
use super::fingerprints::{SemanticFingerprintInputs, collect_semantic_fingerprints};
use super::limits::resource_limit_reason;
use super::member_mutations::collect_semantic_member_mutations;
use super::module_links::{CollectedModuleLinks, collect_semantic_module_links_with_facts};
use super::objects::collect_semantic_objects;
use super::projection::{collect_semantic_projection, immutable_bindings, immutable_scopes};
use super::promises::collect_semantic_promises;
use super::property_paths::PropertyPathKey;
use super::resource_effects::collect_semantic_resources;
use super::returns::collect_semantic_returns_with_values;
use super::state::ResolutionMode;

struct PrimaryPhase<'a> {
    internal_callables: Vec<super::projection::SemanticCallable>,
    scopes: Vec<crate::javascript::contracts::semantic_ir::SemanticScope>,
    bindings: Vec<crate::javascript::contracts::semantic_ir::SemanticBinding>,
    references: Vec<SemanticReference>,
    links: CollectedModuleLinks<'a>,
}

struct CallablePhase<'a> {
    returns: Vec<super::returns::SemanticCallableReturns<'a>>,
    callables: Vec<ContractCallable>,
    module_links: Vec<crate::javascript::contracts::semantic_ir::SemanticModuleLink>,
}

struct DerivedPhase {
    calls: super::calls::SemanticCallAnalysis,
    promises: Vec<crate::javascript::contracts::semantic_ir::SemanticPromiseOperation>,
    async_effects: super::async_effects::AsyncEffectAnalysis,
    child_processes: super::child_processes::ChildProcessAnalysis,
    data_effects: super::data_effects::DataEffectAnalysis,
    resources: Vec<crate::javascript::contracts::semantic_ir::SemanticResourceOperation>,
    objects: Vec<crate::javascript::contracts::semantic_ir::SemanticObjectOperation>,
    fingerprints: Vec<crate::javascript::contracts::semantic_ir::SemanticFunctionFingerprint>,
}

/// Result of the internal source analysis.  The parsed arena and state do not
/// escape this function; every returned record owns its contract data.
pub fn analyze_source(source: &str, path: Option<&str>) -> Result<SemanticIr, Vec<RawDiagnostic>> {
    analyze_source_with_mode(source, path, ResolutionMode::Import)
}

/// Analyze one source using the caller-selected static module-resolution mode.
pub fn analyze_source_with_mode(
    source: &str,
    path: Option<&str>,
    static_import_resolution_mode: ResolutionMode,
) -> Result<SemanticIr, Vec<RawDiagnostic>> {
    match analyze_source_with_mode_and_checkpoint(
        source,
        path,
        static_import_resolution_mode,
        || ControlFlow::<()>::Continue(()),
    ) {
        ControlFlow::Continue(result) => result,
        ControlFlow::Break(()) => unreachable!("the default checkpoint never cancels"),
    }
}

/// Run the producer pipeline with a checkpoint between each expensive phase.
/// `Break` is returned without converting partial producer state into an IR.
pub fn analyze_source_with_checkpoint<B>(
    source: &str,
    path: Option<&str>,
    checkpoint: impl FnMut() -> ControlFlow<B>,
) -> ControlFlow<B, Result<SemanticIr, Vec<RawDiagnostic>>> {
    analyze_source_with_mode_and_checkpoint(source, path, ResolutionMode::Import, checkpoint)
}

/// Run the source pipeline with an explicit module-resolution mode and
/// cancellation checkpoint between producer phases.
pub fn analyze_source_with_mode_and_checkpoint<B>(
    source: &str,
    path: Option<&str>,
    static_import_resolution_mode: ResolutionMode,
    mut checkpoint: impl FnMut() -> ControlFlow<B>,
) -> ControlFlow<B, Result<SemanticIr, Vec<RawDiagnostic>>> {
    let allocator = Allocator::default();
    let parsed = match parse_javascript_analysis_program(&allocator, source, path) {
        Ok(parsed) => parsed,
        Err(diagnostics) => return ControlFlow::Continue(Err(diagnostics)),
    };
    let parser_partial = !parsed.errors.is_empty();
    let context = AstContext::new(parsed.program);

    let mut state = collect_definitions(context, static_import_resolution_mode, &mut checkpoint)?;
    checkpoint()?;

    collect_primary_state_phase(&mut state, &mut checkpoint)?;

    let public_call_writes = collect_public_call_writes(&state);
    let commonjs_receivers = index_commonjs_export_receivers(&state, &public_call_writes);
    let links = collect_semantic_module_links_with_facts(&state, &commonjs_receivers);
    checkpoint()?;

    let primary = collect_primary_projection_phase(&state, links, &mut checkpoint)?;
    let callable_phase = collect_callable_phase(&state, &primary, parser_partial, &mut checkpoint)?;
    let derived = collect_derived_phase(
        &state,
        &primary,
        &callable_phase,
        &callable_phase.callables,
        parser_partial,
        &mut checkpoint,
    )?;

    let mut resource_limits = state.getter_resource_limits.borrow().clone();
    resource_limits.extend(state.value_resource_limits.borrow().iter().cloned());
    resource_limits.sort_by_key(|limit| format!("{limit:?}"));
    resource_limits.dedup();
    let limitations = limitations(&state, parser_partial, &resource_limits);
    let widened_returned_references = state
        .returned_reference_widenings
        .borrow()
        .iter()
        .cloned()
        .map(Into::into)
        .collect();
    let coverage = super::coverage::SemanticCoverage::from_observations(
        parser_partial,
        resource_limits,
        widened_returned_references,
    );

    ControlFlow::Continue(Ok(SemanticIr {
        schema: "JavaScriptSemanticIR".to_owned(),
        scopes: primary.scopes,
        bindings: primary.bindings,
        callables: callable_phase.callables,
        references: primary.references,
        module_links: callable_phase.module_links,
        call_sites: derived.calls.call_sites,
        argument_flows: derived.calls.argument_flows,
        call_return_flows: derived.calls.call_return_flows,
        call_result_flows: derived.calls.call_result_flows,
        closure_captures: derived.calls.closure_captures,
        promise_operations: derived.promises,
        event_operations: derived.async_effects.event_operations,
        timer_operations: derived.async_effects.timer_operations,
        child_process_spawns: derived.child_processes.child_process_spawns,
        child_process_interactions: derived.child_processes.child_process_interactions,
        configuration_operations: derived.data_effects.configuration_operations,
        request_operations: derived.data_effects.request_operations,
        boundary_operations: derived.data_effects.boundary_operations,
        resource_operations: derived.resources,
        object_operations: derived.objects,
        function_fingerprints: derived.fingerprints,
        frontiers: derived.calls.frontiers,
        coverage,
        limitations,
    }))
}

fn collect_primary_state_phase<'a, B>(
    state: &mut super::state::SemanticState<'a>,
    checkpoint: &mut impl FnMut() -> ControlFlow<B>,
) -> ControlFlow<B, ()> {
    index_ambient_writes(state);
    checkpoint()?;

    collect_semantic_member_mutations(state);
    checkpoint()?;

    ControlFlow::Continue(())
}

fn collect_primary_projection_phase<'a, B>(
    state: &super::state::SemanticState<'a>,
    links: CollectedModuleLinks<'a>,
    checkpoint: &mut impl FnMut() -> ControlFlow<B>,
) -> ControlFlow<B, PrimaryPhase<'a>> {
    let (internal_callables, internal_references) = collect_semantic_projection(state);
    let scopes = immutable_scopes(state)
        .into_iter()
        .map(
            |scope| crate::javascript::contracts::semantic_ir::SemanticScope {
                scope_id: scope.scope_id,
                parent_scope_id: scope.parent_scope_id,
                kind: scope.kind,
                location: scope.location.into(),
                bindings_complete: scope.bindings_complete,
                binding_ids: scope.binding_ids,
            },
        )
        .collect();
    let bindings = immutable_bindings(state);
    let references = project_references(internal_references);
    checkpoint()?;

    ControlFlow::Continue(PrimaryPhase {
        internal_callables,
        scopes,
        bindings,
        references,
        links,
    })
}

fn collect_derived_phase<'a, B>(
    state: &'a super::state::SemanticState<'a>,
    primary: &PrimaryPhase<'a>,
    callable_phase: &CallablePhase<'a>,
    callables: &[ContractCallable],
    parser_partial: bool,
    checkpoint: &mut impl FnMut() -> ControlFlow<B>,
) -> ControlFlow<B, DerivedPhase> {
    let calls = collect_semantic_calls(state, callables);
    checkpoint()?;

    let return_sites = return_site_index(&callable_phase.returns);
    let promises = collect_semantic_promises(state, &primary.internal_callables, &return_sites);
    checkpoint()?;

    let async_effects = collect_semantic_async_effects(state.program, state, callables);
    checkpoint()?;

    let child_processes = collect_semantic_child_processes(state.program, state, callables);
    checkpoint()?;

    let data_effects = collect_semantic_data_effects(state.program, state, callables);
    checkpoint()?;

    let resources = collect_semantic_resources(state.program, state, &primary.internal_callables);
    checkpoint()?;

    let objects = collect_semantic_objects(state, &primary.internal_callables);
    checkpoint()?;

    let fingerprints = collect_semantic_fingerprints(
        state,
        &SemanticFingerprintInputs {
            callables,
            call_sites: &calls.call_sites,
            closure_captures: &calls.closure_captures,
            promises: &promises,
            events: &async_effects.event_operations,
            timers: &async_effects.timer_operations,
            child_process_spawns: &child_processes.child_process_spawns,
            child_process_interactions: &child_processes.child_process_interactions,
            requests: &data_effects.request_operations,
            resources: &resources,
        },
        parser_partial,
    );
    checkpoint()?;

    ControlFlow::Continue(DerivedPhase {
        calls,
        promises,
        async_effects,
        child_processes,
        data_effects,
        resources,
        objects,
        fingerprints,
    })
}

fn collect_callable_phase<'a, B>(
    state: &super::state::SemanticState<'a>,
    primary: &PrimaryPhase<'a>,
    parser_partial: bool,
    checkpoint: &mut impl FnMut() -> ControlFlow<B>,
) -> ControlFlow<B, CallablePhase<'a>> {
    let returns =
        collect_semantic_returns_with_values(state, &primary.internal_callables, parser_partial);
    let callables = returns
        .iter()
        .cloned()
        .map(Into::into)
        .collect::<Vec<ContractCallable>>();
    let admitted_callable_ids = callables
        .iter()
        .map(|callable| callable.callable_id.clone())
        .collect::<HashSet<_>>();
    let module_links = super::returns::resolve_semantic_module_callables_from_state(
        state,
        &primary.links,
        &admitted_callable_ids,
    );
    checkpoint()?;

    ControlFlow::Continue(CallablePhase {
        returns,
        callables,
        module_links,
    })
}

fn collect_public_call_writes(state: &super::state::SemanticState<'_>) -> NodeSet {
    state
        .ambient_write_effects
        .iter()
        .filter(|effect| {
            matches!(
                effect.node.babel_type(),
                "CallExpression" | "OptionalCallExpression"
            ) && effect.path.len() <= 2
                && matches!(
                    effect.path.first(),
                    Some(PropertyPathKey::String(root)) if root == "commonjs-module"
                )
                && (effect.path.len() == 1
                    || matches!(
                        effect.path.get(1),
                        Some(PropertyPathKey::String(name)) if name == "exports"
                    ))
        })
        .map(|effect| effect.node.key())
        .collect()
}

fn project_references(
    references: Vec<super::projection::SemanticReference>,
) -> Vec<SemanticReference> {
    references
        .into_iter()
        .map(|reference| SemanticReference {
            name: reference.name.into(),
            role: match reference.role {
                super::reference_role::ReferenceRole::Read => "read",
                super::reference_role::ReferenceRole::Write => "write",
                super::reference_role::ReferenceRole::Export => "export",
            }
            .to_owned(),
            location: reference.location.into(),
            binding_id: reference.binding_id,
            resolution: reference.resolution.to_owned(),
        })
        .collect()
}

fn return_site_index<'a>(
    returns: &[super::returns::SemanticCallableReturns<'a>],
) -> HashMap<String, HashMap<String, String>> {
    returns
        .iter()
        .map(|entry| {
            (
                entry.callable.callable_id.clone(),
                entry
                    .return_sites
                    .iter()
                    .map(|site| (return_site_key(&site.location), site.return_site_id.clone()))
                    .collect(),
            )
        })
        .collect()
}

fn return_site_key(location: &crate::javascript::parser::SourceRange) -> String {
    format!(
        "{}:{}:{}:{}",
        location.start.line, location.start.column, location.end.line, location.end.column
    )
}

fn limitations(
    state: &super::state::SemanticState<'_>,
    parser_partial: bool,
    resource_limits: &[super::value_types::ResourceLimit],
) -> Vec<String> {
    let mut limitations = Vec::new();

    if !state.returned_reference_widenings.borrow().is_empty() {
        limitations.push(
            "Some returned-reference projections widened to preserve uncertainty.".to_owned(),
        );
    }

    limitations.extend(
        resource_limits
            .iter()
            .cloned()
            .map(resource_limit_reason)
            .map(str::to_owned),
    );

    if parser_partial {
        limitations.push(
            "The parser recovered from syntax errors; affected bindings are partial.".to_owned(),
        );
    }

    limitations.extend([
        "Values and aliases were recovered from inert syntax only; no JavaScript was executed.",
        "Return sites include only direct callable returns; nested callable returns remain separate.",
        "Local call, argument, return, and closure relations are static candidates and do not prove runtime invocation.",
        "Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.",
        "Cross-function mutation and dynamic property resolution remain unknown.",
    ]
    .into_iter()
    .map(str::to_owned));

    limitations
}
