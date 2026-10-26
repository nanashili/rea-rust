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
use crate::javascript::parser::{
    ParsedJavaScriptProgram, RawDiagnostic, parse_javascript_analysis_program,
};

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

struct CallablePhase {
    return_sites: HashMap<String, HashMap<String, String>>,
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
}

/// Owns the ordered producer phases shared by static and semantic analysis.
/// Replaying member mutation collection would duplicate effects.
pub(crate) struct PreparedSemanticState<'a> {
    state: super::state::SemanticState<'a>,
    phase: PreparedPhase,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PreparedPhase {
    Definitions,
    AmbientWrites,
    MemberMutations,
}

impl<'a> PreparedSemanticState<'a> {
    /// End semantic evaluation while keeping the syntax view for fingerprints.
    /// The remaining fields, including derived caches, drop on return.
    fn into_context(self) -> AstContext<'a> {
        self.state.context
    }

    pub(crate) fn state(&self) -> &super::state::SemanticState<'a> {
        &self.state
    }

    pub(crate) fn ensure_ambient_writes(&mut self) {
        if self.phase == PreparedPhase::Definitions {
            index_ambient_writes(&mut self.state);
            self.phase = PreparedPhase::AmbientWrites;
        }
    }

    pub(crate) fn ensure_member_mutations(&mut self) {
        self.ensure_ambient_writes();
        if self.phase == PreparedPhase::AmbientWrites {
            collect_semantic_member_mutations(&mut self.state);
            self.phase = PreparedPhase::MemberMutations;
        }
    }

    pub(crate) fn inspect<T>(
        &self,
        inspect: impl FnOnce(&super::state::SemanticState<'a>) -> T,
    ) -> T {
        let _observations = InspectorObservations::new(&self.state);
        inspect(&self.state)
    }
}

/// Static inspectors may evaluate expressions the semantic pass never visits.
/// Keep their warnings in the static result without leaking them or their
/// memoized values into semantic coverage. Producer observations stay intact.
struct InspectorObservations<'state, 'source> {
    state: &'state super::state::SemanticState<'source>,
    widenings: Vec<crate::javascript::parser::SourceRange>,
    getter_limits: Vec<super::value_types::ResourceLimit>,
    value_limits: Vec<super::value_types::ResourceLimit>,
}

impl<'state, 'source> InspectorObservations<'state, 'source> {
    fn new(state: &'state super::state::SemanticState<'source>) -> Self {
        Self {
            state,
            widenings: state.returned_reference_widenings.borrow().clone(),
            getter_limits: state.getter_resource_limits.borrow().clone(),
            value_limits: state.value_resource_limits.borrow().clone(),
        }
    }
}

impl Drop for InspectorObservations<'_, '_> {
    fn drop(&mut self) {
        *self.state.returned_reference_widenings.borrow_mut() = std::mem::take(&mut self.widenings);
        *self.state.getter_resource_limits.borrow_mut() = std::mem::take(&mut self.getter_limits);
        *self.state.value_resource_limits.borrow_mut() = std::mem::take(&mut self.value_limits);
        super::values::clear_semantic_value_caches(self.state);
    }
}

pub(crate) fn prepare_state<'a>(
    parsed: &ParsedJavaScriptProgram<'a>,
    static_import_resolution_mode: ResolutionMode,
) -> PreparedSemanticState<'a> {
    match prepare_state_with_checkpoint(parsed, static_import_resolution_mode, || {
        ControlFlow::<()>::Continue(())
    }) {
        ControlFlow::Continue(prepared) => prepared,
        ControlFlow::Break(()) => unreachable!("the default checkpoint never cancels"),
    }
}

fn prepare_state_with_checkpoint<'a, B>(
    parsed: &ParsedJavaScriptProgram<'a>,
    static_import_resolution_mode: ResolutionMode,
    mut checkpoint: impl FnMut() -> ControlFlow<B>,
) -> ControlFlow<B, PreparedSemanticState<'a>> {
    let context = AstContext::new(parsed.program);
    let state = collect_definitions(context, static_import_resolution_mode, &mut checkpoint)?;
    checkpoint()?;

    ControlFlow::Continue(PreparedSemanticState {
        state,
        phase: PreparedPhase::Definitions,
    })
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

    let prepared =
        prepare_state_with_checkpoint(&parsed, static_import_resolution_mode, &mut checkpoint)?;
    let parser_partial = !parsed.errors.is_empty();
    drop(parsed);
    analyze_prepared_source_with_checkpoint(parser_partial, prepared, checkpoint)
}

/// Continue semantic analysis from state prepared by the static phase.
///
/// The parser's semantic model has already been consumed by the static phase;
/// only its partial-parse status crosses this phase boundary. The caller owns
/// the phase boundary and may have already populated the mutation facts.
pub(crate) fn analyze_prepared_source_with_checkpoint<'a, B>(
    parser_partial: bool,
    mut prepared: PreparedSemanticState<'a>,
    mut checkpoint: impl FnMut() -> ControlFlow<B>,
) -> ControlFlow<B, Result<SemanticIr, Vec<RawDiagnostic>>> {
    let mut ir = collect_semantic_facts(parser_partial, &mut prepared, &mut checkpoint)?;
    let context = prepared.into_context();

    ir.function_fingerprints = collect_semantic_fingerprints(
        &context,
        &SemanticFingerprintInputs {
            callables: &ir.callables,
            call_sites: &ir.call_sites,
            closure_captures: &ir.closure_captures,
            promises: &ir.promise_operations,
            events: &ir.event_operations,
            timers: &ir.timer_operations,
            child_process_spawns: &ir.child_process_spawns,
            child_process_interactions: &ir.child_process_interactions,
            requests: &ir.request_operations,
            resources: &ir.resource_operations,
        },
        parser_partial,
    );
    checkpoint()?;

    ControlFlow::Continue(Ok(ir))
}

/// Finish state-dependent producers before releasing their lookup indexes.
/// Only owned contract data leaves this phase; syntax hashing runs afterward.
fn collect_semantic_facts<'a, B>(
    parser_partial: bool,
    prepared: &mut PreparedSemanticState<'a>,
    checkpoint: &mut impl FnMut() -> ControlFlow<B>,
) -> ControlFlow<B, SemanticIr> {
    collect_primary_state_phase(prepared, checkpoint)?;
    let state = &prepared.state;

    let public_call_writes = collect_public_call_writes(state);
    let commonjs_receivers = index_commonjs_export_receivers(state, &public_call_writes);
    let links = collect_semantic_module_links_with_facts(state, &commonjs_receivers);
    drop(commonjs_receivers);
    drop(public_call_writes);
    checkpoint()?;

    let primary = collect_primary_projection_phase(state, links, checkpoint)?;
    let callable_phase = collect_callable_phase(state, &primary, parser_partial, checkpoint)?;
    let derived = collect_derived_phase(
        state,
        &primary,
        &callable_phase,
        &callable_phase.callables,
        checkpoint,
    )?;

    let (coverage, limitations) = semantic_observations(state, parser_partial);

    ControlFlow::Continue(SemanticIr {
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
        function_fingerprints: Vec::new(),
        frontiers: derived.calls.frontiers,
        coverage,
        limitations,
    })
}

fn semantic_observations(
    state: &super::state::SemanticState<'_>,
    parser_partial: bool,
) -> (super::coverage::SemanticCoverage, Vec<String>) {
    let mut resource_limits = state.getter_resource_limits.borrow().clone();
    resource_limits.extend(state.value_resource_limits.borrow().iter().cloned());
    resource_limits.sort_by_key(|limit| format!("{limit:?}"));
    resource_limits.dedup();
    let limitations = limitations(state, parser_partial, &resource_limits);
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

    (coverage, limitations)
}

fn collect_primary_state_phase<'a, B>(
    prepared: &mut PreparedSemanticState<'a>,
    checkpoint: &mut impl FnMut() -> ControlFlow<B>,
) -> ControlFlow<B, ()> {
    prepared.ensure_ambient_writes();
    checkpoint()?;

    prepared.ensure_member_mutations();
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
    state: &super::state::SemanticState<'a>,
    primary: &PrimaryPhase<'a>,
    callable_phase: &CallablePhase,
    callables: &[ContractCallable],
    checkpoint: &mut impl FnMut() -> ControlFlow<B>,
) -> ControlFlow<B, DerivedPhase> {
    let calls = collect_semantic_calls(state, callables);
    checkpoint()?;

    let promises = collect_semantic_promises(
        state,
        &primary.internal_callables,
        &callable_phase.return_sites,
    );
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

    ControlFlow::Continue(DerivedPhase {
        calls,
        promises,
        async_effects,
        child_processes,
        data_effects,
        resources,
        objects,
    })
}

fn collect_callable_phase<'a, B>(
    state: &super::state::SemanticState<'a>,
    primary: &PrimaryPhase<'a>,
    parser_partial: bool,
    checkpoint: &mut impl FnMut() -> ControlFlow<B>,
) -> ControlFlow<B, CallablePhase> {
    let returns =
        collect_semantic_returns_with_values(state, &primary.internal_callables, parser_partial);
    let return_sites = return_site_index(&returns);
    let callables = returns
        .into_iter()
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
        return_sites,
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

#[cfg(test)]
mod shared_pipeline_tests {
    use super::*;
    use crate::javascript::static_analysis::analyze::analyze_source_with_prepared_state;

    #[test]
    fn semantic_output_matches_an_independent_pass_after_static_inspection() {
        let sources = [
            r#"import { helper } from "./dep.js";
                export function run() { return helper(); }"#,
            r#"const options = { url: "https://first.test" };
                options.url = "https://second.test";
                fetch(options.url);
                export function endpoint() { return options.url; }"#,
            r#"const { BrowserWindow } = require("electron");
                const preferences = { nodeIntegration: false };
                preferences.contextIsolation = true;
                new BrowserWindow({ webPreferences: preferences });"#,
            r#"const cyclic = { get url() { return cyclic.url; } };
                fetch(cyclic.url);
                export function read() { return cyclic.url; }"#,
            r#"const first = {}; const second = {};
                first.next = second; second.next = first;
                first.value = globalThis.URL;
                second[unknownKey] = globalThis.Location;
                consume(first);"#,
        ];

        for source in sources {
            let expected = analyze_source(source, Some("shared.js")).expect("standalone analysis");
            let allocator = Allocator::default();
            let parsed = parse_javascript_analysis_program(&allocator, source, Some("shared.js"))
                .expect("parse source");
            let parser_partial = !parsed.errors.is_empty();
            let prepared = prepare_state(&parsed, ResolutionMode::Import);
            let (_, prepared) =
                analyze_source_with_prepared_state(source, Some("shared.js"), &parsed, prepared);
            drop(parsed);
            let ControlFlow::Continue(Ok(actual)) =
                analyze_prepared_source_with_checkpoint(parser_partial, prepared, || {
                    ControlFlow::<()>::Continue(())
                })
            else {
                panic!("shared analysis did not complete");
            };

            assert_eq!(
                serde_json::to_value(actual).expect("serialize shared IR"),
                serde_json::to_value(expected).expect("serialize standalone IR"),
                "static inspection changed semantic output for {source}",
            );
        }
    }

    #[test]
    fn source_analysis_honors_every_cancellation_checkpoint() {
        let source = "let value = 1; value = 2; export function read() { return value; }";
        let mut checkpoint_count = 0;
        let completed = analyze_source_with_checkpoint(source, Some("cancel.js"), || {
            checkpoint_count += 1;
            ControlFlow::<usize>::Continue(())
        });
        assert!(matches!(completed, ControlFlow::Continue(Ok(_))));
        assert!(checkpoint_count > 2);

        for stop_at in 1..=checkpoint_count {
            let mut observed = 0;
            let cancelled = analyze_source_with_checkpoint(source, Some("cancel.js"), || {
                observed += 1;
                if observed == stop_at {
                    ControlFlow::Break(stop_at)
                } else {
                    ControlFlow::Continue(())
                }
            });
            assert!(matches!(cancelled, ControlFlow::Break(checkpoint) if checkpoint == stop_at));
            assert_eq!(observed, stop_at);
        }
    }
}
