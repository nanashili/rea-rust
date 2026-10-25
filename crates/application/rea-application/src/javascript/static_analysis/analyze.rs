//! Production static-source orchestrator.
//!
//! The individual inspectors in this directory are deliberately small.  This
//! module owns their ordering, the single parsed AST, semantic binding proof,
//! UTF-16 locations, and conversion to the public static-analysis contract.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::ops::ControlFlow;

use oxc_allocator::Allocator;

use crate::javascript::ast::{AstContext, AstVisitor, Field, Node, traverse};
use crate::javascript::contracts::static_analysis::{
    BrowserWindow, ContextBridgeApi, ElectronFindings, EndpointKind, IpcFinding,
    NativeAddonBinding, OptionsStatus, ParseStatus, PathContext, StaticAnalysis, StaticEndpoint,
    StaticValue, UtilityProcess,
};
use crate::javascript::parser::{
    JavaScriptParseOutcome, ModuleReferenceKind, RawDiagnostic, parse_javascript_analysis_program,
    parse_javascript_source,
};
use crate::javascript::semantic::ambient_writes::index_ambient_writes;
use crate::javascript::semantic::definitions::collect_definitions;
use crate::javascript::semantic::member_mutations::collect_semantic_member_mutations;
use crate::javascript::semantic::module_interop::StateFacts;
use crate::javascript::semantic::module_interop::create_module_interop;
use crate::javascript::semantic::mutation_initializers::semantic_binding_at_read;
use crate::javascript::semantic::mutation_initializers::{EffectTiming, effect_timing};
use crate::javascript::semantic::property_paths::PropertyPathKey;
use crate::javascript::semantic::state::{DeclarationKind, ResolutionMode};

use super::super::semantic::ast_values::{StaticObjectProperty, static_object_property, unwrapped};
use super::bundler::{
    inspect_bundler_bootstrap, inspect_bundler_registration, inspect_esbuild_wrapper,
};
use super::bundler_calls::collect_runtime_references;
use super::calls::{self, collect_calls};
use super::electron_browser::browser_window_shape_with_resolver;
use super::electron_context_bridge::{ExposureWorld, exposure_arguments, members_for_exposure};
use super::electron_ipc::{IpcMode, ipc_descriptor};
use super::electron_native::{binding_access, is_commonjs_export_assignment, required_addon};
use super::electron_paths::collect_electron_wrapped_call_paths;
use super::electron_sender;
use super::electron_values::{electron_callee_path, electron_static_value, handler_kind};
use super::finalize::{attribute_modules, finalize_limitations};
use super::graphql::GraphqlScan;
use super::helpers::{self, registration_key, sorted_unique};
use super::rpc::{is_rpc_client_factory, link_endpoint, procedure_endpoint};
use super::semantics::StaticSemantics;
use super::state::StaticAccumulator;
use crate::javascript::semantic::identity_writes::{electron_export_path, is_electron_module};
use crate::javascript::semantic::require_origin::require_origin;
use crate::javascript::semantic::state::ProjectionKey;
use crate::javascript::semantic::value_types::{JsString, Primitive};

/// Analyze one parsed source without replaying a TypeScript oracle.
pub fn analyze_source(
    source: &str,
    path: Option<&str>,
) -> Result<StaticAnalysis, Vec<RawDiagnostic>> {
    let allocator = Allocator::default();
    let parsed = parse_javascript_analysis_program(&allocator, source, path)?;
    let parser_error_count = parsed.errors.len();
    let context = AstContext::new(parsed.program);
    // Babel counts its synthetic `File` wrapper in `visitedNodes`; Oxc starts
    // at `Program`.  Account for that contract node without polluting the
    // semantic traversal with a fabricated AST node.
    let (nodes, visited_ast_nodes) = collect_nodes(context.root(), source);

    let state = match collect_definitions(context, ResolutionMode::Import, || {
        ControlFlow::<()>::Continue(())
    }) {
        ControlFlow::Continue(state) => state,
        ControlFlow::Break(()) => unreachable!("non-cancelling definition pass"),
    };

    // Ambient writes are always needed by the inspectors. The broader member
    // mutation index is populated below only when a deferred consumer exists;
    // that keeps unrelated returned-reference analysis out of ordinary files.
    let mut state = state;
    index_ambient_writes(&mut state);
    let electron_exports = index_electron_exports(&state, &nodes);
    let needs_member_mutation_facts = calls::requires_member_mutation_facts(&state, &nodes)
        || requires_electron_browser_window_mutation_facts(&state, &nodes, &electron_exports);
    if needs_member_mutation_facts {
        collect_semantic_member_mutations(&mut state);
    }
    let semantics = StateFacts::new(&state);
    let mut accumulator = StaticAccumulator::new(source.encode_utf16().count());
    for node in &nodes {
        if node.babel_type() == "CallExpression" || node.babel_type() == "OptionalCallExpression" {
            inspect_bundler_bootstrap(&state.context, node, &mut accumulator, &semantics);
            inspect_bundler_registration(&state.context, node, &mut accumulator, &semantics);
            inspect_esbuild_wrapper(&state.context, node, &mut accumulator, &semantics);
        }
    }

    let factory_require_binding_ids = accumulator
        .factory_require_binding_ids
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let mut calls = collect_calls(&state, &nodes, &factory_require_binding_ids);
    append_rpc_endpoints(&state.context, &nodes, &mut calls.endpoints);
    let runtime_references =
        collect_runtime_references(&state, &nodes, &accumulator.factory_require_binding_ids);
    calls.unknown_findings += runtime_references
        .iter()
        .filter(|reference| reference.specifier.is_none())
        .count() as u64;
    calls.references.extend(runtime_references);
    let (mut type_only_by_specifier, type_only_import_equals, uncertain_type_only_side_effect) =
        match parse_javascript_source(source, path) {
            JavaScriptParseOutcome::Parsed { facts } => {
                let uncertain = facts.uncertain_type_only_side_effect;
                let mut type_only = HashMap::<String, VecDeque<bool>>::new();
                let mut type_only_import_equals = HashSet::new();
                for reference in facts.module_references {
                    match reference.kind {
                        ModuleReferenceKind::StaticImport | ModuleReferenceKind::ReExport => {
                            let Some(specifier) = reference.specifier else {
                                continue;
                            };
                            type_only
                                .entry(specifier)
                                .or_default()
                                .push_back(reference.type_only);
                        }
                        ModuleReferenceKind::ImportEquals if reference.type_only => {
                            type_only_import_equals.insert((
                                reference.range.start.line,
                                reference.range.start.column,
                                reference.range.end.line,
                                reference.range.end.column,
                            ));
                        }
                        _ => {}
                    }
                }
                (type_only, type_only_import_equals, uncertain)
            }
            JavaScriptParseOutcome::Fatal { .. } => (HashMap::new(), HashSet::new(), false),
        };
    calls.references.retain(|reference| {
        if matches!(
            reference.kind,
            crate::javascript::contracts::static_analysis::ReferenceKind::Require
        ) && type_only_import_equals.contains(&(
            reference.location.start.line,
            reference.location.start.column,
            reference.location.end.line,
            reference.location.end.column,
        )) {
            return false;
        }
        if !matches!(
            reference.kind,
            crate::javascript::contracts::static_analysis::ReferenceKind::StaticImport
        ) {
            return true;
        }
        let Some(specifier) = reference.specifier.as_ref().and_then(JsString::as_str) else {
            return true;
        };
        type_only_by_specifier
            .get_mut(specifier)
            .and_then(VecDeque::pop_front)
            .is_none_or(|type_only| !type_only)
    });
    // The Oxc AST is the owner of static-import locations.  The secondary
    // parser is only used to identify type-only side effects; comparing its
    // coordinates against Babel-style ranges drops valid imports from TS
    // sources.  Keep AST imports and retain the uncertainty as a limitation.
    accumulator.unknown_findings = accumulator
        .unknown_findings
        .saturating_add(calls.unknown_findings);

    let mut graphql = GraphqlScan::new(&state.context, &semantics);
    for node in &nodes {
        if let Some(operation) = graphql.inspect(node) {
            calls.endpoints.push(StaticEndpoint {
                module_key: None,
                location: helpers::range(&state.context, node),
                kind: EndpointKind::Network,
                value: JsString::from(operation.value),
                mechanism: operation.mechanism,
                interpretation: None,
                resolution: None,
                module_runtime: None,
            });
        }
    }
    for finding in graphql.finish() {
        calls.endpoints.push(StaticEndpoint {
            module_key: None,
            location: helpers::range(&state.context, &finding.node),
            kind: EndpointKind::Network,
            value: JsString::from(finding.operation.value),
            mechanism: finding.operation.mechanism,
            interpretation: None,
            resolution: None,
            module_runtime: None,
        });
    }
    let has_electron_reference = calls.references.iter().any(|reference| {
        reference
            .specifier
            .as_ref()
            .and_then(JsString::as_str)
            .is_some_and(super::super::semantic::identity_writes::is_electron_module)
    });
    let mut electron = ElectronCollector::new(
        &state.context,
        &electron_exports,
        &mut accumulator.unknown_findings,
        &semantics,
        &state,
    );
    for node in &nodes {
        electron.inspect(*node);

        if node.babel_type() != "VariableDeclarator" {
            if node.babel_type() != "AssignmentExpression" {
                continue;
            }
            let Some(left) = node.field(source, Field::Left) else {
                continue;
            };
            let Some(right) = node.field(source, Field::Right) else {
                continue;
            };
            if !is_commonjs_export_assignment(&state.context, left) {
                continue;
            }
            let Some((specifier, access)) = required_addon(&state.context, right) else {
                continue;
            };
            electron.native_addon_bindings.push(NativeAddonBinding {
                module_key: None,
                location: helpers::range(&state.context, node),
                specifier: JsString::from(specifier),
                binding_kind: "re-export".to_owned(),
                module_kind: "require".to_owned(),
                members: access.members.into_iter().map(JsString::from).collect(),
                namespace_access: Some(access.namespace_access),
                dynamic_member_access: Some(access.dynamic_member_access),
                module_runtime: None,
            });
            continue;
        }
        let Some((specifier, access)) = node
            .field(source, Field::Init)
            .and_then(|init| required_addon(&state.context, init))
        else {
            continue;
        };
        let pattern_access = node
            .field(source, Field::Id)
            .map(|id| binding_access(&state.context, id))
            .unwrap_or(access);
        electron.native_addon_bindings.push(NativeAddonBinding {
            module_key: None,
            location: helpers::range(&state.context, node),
            specifier: JsString::from(specifier),
            binding_kind: "require".to_owned(),
            module_kind: "require".to_owned(),
            members: pattern_access
                .members
                .into_iter()
                .map(JsString::from)
                .collect(),
            namespace_access: Some(pattern_access.namespace_access),
            dynamic_member_access: Some(pattern_access.dynamic_member_access),
            module_runtime: None,
        });
    }
    let mut electron_findings = electron.finish();
    let wrapped = collect_electron_wrapped_call_paths(
        &state.context,
        &nodes,
        &electron_exports,
        &state,
        &mut accumulator.unknown_findings,
    );
    if !wrapped.paths.is_empty() {
        electron_findings.call_paths = Some(wrapped.paths);
    }
    for location in wrapped.context_bridge_replacements {
        for finding in &mut electron_findings.context_bridge_apis {
            if finding.location.start == location {
                finding.resolution_basis = Some("wrapper-substitution".to_owned());
            }
        }
    }
    let unknown_findings = accumulator.unknown_findings;
    let has_electron_call_paths = electron_findings
        .call_paths
        .as_ref()
        .is_some_and(|paths| !paths.is_empty());
    let calls::CallFindings {
        references,
        endpoints,
        storage,
        role_paths,
        source_map_urls,
        unknown_findings: _,
    } = calls;
    let mut analysis = StaticAnalysis {
        parse_status: ParseStatus::Complete,
        parse_error_count: parser_error_count as u64,
        visited_ast_nodes,
        references,
        endpoints,
        storage,
        bundler_registrations: sorted_unique(&accumulator.registrations, registration_key),
        role_paths,
        source_map_urls,
        vendors: helpers::detect_vendors(source)
            .into_iter()
            .map(str::to_owned)
            .collect(),
        electron: electron_findings,
        limitations: Vec::new(),
    };
    attribute_modules(&mut analysis, source, &accumulator.module_range_index);
    finalize_limitations(
        &mut analysis,
        parser_error_count,
        unknown_findings,
        !state.returned_reference_widenings.borrow().is_empty(),
        has_electron_call_paths,
        false,
        uncertain_type_only_side_effect,
        has_electron_reference,
    );
    Ok(analysis)
}

fn append_rpc_endpoints(
    context: &crate::javascript::ast::AstContext<'_>,
    nodes: &[Node<'_>],
    endpoints: &mut Vec<StaticEndpoint>,
) {
    let source = context.source();
    let mut client_roots = BTreeSet::new();

    for node in nodes {
        if node.babel_type() != "VariableDeclarator" {
            continue;
        }
        let Some(identifier) = node
            .field(source, Field::Id)
            .filter(|id| id.babel_type() == "Identifier")
        else {
            continue;
        };
        let Some(initializer) = node.field(source, Field::Init) else {
            continue;
        };
        if is_rpc_client_factory(context, initializer) {
            if let Some(name) = identifier.identifier_name() {
                client_roots.insert(name.to_owned());
            }
        }
    }

    let has_marker = source.contains("createTRPCClient")
        || source.contains("createTRPCProxyClient")
        || source.contains("httpBatchLink");
    for node in nodes {
        if let Some(endpoint) = link_endpoint(context, *node) {
            endpoints.push(StaticEndpoint {
                module_key: None,
                location: helpers::range(context, node),
                kind: EndpointKind::Network,
                value: JsString::from(endpoint.value),
                mechanism: endpoint.mechanism,
                interpretation: None,
                resolution: None,
                module_runtime: None,
            });
            continue;
        }
        let Some(endpoint) = procedure_endpoint(context, *node, &client_roots, has_marker) else {
            continue;
        };
        endpoints.push(StaticEndpoint {
            module_key: None,
            location: helpers::range(context, node),
            kind: EndpointKind::Network,
            value: JsString::from(endpoint.value),
            mechanism: endpoint.mechanism,
            interpretation: None,
            resolution: None,
            module_runtime: None,
        });
    }
}

fn collect_nodes<'ast>(root: Node<'ast>, source: &'ast str) -> (Vec<Node<'ast>>, u64) {
    let mut nodes = Vec::new();
    let mut collector = CollectNodes { nodes: &mut nodes };
    let _: ControlFlow<()> = traverse(root, source, &mut collector, || ControlFlow::Continue(()));
    let count = nodes.len() as u64 + 1;
    (nodes, count)
}

/// Index proven Electron aliases by the source position of their identifier.
///
/// The collector deliberately uses the semantic binding origin rather than
/// matching a familiar local name.  This covers Electron subpath imports and
/// default interop while retaining the source path used by the public
/// contract.  Unresolved or dynamic origins remain absent and therefore
/// unknown to downstream inspectors.
fn index_electron_exports<'a>(
    state: &crate::javascript::semantic::state::SemanticState<'a>,
    nodes: &[Node<'a>],
) -> HashMap<u32, Vec<String>> {
    let mut exports = HashMap::new();
    let mut interop = create_module_interop(state);

    for node in nodes {
        let Some(name) = node.identifier_name() else {
            continue;
        };
        let Some(index) = state.resolve_binding(node, name) else {
            continue;
        };
        let (binding_id, has_member_writes) = {
            let binding = state.binding(index);
            (
                binding.binding_id.clone(),
                !binding.member_writes.is_empty(),
            )
        };
        // A captured Electron namespace is only unusable when a member write
        // replaces part of the namespace.  Passing the namespace through a
        // call records an escape, but that does not replace the lexical
        // module identity; the TypeScript identity index keeps those aliases
        // available and reports uncertainty at the affected member instead.
        if has_member_writes {
            continue;
        }
        let origin = interop
            .origin(&binding_id)
            .map(|origin| (origin.specifier, origin.imported_path))
            .or_else(|| electron_binding_origin(state, index));
        let Some((specifier, imported_path)) = origin else {
            continue;
        };

        let path = electron_export_path(
            &imported_path
                .iter()
                .filter_map(JsString::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>(),
        )
        .to_vec();
        if is_electron_module(specifier.as_str().unwrap_or_default()) {
            exports.insert(state.context.start(node), path);
        }
    }

    exports
}

fn electron_binding_origin<'a>(
    state: &crate::javascript::semantic::state::SemanticState<'a>,
    index: crate::javascript::semantic::state::BindingIndex,
) -> Option<(JsString, Vec<JsString>)> {
    let binding = state.binding(index);
    if let Some(origin) = binding
        .direct_origins
        .iter()
        .find(|origin| is_electron_module(origin.specifier.as_str().unwrap_or_default()))
    {
        return Some((origin.specifier.clone(), origin.imported_path.clone()));
    }

    let initializer = state.stable_initializer(index)?;
    let initializer_projection = initializer.projection.clone();
    let origin = require_origin(state, Some(initializer.node))?.origin;
    let mut imported_path = origin.imported_path;
    for projection in initializer_projection {
        let ProjectionKey::Name(name) = projection else {
            return None;
        };
        imported_path.push(name);
    }
    Some((origin.specifier, imported_path))
}

struct CollectNodes<'nodes, 'ast> {
    nodes: &'nodes mut Vec<Node<'ast>>,
}
impl<'nodes, 'ast> AstVisitor<'ast> for CollectNodes<'nodes, 'ast> {
    fn enter(&mut self, node: &Node<'ast>, _: Option<&Node<'ast>>, _: &[Node<'ast>]) {
        self.nodes.push(*node);
    }
}

fn electron_member_path(mut path: Vec<String>) -> Vec<String> {
    if path.first().is_some_and(|segment| segment == "electron") {
        path.remove(0);
    }
    path
}

fn requires_electron_browser_window_mutation_facts<'a>(
    state: &crate::javascript::semantic::state::SemanticState<'a>,
    nodes: &[Node<'a>],
    exports: &HashMap<u32, Vec<String>>,
) -> bool {
    nodes.iter().copied().any(|node| {
        if node.babel_type() != "NewExpression" {
            return false;
        }
        let Some(callee) = node.field(state.source, Field::Callee) else {
            return false;
        };
        let Some(path) = electron_callee_path(&state.context, callee, exports) else {
            return false;
        };
        if electron_member_path(path) != ["BrowserWindow"] {
            return false;
        }
        let Some(options) = node
            .field_list(state.source, Field::Arguments)
            .first()
            .copied()
            .flatten()
        else {
            return false;
        };
        let options = unwrapped(state.source, options);
        if has_electron_option_object_candidate(state, options) {
            return true;
        }
        let StaticObjectProperty::Explicit(property) =
            static_object_property(state.source, Some(options), "webPreferences", None)
        else {
            return false;
        };
        property
            .field(state.source, Field::Value)
            .map(|value| unwrapped(state.source, value))
            .is_some_and(|value| has_electron_option_object_candidate(state, value))
    })
}

/// Match the TypeScript option-object candidate used by deferred BrowserWindow
/// inspection. A lexical identifier alone is insufficient: it must resolve
/// through const, non-projected, definitely initialized bindings to an object.
fn has_electron_option_object_candidate<'a>(
    state: &crate::javascript::semantic::state::SemanticState<'a>,
    input: Node<'a>,
) -> bool {
    let mut node = unwrapped(state.source, input);
    let mut seen = HashSet::new();

    while let Some(name) = node.identifier_name() {
        let Some(binding_index) = state.resolve_binding(&node, name) else {
            return false;
        };
        if !seen.insert(binding_index) {
            return false;
        }
        let binding = state.binding(binding_index);
        if binding.mutable
            || binding.declaration_kinds.len() != 1
            || binding.declaration_kinds.first() != Some(&DeclarationKind::Const)
        {
            return false;
        }
        let Some(initializer) = state.stable_initializer(binding_index) else {
            return false;
        };
        if !initializer.projection.is_empty()
            || !semantic_binding_at_read(binding, node, &state.parents, state.source)
                .has_definite_initializer
        {
            return false;
        }
        node = unwrapped(state.source, initializer.node);
    }

    node.babel_type() == "ObjectExpression"
}

fn stable_option_alias<'a>(
    semantics: &dyn StaticSemantics<'a>,
    node: Node<'a>,
) -> Option<Node<'a>> {
    let binding = semantics.binding(&node)?;
    let initializer = semantics.stable_initializer(&binding.binding_id)?;
    (initializer.projection_len == 0).then_some(initializer.node)
}

/// Resolve an options identifier only while its object value is still valid at
/// this constructor read.  A stable initializer alone is insufficient: a
/// later member write such as `options.webPreferences = dynamicOptions` must
/// widen the second read while leaving the earlier constructor precise.
fn stable_option_alias_at_read<'a>(
    state: &crate::javascript::semantic::state::SemanticState<'a>,
    semantics: &dyn StaticSemantics<'a>,
    node: Node<'a>,
) -> Option<Node<'a>> {
    let resolved = stable_option_alias(semantics, node)?;
    let name = node.identifier_name()?;
    let binding_index = state.resolve_binding(&node, name)?;
    let binding = state.binding(binding_index);

    let has_prior_mutation = binding
        .member_writes
        .iter()
        .chain(binding.escaped_paths.iter())
        .any(|effect| {
            effect.node.is_none_or(|write| {
                effect_timing(node, Some(write), state, state.source) != EffectTiming::After
            }) && effect.path.first().is_none_or(|key| {
                matches!(key, PropertyPathKey::String(_) | PropertyPathKey::Wildcard)
            })
        });
    (!has_prior_mutation).then_some(resolved)
}

fn browser_option_resolution_sources<'a>(
    context: &AstContext<'a>,
    original_options: Option<Node<'a>>,
    resolved_options: Option<Node<'a>>,
    semantics: &dyn StaticSemantics<'a>,
) -> Option<Vec<crate::javascript::contracts::static_analysis::SourceRange>> {
    let mut sources = Vec::new();
    if let (Some(original), Some(resolved)) = (original_options, resolved_options)
        && (context.start(&original) != context.start(&resolved)
            || context.end(&original) != context.end(&resolved))
    {
        sources.push(helpers::range(context, &resolved));
    }

    let Some(options) = resolved_options.map(|node| unwrapped(context.source(), node)) else {
        return (!sources.is_empty()).then_some(sources);
    };
    let StaticObjectProperty::Explicit(property) =
        static_object_property(context.source(), Some(options), "webPreferences", None)
    else {
        return (!sources.is_empty()).then_some(sources);
    };
    let Some(declared) = property
        .field(context.source(), Field::Value)
        .map(|value| unwrapped(context.source(), value))
    else {
        return (!sources.is_empty()).then_some(sources);
    };
    let resolved = stable_option_alias(semantics, declared).unwrap_or(declared);
    if context.start(&declared) != context.start(&resolved)
        || context.end(&declared) != context.end(&resolved)
    {
        sources.push(helpers::range(context, &resolved));
    }
    (!sources.is_empty()).then_some(sources)
}

struct ElectronCollector<'ast, 'borrow> {
    context: &'borrow AstContext<'ast>,
    exports: &'borrow HashMap<u32, Vec<String>>,
    unknown_findings: &'borrow mut u64,
    semantics: &'borrow dyn StaticSemantics<'ast>,
    state: &'borrow crate::javascript::semantic::state::SemanticState<'ast>,
    browser_windows: Vec<BrowserWindow>,
    context_bridge_apis: Vec<ContextBridgeApi>,
    ipc: Vec<IpcFinding>,
    native_addon_bindings: Vec<NativeAddonBinding>,
    sender_validations: Vec<crate::javascript::contracts::static_analysis::SenderValidation>,
    utility_processes: Vec<UtilityProcess>,
}
impl<'ast, 'borrow> ElectronCollector<'ast, 'borrow> {
    fn new(
        context: &'borrow AstContext<'ast>,
        exports: &'borrow HashMap<u32, Vec<String>>,
        unknown_findings: &'borrow mut u64,
        semantics: &'borrow dyn StaticSemantics<'ast>,
        state: &'borrow crate::javascript::semantic::state::SemanticState<'ast>,
    ) -> Self {
        Self {
            context,
            exports,
            unknown_findings,
            semantics,
            state,
            browser_windows: Vec::new(),
            context_bridge_apis: Vec::new(),
            ipc: Vec::new(),
            native_addon_bindings: Vec::new(),
            sender_validations: Vec::new(),
            utility_processes: Vec::new(),
        }
    }
    fn inspect(&mut self, node: Node<'ast>) {
        electron_sender::inspect(
            self.context,
            node,
            &mut self.sender_validations,
            self.unknown_findings,
        );
        let source = self.context.source();
        if node.babel_type() == "NewExpression" {
            if let Some(callee) = node.field(source, Field::Callee)
                && electron_callee_path(self.context, callee, self.exports)
                    .map(electron_member_path)
                    .is_some_and(|p| p == ["BrowserWindow"])
            {
                let options = node
                    .field_list(source, Field::Arguments)
                    .into_iter()
                    .next()
                    .flatten();
                let resolved_options = options
                    .and_then(|candidate| {
                        stable_option_alias_at_read(self.state, self.semantics, candidate)
                    })
                    .or(options);
                let resolution_sources = browser_option_resolution_sources(
                    self.context,
                    options,
                    resolved_options,
                    self.semantics,
                );
                if let Some(shape) = browser_window_shape_with_resolver(
                    self.context,
                    node,
                    resolved_options,
                    &|candidate| stable_option_alias_at_read(self.state, self.semantics, candidate),
                ) {
                    *self.unknown_findings =
                        (*self.unknown_findings).saturating_add(shape.options.unknown);
                    let preload = shape.preload;
                    let mut web_preferences = shape.options.web_preferences;
                    if let Some(preload) = preload.as_ref() {
                        if let Some(preference) = web_preferences
                            .iter_mut()
                            .rev()
                            .find(|preference| preference.name == "preload")
                        {
                            preference.value = StaticValue {
                                status: "literal".to_owned(),
                                value: Primitive::String(preload.clone()),
                                expression: None,
                            };
                        }
                    }
                    self.browser_windows.push(BrowserWindow {
                        module_key: None,
                        location: helpers::range(self.context, &node),
                        options_status: shape.options.status,
                        web_preferences_status: shape.options.web_preferences_status,
                        web_preferences,
                        resolution_sources,
                        preload_path: preload,
                        preload_resolution_context: shape
                            .preload_resolution_context
                            .map(|context| match context {
                                super::helpers::StaticPathContext::ModuleSpecifier => {
                                    crate::javascript::contracts::static_analysis::PathContext::ModuleSpecifier
                                }
                                super::helpers::StaticPathContext::FilesystemExpression => {
                                    crate::javascript::contracts::static_analysis::PathContext::FilesystemExpression
                                }
                            }),
                        module_runtime: None,
                    });
                }
            }
        }
        if !matches!(
            node.babel_type(),
            "CallExpression" | "OptionalCallExpression"
        ) {
            return;
        }
        let Some(callee) = node.field(source, Field::Callee) else {
            return;
        };
        let Some(path) = electron_callee_path(self.context, callee, self.exports) else {
            return;
        };
        let path = electron_member_path(path);
        if path.len() == 2 && path[0] == "contextBridge" {
            if let Some(args) = exposure_arguments(self.context, &path[1], node) {
                let key = electron_static_value(self.context, args.api_key);
                let (status, members, unknown) = members_for_exposure(self.context, args.api);
                let key_is_unknown = u64::from(key.status == "dynamic");
                let world_is_unknown = u64::from(
                    args.world_id
                        .as_ref()
                        .is_some_and(|world_id| world_id.status == "dynamic"),
                );
                *self.unknown_findings = (*self.unknown_findings)
                    .saturating_add(key_is_unknown)
                    .saturating_add(world_is_unknown)
                    .saturating_add(unknown);
                self.context_bridge_apis.push(ContextBridgeApi {
                    module_key: None,
                    location: helpers::range(self.context, &node),
                    world: match args.world {
                        ExposureWorld::Main => "main".to_owned(),
                        ExposureWorld::Isolated => "isolated".to_owned(),
                    },
                    world_id: args.world_id,
                    api_status: match status.as_str() {
                        "object-literal" => OptionsStatus::ObjectLiteral,
                        "missing" => OptionsStatus::Missing,
                        _ => OptionsStatus::Dynamic,
                    },
                    members,
                    unknown_members: unknown,
                    api_key: (key.status == "literal")
                        .then(|| match key.value {
                            Primitive::String(value) => value,
                            _ => JsString::new_const(),
                        })
                        .filter(|value| !value.is_empty()),
                    api_key_expression: key.expression,
                    module_runtime: None,
                    resolution_basis: None,
                });
            }
        }
        if path == ["utilityProcess", "fork"] {
            self.inspect_utility_process(node);
        }
        if let Some(descriptor) = ipc_descriptor(&path) {
            let value = electron_static_value(
                self.context,
                node.field_list(source, Field::Arguments)
                    .into_iter()
                    .next()
                    .flatten(),
            );
            let literal = if value.status == "literal" {
                if let Primitive::String(s) = value.value {
                    Some(s)
                } else {
                    None
                }
            } else {
                None
            };
            let handler = node
                .field_list(source, Field::Arguments)
                .into_iter()
                .nth(1)
                .flatten();
            let handler_is_missing =
                matches!(descriptor.mode, IpcMode::Listen | IpcMode::Handle) && handler.is_none();
            if literal.is_none() || handler_is_missing {
                *self.unknown_findings = (*self.unknown_findings).saturating_add(1);
            }
            self.ipc.push(IpcFinding {
                module_key: None,
                location: helpers::range(self.context, &node),
                side: descriptor.side.to_owned(),
                operation: descriptor.operation.to_owned(),
                mode: format!("{:?}", descriptor.mode).to_lowercase(),
                handler_kind: matches!(descriptor.mode, IpcMode::Listen | IpcMode::Handle)
                    .then(|| handler_kind(handler).to_owned()),
                handler_location: handler.map(|node| helpers::range(self.context, &node)),
                channel: literal,
                channel_expression: value.expression,
                module_runtime: None,
                resolution_basis: None,
                invocation_location: None,
            });
        }
    }

    fn inspect_utility_process(&mut self, node: Node<'ast>) {
        let source = self.context.source();
        let arguments = node.field_list(source, Field::Arguments);
        let module_node = arguments.first().copied().flatten();
        let module_path = module_node.and_then(|node| helpers::static_path(self.context, node));
        let options = arguments.get(2).copied().flatten();
        let service_name_property = static_object_property(
            source,
            options.map(|node| unwrapped(source, node)),
            "serviceName",
            None,
        );
        let service_name = match service_name_property {
            StaticObjectProperty::Explicit(property) => property
                .field(source, Field::Value)
                .and_then(|value| helpers::static_path(self.context, value)),
            StaticObjectProperty::Missing | StaticObjectProperty::Dynamic => None,
        };
        let service_name_is_unknown =
            !matches!(service_name_property, StaticObjectProperty::Missing)
                && service_name.is_none();
        if service_name_is_unknown {
            *self.unknown_findings += 1;
        }
        if module_path.is_none() {
            *self.unknown_findings += 1;
        }
        let module_expression = module_path
            .is_none()
            .then(|| super::electron_values::bounded_expression(self.context, module_node));
        let module_resolution_context = module_node.filter(|_| module_path.is_some()).map(|node| {
            match helpers::static_path_resolution_context(self.context, node) {
                super::helpers::StaticPathContext::ModuleSpecifier => PathContext::ModuleSpecifier,
                super::helpers::StaticPathContext::FilesystemExpression => {
                    PathContext::FilesystemExpression
                }
            }
        });
        self.utility_processes.push(UtilityProcess {
            module_key: None,
            location: helpers::range(self.context, &node),
            service_name,
            module_path,
            module_resolution_context,
            module_expression,
            module_runtime: None,
        });
    }

    fn finish(self) -> ElectronFindings {
        ElectronFindings {
            call_paths: None,
            browser_windows: self.browser_windows,
            context_bridge_apis: self.context_bridge_apis,
            ipc: self.ipc,
            sender_validations: self.sender_validations,
            utility_processes: self.utility_processes,
            native_addon_bindings: self.native_addon_bindings,
        }
    }
}
