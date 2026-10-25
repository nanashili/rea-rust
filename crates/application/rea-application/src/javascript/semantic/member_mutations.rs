//! Source-owned member mutation collection.
//!
//! This pass records effects at the binding that owns the receiver. It keeps
//! traversal and mutation ownership here; value interpretation remains in
//! `values`, and cache invalidation is performed immediately after a retained
//! effect.

use std::collections::{HashMap, HashSet};

use crate::javascript::ast::{AstVisitor, Field, Node, NodeKey, traverse};

use super::ast_values::{
    is_class, is_function, object_pattern_keys, static_property_key, unwrapped, write_site_target,
    write_targets,
};
use super::iteration_sources::{SemanticIterationSource, semantic_iteration_sources};
use super::map_operations::{MapReferenceMutationIndex, is_intrinsic_map_lookup};
use super::mutation_initializers::mutation_initializers;
use super::mutation_initializers::{EffectTiming, effect_timing};
use super::opaque_effects::{OpaqueEffects, index_opaque_effects};
use super::property_paths::{
    PropertyPath, PropertyPathKey, PropertySelection, SemanticPropertyPathCoverage,
    semantic_array_index_units, semantic_property_path_key_matches,
};
use super::reference_sources::{
    ReferenceSource, SemanticExpressionEvaluator, semantic_reference_sources_inactive,
};
use super::returned_references::create_semantic_returned_references;
use super::state::{
    BindingIndex, DefinitionKind, Initializer, MemberEffect, ProjectionKey, ReferenceInitializer,
    RequiredModuleEffect, RequiredModuleEffectKind, SemanticState,
};
use super::value_types::{Coverage, JsString, Primitive, SemanticValue};
use super::values::{
    clear_semantic_value_caches, evaluate_semantic_binding,
    evaluate_semantic_binding_with_opaque_effects, evaluate_semantic_expression,
    evaluate_semantic_expression_with_opaque_effects,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MemberMutationKind {
    Write,
    Escape,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ActiveTraversalKey {
    node: NodeKey,
    effect: MemberMutationKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ActiveBindingKey {
    binding: BindingIndex,
    effect: MemberMutationKind,
}

impl MemberMutationKind {
    fn is_write(self) -> bool {
        matches!(self, Self::Write)
    }
}

/// Collect source-local member writes and reference escapes.
pub fn collect_semantic_member_mutations<'a>(state: &mut SemanticState<'a>) {
    let mut collector = Collector::new(state);
    let program = collector.state.program;
    let source = collector.state.source;
    let _ = traverse(program, source, &mut collector, || {
        std::ops::ControlFlow::<()>::Continue(())
    });

    collector.replay_deferred_work();

    clear_semantic_value_caches(collector.state);
}

struct Collector<'s, 'a> {
    state: &'s mut SemanticState<'a>,
    coverage: HashMap<String, SemanticPropertyPathCoverage>,
    active_traversals: HashMap<ActiveTraversalKey, PropertyPath>,
    active_bindings: HashMap<ActiveBindingKey, PropertyPath>,
    opaque_effects: OpaqueEffects<'a>,
    deferred_iteration_sources: Vec<SemanticIterationSource<'a>>,
    sources_deferred: bool,
    deferred_references: Vec<DeferredReference<'a>>,
    deferred_iterables: Vec<DeferredIterable<'a>>,
    map_receivers: Vec<Node<'a>>,
    array_iteration_unknown: bool,
    unknown_binding_values: HashMap<BindingIndex, bool>,
}

impl<'s, 'a> Collector<'s, 'a> {
    fn new(state: &'s mut SemanticState<'a>) -> Self {
        let opaque_effects = index_opaque_effects(state);
        Self {
            state,
            coverage: HashMap::new(),
            active_traversals: HashMap::new(),
            active_bindings: HashMap::new(),
            opaque_effects,
            deferred_iteration_sources: Vec::new(),
            sources_deferred: false,
            deferred_references: Vec::new(),
            deferred_iterables: Vec::new(),
            map_receivers: Vec::new(),
            array_iteration_unknown: false,
            unknown_binding_values: HashMap::new(),
        }
    }

    fn replay_deferred_work(&mut self) {
        let mut previous_effects = self.effect_count();
        loop {
            let before = self.effect_count();
            let queued_before = self.deferred_references.len() + self.deferred_iterables.len();
            let iteration_before = self.array_iteration_unknown;
            if !self.sources_deferred {
                let sources = self.deferred_iteration_sources.clone();
                for source in &sources {
                    self.defer_iteration_source(source);
                }
                self.sources_deferred = true;
            }

            self.replay_deferred_references();
            self.replay_deferred_iterables();
            self.replay_map_receivers();

            let after = self.effect_count();
            let queued_after = self.deferred_references.len() + self.deferred_iterables.len();
            if after == before
                && after == previous_effects
                && queued_after == queued_before
                && self.array_iteration_unknown == iteration_before
            {
                break;
            }
            previous_effects = after;
        }
    }

    fn effect_count(&self) -> usize {
        self.state
            .bindings
            .iter()
            .map(|binding| binding.member_writes.len() + binding.escaped_paths.len())
            .sum::<usize>()
            + self
                .state
                .required_module_effects
                .iter()
                .map(|(_, effects)| effects.len())
                .sum::<usize>()
    }

    fn defer_iteration_source(&mut self, source: &SemanticIterationSource<'a>) {
        let root_projection = if source.projection.is_empty()
            && source.kind == super::iteration_sources::IterationSourceKind::Iteration
        {
            for_of_array_rest_start(self.state, source.mutation)
                .map(|index| vec![PropertyPathKey::String(JsString::from(index.to_string()))])
                .unwrap_or_default()
        } else {
            source.projection.clone()
        };
        self.deferred_iterables.push(DeferredIterable {
            node: source.node,
            projection: root_projection.clone(),
            path: root_projection.clone(),
            fallback_path: root_projection,
            required_sources: source.required_sources.clone(),
            fallback_sources: source.fallback_sources.clone(),
            effect: MemberMutationKind::Escape,
            mutation: Some(source.mutation),
            origin_at: Some(source.mutation),
            widened_getter_result: false,
            iteration_only: source.kind == super::iteration_sources::IterationSourceKind::Iteration,
        });
    }

    fn replay_deferred_iterables(&mut self) {
        let deferred = std::mem::take(&mut self.deferred_iterables);
        for iterable in deferred {
            let required_sources = iterable
                .required_sources
                .iter()
                .map(|source| ReferenceSource {
                    node: source.node,
                    projection: source.projection.clone(),
                })
                .collect::<Vec<_>>();
            let fallback_sources = iterable
                .fallback_sources
                .iter()
                .map(|source| ReferenceSource {
                    node: source.node,
                    projection: source.projection.clone(),
                })
                .collect::<Vec<_>>();
            let mut evaluator = ExpressionEvaluator;
            if semantic_reference_sources_inactive(
                &required_sources,
                &fallback_sources,
                self.state,
                &mut evaluator,
            ) {
                self.deferred_iterables.push(iterable);
                continue;
            }

            if iterable.iteration_only
                && iterable.projection.first() == Some(&PropertyPathKey::Wildcard)
                && let Some(mutation) = iterable.mutation
                && mutation.babel_type() == "ForOfStatement"
                && let Some(right) = mutation.field(self.state.source, Field::Right)
                && let SemanticValue::Array {
                    items,
                    coverage: Coverage::Exact,
                } = evaluate_semantic_expression(right, self.state, Some(mutation))
                && items
                    .iter()
                    .all(|item| semantic_array_index_units(&item.name).is_some())
            {
                for item in items {
                    let Some(index) = semantic_array_index_units(&item.name) else {
                        continue;
                    };
                    let mut selected = iterable.clone();
                    selected.projection[0] = PropertyPathKey::Number(index);
                    selected.path[0] = PropertyPathKey::Number(index);
                    selected.fallback_path[0] = PropertyPathKey::Number(index);
                    selected.iteration_only = false;
                    self.deferred_iterables.push(selected);
                }
                continue;
            }

            let known_array = !self.array_iteration_unknown
                && is_known_array_projection(
                    self.state,
                    iterable.node,
                    &iterable.projection,
                    iterable.mutation,
                    &self.opaque_effects,
                );
            if known_array && iterable.iteration_only && !iterable.projection.is_empty() {
                continue;
            }

            let (path, effect) = if known_array {
                (iterable.path, iterable.effect)
            } else {
                (iterable.fallback_path, MemberMutationKind::Escape)
            };

            self.mark_value_at(
                iterable.node,
                path,
                effect,
                iterable.mutation,
                iterable.origin_at,
                iterable.widened_getter_result,
            );
        }
    }

    fn replay_deferred_references(&mut self) {
        let deferred = std::mem::take(&mut self.deferred_references);
        for reference in deferred {
            let required_sources = reference
                .initializer
                .required_sources
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|initializer| ReferenceSource {
                    node: initializer.node,
                    projection: projection_path(&initializer.projection),
                })
                .collect::<Vec<_>>();
            let fallback_sources = reference
                .initializer
                .fallback_sources
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|initializer| ReferenceSource {
                    node: initializer.node,
                    projection: projection_path(&initializer.projection),
                })
                .collect::<Vec<_>>();
            let mut evaluator = ExpressionEvaluator;
            if semantic_reference_sources_inactive(
                &required_sources,
                &fallback_sources,
                self.state,
                &mut evaluator,
            ) {
                self.deferred_references.push(reference);
                continue;
            }

            if reference.initializer.node.babel_type() == "ForOfStatement"
                && let Some(iterable) = reference
                    .initializer
                    .node
                    .field(self.state.source, Field::Right)
            {
                if for_of_object_rest_owns_property(
                    self.state.source,
                    reference.initializer.node,
                    &reference.path,
                ) || object_rest_owns_property(&reference.initializer, &reference.path)
                {
                    continue;
                }

                if reference.initializer.copy_kind == Some(super::state::CopyKind::ArrayRest)
                    && matches!(reference.path.first(), Some(PropertyPathKey::Selection(_)))
                {
                    let mut rest_path = vec![PropertyPathKey::Wildcard];
                    rest_path.extend(array_rest_source_path(
                        &reference.initializer,
                        &reference.path,
                    ));
                    self.mark_value_at(
                        iterable,
                        rest_path,
                        reference.effect,
                        reference.mutation,
                        reference.origin_at,
                        reference.widened_getter_result,
                    );
                    continue;
                }
                let mut path = vec![PropertyPathKey::Wildcard];
                path.extend(array_rest_source_path(
                    &reference.initializer,
                    &reference.path,
                ));
                let required_sources = reference
                    .initializer
                    .required_sources
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .map(
                        |initializer| super::iteration_sources::IterationSourceValue {
                            node: initializer.node,
                            projection: projection_path(&initializer.projection),
                        },
                    )
                    .collect();
                let fallback_sources = reference
                    .initializer
                    .fallback_sources
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .map(
                        |initializer| super::iteration_sources::IterationSourceValue {
                            node: initializer.node,
                            projection: projection_path(&initializer.projection),
                        },
                    )
                    .collect();
                self.deferred_iterables.push(DeferredIterable {
                    node: iterable,
                    projection: vec![PropertyPathKey::Wildcard],
                    path,
                    fallback_path: Vec::new(),
                    required_sources,
                    fallback_sources,
                    effect: reference.effect,
                    mutation: reference.mutation,
                    origin_at: Some(reference.initializer.node),
                    widened_getter_result: false,
                    iteration_only: false,
                });
                continue;
            }

            if reference.initializer.copy_kind == Some(super::state::CopyKind::ArrayRest)
                && reference.initializer.copy_projection_offset.is_some()
            {
                let offset = reference
                    .initializer
                    .copy_projection_offset
                    .unwrap_or_default();
                let projection = projection_path(&reference.initializer.projection[..offset]);
                let required_sources = reference
                    .initializer
                    .required_sources
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .map(
                        |initializer| super::iteration_sources::IterationSourceValue {
                            node: initializer.node,
                            projection: projection_path(&initializer.projection),
                        },
                    )
                    .collect();
                let fallback_sources = reference
                    .initializer
                    .fallback_sources
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .map(
                        |initializer| super::iteration_sources::IterationSourceValue {
                            node: initializer.node,
                            projection: projection_path(&initializer.projection),
                        },
                    )
                    .collect();
                self.deferred_iterables.push(DeferredIterable {
                    node: reference.initializer.node,
                    projection: projection.clone(),
                    path: reference.path,
                    fallback_path: projection,
                    required_sources,
                    fallback_sources,
                    effect: reference.effect,
                    mutation: reference.mutation,
                    origin_at: reference.origin_at,
                    widened_getter_result: reference.widened_getter_result,
                    iteration_only: false,
                });
                continue;
            }

            self.mark_value_at(
                reference.initializer.node,
                reference.path,
                reference.effect,
                reference.mutation,
                reference.origin_at,
                reference.widened_getter_result,
            );
        }
    }

    fn replay_map_receivers(&mut self) {
        let receivers = self.map_receivers.clone();
        for call in receivers {
            let Some(callee) = call.field(self.state.source, Field::Callee) else {
                continue;
            };
            let callee = unwrapped(self.state.source, callee);
            let Some(receiver) = callee.field(self.state.source, Field::Object) else {
                continue;
            };
            if is_intrinsic_map_lookup(call, self.state, &self.opaque_effects, Some(self))
                == Some(false)
                && receiver_is_known_value(self.state, receiver)
                && let Some(receiver) = callee.field(self.state.source, Field::Object)
            {
                self.mark_value(receiver, Vec::new(), MemberMutationKind::Escape, Some(call));
            }
        }
    }

    fn mark_target(&mut self, site: Node<'a>) {
        let Some(root) = write_site_target(self.state.source, &site) else {
            return;
        };
        for target in write_targets(self.state.source, root) {
            if target.babel_type() == "Identifier" {
                continue;
            }
            let Some(object) = target.field(self.state.source, Field::Object) else {
                continue;
            };
            let path = vec![property_key(self.state.source, target)];
            self.mark_value(object, path, MemberMutationKind::Write, Some(site));
        }
    }

    fn mark_call(&mut self, call: Node<'a>) {
        self.mark_returned_references(call);

        for argument in call.field_list(self.state.source, Field::Arguments) {
            let Some(argument) = argument else { continue };
            if argument.babel_type() == "SpreadElement" {
                if let Some(value) = argument.field(self.state.source, Field::Argument) {
                    self.deferred_iterables.push(DeferredIterable {
                        node: value,
                        projection: Vec::new(),
                        path: vec![PropertyPathKey::Wildcard],
                        fallback_path: Vec::new(),
                        required_sources: Vec::new(),
                        fallback_sources: Vec::new(),
                        effect: MemberMutationKind::Escape,
                        mutation: Some(call),
                        origin_at: Some(call),
                        widened_getter_result: false,
                        iteration_only: false,
                    });
                }
            } else {
                self.mark_value(argument, Vec::new(), MemberMutationKind::Escape, Some(call));
            }
        }

        let Some(callee) = call.field(self.state.source, Field::Callee) else {
            return;
        };
        let callee = unwrapped(self.state.source, callee);
        if !matches!(call.babel_type(), "NewExpression")
            && matches!(
                callee.babel_type(),
                "MemberExpression" | "OptionalMemberExpression"
            )
            && let Some(receiver) = callee.field(self.state.source, Field::Object)
        {
            self.map_receivers.push(call);
            match is_intrinsic_map_lookup(call, self.state, &self.opaque_effects, Some(self)) {
                Some(false) if receiver_is_known_value(self.state, receiver) => {
                    self.mark_value(receiver, Vec::new(), MemberMutationKind::Escape, Some(call))
                }
                Some(false) => {}
                Some(true) | None => {}
            }
        }
    }

    fn mark_returned_references(&mut self, call: Node<'a>) {
        let Some(callee) = call.field(self.state.source, Field::Callee) else {
            return;
        };
        let callee = unwrapped(self.state.source, callee);
        let returned_references = {
            let mut resolver = create_semantic_returned_references(self.state);
            resolver(callee).references
        };
        for result in returned_references {
            self.mark_value(
                result.node,
                result.projection,
                MemberMutationKind::Escape,
                Some(call),
            );
        }
    }

    fn mark_value(
        &mut self,
        node: Node<'a>,
        path: PropertyPath,
        effect: MemberMutationKind,
        mutation: Option<Node<'a>>,
    ) {
        self.mark_value_at(node, path, effect, mutation, mutation, false);
    }

    fn mark_value_at(
        &mut self,
        node: Node<'a>,
        path: PropertyPath,
        effect: MemberMutationKind,
        mutation: Option<Node<'a>>,
        origin_at: Option<Node<'a>>,
        widened_getter_result: bool,
    ) {
        let node = unwrapped(self.state.source, node);
        let active_key = ActiveTraversalKey {
            node: node.key(),
            effect,
        };

        // A recursive binding can keep extending `path`, so a path-inclusive
        // key never recognizes that the same semantic value is already active.
        // The node/effect pair identifies the active semantic expansion while
        // still allowing the node to be revisited after this branch completes.
        let previous_path = self.active_traversals.get(&active_key).cloned();
        if let Some(previous_path) = previous_path {
            self.record_dynamic_cycle_effect(node, &path, &previous_path, mutation);
            return;
        }

        self.active_traversals.insert(active_key, path.clone());

        self.mark_value_at_active(
            node,
            path,
            effect,
            mutation,
            origin_at,
            widened_getter_result,
        );

        self.active_traversals.remove(&active_key);
    }

    fn record_dynamic_cycle_effect(
        &mut self,
        node: Node<'a>,
        path: &[PropertyPathKey],
        previous_path: &[PropertyPathKey],
        mutation: Option<Node<'a>>,
    ) {
        let Some(repeated_prefix) = path.strip_suffix(previous_path) else {
            return;
        };
        if repeated_prefix.is_empty()
            || !repeated_prefix.iter().any(|key| {
                matches!(
                    key,
                    PropertyPathKey::Wildcard | PropertyPathKey::Selection(_)
                )
            })
        {
            return;
        }
        let Some(name) = node.identifier_name() else {
            return;
        };
        let Some(binding) = self.state.resolve_binding(&node, name) else {
            return;
        };
        self.record_effect(
            binding,
            repeated_prefix.to_vec(),
            MemberMutationKind::Escape,
            mutation,
        );
    }

    fn mark_value_at_active(
        &mut self,
        node: Node<'a>,
        path: PropertyPath,
        effect: MemberMutationKind,
        mutation: Option<Node<'a>>,
        origin_at: Option<Node<'a>>,
        widened_getter_result: bool,
    ) {
        self.note_array_iteration_unknown(node, &path);

        if let Some(process_path) = global_process_path(self.state, node, &path) {
            self.record_required_effect(
                &JsString::from("node:process"),
                process_path,
                effect,
                mutation,
            );
            return;
        }

        if node.babel_type() == "Identifier"
            && let Some(name) = node.identifier_name()
            && let Some(binding) = self.state.resolve_binding(&node, name)
        {
            let binding_key = ActiveBindingKey { binding, effect };
            let previous_binding_path = self.active_bindings.get(&binding_key).cloned();
            if let Some(previous_binding_path) = previous_binding_path {
                self.record_dynamic_cycle_effect(node, &path, &previous_binding_path, mutation);
                return;
            }

            self.active_bindings.insert(binding_key, path.clone());

            let next_path = path.clone();
            let owns_unknown_callable =
                effect.is_escape() && is_unknown_callable_source(self.state, node);
            if !owns_unknown_callable {
                self.record_effect(binding, path, effect, mutation);
            }
            let direct_origins = self.state.binding(binding).direct_origins.clone();
            if let Some(module_path) = concrete_module_path(&next_path) {
                for origin in &direct_origins {
                    if let Some((specifier, origin_path)) =
                        super::require_origin::mutable_builtin_origin(origin, &module_path)
                    {
                        let path = origin_path
                            .into_iter()
                            .map(PropertyPathKey::String)
                            .collect();
                        self.record_required_effect(&specifier, path, effect, mutation);
                    }
                }
            }
            let origins = self.origins(binding, origin_at.or(mutation));
            let initializers = origins.initializers;
            for initializer in initializers {
                let mut projected = projection_path(&initializer.projection);
                projected.extend(next_path.clone());
                self.mark_value_at(
                    initializer.node,
                    projected,
                    effect,
                    mutation,
                    Some(initializer.node),
                    widened_getter_result,
                );
            }
            for initializer in origins.reference_initializers {
                let Some(projected) = reference_projection(&initializer, &next_path, effect) else {
                    continue;
                };
                self.deferred_references.push(DeferredReference {
                    initializer,
                    path: projected,
                    effect,
                    mutation,
                    origin_at,
                    widened_getter_result,
                });
            }
            self.active_bindings.remove(&binding_key);
            return;
        }

        if let Some(origin) = super::require_origin::require_origin(self.state, Some(node)) {
            let mut origin_path = origin
                .origin
                .imported_path
                .into_iter()
                .map(PropertyPathKey::String)
                .collect::<PropertyPath>();
            origin_path.extend(path);
            self.record_required_effect(&origin.origin.specifier, origin_path, effect, mutation);
            return;
        }

        match node.babel_type() {
            "MemberExpression" | "OptionalMemberExpression" => {
                if let Some(object) = node.field(self.state.source, Field::Object) {
                    let mut projected = vec![property_key(self.state.source, node)];
                    projected.extend(path);
                    self.mark_value(object, projected, effect, mutation);
                }
            }
            "ObjectExpression" => {
                if effect.is_write() && path.len() < 2 {
                    return;
                }
                let path = if path.is_empty()
                    && node
                        .field_list(self.state.source, Field::Properties)
                        .into_iter()
                        .flatten()
                        .any(|property| property.babel_type() == "SpreadElement")
                {
                    vec![PropertyPathKey::Selection(PropertySelection {
                        excluded_keys: Vec::new(),
                        start_index: None,
                    })]
                } else {
                    path
                };
                for reference in super::object_references::semantic_object_property_references(
                    &*self.state,
                    node,
                    path,
                ) {
                    let next_effect = if reference.escapes || reference.widened_getter_result {
                        MemberMutationKind::Escape
                    } else {
                        effect
                    };
                    self.mark_value(reference.node, reference.path, next_effect, mutation);
                }
            }
            "ArrayExpression" => {
                if (path.first() == Some(&PropertyPathKey::String("__proto__".into()))
                    && (effect.is_escape() || path.len() > 1))
                    || (path.first() == Some(&PropertyPathKey::String("constructor".into()))
                        && path.get(1) == Some(&PropertyPathKey::String("prototype".into())))
                {
                    self.array_iteration_unknown = true;
                }
                if effect.is_write() && path.len() < 2 {
                    return;
                }
                for reference in array_property_references(self.state.source, node, path) {
                    let next_effect = if reference.escapes
                        || reference.widened_getter_result
                        || widened_getter_result
                    {
                        MemberMutationKind::Escape
                    } else {
                        effect
                    };
                    self.mark_value(reference.node, reference.path, next_effect, mutation);
                }
            }
            _ if is_function(&node) && matches!(effect, MemberMutationKind::Escape) => {
                let returned_references = {
                    let mut resolver = create_semantic_returned_references(self.state);
                    resolver(node).references
                };
                for result in returned_references {
                    let mut result_path = result.projection;
                    if result_path.is_empty() {
                        result_path = path.clone();
                    }
                    self.mark_value(result.node, result_path, effect, mutation);
                }
            }
            "ClassDeclaration" | "ClassExpression" | "NewExpression" => {
                self.mark_constructed_value(node, path, effect, mutation, widened_getter_result);
            }
            "AssignmentExpression" => {
                if matches!(node.operator(), Some("||=") | Some("&&=") | Some("??="))
                    && let Some(left) = node.field(self.state.source, Field::Left)
                {
                    self.mark_value(left, path.clone(), effect, mutation);
                }
                if let Some(right) = node.field(self.state.source, Field::Right) {
                    self.mark_value(right, path, effect, mutation);
                }
            }
            "CallExpression" | "OptionalCallExpression" => {
                for value in map_lookup_values(self.state, node) {
                    self.mark_value(value, path.clone(), effect, mutation);
                }
            }
            "ConditionalExpression" => {
                for field in [Field::Consequent, Field::Alternate] {
                    if let Some(value) = node.field(self.state.source, field) {
                        self.mark_value(value, path.clone(), effect, mutation);
                    }
                }
            }
            "LogicalExpression" => {
                for field in [Field::Left, Field::Right] {
                    if let Some(value) = node.field(self.state.source, field) {
                        self.mark_value(value, path.clone(), effect, mutation);
                    }
                }
            }
            "AwaitExpression" => {
                if let Some(value) = node.field(self.state.source, Field::Argument) {
                    self.mark_value(value, path, effect, mutation);
                }
            }
            "SequenceExpression" => {
                if let Some(value) = node
                    .field_list(self.state.source, Field::Expressions)
                    .into_iter()
                    .flatten()
                    .last()
                {
                    self.mark_value(value, path, effect, mutation);
                }
            }
            "ForOfStatement" => {
                if !path.is_empty()
                    && let Some(iterable) = node.field(self.state.source, Field::Right)
                {
                    let mut iterable_path = vec![PropertyPathKey::Wildcard];
                    iterable_path.extend(path);
                    self.deferred_iterables.push(DeferredIterable {
                        node: iterable,
                        projection: Vec::new(),
                        path: iterable_path,
                        fallback_path: Vec::new(),
                        required_sources: Vec::new(),
                        fallback_sources: Vec::new(),
                        effect,
                        mutation,
                        origin_at,
                        widened_getter_result,
                        iteration_only: false,
                    });
                }
            }
            _ => {}
        }
    }

    fn note_array_iteration_unknown(&mut self, node: Node<'a>, path: &[PropertyPathKey]) {
        let Some(name) = node.identifier_name() else {
            return;
        };
        if self.state.resolve_binding(&node, name).is_some() {
            return;
        }
        if name == "Array"
            && matches!(
                path.first(),
                Some(PropertyPathKey::String(value)) if value == "prototype"
            )
        {
            self.array_iteration_unknown = true;
        }
        if matches!(name, "globalThis" | "global" | "window" | "self")
            && matches!(
                path.first(),
                Some(PropertyPathKey::String(value)) if value == "Array"
            )
            && matches!(
                path.get(1),
                Some(PropertyPathKey::String(value)) if value == "prototype"
            )
        {
            self.array_iteration_unknown = true;
        }
    }

    fn origins(&self, binding: BindingIndex, mutation: Option<Node<'a>>) -> BindingOrigins<'a> {
        let selected = mutation.map(|node| {
            mutation_initializers(
                self.state.binding(binding),
                node,
                &self.state.parents,
                self.state.source,
            )
        });
        let source = selected
            .as_ref()
            .unwrap_or_else(|| self.state.binding(binding));
        BindingOrigins {
            initializers: source.initializers.clone(),
            reference_initializers: source.reference_initializers.clone(),
        }
    }

    fn mark_constructed_value(
        &mut self,
        node: Node<'a>,
        mut path: PropertyPath,
        effect: MemberMutationKind,
        mutation: Option<Node<'a>>,
        widened_getter_result: bool,
    ) {
        if path.is_empty() && widened_getter_result {
            path.push(PropertyPathKey::Wildcard);
        }
        let Some(key) = path.first().cloned() else {
            return;
        };
        if matches!(effect, MemberMutationKind::Write) && path.len() == 1 {
            return;
        }
        let owners = if is_class(&node) {
            vec![node]
        } else {
            node.field(self.state.source, Field::Callee)
                .map(|callee| {
                    super::object_references::semantic_class_candidates(&*self.state, callee)
                })
                .unwrap_or_default()
        };
        let remaining = path.into_iter().skip(1).collect::<PropertyPath>();
        for owner in owners {
            let mut projected = vec![key.clone()];
            projected.extend(remaining.clone());
            for reference in super::object_references::semantic_class_property_references(
                &*self.state,
                owner,
                owner,
                projected,
            ) {
                let next_effect = if reference.widened_getter_result || widened_getter_result {
                    MemberMutationKind::Escape
                } else {
                    effect
                };
                self.mark_value(reference.node, reference.path, next_effect, mutation);
            }
        }
    }

    fn record_effect(
        &mut self,
        binding: BindingIndex,
        path: PropertyPath,
        effect: MemberMutationKind,
        node: Option<Node<'a>>,
    ) {
        let binding_state = self.state.binding(binding);
        let has_no_source = binding_state.initializers.is_empty()
            && binding_state.reference_initializers.is_empty();
        let can_receive_caller_value = effect.is_write()
            && matches!(
                binding_state.kind,
                DefinitionKind::Parameter | DefinitionKind::Catch
            );
        if has_no_source && !can_receive_caller_value {
            return;
        }
        if is_object_rest_source_write(self.state, node, &path, effect) {
            return;
        }
        if is_known_object_rest_loop_escape(self.state, node, &path, effect, &self.opaque_effects) {
            return;
        }
        if is_known_for_of_loop_escape(self.state, node, &path, effect, &self.opaque_effects) {
            return;
        }
        let binding_id = self.state.binding(binding).binding_id.clone();
        let mutation_identity = node
            .map(|mutation| format!(":{}:{}", mutation.span().start, mutation.span().end))
            .unwrap_or_default();
        let coverage_key = format!("{binding_id}:{effect:?}{mutation_identity}");

        let path = normalize_iterated_array_path(self.state, node, path, effect);
        let path = normalize_array_rest_escape_path(self.state, node, path, effect);
        let mut path = self.normalize_unknown_write_path(binding, path, effect);
        if effect.is_write()
            && node.is_none_or(|mutation| {
                !(mutation.babel_type() == "UnaryExpression"
                    && mutation.operator() == Some("delete"))
            })
            && let Some(receiver) = local_setter_receiver(self.state, binding, &path, node)
        {
            path = receiver
                .into_iter()
                .map(PropertyPathKey::String)
                .chain(std::iter::once(PropertyPathKey::Wildcard))
                .collect();
        }
        if !self.coverage.entry(coverage_key).or_default().retain(&path) {
            return;
        }

        let primitive_write = if effect.is_write() {
            let binding_state = self.state.binding(binding);
            path.is_empty()
                && binding_state.member_writes.is_empty()
                && matches!(
                    evaluate_semantic_binding(binding_state, &*self.state),
                    SemanticValue::Literal { .. } | SemanticValue::Union { .. }
                )
        } else {
            false
        };
        if primitive_write {
            return;
        }

        // Exact nested writes and escaped child paths preserve the container
        // shape. Empty paths and wildcard writes can invalidate the whole
        // value, so allow the next normalization to re-evaluate it.
        let invalidates_cached_binding_value = path.is_empty()
            || (effect.is_write() && matches!(path.first(), Some(PropertyPathKey::Wildcard)));

        let target = &mut self.state.bindings[binding];
        let member_effect = MemberEffect { path, node };
        if effect.is_write() {
            target.member_writes.push(member_effect);
        } else if member_effect.path.is_empty()
            && target
                .escaped_paths
                .iter()
                .all(|existing| existing.path.is_empty())
        {
            let insertion_index = target
                .escaped_paths
                .iter()
                .position(|existing| effect_start(existing.node) > effect_start(member_effect.node))
                .unwrap_or(target.escaped_paths.len());
            target.escaped_paths.insert(insertion_index, member_effect);
        } else {
            target.escaped_paths.push(member_effect);
        }

        if invalidates_cached_binding_value {
            self.unknown_binding_values.remove(&binding);
        }
        clear_semantic_value_caches(&*self.state);
    }

    fn normalize_unknown_write_path(
        &mut self,
        binding: BindingIndex,
        path: PropertyPath,
        effect: MemberMutationKind,
    ) -> PropertyPath {
        if !effect.is_write() || path.is_empty() {
            return path;
        }
        let has_new_expression_initializer =
            self.state
                .binding(binding)
                .initializers
                .iter()
                .any(|initializer| {
                    unwrapped(self.state.source, initializer.node).babel_type() == "NewExpression"
                });
        if has_new_expression_initializer {
            return path;
        }
        let has_external_origin = {
            let binding_state = self.state.binding(binding);
            !binding_state.reference_initializers.is_empty()
                || !binding_state.direct_origins.is_empty()
                || binding_state.initializers.iter().any(|initializer| {
                    super::require_origin::require_origin(self.state, Some(initializer.node))
                        .is_some()
                })
        };
        if has_external_origin {
            return path;
        }
        let binding_is_unknown = if let Some(value) = self.unknown_binding_values.get(&binding) {
            *value
        } else {
            let is_unknown = {
                let binding_state = self.state.binding(binding);
                matches!(
                    evaluate_semantic_binding_with_opaque_effects(
                        binding_state,
                        &*self.state,
                        &self.opaque_effects,
                    ),
                    SemanticValue::Unknown { .. }
                )
            };
            self.unknown_binding_values.insert(binding, is_unknown);
            is_unknown
        };
        if binding_is_unknown {
            return vec![PropertyPathKey::Wildcard];
        }

        // Exact writes to a missing slot remain exact. The mutation value owner
        // records that slot as unknown coverage, including nested paths; widening
        // here would incorrectly invalidate every sibling property.
        path
    }

    fn record_required_effect(
        &mut self,
        specifier: &JsString,
        path: PropertyPath,
        effect: MemberMutationKind,
        node: Option<Node<'a>>,
    ) {
        let (specifier, path) = match concrete_module_path(&path) {
            Some(module_path) => {
                let (specifier, normalized) =
                    super::require_origin::require_exports_identity(specifier, &module_path);
                (
                    specifier,
                    normalized
                        .into_iter()
                        .map(PropertyPathKey::String)
                        .collect(),
                )
            }
            None => (specifier.clone(), path),
        };
        if effect.is_escape() && is_known_process_slot(&specifier, &path) {
            return;
        }
        let path = widen_unknown_process_path(&specifier, path);
        let effects = self.state.required_module_effects.entry_or(&specifier);
        let kind = match effect {
            MemberMutationKind::Write => RequiredModuleEffectKind::Write,
            MemberMutationKind::Escape => RequiredModuleEffectKind::Escape,
        };
        let duplicate = effects.iter().any(|existing| {
            existing.path == path
                && existing.node.map(|value| value.key()) == node.map(|value| value.key())
                && existing.kind == kind
        });
        if !duplicate {
            effects.push(RequiredModuleEffect { path, node, kind });
        }
    }
}

fn effect_start(node: Option<Node<'_>>) -> u32 {
    node.map_or(u32::MAX, |node| node.span().start)
}

fn normalize_iterated_array_path<'a>(
    state: &SemanticState<'a>,
    mutation: Option<Node<'a>>,
    path: PropertyPath,
    effect: MemberMutationKind,
) -> PropertyPath {
    if !effect.is_write() || path.first() != Some(&PropertyPathKey::Wildcard) {
        return path;
    }
    let Some(PropertyPathKey::String(name)) = path.get(1) else {
        return path;
    };
    let Some(index) = semantic_array_index_units(name) else {
        return path;
    };
    let start = mutation
        .and_then(|mutation| array_rest_start_in_ancestor(state, mutation))
        .unwrap_or_default();
    let mut normalized = path;
    normalized[1] = PropertyPathKey::Number(index.saturating_add(start));
    normalized
}

fn array_rest_start_in_ancestor<'a>(
    state: &SemanticState<'a>,
    mutation: Node<'a>,
) -> Option<usize> {
    let mut current = mutation;
    while let Some(parent) = state.parents.get(&current.key()).copied() {
        if parent.babel_type() == "ForOfStatement" {
            let left = parent.field(state.source, Field::Left)?;
            let pattern = if left.babel_type() == "VariableDeclaration" {
                left.field_list(state.source, Field::Declarations)
                    .into_iter()
                    .flatten()
                    .next()?
                    .field(state.source, Field::Id)?
            } else {
                left
            };
            if pattern.babel_type() != "ArrayPattern" {
                return None;
            }
            return pattern
                .field_list(state.source, Field::Elements)
                .into_iter()
                .enumerate()
                .find_map(|(index, element)| {
                    element
                        .filter(|element| element.babel_type() == "RestElement")
                        .map(|_| index)
                });
        }
        current = parent;
    }
    None
}

fn for_of_array_rest_start<'a>(state: &SemanticState<'a>, mutation: Node<'a>) -> Option<usize> {
    if mutation.babel_type() != "ForOfStatement" {
        return None;
    }
    let left = mutation.field(state.source, Field::Left)?;
    let pattern = if left.babel_type() == "VariableDeclaration" {
        left.field_list(state.source, Field::Declarations)
            .into_iter()
            .flatten()
            .next()?
            .field(state.source, Field::Id)?
    } else {
        left
    };
    if pattern.babel_type() != "ArrayPattern" {
        return None;
    }
    pattern
        .field_list(state.source, Field::Elements)
        .into_iter()
        .enumerate()
        .find_map(|(index, element)| {
            element
                .filter(|element| element.babel_type() == "RestElement")
                .map(|_| index)
        })
}

fn is_object_rest_source_write<'a>(
    state: &SemanticState<'a>,
    mutation: Option<Node<'a>>,
    path: &[PropertyPathKey],
    effect: MemberMutationKind,
) -> bool {
    if !effect.is_write() || path.first() != Some(&PropertyPathKey::Wildcard) {
        return false;
    }
    let Some(PropertyPathKey::String(property)) = path.get(1) else {
        return false;
    };
    let Some(mut current) = mutation else {
        return false;
    };
    while let Some(parent) = state.parents.get(&current.key()).copied() {
        if parent.babel_type() == "ForOfStatement" {
            let Some(left) = parent.field(state.source, Field::Left) else {
                return false;
            };
            let pattern = if left.babel_type() == "VariableDeclaration" {
                left.field_list(state.source, Field::Declarations)
                    .into_iter()
                    .flatten()
                    .find_map(|declaration| declaration.field(state.source, Field::Id))
            } else {
                Some(left)
            };
            let Some(pattern) = pattern else {
                return false;
            };
            return pattern.babel_type() == "ObjectPattern"
                && pattern
                    .field_list(state.source, Field::Properties)
                    .into_iter()
                    .flatten()
                    .any(|property| property.babel_type() == "RestElement")
                && !object_pattern_keys(state.source, &pattern)
                    .iter()
                    .any(|key| key == property);
        }
        current = parent;
    }
    false
}

fn is_known_object_rest_loop_escape<'a>(
    state: &SemanticState<'a>,
    mutation: Option<Node<'a>>,
    path: &[PropertyPathKey],
    effect: MemberMutationKind,
    opaque: &OpaqueEffects<'a>,
) -> bool {
    if !effect.is_escape() || !path.is_empty() {
        return false;
    }
    let Some(mutation) = mutation else {
        return false;
    };
    if mutation.babel_type() != "ForOfStatement" {
        return false;
    }
    let Some(left) = mutation.field(state.source, Field::Left) else {
        return false;
    };
    let pattern = if left.babel_type() == "VariableDeclaration" {
        left.field_list(state.source, Field::Declarations)
            .into_iter()
            .flatten()
            .find_map(|declaration| declaration.field(state.source, Field::Id))
    } else {
        Some(left)
    };
    let Some(pattern) = pattern else {
        return false;
    };
    if pattern.babel_type() != "ObjectPattern"
        || !pattern
            .field_list(state.source, Field::Properties)
            .into_iter()
            .flatten()
            .any(|property| property.babel_type() == "RestElement")
    {
        return false;
    }
    let Some(right) = mutation.field(state.source, Field::Right) else {
        return false;
    };
    matches!(
        evaluate_semantic_expression_with_opaque_effects(right, state, Some(mutation), opaque),
        SemanticValue::Array {
            coverage: Coverage::Exact,
            ..
        }
    )
}

fn is_known_for_of_loop_escape<'a>(
    state: &SemanticState<'a>,
    mutation: Option<Node<'a>>,
    path: &[PropertyPathKey],
    effect: MemberMutationKind,
    opaque: &OpaqueEffects<'a>,
) -> bool {
    if !effect.is_escape() || !path.is_empty() {
        return false;
    }
    let Some(mutation) = mutation else {
        return false;
    };
    if mutation.babel_type() != "ForOfStatement" {
        return false;
    }
    let Some(left) = mutation.field(state.source, Field::Left) else {
        return false;
    };
    let pattern = if left.babel_type() == "VariableDeclaration" {
        left.field_list(state.source, Field::Declarations)
            .into_iter()
            .flatten()
            .find_map(|declaration| declaration.field(state.source, Field::Id))
    } else {
        Some(left)
    };
    let Some(pattern) = pattern else {
        return false;
    };
    if pattern.babel_type() != "Identifier" {
        return false;
    }
    let Some(right) = mutation.field(state.source, Field::Right) else {
        return false;
    };
    matches!(
        evaluate_semantic_expression_with_opaque_effects(right, state, Some(mutation), opaque),
        SemanticValue::Array {
            coverage: Coverage::Exact,
            ..
        }
    )
}

fn is_array_rest_selected_escape_with_write<'a>(
    state: &SemanticState<'a>,
    mutation: Option<Node<'a>>,
    path: &[PropertyPathKey],
    effect: MemberMutationKind,
) -> bool {
    if !effect.is_escape() || path.len() != 1 {
        return false;
    }
    let Some(first) = path.first() else {
        return false;
    };
    if !matches!(first, PropertyPathKey::Wildcard)
        && !matches!(first, PropertyPathKey::String(index) if semantic_array_index_units(index).is_some())
    {
        return false;
    }
    let Some(mutation) = mutation else {
        return false;
    };
    if mutation.babel_type() != "ForOfStatement" {
        return false;
    }
    let Some(left) = mutation.field(state.source, Field::Left) else {
        return false;
    };
    let pattern = if left.babel_type() == "VariableDeclaration" {
        left.field_list(state.source, Field::Declarations)
            .into_iter()
            .flatten()
            .find_map(|declaration| declaration.field(state.source, Field::Id))
    } else {
        Some(left)
    };
    let Some(pattern) = pattern else {
        return false;
    };
    let Some(rest) = pattern
        .field_list(state.source, Field::Elements)
        .into_iter()
        .flatten()
        .find(|element| element.babel_type() == "RestElement")
        .and_then(|element| element.field(state.source, Field::Argument))
    else {
        return false;
    };
    let Some(name) = rest.identifier_name() else {
        return false;
    };
    let Some(binding) = state.resolve_binding(&rest, name) else {
        return false;
    };
    !state.binding(binding).member_writes.is_empty()
}

fn normalize_array_rest_escape_path<'a>(
    state: &SemanticState<'a>,
    mutation: Option<Node<'a>>,
    path: PropertyPath,
    effect: MemberMutationKind,
) -> PropertyPath {
    if is_array_rest_selected_escape_with_write(state, mutation, &path, effect)
        && (path == [PropertyPathKey::Wildcard]
            || path.iter().all(|key| {
                matches!(key, PropertyPathKey::String(value) if semantic_array_index_units(value).is_some())
            }))
    {
        Vec::new()
    } else {
        path
    }
}

fn is_unknown_callable_source<'a>(state: &SemanticState<'a>, node: Node<'a>) -> bool {
    let node = unwrapped(state.source, node);
    let Some(name) = node.identifier_name() else {
        return false;
    };
    let Some(binding) = state.resolve_binding(&node, name) else {
        return false;
    };
    state
        .stable_initializer(binding)
        .is_some_and(|initializer| {
            let initializer_node = unwrapped(state.source, initializer.node);
            if super::require_origin::require_origin(state, Some(initializer_node)).is_some() {
                return false;
            }
            matches!(
                initializer_node.babel_type(),
                "CallExpression" | "OptionalCallExpression"
            )
        })
}

fn widen_unknown_process_path(specifier: &JsString, path: PropertyPath) -> PropertyPath {
    if specifier != "process" || path.len() != 2 {
        return path;
    }
    let Some(PropertyPathKey::String(container)) = path.first() else {
        return path;
    };
    if container != "env" && container != "argv" {
        return path;
    }
    vec![
        PropertyPathKey::String(container.clone()),
        PropertyPathKey::Wildcard,
    ]
}

impl MemberMutationKind {
    fn is_escape(self) -> bool {
        matches!(self, Self::Escape)
    }
}

/// An escape of an unknown `process.env`/`process.argv` slot exposes the
/// mutable container. Known value slots remain local to the required module.
fn is_known_process_slot(specifier: &JsString, path: &[PropertyPathKey]) -> bool {
    if specifier != "process" || path.len() != 2 {
        return false;
    }
    let PropertyPathKey::String(container) = &path[0] else {
        return false;
    };
    let selected = match &path[1] {
        PropertyPathKey::String(selected) => selected.clone(),
        PropertyPathKey::Number(index) => JsString::from(index.to_string()),
        PropertyPathKey::Wildcard | PropertyPathKey::Selection(_) => return false,
    };
    if container == "argv" {
        return selected == "length" || semantic_array_index_units(&selected).is_some();
    }
    if container != "env" {
        return false;
    }
    ![
        "__defineGetter__",
        "__defineSetter__",
        "__lookupGetter__",
        "__lookupSetter__",
        "__proto__",
        "constructor",
        "hasOwnProperty",
        "isPrototypeOf",
        "propertyIsEnumerable",
        "toLocaleString",
        "toString",
        "valueOf",
    ]
    .into_iter()
    .any(|name| selected == name)
}

fn global_process_path<'a>(
    state: &SemanticState<'a>,
    node: Node<'a>,
    path: &[PropertyPathKey],
) -> Option<PropertyPath> {
    let root = node.identifier_name()?;
    let process_offset = if root == "process" {
        0
    } else if matches!(root, "globalThis" | "global" | "window" | "self")
        && path.first() == Some(&PropertyPathKey::String("process".into()))
    {
        1
    } else {
        return None;
    };
    if state.resolve_binding(&node, root).is_some() || state.resolution_blocked(&node, root) {
        return None;
    }
    let mut writes = state
        .ambient_binding_writes
        .get("process")
        .into_iter()
        .flatten();
    if writes
        .any(|write| effect_timing(node, Some(*write), state, state.source) != EffectTiming::After)
    {
        return None;
    }
    Some(path[process_offset..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string_path(container: &str, selected: &str) -> PropertyPath {
        vec![
            PropertyPathKey::String(container.into()),
            PropertyPathKey::String(selected.into()),
        ]
    }

    #[test]
    fn process_escape_keeps_known_env_and_argv_slots_local() {
        let process = JsString::from("process");
        assert!(is_known_process_slot(
            &process,
            &string_path("env", "APP_MODE")
        ));
        assert!(is_known_process_slot(
            &process,
            &string_path("argv", "length")
        ));
        assert!(is_known_process_slot(&process, &string_path("argv", "0")));
    }

    #[test]
    fn process_escape_widens_prototype_and_unknown_slots() {
        let process = JsString::from("process");
        assert!(!is_known_process_slot(
            &process,
            &string_path("env", "toString")
        ));
        assert!(!is_known_process_slot(
            &process,
            &string_path("argv", "custom")
        ));
    }
}

fn local_setter_receiver<'a>(
    state: &SemanticState<'a>,
    binding: BindingIndex,
    path: &[PropertyPathKey],
    mutation: Option<Node<'a>>,
) -> Option<Vec<JsString>> {
    let PropertyPathKey::String(last_key) = path.last()? else {
        return None;
    };
    let receiver = &path[..path.len().saturating_sub(1)];
    let receiver_names = receiver
        .iter()
        .map(|key| match key {
            PropertyPathKey::String(name) => Some(name.clone()),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    let origins = if let Some(node) = mutation {
        mutation_initializers(state.binding(binding), node, &state.parents, state.source)
            .initializers
    } else {
        state.binding(binding).initializers.clone()
    };

    for initializer in origins {
        if !initializer.projection.is_empty() {
            continue;
        }
        let mut object = unwrapped(state.source, initializer.node);
        for segment in &receiver_names {
            if object.babel_type() != "ObjectExpression" {
                break;
            }
            let next = object
                .field_list(state.source, Field::Properties)
                .into_iter()
                .flatten()
                .rev()
                .find(|property| {
                    let Some(key) = property.field(state.source, Field::Key) else {
                        return false;
                    };
                    property.babel_type() == "ObjectProperty"
                        && static_property_key(state.source, key, property.computed())
                            .is_some_and(|name| name == *segment)
                })
                .and_then(|property| property.field(state.source, Field::Value));
            let Some(next) = next else { break };
            object = unwrapped(state.source, next);
        }
        if object.babel_type() != "ObjectExpression" {
            continue;
        }
        let mut setter = false;
        for property in object
            .field_list(state.source, Field::Properties)
            .into_iter()
            .flatten()
        {
            let Some(key) = property.field(state.source, Field::Key) else {
                continue;
            };
            let matches = static_property_key(state.source, key, property.computed())
                .is_some_and(|name| name == *last_key);
            if !matches {
                continue;
            }
            if property.babel_type() == "ObjectMethod" && property.declaration_kind() == Some("set")
            {
                setter = true;
            } else if property.babel_type() != "SpreadElement" {
                setter = false;
            }
        }
        if setter {
            return Some(receiver_names);
        }
    }
    None
}

struct ExpressionEvaluator;

fn receiver_is_known_value<'a>(state: &SemanticState<'a>, receiver: Node<'a>) -> bool {
    let mut receiver = unwrapped(state.source, receiver);
    let mut seen = HashSet::new();
    loop {
        let Some(name) = receiver.identifier_name() else {
            return true;
        };
        let Some(binding) = state.resolve_binding(&receiver, name) else {
            return false;
        };
        if !seen.insert(binding) {
            return false;
        }
        let Some(initializer) = state.stable_initializer(binding) else {
            return true;
        };
        receiver = unwrapped(state.source, initializer.node);
        if matches!(
            receiver.babel_type(),
            "CallExpression" | "OptionalCallExpression"
        ) {
            return false;
        }
    }
}

fn is_known_array_projection<'a>(
    state: &SemanticState<'a>,
    node: Node<'a>,
    projection: &[PropertyPathKey],
    capture_point: Option<Node<'a>>,
    opaque: &OpaqueEffects<'a>,
) -> bool {
    let value =
        evaluate_semantic_expression_with_opaque_effects(node, state, capture_point, opaque);
    let value = projection.iter().try_fold(value, |value, key| match key {
        PropertyPathKey::String(name) => match value {
            SemanticValue::Object { properties, .. } => properties
                .into_iter()
                .find(|property| property.name == *name)
                .map(|property| property.value),
            _ => None,
        },
        PropertyPathKey::Number(index) => match value {
            SemanticValue::Array { items, .. } => items
                .into_iter()
                .find(|item| item.name == JsString::from(index.to_string()))
                .map(|item| item.value),
            _ => None,
        },
        PropertyPathKey::Wildcard => match value {
            value @ SemanticValue::Array {
                coverage: Coverage::Exact,
                ..
            } => Some(value),
            _ => None,
        },
        PropertyPathKey::Selection(_) => None,
    });
    let Some(value) = value else {
        return false;
    };
    matches!(
        value,
        SemanticValue::Array { ref items, .. }
            if items.iter().all(|item| semantic_array_index_units(&item.name).is_some())
    )
}

impl<'a> SemanticExpressionEvaluator<'a> for ExpressionEvaluator {
    fn evaluate(
        &mut self,
        state: &SemanticState<'a>,
        node: Node<'a>,
        capture_point: Option<Node<'a>>,
    ) -> SemanticValue {
        evaluate_semantic_expression(node, state, capture_point)
    }
}

impl<'a> MapReferenceMutationIndex<'a> for Collector<'_, 'a> {
    fn reference_may_have_changed_at(
        &self,
        site: Node<'a>,
        reference: Node<'a>,
        path: &[&str],
    ) -> bool {
        let Some(name) = reference.identifier_name() else {
            return true;
        };
        let Some(binding) = self.state.resolve_binding(&reference, name) else {
            return true;
        };
        let binding = self.state.binding(binding);
        binding
            .member_writes
            .iter()
            .chain(binding.escaped_paths.iter())
            .any(|effect| effect_path_covers(effect, site, path, self.state))
    }
}

fn effect_path_covers<'a>(
    effect: &MemberEffect<'a>,
    site: Node<'a>,
    path: &[&str],
    state: &SemanticState<'a>,
) -> bool {
    if effect.node.is_some_and(|node| {
        effect_timing(site, Some(node), state, state.source) == EffectTiming::After
    }) {
        return false;
    }
    if effect.path.len() > path.len() {
        return false;
    }
    effect
        .path
        .iter()
        .zip(path.iter())
        .all(|(key, value)| semantic_property_path_key_matches(key, JsString::from(*value)))
}

impl<'a> AstVisitor<'a> for Collector<'_, 'a> {
    fn enter(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>, ancestors: &[Node<'a>]) {
        self.deferred_iteration_sources
            .extend(semantic_iteration_sources(
                self.state.source,
                *node,
                parent.copied(),
            ));
        self.mark_target(*node);
        match node.babel_type() {
            "CallExpression" | "OptionalCallExpression" | "NewExpression" => self.mark_call(*node),
            "TaggedTemplateExpression" => {
                // The tag is visited as the first child.  Its span starts at
                // the tagged expression, whereas the quasi starts later.
            }
            _ => {}
        }
        if parent.is_some_and(|parent| {
            parent.babel_type() == "TaggedTemplateExpression"
                && node.span().start == parent.span().start
        }) {
            if matches!(
                node.babel_type(),
                "MemberExpression" | "OptionalMemberExpression"
            ) && let Some(receiver) = node.field(self.state.source, Field::Object)
            {
                self.mark_value(
                    receiver,
                    Vec::new(),
                    MemberMutationKind::Escape,
                    parent.copied(),
                );
            }
        }

        if parent.is_some_and(|parent| parent.babel_type() == "TemplateLiteral")
            && let Some(tagged_template) = ancestors
                .iter()
                .rev()
                .find(|ancestor| ancestor.babel_type() == "TaggedTemplateExpression")
        {
            self.mark_value(
                *node,
                Vec::new(),
                MemberMutationKind::Escape,
                Some(*tagged_template),
            );
        }
    }
}

struct BindingOrigins<'a> {
    initializers: Vec<Initializer<'a>>,
    reference_initializers: Vec<ReferenceInitializer<'a>>,
}

struct DeferredReference<'a> {
    initializer: ReferenceInitializer<'a>,
    path: PropertyPath,
    effect: MemberMutationKind,
    mutation: Option<Node<'a>>,
    origin_at: Option<Node<'a>>,
    widened_getter_result: bool,
}

#[derive(Clone)]
struct DeferredIterable<'a> {
    node: Node<'a>,
    projection: PropertyPath,
    path: PropertyPath,
    fallback_path: PropertyPath,
    required_sources: Vec<super::iteration_sources::IterationSourceValue<'a>>,
    fallback_sources: Vec<super::iteration_sources::IterationSourceValue<'a>>,
    effect: MemberMutationKind,
    mutation: Option<Node<'a>>,
    origin_at: Option<Node<'a>>,
    widened_getter_result: bool,
    iteration_only: bool,
}

fn projection_path(projection: &[ProjectionKey]) -> PropertyPath {
    projection
        .iter()
        .map(|key| match key {
            ProjectionKey::Name(name) => PropertyPathKey::String(name.clone()),
            ProjectionKey::Index(index) => PropertyPathKey::Number(*index),
            ProjectionKey::Dynamic => PropertyPathKey::Wildcard,
        })
        .collect()
}

fn object_rest_owns_property(
    initializer: &ReferenceInitializer<'_>,
    path: &[PropertyPathKey],
) -> bool {
    if initializer.copy_kind != Some(super::state::CopyKind::ObjectRest) {
        return false;
    }
    let Some(first) = path.first() else {
        return false;
    };
    let excluded = initializer
        .copy_excluded_keys
        .as_deref()
        .unwrap_or_default();
    matches!(first, PropertyPathKey::String(name) if !excluded.iter().any(|key| key == name))
}

fn for_of_object_rest_owns_property(
    source: &str,
    for_of: Node<'_>,
    path: &[PropertyPathKey],
) -> bool {
    let Some(left) = for_of.field(source, Field::Left) else {
        return false;
    };
    let pattern = if left.babel_type() == "VariableDeclaration" {
        left.field_list(source, Field::Declarations)
            .into_iter()
            .flatten()
            .find_map(|declaration| declaration.field(source, Field::Id))
    } else {
        Some(left)
    };
    let Some(pattern) = pattern else {
        return false;
    };
    let Some(first) = path.first() else {
        return false;
    };
    pattern.babel_type() == "ObjectPattern"
        && pattern
            .field_list(source, Field::Properties)
            .into_iter()
            .flatten()
            .any(|property| property.babel_type() == "RestElement")
        && matches!(first, PropertyPathKey::String(name)
            if !object_pattern_keys(source, &pattern).iter().any(|key| key == name))
}

fn array_rest_source_path(
    initializer: &ReferenceInitializer<'_>,
    path: &[PropertyPathKey],
) -> PropertyPath {
    if initializer.copy_kind != Some(super::state::CopyKind::ArrayRest) {
        return path.to_vec();
    }
    let Some(start) = initializer.copy_start_index else {
        return path.to_vec();
    };
    let Some((first, remaining)) = path.split_first() else {
        return path.to_vec();
    };
    let first = match first {
        PropertyPathKey::String(name) => semantic_array_index_units(name)
            .map(|index| PropertyPathKey::Number(index.saturating_add(start)))
            .unwrap_or_else(|| first.clone()),
        PropertyPathKey::Number(index) => PropertyPathKey::Number(index.saturating_add(start)),
        _ => first.clone(),
    };
    std::iter::once(first)
        .chain(remaining.iter().cloned())
        .collect()
}

fn reference_projection(
    initializer: &ReferenceInitializer<'_>,
    path: &[PropertyPathKey],
    effect: MemberMutationKind,
) -> Option<PropertyPath> {
    let Some(offset) = initializer.copy_projection_offset else {
        let mut result = projection_path(&initializer.projection);
        result.extend_from_slice(path);
        return Some(result);
    };
    if offset > initializer.projection.len() {
        return None;
    }
    let mut copied = projection_path(&initializer.projection[offset + 1..]);
    copied.extend_from_slice(path);
    if effect.is_write() && copied.len() < 2 {
        return None;
    }

    let key = copied.first().cloned();
    let (key, remaining) = match initializer.copy_kind {
        Some(super::state::CopyKind::ArrayRest) => {
            let start = initializer.copy_start_index.unwrap_or_default();
            let selected = match key {
                None | Some(PropertyPathKey::Wildcard) => {
                    PropertyPathKey::Selection(PropertySelection {
                        excluded_keys: Vec::new(),
                        start_index: Some(start),
                    })
                }
                Some(PropertyPathKey::Number(index)) => {
                    PropertyPathKey::Number(index.saturating_add(start))
                }
                Some(PropertyPathKey::String(name)) => {
                    let Some(index) = semantic_array_index_units(&name) else {
                        return None;
                    };
                    PropertyPathKey::Number(index.saturating_add(start))
                }
                Some(PropertyPathKey::Selection(selection)) => {
                    PropertyPathKey::Selection(PropertySelection {
                        excluded_keys: selection.excluded_keys,
                        start_index: Some(
                            selection
                                .start_index
                                .unwrap_or_default()
                                .saturating_add(start),
                        ),
                    })
                }
            };
            (selected, copied.into_iter().skip(1).collect())
        }
        _ => {
            let excluded = initializer.copy_excluded_keys.clone().unwrap_or_default();
            if let Some(key) = key {
                if excluded.iter().any(
                    |excluded| matches!(&key, PropertyPathKey::String(value) if value == excluded),
                ) {
                    return None;
                }
                (key, copied.into_iter().skip(1).collect())
            } else {
                (
                    PropertyPathKey::Selection(PropertySelection {
                        excluded_keys: excluded,
                        start_index: None,
                    }),
                    Vec::new(),
                )
            }
        }
    };

    let mut result = projection_path(&initializer.projection[..offset]);
    result.push(key);
    result.extend(remaining);
    Some(result)
}

fn property_key(source: &str, member: Node<'_>) -> PropertyPathKey {
    member
        .field(source, Field::Property)
        .and_then(|property| static_property_key(source, property, member.computed()))
        .map_or(PropertyPathKey::Wildcard, PropertyPathKey::String)
}

fn array_property_references<'a>(
    source: &'a str,
    array: Node<'a>,
    path: PropertyPath,
) -> Vec<super::getter_queries::SemanticObjectReference<'a>> {
    let Some(key) = path.first() else {
        return Vec::new();
    };
    let remaining = path.iter().skip(1).cloned().collect::<PropertyPath>();
    array
        .field_list(source, Field::Elements)
        .into_iter()
        .enumerate()
        .filter_map(|(index, element)| {
            let element = element?;
            let matches = match key {
                PropertyPathKey::Number(value) => *value == index,
                PropertyPathKey::String(value) => value == &index.to_string(),
                PropertyPathKey::Wildcard | PropertyPathKey::Selection(_) => true,
            };
            matches.then(|| super::getter_queries::SemanticObjectReference {
                node: element,
                path: remaining.clone(),
                escapes: false,
                widened_getter_result: false,
                owner_initializer: None,
            })
        })
        .collect()
}

fn concrete_module_path(path: &[PropertyPathKey]) -> Option<Vec<JsString>> {
    path.iter()
        .map(|key| match key {
            PropertyPathKey::String(value) => Some(value.clone()),
            PropertyPathKey::Number(value) => Some(JsString::from(value.to_string())),
            PropertyPathKey::Wildcard | PropertyPathKey::Selection(_) => None,
        })
        .collect()
}

fn map_lookup_values<'a>(state: &SemanticState<'a>, call: Node<'a>) -> Vec<Node<'a>> {
    let Some(callee) = call.field(state.source, Field::Callee) else {
        return Vec::new();
    };
    let callee = unwrapped(state.source, callee);
    if callee.babel_type() != "MemberExpression"
        && callee.babel_type() != "OptionalMemberExpression"
    {
        return Vec::new();
    }
    let Some(property) = callee.field(state.source, Field::Property) else {
        return Vec::new();
    };
    if static_property_key(state.source, property, callee.computed()).as_ref()
        != Some(&JsString::from("get"))
    {
        return Vec::new();
    }
    let Some(receiver) = callee.field(state.source, Field::Object) else {
        return Vec::new();
    };
    let receiver = unwrapped(state.source, receiver);
    let Some(name) = receiver.identifier_name() else {
        return Vec::new();
    };
    let Some(binding) = state.resolve_binding(&receiver, name) else {
        return Vec::new();
    };
    let Some(initializer) = state.stable_initializer(binding) else {
        return Vec::new();
    };
    let map = unwrapped(state.source, initializer.node);
    if map.babel_type() != "NewExpression"
        || !map
            .field(state.source, Field::Callee)
            .is_some_and(|constructor| {
                super::ambient_writes::is_unmodified_global_reference(state, constructor, "Map")
            })
    {
        return Vec::new();
    }
    let Some(key_node) = call
        .field_list(state.source, Field::Arguments)
        .into_iter()
        .flatten()
        .next()
    else {
        return Vec::new();
    };
    let key = match evaluate_semantic_expression(key_node, state, Some(call)) {
        SemanticValue::Literal {
            value: Primitive::String(value),
        } => value,
        _ => return Vec::new(),
    };
    let Some(entries) = map
        .field_list(state.source, Field::Arguments)
        .into_iter()
        .flatten()
        .next()
    else {
        return Vec::new();
    };
    if entries.babel_type() != "ArrayExpression" {
        return Vec::new();
    }
    entries
        .field_list(state.source, Field::Elements)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            if entry.babel_type() != "ArrayExpression" {
                return None;
            }
            let values = entry
                .field_list(state.source, Field::Elements)
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            if values.len() < 2 {
                return None;
            }
            let entry_key = match evaluate_semantic_expression(values[0], state, Some(entry)) {
                SemanticValue::Literal {
                    value: Primitive::String(value),
                } => value,
                _ => return None,
            };
            (entry_key == key).then_some(values[1])
        })
        .collect()
}
