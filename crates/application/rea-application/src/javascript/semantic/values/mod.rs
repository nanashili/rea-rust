//! Bounded, execution-free JavaScript values and module provenance.
//!
//! Effect-dependent caches belong to one semantic state. Temporal snapshots
//! and provenance proofs belong to one query, so an earlier capture cannot
//! publish a value into a live reader's cache.

mod expressions;
mod provenance;

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use crate::javascript::ast::{Node, NodeKey};

use super::dependencies::{SemanticDependencyProof, SemanticDependencyProofs};
use super::mutation_values::{invalidate_escaped_path, invalidate_mutation_paths};
use super::opaque_effects::{
    OpaqueEffects, binding_can_be_rebound, binding_may_have_opaque_effect, index_opaque_effects,
};
use super::provenance::{BindingProvenance, semantic_ambiguous_provenance};
use super::state::{BindingState, ProjectionKey, SemanticState};
use super::value_types::{JsString, ResourceLimit, SemanticValue};

const CALLER_INDEPENDENT: isize = isize::MAX;
const EVERY_CALLER: isize = -1;
// Keep the projection-wide memo bounded. Missing entries are recomputed and
// therefore cannot change semantic coverage or values.
const MAX_SHARED_PROJECTION_SNAPSHOTS: usize = 256;

#[derive(Clone)]
struct Memoized<T> {
    value: T,
    dependencies: Option<SemanticDependencyProof>,
}

#[derive(Clone)]
struct IndependentBindingValue {
    evaluated: Memoized<SemanticValue>,
    depth: usize,
}

#[derive(Clone)]
struct SnapshotValue {
    evaluated: Memoized<SemanticValue>,
    depth_dependent: bool,
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct SnapshotKey {
    initializer_id: usize,
    initializer_node: NodeKey,
    projection: Vec<ProjectionKey>,
    binding_id: String,
    capture_point: Option<NodeKey>,
    depth: usize,
}

struct BindingCacheEntries {
    snapshot_key: Option<SnapshotKey>,
    independent: bool,
    retained: Option<IndependentBindingValue>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BindingDependence {
    Independent,
    ActiveCaller,
    ExpressionDepth,
}

struct BindingEvaluation {
    evaluated: Memoized<SemanticValue>,
    dependence: BindingDependence,
}

/// Only binding identity proofs survive an effects-boundary invalidation.
#[derive(Default)]
pub(crate) struct ValueCaches {
    dependencies: Option<Rc<RefCell<SemanticDependencyProofs>>>,
    primitive_bindings: HashMap<String, SemanticValue>,
    captured_bindings: HashMap<NodeKey, HashMap<String, SemanticValue>>,
    primitive_expressions: HashMap<NodeKey, SemanticValue>,
    independent_bindings: HashMap<String, IndependentBindingValue>,
}

#[derive(Default)]
struct EvaluationMemo {
    snapshots: HashMap<SnapshotKey, SnapshotValue>,
    provenance: HashMap<String, HashMap<usize, Memoized<BindingProvenance>>>,
    dependency_frames: Vec<Option<SemanticDependencyProof>>,
}

#[derive(Clone, Copy)]
struct EvaluationPoint<'a> {
    depth: usize,
    capture_point: Option<Node<'a>>,
}

impl<'a> EvaluationPoint<'a> {
    fn live() -> Self {
        Self {
            depth: 0,
            capture_point: None,
        }
    }

    fn nested(self) -> Self {
        Self {
            depth: self.depth + 1,
            ..self
        }
    }
}

struct Evaluation<'s, 'a> {
    state: &'s SemanticState<'a>,
    opaque: OpaqueSource<'s, 'a>,
    bindings: HashMap<String, usize>,
    lowest: isize,
    memo: EvaluationMemo,
    dependencies: Rc<RefCell<SemanticDependencyProofs>>,
    demanded_member_path: Option<Vec<JsString>>,
}

enum OpaqueSource<'s, 'a> {
    Borrowed(&'s OpaqueEffects<'a>),
    Shared(Rc<OpaqueEffects<'a>>),
}

impl<'s, 'a> OpaqueSource<'s, 'a> {
    fn as_ref(&self) -> &OpaqueEffects<'a> {
        match self {
            Self::Borrowed(effects) => effects,
            Self::Shared(effects) => effects,
        }
    }
}

/// Discard values derived before member or escape effects changed.
pub fn clear_semantic_value_caches(state: &SemanticState<'_>) {
    let mut caches = state.value_caches.borrow_mut();
    caches.primitive_bindings.clear();
    caches.captured_bindings.clear();
    caches.primitive_expressions.clear();
    caches.independent_bindings.clear();
}

pub fn evaluate_semantic_binding<'a>(
    binding: &BindingState<'a>,
    state: &SemanticState<'a>,
) -> SemanticValue {
    let mut evaluation = Evaluation::new(state);
    evaluation.evaluate_public_binding(binding)
}

/// Reuses one value evaluator memo across the immutable binding projection.
///
/// Provenance stays query-local because its memo is sensitive to effective
/// read/capture context that is not part of the value snapshot key.
pub(crate) struct ImmutableBindingEvaluator<'s, 'a> {
    evaluation: Evaluation<'s, 'a>,
}

impl<'s, 'a> ImmutableBindingEvaluator<'s, 'a> {
    pub(crate) fn new(state: &'s SemanticState<'a>) -> Self {
        Self {
            evaluation: Evaluation::new(state),
        }
    }

    pub(crate) fn evaluate(&mut self, binding: &BindingState<'a>) -> SemanticValue {
        self.evaluation.evaluate_public_binding(binding)
    }
}

pub(crate) fn evaluate_semantic_binding_with_opaque_effects<'a>(
    binding: &BindingState<'a>,
    state: &SemanticState<'a>,
    opaque: &OpaqueEffects<'a>,
) -> SemanticValue {
    let mut evaluation = Evaluation::new_with_opaque(state, opaque);
    if binding_can_be_rebound(binding)
        && binding_may_have_opaque_effect(evaluation.opaque.as_ref(), state, binding, None, false)
    {
        return unknown("Direct eval may have changed this lexical binding.");
    }
    evaluation.evaluate_binding(binding, EvaluationPoint::live(), true)
}

pub fn evaluate_semantic_expression<'a>(
    node: Node<'a>,
    state: &SemanticState<'a>,
    capture_point: Option<Node<'a>>,
) -> SemanticValue {
    let mut evaluation = Evaluation::new(state);
    let point = capture_point
        .and_then(|capture| evaluation.capture_context_at(capture, EvaluationPoint::live()))
        .unwrap_or_else(EvaluationPoint::live);
    evaluation.evaluate_expression(node, point)
}

pub(crate) fn evaluate_semantic_expression_with_opaque_effects<'a>(
    node: Node<'a>,
    state: &SemanticState<'a>,
    capture_point: Option<Node<'a>>,
    opaque: &OpaqueEffects<'a>,
) -> SemanticValue {
    let mut evaluation = Evaluation::new_with_opaque(state, opaque);
    let point = capture_point
        .and_then(|capture| evaluation.capture_context_at(capture, EvaluationPoint::live()))
        .unwrap_or_else(EvaluationPoint::live);
    evaluation.evaluate_expression(node, point)
}

pub fn evaluate_semantic_expression_provenance<'a>(
    node: Node<'a>,
    state: &SemanticState<'a>,
) -> BindingProvenance {
    Evaluation::new(state).provenance_for_expression(node, EvaluationPoint::live())
}

pub fn evaluate_semantic_provenance<'a>(
    binding: &BindingState<'a>,
    state: &SemanticState<'a>,
) -> BindingProvenance {
    let mut evaluation = Evaluation::new(state);
    evaluation.evaluate_public_provenance(binding)
}

impl<'s, 'a> Evaluation<'s, 'a> {
    fn evaluate_public_binding(&mut self, binding: &BindingState<'a>) -> SemanticValue {
        if binding_can_be_rebound(binding)
            && binding_may_have_opaque_effect(
                self.opaque.as_ref(),
                self.state,
                binding,
                None,
                false,
            )
        {
            return unknown("Direct eval may have changed this lexical binding.");
        }
        self.evaluate_binding(binding, EvaluationPoint::live(), true)
    }

    fn evaluate_public_provenance(&mut self, binding: &BindingState<'a>) -> BindingProvenance {
        let provenance = self.provenance_for_binding(binding, EvaluationPoint::live());
        if binding_can_be_rebound(binding)
            && binding_may_have_opaque_effect(
                self.opaque.as_ref(),
                self.state,
                binding,
                None,
                false,
            )
        {
            semantic_ambiguous_provenance(
                provenance.origins(),
                "Direct eval may have changed this runtime value.",
            )
        } else {
            provenance
        }
    }
}

pub fn evaluate_semantic_provenance_at_read<'a>(
    binding: &BindingState<'a>,
    read: Node<'a>,
    state: &SemanticState<'a>,
) -> BindingProvenance {
    Evaluation::new(state).provenance_for_binding_at_read(binding, read, EvaluationPoint::live())
}

impl<'s, 'a> Evaluation<'s, 'a> {
    fn new(state: &'s SemanticState<'a>) -> Self {
        let opaque = {
            let mut cache = state.opaque_effects_cache.borrow_mut();
            cache
                .get_or_insert_with(|| Rc::new(index_opaque_effects(state)))
                .clone()
        };
        Self::new_with_opaque_value(state, OpaqueSource::Shared(opaque))
    }

    fn new_with_opaque(state: &'s SemanticState<'a>, opaque: &'s OpaqueEffects<'a>) -> Self {
        Self::new_with_opaque_value(state, OpaqueSource::Borrowed(opaque))
    }

    fn new_with_opaque_value(state: &'s SemanticState<'a>, opaque: OpaqueSource<'s, 'a>) -> Self {
        let dependencies = {
            let mut caches = state.value_caches.borrow_mut();
            caches
                .dependencies
                .get_or_insert_with(|| {
                    Rc::new(RefCell::new(SemanticDependencyProofs::new(
                        state
                            .bindings
                            .iter()
                            .map(|binding| binding.binding_id.clone()),
                    )))
                })
                .clone()
        };

        Self {
            state,
            opaque,
            bindings: HashMap::new(),
            lowest: CALLER_INDEPENDENT,
            memo: EvaluationMemo::default(),
            dependencies,
            demanded_member_path: None,
        }
    }

    fn retain_dependency_proof(&mut self, proof: Option<&SemanticDependencyProof>) {
        if let Some(parent) = self.memo.dependency_frames.last_mut() {
            *parent = SemanticDependencyProofs::union(parent.as_ref(), proof);
        }
    }

    fn record_binding_dependency(&mut self, binding: &BindingState<'a>) {
        let proof = self.dependencies.borrow_mut().binding(&binding.binding_id);
        self.retain_dependency_proof(Some(&proof));
    }

    fn read_memoized<T: Clone>(&mut self, entry: &Memoized<T>) -> Option<T> {
        if self
            .dependencies
            .borrow()
            .intersects(entry.dependencies.as_ref(), &self.bindings)
        {
            return None;
        }
        self.retain_dependency_proof(entry.dependencies.as_ref());
        Some(entry.value.clone())
    }

    fn collect_dependencies<T>(
        &mut self,
        binding: &BindingState<'a>,
        evaluate: impl FnOnce(&mut Self) -> T,
    ) -> Memoized<T> {
        let proof = self.dependencies.borrow_mut().binding(&binding.binding_id);
        self.memo.dependency_frames.push(Some(proof));
        let value = evaluate(self);
        let dependencies = self.memo.dependency_frames.pop().flatten();
        self.retain_dependency_proof(dependencies.as_ref());
        Memoized {
            value,
            dependencies,
        }
    }

    fn evaluate_expression(&mut self, node: Node<'a>, point: EvaluationPoint<'a>) -> SemanticValue {
        let value = self.expression_value(node, point);
        if let SemanticValue::Unknown {
            resource_limit: Some(limit),
            ..
        } = &value
        {
            self.state.record_value_resource_limit(limit.clone());
        }
        value
    }

    fn primitive_binding_value(
        &self,
        binding: &str,
        point: EvaluationPoint<'a>,
    ) -> Option<SemanticValue> {
        let caches = self.state.value_caches.borrow();
        match point.capture_point {
            Some(capture) => caches.captured_bindings.get(&capture.key())?.get(binding),
            None => caches.primitive_bindings.get(binding),
        }
        .cloned()
    }

    fn retain_primitive_binding(
        &self,
        binding: &str,
        point: EvaluationPoint<'a>,
        value: SemanticValue,
    ) {
        let mut caches = self.state.value_caches.borrow_mut();
        let values = match point.capture_point {
            Some(capture) => caches.captured_bindings.entry(capture.key()).or_default(),
            None => &mut caches.primitive_bindings,
        };
        values.insert(binding.to_owned(), value);
    }

    fn evaluate_binding(
        &mut self,
        binding: &BindingState<'a>,
        mut point: EvaluationPoint<'a>,
        whole_binding: bool,
    ) -> SemanticValue {
        self.record_binding_dependency(binding);
        if let Some(&head) = self.bindings.get(&binding.binding_id) {
            self.lowest = self.lowest.min(head as isize);
            return SemanticValue::Cycle {
                reason: format!("Alias cycle at {}.", binding.name).into(),
                resource_limit: None,
            };
        }

        if whole_binding
            && point.capture_point.is_some_and(|capture| {
                !self
                    .state
                    .semantic_binding_precedes_capture(binding, capture)
            })
        {
            point.capture_point = None;
        }
        if whole_binding
            && let Some(cached) = self.primitive_binding_value(&binding.binding_id, point)
        {
            return cached;
        }

        let caches = self.binding_cache_entries(binding, point, whole_binding);
        if let Some(value) = self.read_binding_caches(&caches, point) {
            return value;
        }
        if let Some(failure) = self.initializer_failure(binding, whole_binding) {
            return failure;
        }

        let mut result = self.evaluate_active_binding(binding, point);
        result.evaluated.value = self.apply_binding_effects(binding, point, result.evaluated.value);
        let value = result.evaluated.value.clone();

        self.retain_binding_evaluation(binding, point, whole_binding, caches, result);
        value
    }

    fn binding_cache_entries(
        &self,
        binding: &BindingState<'a>,
        point: EvaluationPoint<'a>,
        whole_binding: bool,
    ) -> BindingCacheEntries {
        let independent = whole_binding && point.capture_point.is_none();
        let retained = independent
            .then(|| {
                self.state
                    .value_caches
                    .borrow()
                    .independent_bindings
                    .get(&binding.binding_id)
                    .cloned()
            })
            .flatten();
        BindingCacheEntries {
            snapshot_key: self.snapshot_key(binding, point, whole_binding),
            independent,
            retained,
        }
    }

    fn read_binding_caches(
        &mut self,
        caches: &BindingCacheEntries,
        point: EvaluationPoint<'a>,
    ) -> Option<SemanticValue> {
        if let Some(snapshot) = caches
            .snapshot_key
            .as_ref()
            .and_then(|key| self.memo.snapshots.get(key))
            .cloned()
            && let Some(value) = self.read_memoized(&snapshot.evaluated)
        {
            if snapshot.depth_dependent {
                self.lowest = EVERY_CALLER;
            }
            return Some(value);
        }

        if let Some(retained) = &caches.retained
            && point.depth <= retained.depth
            && let Some(value) = self.read_memoized(&retained.evaluated)
        {
            return Some(value);
        }
        None
    }

    fn evaluate_active_binding(
        &mut self,
        binding: &BindingState<'a>,
        point: EvaluationPoint<'a>,
    ) -> BindingEvaluation {
        let position = self.bindings.len();
        let caller_dependence = self.lowest;
        self.lowest = CALLER_INDEPENDENT;
        self.bindings.insert(binding.binding_id.clone(), position);
        let evaluated = self.collect_dependencies(binding, |evaluation| {
            evaluation.evaluate_initializer(binding, point.nested())
        });
        let dependence = if self.lowest == EVERY_CALLER {
            BindingDependence::ExpressionDepth
        } else if self.lowest > position as isize {
            BindingDependence::Independent
        } else {
            BindingDependence::ActiveCaller
        };
        self.bindings.remove(&binding.binding_id);
        self.lowest = if dependence == BindingDependence::Independent {
            caller_dependence
        } else {
            caller_dependence.min(self.lowest)
        };

        BindingEvaluation {
            evaluated,
            dependence,
        }
    }

    fn initializer_failure(
        &self,
        binding: &BindingState<'a>,
        whole_binding: bool,
    ) -> Option<SemanticValue> {
        if binding.initializers.is_empty() {
            return Some(unknown(&format!(
                "Binding {} has {}.",
                binding.name,
                if whole_binding {
                    "no constant initializer"
                } else {
                    "no proven initializer at this read"
                }
            )));
        }
        if binding.initializers.iter().any(|initializer| {
            initializer.node.babel_type() == "UpdateExpression"
                || (initializer.node.babel_type() == "AssignmentExpression"
                    && !matches!(
                        initializer.node.operator(),
                        Some("=" | "&&=" | "||=" | "??=")
                    ))
        }) {
            return Some(unknown(&format!(
                "Binding {} has a compound or update write.",
                binding.name
            )));
        }
        if binding.initializers.len() > 1 {
            return Some(SemanticValue::Ambiguous {
                reason: format!(
                    "Binding {} has multiple possible assignments.",
                    binding.name
                )
                .into(),
                resource_limit: None,
            });
        }
        if self
            .state
            .conditionally_skipped
            .contains(&binding.initializers[0].node.key())
        {
            return Some(unknown(&format!(
                "Binding {} may remain uninitialized.",
                binding.name
            )));
        }
        None
    }

    fn evaluate_initializer(
        &mut self,
        binding: &BindingState<'a>,
        point: EvaluationPoint<'a>,
    ) -> SemanticValue {
        let initializer = &binding.initializers[0];
        let mut value = expressions::project_value(
            self.evaluate_expression(initializer.node, point),
            &initializer.projection,
        );
        if can_capture_primitive(&value)
            && let Some(capture) = self.primitive_capture_context(initializer.node, point)
        {
            let captured = expressions::project_value(
                self.evaluate_expression(initializer.node, capture),
                &initializer.projection,
            );
            if is_primitive(&captured) {
                value = captured;
            }
        }
        value
    }

    fn apply_binding_effects(
        &self,
        binding: &BindingState<'a>,
        point: EvaluationPoint<'a>,
        value: SemanticValue,
    ) -> SemanticValue {
        let writes = binding
            .member_writes
            .iter()
            .map(|effect| effect.path.clone())
            .collect::<Vec<_>>();
        let mut value = invalidate_mutation_paths(value, &writes);
        for escape in &binding.escaped_paths {
            if !matches!(
                value,
                SemanticValue::Object { .. } | SemanticValue::Array { .. }
            ) {
                break;
            }
            if point.capture_point.is_some_and(|capture| {
                self.state
                    .semantic_escape_follows_capture(binding, capture, escape.node)
            }) {
                continue;
            }
            value = invalidate_escaped_path(value, &escape.path);
        }
        if matches!(
            value,
            SemanticValue::Object { .. } | SemanticValue::Array { .. }
        ) && binding_may_have_opaque_effect(
            self.opaque.as_ref(),
            self.state,
            binding,
            point.capture_point,
            true,
        ) {
            return unknown("Direct eval may have mutated this object reference.");
        }
        value
    }

    fn snapshot_key(
        &self,
        binding: &BindingState<'a>,
        point: EvaluationPoint<'a>,
        whole_binding: bool,
    ) -> Option<SnapshotKey> {
        // Object and array literals can be evaluated demand-driven for a
        // member read. Their result then depends on the active path, which
        // is intentionally local evaluator state rather than binding state.
        // Do not retain such a partial value under a path-independent key.
        if whole_binding || self.demanded_member_path.is_some() || binding.initializers.len() != 1 {
            return None;
        }
        Some(SnapshotKey {
            initializer_id: binding.initializers[0].record_id,
            initializer_node: binding.initializers[0].node.key(),
            projection: binding.initializers[0].projection.clone(),
            binding_id: binding.binding_id.clone(),
            capture_point: point.capture_point.map(|node| node.key()),
            depth: point.depth,
        })
    }

    fn retain_binding_evaluation(
        &mut self,
        binding: &BindingState<'a>,
        point: EvaluationPoint<'a>,
        whole_binding: bool,
        caches: BindingCacheEntries,
        result: BindingEvaluation,
    ) {
        if caches.independent
            && result.dependence == BindingDependence::Independent
            && caches
                .retained
                .as_ref()
                .is_none_or(|prior| prior.depth < point.depth)
        {
            self.state
                .value_caches
                .borrow_mut()
                .independent_bindings
                .insert(
                    binding.binding_id.clone(),
                    IndependentBindingValue {
                        evaluated: result.evaluated.clone(),
                        depth: point.depth,
                    },
                );
        }

        if self.memo.snapshots.len() < MAX_SHARED_PROJECTION_SNAPSHOTS
            && let Some(key) = caches.snapshot_key
            && result.dependence != BindingDependence::ActiveCaller
            && !self
                .dependencies
                .borrow()
                .intersects(result.evaluated.dependencies.as_ref(), &self.bindings)
        {
            self.memo.snapshots.insert(
                key,
                SnapshotValue {
                    evaluated: result.evaluated.clone(),
                    depth_dependent: result.dependence == BindingDependence::ExpressionDepth,
                },
            );
        }

        let retain_primitive = point.capture_point.is_some()
            || is_primitive(&result.evaluated.value)
            || matches!(
                &result.evaluated.value,
                SemanticValue::Unknown {
                    resource_limit: Some(
                        ResourceLimit::PrimitiveBytes | ResourceLimit::PrimitiveCandidates
                    ),
                    ..
                }
            );
        if whole_binding && retain_primitive {
            self.retain_primitive_binding(&binding.binding_id, point, result.evaluated.value);
        }
    }

    fn capture_context_at(
        &self,
        node: Node<'a>,
        point: EvaluationPoint<'a>,
    ) -> Option<EvaluationPoint<'a>> {
        if point.capture_point.is_some() || self.state.semantic_capture_position(node).is_none() {
            return None;
        }
        Some(EvaluationPoint {
            capture_point: Some(node),
            ..point
        })
    }

    fn primitive_capture_context(
        &self,
        node: Node<'a>,
        point: EvaluationPoint<'a>,
    ) -> Option<EvaluationPoint<'a>> {
        if matches!(node.babel_type(), "ObjectExpression" | "ArrayExpression") {
            None
        } else {
            self.capture_context_at(node, point)
        }
    }

    fn captured_expression(&mut self, node: Node<'a>, point: EvaluationPoint<'a>) -> SemanticValue {
        let cached = self
            .state
            .value_caches
            .borrow()
            .primitive_expressions
            .get(&node.key())
            .cloned();
        if let Some(cached) = cached {
            return cached;
        }
        let mut value = self.evaluate_expression(node, point);
        if can_capture_primitive(&value)
            && let Some(capture) = self.primitive_capture_context(node, point)
        {
            let captured = self.evaluate_expression(node, capture);
            if is_primitive(&captured) {
                value = captured;
            }
        }
        if point.capture_point.is_none() && is_primitive(&value) {
            self.state
                .value_caches
                .borrow_mut()
                .primitive_expressions
                .insert(node.key(), value.clone());
        }
        value
    }
}

fn unknown(reason: &str) -> SemanticValue {
    SemanticValue::Unknown {
        reason: reason.into(),
        resource_limit: None,
    }
}

fn is_primitive(value: &SemanticValue) -> bool {
    matches!(
        value,
        SemanticValue::Literal { .. } | SemanticValue::Union { .. }
    )
}

fn can_capture_primitive(value: &SemanticValue) -> bool {
    !is_primitive(value)
        && !matches!(
            value,
            SemanticValue::Unknown {
                resource_limit: Some(ResourceLimit::ExpressionDepth),
                ..
            }
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::javascript::parser::parse_javascript_analysis_program;
    use crate::javascript::semantic::analysis::prepare_state;
    use crate::javascript::semantic::state::ResolutionMode;
    use oxc_allocator::Allocator;

    #[test]
    fn demand_driven_member_values_are_not_snapshot_cached_by_path() {
        let allocator = Allocator::default();
        let parsed = parse_javascript_analysis_program(
            &allocator,
            "const value = { first: 1, second: 2 };",
            Some("demanded-member-cache.js"),
        )
        .expect("member cache source parses");
        let mut prepared = prepare_state(&parsed, ResolutionMode::Import);
        prepared.ensure_member_mutations();
        let state = prepared.state();
        let binding = state
            .bindings_by_id
            .values()
            .map(|index| state.binding(*index))
            .find(|binding| binding.name == "value")
            .expect("value binding exists");
        let mut evaluation = Evaluation::new(state);

        evaluation.demanded_member_path = Some(vec![JsString::from("first")]);
        let first = evaluation.evaluate_binding(binding, EvaluationPoint::live(), false);
        evaluation.demanded_member_path = Some(vec![JsString::from("second")]);
        let second = evaluation.evaluate_binding(binding, EvaluationPoint::live(), false);

        assert_eq!(object_property_number(&first, "first"), Some(1.0));
        assert_eq!(object_property_number(&second, "second"), Some(2.0));
    }

    fn object_property_number(value: &SemanticValue, name: &str) -> Option<f64> {
        let SemanticValue::Object { properties, .. } = value else {
            return None;
        };
        properties
            .iter()
            .find(|property| property.name == name)
            .and_then(|property| match property.value {
                SemanticValue::Literal {
                    value: super::super::value_types::Primitive::Number(number),
                } => Some(number),
                _ => None,
            })
    }
}
