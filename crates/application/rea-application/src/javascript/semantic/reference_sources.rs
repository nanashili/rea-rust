//! Retained source-slot selection for semantic references.
//!
//! This is the Rust counterpart of `javascriptSemanticReferenceSources.ts`.
//! The expression evaluator remains owned by the values pass.  Until that
//! owner is complete, callers supply the evaluator explicitly; this keeps
//! source selection faithful without inventing a second value interpreter.

use crate::javascript::ast::Node;

use super::property_paths::{PropertyPath, PropertyPathKey};
use super::slots::semantic_slot_at_path;
use super::state::SemanticState;
use super::value_types::{SemanticValue, SlotPresence};

/// One retained expression and the property projection selected from it.
#[derive(Clone, Debug)]
pub struct ReferenceSource<'a> {
    pub node: Node<'a>,
    pub projection: PropertyPath,
}

/// Owner callback for evaluating one expression at its capture point.
///
/// `capture_point == None` preserves the TypeScript evaluator's default
/// capture context.  The callback owns all source-order and value-lattice
/// interpretation; this module only selects a retained slot.
pub trait SemanticExpressionEvaluator<'a> {
    fn evaluate(
        &mut self,
        state: &SemanticState<'a>,
        node: Node<'a>,
        capture_point: Option<Node<'a>>,
    ) -> SemanticValue;
}

/// Exclude references whose required slot is absent or whose fallback slot
/// was a retained value that should have been selected during destructuring.
pub fn semantic_reference_sources_inactive<'a, E: SemanticExpressionEvaluator<'a>>(
    required_sources: &[ReferenceSource<'a>],
    fallback_sources: &[ReferenceSource<'a>],
    state: &SemanticState<'a>,
    evaluator: &mut E,
) -> bool {
    if required_sources.iter().any(|source| {
        semantic_selected_reference_slot(source, state, Some(source.node), evaluator)
            .is_some_and(|slot| slot.presence == SlotPresence::Absent)
    }) {
        return true;
    }

    // Selection precedes effects through the chosen reference. A later escape
    // cannot make a fallback that was excluded at destructuring reachable.
    fallback_sources.iter().any(|source| {
        semantic_selected_reference_slot(source, state, Some(source.node), evaluator).is_some_and(
            |slot| {
                slot.presence == SlotPresence::Present
                    && matches!(
                        slot.value,
                        SemanticValue::Literal { .. }
                            | SemanticValue::Union { .. }
                            | SemanticValue::Object { .. }
                            | SemanticValue::Array { .. }
                    )
            },
        )
    })
}

/// Select a retained source slot at its capture, before later effects.
pub fn semantic_selected_reference_slot<'a, E: SemanticExpressionEvaluator<'a>>(
    source: &ReferenceSource<'a>,
    state: &SemanticState<'a>,
    capture_point: Option<Node<'a>>,
    evaluator: &mut E,
) -> Option<super::value_types::Property> {
    let mut path = Vec::with_capacity(source.projection.len());
    for key in &source.projection {
        match key {
            PropertyPathKey::String(value) => path.push(value.clone()),
            PropertyPathKey::Number(value) => path.push(value.to_string().into()),
            // TS rejects null and object-valued path components. Wildcards
            // and copy selections are the corresponding non-scalar Rust keys.
            PropertyPathKey::Wildcard | PropertyPathKey::Selection(_) => return None,
        }
    }

    let value = evaluator.evaluate(state, source.node, capture_point);
    Some(semantic_slot_at_path(&value, &path))
}
