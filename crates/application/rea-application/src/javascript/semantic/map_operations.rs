//! Proof of unchanged `Map.get` and `Map.delete` operations.
//!
//! A named receiver also needs member-mutation facts. The result keeps that
//! missing dependency distinct from a disproven intrinsic identity.

use std::collections::HashSet;

use crate::javascript::ast::{Field, Node};

use super::ambient_writes::is_unmodified_global_reference;
use super::ast_values::{is_member, static_property_name, unwrapped};
use super::mutation_initializers::semantic_binding_at_read;
use super::opaque_effects::{OpaqueEffects, opaque_global_may_have_changed};
use super::property_paths::PropertyPathKey;
use super::state::SemanticState;

/// The member-mutation query required when a `Map` receiver has local aliases.
pub trait MapReferenceMutationIndex<'a> {
    fn reference_may_have_changed_at(
        &self,
        site: Node<'a>,
        reference: Node<'a>,
        path: &[&str],
    ) -> bool;
}

/// `isIntrinsicMapLookup`: `None` requests the shared member-mutation index.
pub fn is_intrinsic_map_lookup<'a>(
    node: Node<'a>,
    state: &SemanticState<'a>,
    opaque_effects: &OpaqueEffects<'a>,
    index: Option<&dyn MapReferenceMutationIndex<'a>>,
) -> Option<bool> {
    let Some(callee) = node.field(state.source, Field::Callee) else {
        return Some(false);
    };
    let callee = unwrapped(state.source, callee);
    if !is_member(&callee) {
        return Some(false);
    }

    let Some(property) = callee.field(state.source, Field::Property) else {
        return Some(false);
    };
    let method = static_property_name(state.source, property, callee.computed());
    let method_name = if method == "get" {
        "get"
    } else if method == "delete" {
        "delete"
    } else {
        return Some(false);
    };
    if prototype_member_may_have_changed(state, method_name) {
        return Some(false);
    }

    let Some(object) = callee.field(state.source, Field::Object) else {
        return Some(false);
    };
    let mut receiver = unwrapped(state.source, object);
    let mut seen = HashSet::new();
    while let Some(name) = receiver.identifier_name() {
        if index.is_some_and(|index| {
            index.reference_may_have_changed_at(node, receiver, &[method_name])
                || index.reference_may_have_changed_at(node, receiver, &["__proto__"])
        }) {
            return Some(false);
        }

        let Some(binding_index) = state.resolve_binding(&receiver, name) else {
            return Some(false);
        };
        if !seen.insert(binding_index) {
            return Some(false);
        }
        let Some(initializer) = state.stable_initializer(binding_index) else {
            return Some(false);
        };
        if !initializer.projection.is_empty()
            || !semantic_binding_at_read(
                state.binding(binding_index),
                receiver,
                &state.parents,
                state.source,
            )
            .has_definite_initializer
        {
            return Some(false);
        }
        receiver = unwrapped(state.source, initializer.node);
    }

    if receiver.babel_type() != "NewExpression"
        || !receiver
            .field(state.source, Field::Callee)
            .is_some_and(|constructor| is_unmodified_global_reference(state, constructor, "Map"))
    {
        return Some(false);
    }
    // Iterable construction invokes the instance's set hook, which can install
    // its own lookup methods before the constructed value is read.
    if !receiver
        .field_list(state.source, Field::Arguments)
        .is_empty()
        && prototype_member_may_have_changed(state, "set")
    {
        return Some(false);
    }
    if opaque_global_may_have_changed(callee, state, opaque_effects) {
        return Some(false);
    }

    if index.is_none() && !seen.is_empty() {
        None
    } else {
        Some(true)
    }
}

fn prototype_member_may_have_changed(state: &SemanticState<'_>, member: &str) -> bool {
    let unbound_map_write = state
        .ambient_binding_writes
        .get("Map")
        .is_some_and(|writes| !writes.is_empty());
    ["Map", "Object"].into_iter().any(|owner| {
        let path =
            ["global", owner, "prototype", member].map(|key| PropertyPathKey::String(key.into()));
        let unqualified_path =
            [owner, "prototype", member].map(|key| PropertyPathKey::String(key.into()));
        (owner == "Map" && unbound_map_write)
            || state.ambient_writes.covers(&path)
            || state.ambient_writes.covers(&unqualified_path)
            || state.ambient_escapes.covers(&path)
            || state.ambient_escapes.covers(&unqualified_path)
            || state.ambient_write_effects.iter().any(|effect| {
                effect.path.ends_with(&path[1..]) || effect.path.ends_with(&unqualified_path)
            })
    })
}
