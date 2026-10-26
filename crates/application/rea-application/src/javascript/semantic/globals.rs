//! Global-identity reads the definitions pass needs, ported from
//! `javascriptElectronMemberWrites.electronMemberPath` and
//! `javascriptSemanticAmbientWrites.isUnmodifiedGlobalReference`.
//!
//! The definitions pass runs before ambient writes are indexed, so the TS
//! `state.ambientWrites.covers(...)` checks are always false here. The
//! ambient-writes package (D2) owns the general form and must add that
//! coverage when it lands; until then this is only valid during
//! `collect_definitions`.

use crate::javascript::ast::{Field, Node};

use super::ast_values::{is_member, static_property_key, unwrapped};
use super::state::SemanticState;
use super::value_types::JsString;

/// Decoded identifiers every supported global `eval` origin starts with.
pub const GLOBAL_EVAL_ROOTS: [&str; 5] = ["eval", "globalThis", "global", "window", "self"];

/// `GLOBAL_OBJECT_NAMES`.
pub const GLOBAL_OBJECT_NAMES: [&str; 4] = ["globalThis", "global", "window", "self"];

/// `electronMemberPath`: the unwrapped root and its static member keys
/// (`None` for dynamic keys), outermost-first.
pub fn member_path<'a>(source: &'a str, node: Node<'a>) -> (Node<'a>, Vec<Option<JsString>>) {
    let mut root = unwrapped(source, node);
    let mut members = Vec::new();
    while is_member(&root) {
        members.push(
            root.field(source, Field::Property)
                .and_then(|property| static_property_key(source, property, root.computed())),
        );
        match root.field(source, Field::Object) {
            Some(object) => root = unwrapped(source, object),
            None => break,
        }
    }
    members.reverse();
    (root, members)
}

/// `isUnmodifiedGlobalReference` for a one-segment path, with no ambient
/// writes indexed yet.
pub fn is_unmodified_global_reference<'a>(
    state: &SemanticState<'a>,
    callee: &Node<'a>,
    name: &str,
) -> bool {
    let callee = unwrapped(state.source, *callee);
    if !is_member(&callee) {
        return state.is_unshadowed_global(&callee, name);
    }

    let Some(object) = callee.field(state.source, Field::Object) else {
        return false;
    };
    let object = unwrapped(state.source, object);
    let Some(namespace) = object.identifier_name() else {
        return false;
    };
    if !GLOBAL_OBJECT_NAMES.contains(&namespace) {
        return false;
    }

    let Some(property) = callee.field(state.source, Field::Property) else {
        return false;
    };
    let Some(property_name) = static_property_key(state.source, property, callee.computed()) else {
        return false;
    };

    property_name == name && state.is_unshadowed_global(&object, namespace)
}
