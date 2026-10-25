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
    let (root, members) = member_path(state.source, *callee);
    if members.is_empty() && state.is_unshadowed_global(&root, name) {
        return true;
    }
    GLOBAL_OBJECT_NAMES
        .into_iter()
        .any(|namespace| state.is_unshadowed_global(&root, namespace))
        && matches!(members.as_slice(), [Some(member)] if member == name)
}
