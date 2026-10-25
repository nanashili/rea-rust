//! Property-path selectors used by execution-free JavaScript mutation analysis.
//!
//! A path component is either an exact property name, an array index, a
//! wildcard, or the selector retained by a shallow copy.  The coverage index
//! deliberately keeps exact paths and selectors separate: a selector must not
//! widen a distinct exact member path.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::value_types::JsString;

/// Slots retained by a shallow copy after exclusions or an array prefix.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertySelection {
    pub excluded_keys: Vec<JsString>,
    pub start_index: Option<usize>,
}

/// One internal mutation path component.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PropertyPathKey {
    String(JsString),
    Number(usize),
    Wildcard,
    Selection(PropertySelection),
}

pub type PropertyPath = Vec<PropertyPathKey>;

/// Read only canonical JavaScript array indices, excluding named properties.
pub fn semantic_array_index(key: &str) -> Option<usize> {
    let index = key.parse::<usize>().ok()?;
    (index < 4_294_967_295 && index.to_string() == key).then_some(index)
}

/// Test an exact key, wildcard, or copied-slot selection against an own key.
pub fn semantic_property_path_key_matches<N: Into<JsString>>(
    key: &PropertyPathKey,
    name: N,
) -> bool {
    let name = name.into();
    match key {
        PropertyPathKey::Wildcard => true,
        PropertyPathKey::String(value) => value == &name,
        PropertyPathKey::Number(value) => JsString::from(value.to_string()) == name,
        PropertyPathKey::Selection(selection) => {
            !selection
                .excluded_keys
                .iter()
                .any(|excluded| excluded == &name)
                && selection.start_index.is_none_or(|start| {
                    semantic_array_index_units(&name).is_some_and(|index| index >= start)
                })
        }
    }
}

#[derive(Default)]
struct CoverageNode {
    terminal: bool,
    exact: HashMap<JsString, CoverageNode>,
    selectors: HashMap<String, (PropertyPathKey, CoverageNode)>,
}

/// Index exact effect prefixes without widening distinct member paths.
#[derive(Default)]
pub struct SemanticPropertyPathCoverage {
    root: CoverageNode,
}

impl SemanticPropertyPathCoverage {
    /// Retain a path only when no previously retained prefix covers it.
    pub fn retain(&mut self, path: &[PropertyPathKey]) -> bool {
        if self.covers(path) {
            return false;
        }

        let mut node = &mut self.root;
        for key in path {
            if let Some(name) = exact_key_name(key) {
                node = node.exact.entry(name).or_default();
            } else {
                let identity = serde_json::to_string(key).expect("property key is serializable");
                node = &mut node
                    .selectors
                    .entry(identity)
                    .or_insert_with(|| (key.clone(), CoverageNode::default()))
                    .1;
            }
        }
        node.terminal = true;
        node.exact.clear();
        node.selectors.clear();
        true
    }

    /// Query retained prefixes without changing the coverage index.
    pub fn covers(&self, path: &[PropertyPathKey]) -> bool {
        let mut pending = vec![(&self.root, 0usize)];
        while let Some((node, offset)) = pending.pop() {
            if node.terminal {
                return true;
            }
            let Some(key) = path.get(offset) else {
                continue;
            };
            if let Some(name) = exact_key_name(key)
                && let Some(child) = node.exact.get(&name)
            {
                pending.push((child, offset + 1));
            }
            for (covering, child) in node.selectors.values() {
                if key_covers(covering, key) {
                    pending.push((child, offset + 1));
                }
            }
        }
        false
    }
}

fn exact_key_name(key: &PropertyPathKey) -> Option<JsString> {
    match key {
        PropertyPathKey::String(value) => Some(value.clone()),
        PropertyPathKey::Number(value) => Some(JsString::from(value.to_string())),
        PropertyPathKey::Wildcard | PropertyPathKey::Selection(_) => None,
    }
}

fn key_covers(covering: &PropertyPathKey, key: &PropertyPathKey) -> bool {
    match (covering, key) {
        (PropertyPathKey::Wildcard, _) => true,
        (_, PropertyPathKey::Wildcard) => false,
        (PropertyPathKey::Selection(left), PropertyPathKey::Selection(right)) => {
            left.excluded_keys
                .iter()
                .all(|name| right.excluded_keys.iter().any(|other| other == name))
                && (left.start_index.is_none()
                    || right
                        .start_index
                        .is_some_and(|start| left.start_index.unwrap() <= start))
        }
        (PropertyPathKey::Selection(_), other) => exact_key_name(other)
            .is_some_and(|name| semantic_property_path_key_matches(covering, &name)),
        (
            PropertyPathKey::String(_) | PropertyPathKey::Number(_),
            PropertyPathKey::Selection(_),
        ) => false,
        (PropertyPathKey::String(left), PropertyPathKey::String(right)) => left == right,
        (PropertyPathKey::Number(left), PropertyPathKey::Number(right)) => left == right,
        (PropertyPathKey::String(left), PropertyPathKey::Number(right)) => {
            *left == JsString::from(right.to_string())
        }
        (PropertyPathKey::Number(left), PropertyPathKey::String(right)) => {
            JsString::from(left.to_string()) == *right
        }
    }
}

pub fn semantic_array_index_units(key: &JsString) -> Option<usize> {
    let key = String::from_utf16(key.units()).ok()?;
    semantic_array_index(&key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn array_indices_reject_named_and_out_of_range_keys() {
        assert_eq!(semantic_array_index("0"), Some(0));
        assert_eq!(semantic_array_index("4294967294"), Some(4_294_967_294));
        assert_eq!(semantic_array_index("01"), None);
        assert_eq!(semantic_array_index("4294967295"), None);
        assert_eq!(semantic_array_index("length"), None);
    }

    #[test]
    fn coverage_keeps_exact_members_distinct_from_copy_selectors() {
        let mut coverage = SemanticPropertyPathCoverage::default();
        let exact = vec![PropertyPathKey::String("name".into())];
        let selection = vec![PropertyPathKey::Selection(PropertySelection {
            excluded_keys: vec!["other".into()],
            start_index: None,
        })];
        assert!(coverage.retain(&exact));
        assert!(coverage.retain(&selection));
        assert!(coverage.covers(&exact));
        assert!(coverage.covers(&[
            PropertyPathKey::String("name".into()),
            PropertyPathKey::String("child".into())
        ]));
    }

    #[test]
    fn exact_surrogate_keys_remain_distinct_from_replacement_keys() {
        let surrogate = JsString::from_utf16([0xd800]);
        let replacement = JsString::from("\u{fffd}");
        assert_ne!(surrogate, replacement);
        assert!(semantic_property_path_key_matches(
            &PropertyPathKey::String(surrogate.clone()),
            &surrogate
        ));
        assert!(!semantic_property_path_key_matches(
            &PropertyPathKey::String(surrogate),
            &replacement
        ));
    }
}
