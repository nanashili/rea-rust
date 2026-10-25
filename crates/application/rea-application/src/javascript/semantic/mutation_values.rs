//! Mutation invalidation for the JavaScript semantic value lattice.
//!
//! The shapes mirror javascriptSemanticValueTypes.ts and
//! javascriptSemanticPropertyPaths.ts, including coverage metadata and
//! shallow-copy selectors.

use std::collections::HashSet;

use super::value_types::{Coverage, Property, SemanticValue, SlotPresence};

pub use super::property_paths::{
    PropertyPath, PropertyPathKey, PropertySelection, semantic_array_index,
    semantic_property_path_key_matches as property_path_key_matches,
};

impl SemanticValue {
    fn unknown(reason: &str) -> Self {
        Self::Unknown {
            reason: reason.into(),
            resource_limit: None,
        }
    }
    fn slots(&self) -> Option<&[Property]> {
        match self {
            Self::Object { properties, .. } => Some(properties),
            Self::Array { items, .. } => Some(items),
            _ => None,
        }
    }
}

/// Invalidate a path reached through an escaped object reference.
pub fn invalidate_escaped_path(value: SemanticValue, path: &[PropertyPathKey]) -> SemanticValue {
    if value.slots().is_none() {
        return value;
    }
    let Some((key, rest)) = path.split_first() else {
        return SemanticValue::unknown("This object reference may have been mutated by a call.");
    };
    match value {
        SemanticValue::Object {
            mut properties,
            coverage,
        } => {
            for property in &mut properties {
                if property_path_key_matches(key, &property.name) {
                    property.value = invalidate_escaped_path(property.value.clone(), rest);
                }
            }
            SemanticValue::Object {
                properties,
                coverage,
            }
        }
        SemanticValue::Array {
            mut items,
            coverage,
        } => {
            for property in &mut items {
                if property_path_key_matches(key, &property.name) {
                    property.value = invalidate_escaped_path(property.value.clone(), rest);
                }
            }
            SemanticValue::Array { items, coverage }
        }
        other => other,
    }
}

/// Apply explicit mutation paths in source order.
pub fn invalidate_mutation_paths(value: SemanticValue, paths: &[PropertyPath]) -> SemanticValue {
    if paths.is_empty() {
        return value;
    }
    if value.slots().is_none()
        || paths
            .iter()
            .any(|path| matches!(path.first(), None | Some(PropertyPathKey::Wildcard)))
    {
        return SemanticValue::unknown("This property may have been mutated.");
    }

    let reset = if matches!(value, SemanticValue::Array { .. }) {
        paths.iter().rposition(
            |path| matches!(path.first(), Some(PropertyPathKey::String(name)) if name == "length"),
        )
    } else {
        None
    };
    let mut base = match (value, reset) {
        (SemanticValue::Array { .. }, Some(_)) => SemanticValue::Array {
            items: Vec::new(),
            coverage: Coverage::Unknown { omitted: None },
        },
        (value, _) => value,
    };
    let slots = base.slots().expect("container checked above");
    let mut selected: Vec<Vec<PropertyPath>> = vec![Vec::new(); slots.len()];
    let mut replaced = vec![false; slots.len()];
    let mut added = Vec::new();
    let mut added_names = HashSet::new();
    let first_path = reset.map_or(0, |index| index + 1);

    for path in paths.iter().skip(first_path) {
        let Some((key, rest)) = path.split_first() else {
            continue;
        };
        let mut matched = false;
        for (index, property) in slots.iter().enumerate() {
            if property_path_key_matches(key, &property.name) {
                matched = true;
                selected[index].push(rest.to_vec());
                if rest.is_empty() {
                    replaced[index] = true;
                }
            }
        }
        if !matched {
            let name = match key {
                PropertyPathKey::String(name) => name.clone(),
                PropertyPathKey::Number(index) => index.to_string().into(),
                PropertyPathKey::Selection(_) | PropertyPathKey::Wildcard => continue,
            };
            if added_names.insert(name.clone()) {
                added.push(name);
            }
        }
    }

    match &mut base {
        SemanticValue::Object { properties, .. }
        | SemanticValue::Array {
            items: properties, ..
        } => {
            for (index, property) in properties.iter_mut().enumerate() {
                if !selected[index].is_empty() {
                    property.value =
                        invalidate_mutation_paths(property.value.clone(), &selected[index]);
                }
                if replaced[index] {
                    property.presence = SlotPresence::UnknownCoverage;
                }
            }
            for name in added {
                properties.push(Property {
                    name,
                    value: SemanticValue::unknown("This property may have been mutated."),
                    presence: SlotPresence::UnknownCoverage,
                });
            }
        }
        _ => unreachable!("container checked above"),
    }
    base
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_serializes_to_the_typescript_contract() {
        let value = SemanticValue::Object {
            properties: Vec::new(),
            coverage: Coverage::Exact,
        };
        let encoded = serde_json::to_value(value).expect("serialize exact coverage");
        assert_eq!(encoded["unknownProperties"], false);
        assert_eq!(encoded["omittedProperties"], 0);
    }

    #[test]
    fn coverage_rejects_invalid_exact_omission_metadata() {
        let invalid = serde_json::json!({
            "status": "object",
            "properties": [],
            "unknownProperties": false,
            "omittedProperties": null,
        });
        assert!(serde_json::from_value::<SemanticValue>(invalid).is_err());
    }
}
