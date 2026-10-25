//! Static own-slot lookup for semantic objects and arrays.

use super::value_types::{Coverage, JsString, Property, SemanticValue, SlotPresence};

pub fn semantic_slot_at_path(value: &SemanticValue, path: &[JsString]) -> Property {
    let leaf_name = path.last().cloned().unwrap_or_else(|| "".into());
    let mut current = Property {
        name: "".into(),
        value: value.clone(),
        presence: SlotPresence::Present,
    };

    for (index, name) in path.iter().enumerate() {
        let Some((slots, complete)) = container_slots(&current.value) else {
            return unknown_property(&leaf_name, &current.value, path, index);
        };
        if current.presence != SlotPresence::Present {
            return unknown_property(&leaf_name, &current.value, path, index);
        }
        if matches!(current.value, SemanticValue::Array { .. }) && name == "length" {
            current = Property {
                name: name.clone(),
                value: SemanticValue::Unknown {
                    reason: "Array length is present but its value is not retained.".into(),
                    resource_limit: None,
                },
                presence: SlotPresence::Present,
            };
            continue;
        }
        current = slots
            .iter()
            .find(|slot| slot.name == *name)
            .cloned()
            .unwrap_or_else(|| Property {
                name: name.clone(),
                value: SemanticValue::Unknown {
                    reason: JsString::from("Own property ")
                        .concat(name)
                        .concat(&" was not observed.".into()),
                    resource_limit: None,
                },
                presence: if complete {
                    SlotPresence::Absent
                } else {
                    SlotPresence::UnknownCoverage
                },
            });
    }
    current
}

fn container_slots(value: &SemanticValue) -> Option<(&[Property], bool)> {
    match value {
        SemanticValue::Object {
            properties,
            coverage,
        }
        | SemanticValue::Array {
            items: properties,
            coverage,
        } => Some((properties, matches!(coverage, Coverage::Exact))),
        _ => None,
    }
}

fn unknown_property(
    name: &JsString,
    value: &SemanticValue,
    path: &[JsString],
    index: usize,
) -> Property {
    let reason = match value {
        SemanticValue::Unknown { reason, .. }
        | SemanticValue::Ambiguous { reason, .. }
        | SemanticValue::Cycle { reason, .. } => reason
            .concat(&" Cannot continue ".into())
            .concat(&pointer(path))
            .concat(&" through receiver ".into())
            .concat(&pointer(&path[..index]))
            .concat(&".".into()),
        _ => JsString::from("Cannot resolve ")
            .concat(&pointer(path))
            .concat(&" through ".into())
            .concat(&value_status(value).into())
            .concat(&" receiver ".into())
            .concat(&pointer(&path[..index]))
            .concat(&".".into()),
    };
    let result_value = match value {
        SemanticValue::Unknown { resource_limit, .. } => SemanticValue::Unknown {
            reason,
            resource_limit: resource_limit.clone(),
        },
        SemanticValue::Ambiguous { resource_limit, .. } => SemanticValue::Ambiguous {
            reason,
            resource_limit: resource_limit.clone(),
        },
        SemanticValue::Cycle { resource_limit, .. } => SemanticValue::Cycle {
            reason,
            resource_limit: resource_limit.clone(),
        },
        _ => SemanticValue::Unknown {
            reason,
            resource_limit: None,
        },
    };
    Property {
        name: name.clone(),
        value: result_value,
        presence: SlotPresence::UnknownCoverage,
    }
}

fn pointer(path: &[JsString]) -> JsString {
    let mut units = Vec::new();
    for key in path {
        units.push(u16::from(b'/'));
        append_pointer_key(&mut units, key);
    }
    JsString::from_utf16(units)
}

fn append_pointer_key(units: &mut Vec<u16>, key: &JsString) {
    for unit in key.encode_utf16() {
        match unit {
            0x7e => units.extend([u16::from(b'~'), u16::from(b'0')]),
            0x2f => units.extend([u16::from(b'~'), u16::from(b'1')]),
            _ => units.push(unit),
        }
    }
}

fn value_status(value: &SemanticValue) -> &'static str {
    match value {
        SemanticValue::Literal { .. } => "literal",
        SemanticValue::Union { .. } => "union",
        SemanticValue::Object { .. } => "object",
        SemanticValue::Array { .. } => "array",
        SemanticValue::Unknown { .. } => "unknown",
        SemanticValue::Ambiguous { .. } => "ambiguous",
        SemanticValue::Cycle { .. } => "cycle",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::javascript::semantic::value_types::Coverage;

    #[test]
    fn array_length_is_present_even_when_items_are_partial() {
        let value = SemanticValue::Array {
            items: Vec::new(),
            coverage: Coverage::Unknown { omitted: None },
        };
        let property = semantic_slot_at_path(&value, &["length".into()]);
        assert_eq!(property.presence, SlotPresence::Present);
        assert!(matches!(property.value, SemanticValue::Unknown { .. }));
    }

    #[test]
    fn missing_partial_sibling_remains_unknown_coverage() {
        let value = SemanticValue::Object {
            properties: Vec::new(),
            coverage: Coverage::Unknown { omitted: Some(1) },
        };
        let property = semantic_slot_at_path(&value, &["missing".into()]);
        assert_eq!(property.presence, SlotPresence::UnknownCoverage);
    }

    #[test]
    fn continuation_preserves_unknown_kind_limit_and_pointer() {
        let value = SemanticValue::Ambiguous {
            reason: "receiver widened".into(),
            resource_limit: Some(super::super::value_types::ResourceLimit::GetterExpansion),
        };
        let property = semantic_slot_at_path(&value, &["a/b".into(), "c".into()]);
        assert_eq!(property.presence, SlotPresence::UnknownCoverage);
        assert!(matches!(
            property.value,
            SemanticValue::Ambiguous {
                resource_limit: Some(super::super::value_types::ResourceLimit::GetterExpansion),
                ref reason
            } if reason.try_to_string().is_ok_and(|text| text.contains("/a~1b/c") && text.contains("/a~1b"))
        ));
    }
}
