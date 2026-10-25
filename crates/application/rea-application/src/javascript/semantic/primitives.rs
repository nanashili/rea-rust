//! Primitive normalization for the execution-free semantic value lattice.

use super::limits::{
    SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT, exceeds_primitive_string_byte_budget, resource_limit_reason,
};
use super::value_types::{Primitive, ResourceLimit, SemanticValue};
use crate::javascript::graph::json::compare_code_points;
use crate::javascript::semantic::provenance::semantic_primitive_key;

pub fn semantic_primitive_set(values: &[Primitive]) -> SemanticValue {
    if values.len() == 1 {
        return match &values[0] {
            Primitive::Number(value) if !value.is_finite() => unknown(
                "Nonfinite numbers are outside the JSON primitive lattice.",
                None,
            ),
            Primitive::Number(value) if value.is_sign_negative() && *value == 0.0 => unknown(
                "Negative zero cannot be preserved by JSON primitive evidence.",
                None,
            ),
            Primitive::String(value)
                if exceeds_primitive_string_byte_budget(std::slice::from_ref(value)) =>
            {
                unknown(
                    resource_limit_reason(ResourceLimit::PrimitiveBytes),
                    Some(ResourceLimit::PrimitiveBytes),
                )
            }
            value => SemanticValue::Literal {
                value: value.clone(),
            },
        };
    }

    let mut unique = Vec::new();
    for value in values {
        if let Primitive::Number(number) = value {
            if !number.is_finite() {
                return unknown(
                    "Nonfinite numbers are outside the JSON primitive lattice.",
                    None,
                );
            }
            if number.is_sign_negative() && *number == 0.0 {
                return unknown(
                    "Negative zero cannot be preserved by JSON primitive evidence.",
                    None,
                );
            }
        }
        if !unique.iter().any(|existing| existing == value) {
            unique.push(value.clone());
        }
        if unique.len() > SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT {
            return unknown(
                resource_limit_reason(ResourceLimit::PrimitiveCandidates),
                Some(ResourceLimit::PrimitiveCandidates),
            );
        }
    }
    let strings = unique
        .iter()
        .filter_map(|value| match value {
            Primitive::String(value) => Some(value.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if exceeds_primitive_string_byte_budget(&strings) {
        return unknown(
            resource_limit_reason(ResourceLimit::PrimitiveBytes),
            Some(ResourceLimit::PrimitiveBytes),
        );
    }
    if unique.len() == 1 {
        return SemanticValue::Literal {
            value: unique.remove(0),
        };
    }
    unique.sort_by(|left, right| {
        compare_code_points(
            &semantic_primitive_key(left),
            &semantic_primitive_key(right),
        )
    });
    SemanticValue::Union { values: unique }
}

pub fn semantic_primitive_candidates(value: &SemanticValue) -> Option<Vec<Primitive>> {
    match value {
        SemanticValue::Literal { value } => Some(vec![value.clone()]),
        SemanticValue::Union { values } => Some(values.clone()),
        _ => None,
    }
}

fn unknown(reason: &str, resource_limit: Option<ResourceLimit>) -> SemanticValue {
    SemanticValue::Unknown {
        reason: reason.into(),
        resource_limit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitive_set_deduplicates_without_reordering_distinct_values() {
        let value = semantic_primitive_set(&[
            Primitive::String("b".into()),
            Primitive::String("a".into()),
            Primitive::String("b".into()),
        ]);
        assert_eq!(
            value,
            SemanticValue::Union {
                values: vec![Primitive::String("a".into()), Primitive::String("b".into())]
            }
        );
    }

    #[test]
    fn primitive_set_rejects_non_json_numbers_and_negative_zero() {
        assert!(matches!(
            semantic_primitive_set(&[Primitive::Number(f64::NAN)]),
            SemanticValue::Unknown {
                resource_limit: None,
                ..
            }
        ));
        assert!(matches!(
            semantic_primitive_set(&[Primitive::Number(-0.0)]),
            SemanticValue::Unknown {
                resource_limit: None,
                ..
            }
        ));
    }
}
