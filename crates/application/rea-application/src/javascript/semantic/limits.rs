//! Resource bounds from `javascriptSemanticResourceLimits.ts`.

use super::ast_values::js_number_string;

/// `SEMANTIC_EXPRESSION_DEPTH_LIMIT`, compared with `>`.
pub const SEMANTIC_EXPRESSION_DEPTH_LIMIT: usize = 256;
pub const SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT: usize = 256;
pub const SEMANTIC_GETTER_EXPANSION_LIMIT: usize = 512;
pub const SEMANTIC_PRIMITIVE_JSON_BYTES_LIMIT: usize = 1_048_576;

pub fn primitive_json_string_bytes(code_units: usize) -> usize {
    code_units.saturating_mul(6).saturating_add(2)
}

pub fn exceeds_primitive_string_byte_budget(strings: &[super::value_types::JsString]) -> bool {
    let mut total = 0usize;
    for value in strings {
        total = total.saturating_add(primitive_json_string_bytes(value.len()));
        if total > SEMANTIC_PRIMITIVE_JSON_BYTES_LIMIT {
            return true;
        }
    }
    false
}

/// Bound every string result from primitive pairwise addition before allocation.
pub fn exceeds_primitive_addition_byte_budget(
    left: &[super::value_types::Primitive],
    right: &[super::value_types::Primitive],
) -> bool {
    let mut total = 0usize;
    for left_value in left {
        for right_value in right {
            if !matches!(left_value, super::value_types::Primitive::String(_))
                && !matches!(right_value, super::value_types::Primitive::String(_))
            {
                continue;
            }
            let length = primitive_string_length(left_value) + primitive_string_length(right_value);
            total = total.saturating_add(primitive_json_string_bytes(length));
            if total > SEMANTIC_PRIMITIVE_JSON_BYTES_LIMIT {
                return true;
            }
        }
    }
    false
}

/// Bound template interpolation results before constructing concatenated values.
pub fn exceeds_template_byte_budget(
    prefixes: &[super::value_types::JsString],
    suffixes: &[super::value_types::JsString],
) -> bool {
    let mut total = 0usize;
    for prefix in prefixes {
        for suffix in suffixes {
            total = total.saturating_add(primitive_json_string_bytes(prefix.len() + suffix.len()));
            if total > SEMANTIC_PRIMITIVE_JSON_BYTES_LIMIT {
                return true;
            }
        }
    }
    false
}

fn primitive_string_length(value: &super::value_types::Primitive) -> usize {
    match value {
        super::value_types::Primitive::String(value) => value.len(),
        super::value_types::Primitive::Number(value) => {
            js_number_string(*value).encode_utf16().count()
        }
        super::value_types::Primitive::Boolean(value) => {
            if *value {
                4
            } else {
                5
            }
        }
        super::value_types::Primitive::Null => 4,
    }
}

pub fn resource_limit_reason(limit: super::value_types::ResourceLimit) -> &'static str {
    match limit {
        super::value_types::ResourceLimit::PrimitiveCandidates => {
            "Primitive candidate budget exceeded (maximum 256 alternatives)."
        }
        super::value_types::ResourceLimit::PrimitiveBytes => {
            "Primitive string-byte budget exceeded (maximum 1048576 estimated JSON bytes)."
        }
        super::value_types::ResourceLimit::ExpressionDepth => {
            "Semantic expression depth budget exceeded (maximum 256 nested expressions)."
        }
        super::value_types::ResourceLimit::GetterExpansion => {
            "Getter expansion was conservatively bounded (maximum 512 scheduled states or a growing receiver cycle)."
        }
    }
}
