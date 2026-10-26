//! Expression-level operations for the semantic value lattice.
//!
//! The stateful evaluator owns binding lookup, capture points, and recursion
//! accounting.  This module keeps the expression cases themselves small and
//! deterministic so those concerns do not get mixed into object/member
//! interpretation.

use super::super::ast_values::static_property_key;
use super::super::ast_values::{ExactLiteral, read_exact_literal, unwrap_expression};
use super::super::limits::{
    SEMANTIC_EXPRESSION_DEPTH_LIMIT, SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT,
    exceeds_primitive_addition_byte_budget, exceeds_template_byte_budget, resource_limit_reason,
};
use super::super::mutation_initializers::BindingReadStatus;
use super::super::opaque_effects::opaque_binding_read_may_have_changed;
use super::super::primitives::{semantic_primitive_candidates, semantic_primitive_set};
use super::super::slots::semantic_slot_at_path;
use super::super::state::DefinitionKind;
use super::super::state::ProjectionKey;
use super::super::value_types::{
    Coverage, JsString, Primitive, Property, ResourceLimit, SemanticValue, SlotPresence,
};
use crate::javascript::ast::{Field, Node};
use crate::javascript::graph::json::compare_code_points;

/// The small callback needed while evaluating a nested expression.
pub(crate) fn evaluate_template<'a, F>(
    source: &'a str,
    node: Node<'a>,
    read: &mut F,
) -> SemanticValue
where
    F: FnMut(Node<'a>) -> SemanticValue,
{
    let mut candidates = vec![JsString::from_utf16(Vec::new())];
    let quasis = node.field_list(source, Field::Quasis);
    let expressions = node.field_list(source, Field::Expressions);

    for (index, quasi) in quasis.into_iter().enumerate() {
        let Some(quasi) = quasi else {
            return unknown("Template text has no cooked representation.");
        };
        let Some(text) = quasi.template_cooked_units() else {
            return unknown("Template text has no cooked representation.");
        };
        let text = JsString::from_utf16(text);
        if exceeds_template_byte_budget(&candidates, std::slice::from_ref(&text)) {
            return limited(ResourceLimit::PrimitiveBytes);
        }
        for candidate in &mut candidates {
            candidate.extend(&text);
        }

        let Some(expression) = expressions.get(index).copied().flatten() else {
            continue;
        };
        let evaluated = read(expression);
        let Some(values) = semantic_primitive_candidates(&evaluated) else {
            return if is_resource_limit(&evaluated) {
                evaluated
            } else {
                unknown("Template expression is not a bounded primitive.")
            };
        };
        if candidates.len() > SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT / values.len().max(1) {
            return limited(ResourceLimit::PrimitiveCandidates);
        }
        let suffixes = values
            .iter()
            .map(primitive_to_js_string)
            .collect::<Vec<_>>();
        if exceeds_template_byte_budget(&candidates, &suffixes) {
            return limited(ResourceLimit::PrimitiveBytes);
        }
        candidates = candidates
            .into_iter()
            .flat_map(|prefix| suffixes.iter().map(move |suffix| prefix.concat(suffix)))
            .collect();
    }

    semantic_primitive_set(
        &candidates
            .into_iter()
            .map(|value| Primitive::String(value.into()))
            .collect::<Vec<_>>(),
    )
}

pub(crate) fn evaluate_object<'a, F>(
    source: &'a str,
    node: Node<'a>,
    demanded_key: Option<&JsString>,
    read: &mut F,
) -> SemanticValue
where
    F: FnMut(Node<'a>) -> SemanticValue,
{
    let mut properties = Vec::<Property>::new();
    let mut unknown_properties = false;
    let mut omitted_properties = Some(0usize);
    let source_properties = node.field_list(source, Field::Properties);
    let demanded_property = demanded_key.and_then(|demanded| {
        source_properties
            .iter()
            .copied()
            .flatten()
            .rev()
            .find(|property| {
                property
                    .field(source, Field::Key)
                    .and_then(|key| static_property_key(source, key, property.computed()))
                    .is_some_and(|key| &key == demanded)
            })
            .map(|property| property.key())
    });

    for property in source_properties.into_iter().flatten() {
        if property.babel_type() == "SpreadElement" {
            unknown_properties = true;
            omitted_properties = None;
            invalidate_earlier_properties(&mut properties);
            continue;
        }
        let Some(key) = property
            .field(source, Field::Key)
            .and_then(|key| static_property_key(source, key, property.computed()))
        else {
            unknown_properties = true;
            if let Some(omitted) = &mut omitted_properties {
                *omitted += 1;
            }
            invalidate_earlier_properties(&mut properties);
            continue;
        };

        if demanded_key.is_some_and(|demanded| demanded != &key)
            || demanded_property.is_some_and(|selected| selected != property.key())
        {
            continue;
        }
        if property.babel_type() == "ObjectProperty"
            && !property.computed()
            && !property.shorthand()
            && key == "__proto__"
        {
            unknown_properties = true;
            if let Some(omitted) = &mut omitted_properties {
                *omitted += 1;
            }
            continue;
        }
        let value = if property.babel_type() == "ObjectProperty" {
            property
                .field(source, Field::Value)
                .map_or_else(|| unknown("Object property has no value."), &mut *read)
        } else {
            unknown("Object method or accessor value is not a primitive.")
        };
        if let Some(existing) = properties.iter_mut().find(|entry| entry.name == key) {
            existing.value = value;
            existing.presence = SlotPresence::Present;
        } else {
            properties.push(Property {
                name: key,
                presence: SlotPresence::Present,
                value,
            });
        }
    }

    properties.sort_by(|left, right| compare_js_strings(&left.name, &right.name));
    SemanticValue::Object {
        properties: properties.into(),
        coverage: if unknown_properties {
            Coverage::Unknown {
                omitted: omitted_properties,
            }
        } else {
            Coverage::Exact
        },
    }
}

pub(crate) fn evaluate_array<'a, F>(source: &'a str, node: Node<'a>, read: &mut F) -> SemanticValue
where
    F: FnMut(Node<'a>) -> SemanticValue,
{
    let mut items = Vec::new();
    let mut unknown_items = false;
    let mut omitted_items = Some(0usize);
    for element in node.field_list(source, Field::Elements) {
        let index = JsString::from(items.len().to_string());
        let Some(element) = element else {
            items.push(Property {
                name: index,
                presence: SlotPresence::Absent,
                value: unknown("Array hole has no own value."),
            });
            continue;
        };
        if element.babel_type() == "SpreadElement" {
            unknown_items = true;
            omitted_items = None;
            break;
        }
        items.push(Property {
            name: index,
            presence: SlotPresence::Present,
            value: read(element),
        });
    }
    SemanticValue::Array {
        items: items.into(),
        coverage: if unknown_items {
            Coverage::Unknown {
                omitted: omitted_items,
            }
        } else {
            Coverage::Exact
        },
    }
}

pub(crate) fn evaluate_member<'a, F>(source: &'a str, node: Node<'a>, read: &mut F) -> SemanticValue
where
    F: FnMut(Node<'a>) -> SemanticValue,
{
    let mut keys = Vec::new();
    let mut current = node;
    while matches!(
        current.babel_type(),
        "MemberExpression" | "OptionalMemberExpression"
    ) {
        let Some(object) = current.field(source, Field::Object) else {
            return unknown("Unsupported member base.");
        };
        let Some(property) = current.field(source, Field::Property) else {
            return unknown("Dynamic member key.");
        };
        let Some(key) = static_property_key(source, property, current.computed()) else {
            return unknown("Dynamic member key.");
        };
        keys.push(key);
        current = object;
    }
    let mut value = read(current);
    for key in keys.iter().rev() {
        value = project_value(value, &[ProjectionKey::Name(key.clone())]);
    }
    value
}

pub(crate) fn evaluate_addition<'a, F>(
    source: &'a str,
    node: Node<'a>,
    read: &mut F,
) -> SemanticValue
where
    F: FnMut(Node<'a>) -> SemanticValue,
{
    let mut pending = Vec::<(Node<'a>, Option<SemanticValue>)>::new();
    let mut current = node;

    loop {
        if current.babel_type() == "BinaryExpression" && current.operator() == Some("+") {
            pending.push((current, None));
            let Some(left) = current.field(source, Field::Left) else {
                return unknown("Addition has no left operand.");
            };
            current = left;
            continue;
        }

        let mut value = read(current);
        loop {
            let Some((parent, left)) = pending.last_mut() else {
                return value;
            };
            if left.is_none() {
                *left = Some(value);
                let Some(right) = parent.field(source, Field::Right) else {
                    return unknown("Addition has no right operand.");
                };
                current = right;
                break;
            }
            value = add_primitive_values(left.take().expect("checked above"), value);
            pending.pop();
        }
    }
}

pub(crate) fn evaluate_unary<'a, F>(source: &'a str, node: Node<'a>, read: &mut F) -> SemanticValue
where
    F: FnMut(Node<'a>) -> SemanticValue,
{
    let Some(argument) = node.field(source, Field::Argument) else {
        return unknown("Unary expression has no operand.");
    };
    let evaluated = read(argument);
    let Some(values) = semantic_primitive_candidates(&evaluated) else {
        return if is_resource_limit(&evaluated) {
            evaluated
        } else {
            unknown("Non-primitive unary operand.")
        };
    };
    let mapped = values
        .iter()
        .map(|value| match node.operator() {
            Some("!") => Primitive::Boolean(!primitive_truthy(value)),
            Some("+") => Primitive::Number(primitive_to_number(value)),
            Some("-") => Primitive::Number(-primitive_to_number(value)),
            _ => Primitive::String(JsString::from_utf16(Vec::new())),
        })
        .collect::<Vec<_>>();
    if !matches!(node.operator(), Some("!") | Some("+") | Some("-")) {
        return unknown(&format!(
            "Unsupported unary {}.",
            node.operator().unwrap_or("")
        ));
    }
    semantic_primitive_set(&mapped)
}

pub(super) fn project_value(value: SemanticValue, projection: &[ProjectionKey]) -> SemanticValue {
    if is_resource_limit(&value) {
        return value;
    }
    let path = projection
        .iter()
        .map(|key| match key {
            ProjectionKey::Name(name) => name.clone(),
            ProjectionKey::Index(index) => JsString::from(index.to_string()),
            ProjectionKey::Dynamic => JsString::from_utf16(Vec::new()),
        })
        .collect::<Vec<_>>();
    if projection
        .iter()
        .any(|key| matches!(key, ProjectionKey::Dynamic))
    {
        return unknown("Cannot project a dynamic property.");
    }
    let slot = semantic_slot_at_path(&value, &path);
    if slot.presence == SlotPresence::Present || is_resource_limit(&slot.value) {
        slot.value
    } else {
        let presence = match slot.presence {
            SlotPresence::Absent => "absent",
            SlotPresence::UnknownCoverage => "unknown-coverage",
            SlotPresence::Present => "present",
        };
        let reason = JsString::from("Own property ")
            .concat(&join_projection_path(&path))
            .concat(&JsString::from(" is "))
            .concat(&JsString::from(presence))
            .concat(&JsString::from("."));
        unknown(reason)
    }
}

pub(super) fn merge_values(values: impl IntoIterator<Item = SemanticValue>) -> SemanticValue {
    let values = values.into_iter().collect::<Vec<_>>();
    if let Some(limit) = values.iter().find(|value| is_resource_limit(value)) {
        return limit.clone();
    }
    if values.iter().all(|value| {
        matches!(
            value,
            SemanticValue::Literal { .. } | SemanticValue::Union { .. }
        )
    }) {
        let primitives = values
            .into_iter()
            .flat_map(|value| match value {
                SemanticValue::Literal { value } => vec![value],
                SemanticValue::Union { values } => values,
                _ => Vec::new(),
            })
            .collect::<Vec<_>>();
        return semantic_primitive_set(&primitives);
    }
    SemanticValue::Ambiguous {
        reason: JsString::from("Branches have incompatible values."),
        resource_limit: None,
    }
}

fn add_primitive_values(left: SemanticValue, right: SemanticValue) -> SemanticValue {
    let left_candidates = semantic_primitive_candidates(&left);
    let right_candidates = semantic_primitive_candidates(&right);
    let (Some(left), Some(right)) = (left_candidates, right_candidates) else {
        if is_resource_limit(&left) {
            return left;
        }
        if is_resource_limit(&right) {
            return right;
        }
        return unknown("Non-primitive addition.");
    };
    if left.len() > SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT / right.len().max(1) {
        return limited(ResourceLimit::PrimitiveCandidates);
    }
    if exceeds_primitive_addition_byte_budget(&left, &right) {
        return limited(ResourceLimit::PrimitiveBytes);
    }
    let values = left
        .iter()
        .flat_map(|left| {
            right.iter().map(move |right| {
                if matches!(left, Primitive::String(_)) || matches!(right, Primitive::String(_)) {
                    Primitive::String(
                        primitive_to_js_string(left).concat(&primitive_to_js_string(right)),
                    )
                } else {
                    Primitive::Number(primitive_to_number(left) + primitive_to_number(right))
                }
            })
        })
        .collect::<Vec<_>>();
    semantic_primitive_set(&values)
}

fn invalidate_earlier_properties(properties: &mut [Property]) {
    for property in properties {
        property.value = unknown("A later property may overwrite this value.");
        property.presence = SlotPresence::Present;
    }
}

fn primitive_truthy(value: &Primitive) -> bool {
    match value {
        Primitive::String(value) => !value.is_empty(),
        Primitive::Number(value) => *value != 0.0 && !value.is_nan(),
        Primitive::Boolean(value) => *value,
        Primitive::Null => false,
    }
}

fn primitive_to_number(value: &Primitive) -> f64 {
    match value {
        Primitive::Number(value) => *value,
        Primitive::Boolean(value) => f64::from(*value),
        Primitive::Null => 0.0,
        Primitive::String(value) => javascript_number(value),
    }
}

fn javascript_number(value: &JsString) -> f64 {
    let Ok(value) = String::from_utf16(value.units()) else {
        return f64::NAN;
    };
    let value = value.trim_matches(is_javascript_whitespace);
    if value.is_empty() {
        return 0.0;
    }
    if matches!(value, "Infinity" | "+Infinity") {
        return f64::INFINITY;
    }
    if value == "-Infinity" {
        return f64::NEG_INFINITY;
    }

    let (radix, digits) = match value.as_bytes() {
        [b'0', b'x' | b'X', rest @ ..] => (Some(16), rest),
        [b'0', b'b' | b'B', rest @ ..] => (Some(2), rest),
        [b'0', b'o' | b'O', rest @ ..] => (Some(8), rest),
        _ => (None, value.as_bytes()),
    };
    if let Some(radix) = radix {
        if digits.is_empty() {
            return f64::NAN;
        }
        let mut number = 0.0;
        for digit in digits {
            let Some(digit) = (*digit as char).to_digit(radix) else {
                return f64::NAN;
            };
            number = number * f64::from(radix) + f64::from(digit);
        }
        return number;
    }
    if value.eq_ignore_ascii_case("inf")
        || value.eq_ignore_ascii_case("+inf")
        || value.eq_ignore_ascii_case("-inf")
        || value.eq_ignore_ascii_case("infinity")
        || value.eq_ignore_ascii_case("+infinity")
        || value.eq_ignore_ascii_case("-infinity")
    {
        return f64::NAN;
    }

    value.parse::<f64>().unwrap_or(f64::NAN)
}

fn is_javascript_whitespace(character: char) -> bool {
    matches!(
        character,
        '\u{0009}'..='\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
            | '\u{FEFF}'
    )
}

fn primitive_to_js_string(value: &Primitive) -> JsString {
    match value {
        Primitive::String(value) => value.clone(),
        Primitive::Number(value) => {
            JsString::from(super::super::ast_values::js_number_string(*value))
        }
        Primitive::Boolean(value) => JsString::from(value.to_string()),
        Primitive::Null => JsString::from("null"),
    }
}

fn unknown(reason: impl Into<JsString>) -> SemanticValue {
    SemanticValue::Unknown {
        reason: reason.into(),
        resource_limit: None,
    }
}

fn limited(limit: ResourceLimit) -> SemanticValue {
    SemanticValue::Unknown {
        reason: JsString::from(resource_limit_reason(limit.clone())),
        resource_limit: Some(limit),
    }
}

fn join_projection_path(path: &[JsString]) -> JsString {
    let mut result = JsString::from_utf16(Vec::new());
    for (index, segment) in path.iter().enumerate() {
        if index > 0 {
            result = result.concat(&JsString::from("/"));
        }
        result = result.concat(segment);
    }
    result
}

fn compare_js_strings(left: &JsString, right: &JsString) -> std::cmp::Ordering {
    if let (Ok(left_text), Ok(right_text)) = (
        String::from_utf16(left.units()),
        String::from_utf16(right.units()),
    ) {
        return compare_code_points(&left_text, &right_text);
    }
    left.units().cmp(right.units())
}

fn is_resource_limit(value: &SemanticValue) -> bool {
    matches!(
        value,
        SemanticValue::Unknown {
            resource_limit: Some(_),
            ..
        }
    )
}

impl<'s, 'a> super::Evaluation<'s, 'a> {
    pub(super) fn expression_value(
        &mut self,
        node: Node<'a>,
        point: super::EvaluationPoint<'a>,
    ) -> SemanticValue {
        if point.depth > SEMANTIC_EXPRESSION_DEPTH_LIMIT {
            self.lowest = -1;
            return limited(ResourceLimit::ExpressionDepth);
        }

        let unwrapped = unwrap_expression(self.state.source, node, false);
        if unwrapped.depth > 0 {
            if point.depth + unwrapped.depth > SEMANTIC_EXPRESSION_DEPTH_LIMIT {
                self.lowest = -1;
                return limited(ResourceLimit::ExpressionDepth);
            }
            return self.evaluate_expression(
                unwrapped.node,
                super::EvaluationPoint {
                    depth: point.depth + unwrapped.depth,
                    ..point
                },
            );
        }

        if let Some(units) = unwrapped.node.string_value_units() {
            return semantic_primitive_set(&[Primitive::String(JsString::from_utf16(units))]);
        }

        if node.babel_type() != "TemplateLiteral"
            && let Some(literal) = read_exact_literal(self.state.source, node)
        {
            return exact_literal_value(literal);
        }

        match node.babel_type() {
            "Identifier" => self.evaluate_identifier(node, point),
            "TemplateLiteral" => evaluate_template(self.state.source, node, &mut |expression| {
                self.evaluate_expression(expression, point.nested())
            }),
            "ConditionalExpression" | "LogicalExpression" => {
                let source = self.state.source;
                let (left, right) = if node.babel_type() == "ConditionalExpression" {
                    let Some(_condition) = node.field(source, Field::Test) else {
                        return unknown("Conditional expression has no test.");
                    };
                    let Some(left) = node.field(source, Field::Consequent) else {
                        return unknown("Conditional expression has no consequent.");
                    };
                    let Some(right) = node.field(source, Field::Alternate) else {
                        return unknown("Conditional expression has no alternate.");
                    };
                    (left, right)
                } else {
                    let Some(left) = node.field(source, Field::Left) else {
                        return unknown("Expression has no left branch.");
                    };
                    let Some(right) = node.field(source, Field::Right) else {
                        return unknown("Expression has no right branch.");
                    };
                    (left, right)
                };
                merge_values([
                    self.evaluate_expression(left, point.nested()),
                    self.evaluate_expression(right, point.nested()),
                ])
            }
            "ObjectExpression" => {
                let demanded_path = self.demanded_member_path.take();
                let demanded_key = demanded_path
                    .as_deref()
                    .and_then(|path| path.first())
                    .cloned();
                let remaining_path = demanded_path
                    .as_deref()
                    .filter(|path| !path.is_empty())
                    .map(|path| path[1..].to_vec());
                evaluate_object(
                    self.state.source,
                    node,
                    demanded_key.as_ref(),
                    &mut |expression| {
                        let previous_path = std::mem::replace(
                            &mut self.demanded_member_path,
                            remaining_path.clone(),
                        );
                        let value = self.captured_expression(expression, point.nested());
                        self.demanded_member_path = previous_path;
                        value
                    },
                )
            }
            "ArrayExpression" => evaluate_array(self.state.source, node, &mut |expression| {
                self.captured_expression(expression, point.nested())
            }),
            "MemberExpression" | "OptionalMemberExpression" => {
                let mut keys = Vec::new();
                let mut current = node;
                while matches!(
                    current.babel_type(),
                    "MemberExpression" | "OptionalMemberExpression"
                ) {
                    let Some(property) = current.field(self.state.source, Field::Property) else {
                        break;
                    };
                    let Some(key) =
                        static_property_key(self.state.source, property, current.computed())
                    else {
                        break;
                    };
                    keys.push(key);
                    let Some(object) = current.field(self.state.source, Field::Object) else {
                        break;
                    };
                    current = object;
                }
                let demanded_path = keys.into_iter().rev().collect::<Vec<_>>();
                let previous_path = self.demanded_member_path.replace(demanded_path);
                let value = evaluate_member(self.state.source, node, &mut |expression| {
                    self.evaluate_expression(expression, point.nested())
                });
                self.demanded_member_path = previous_path;
                value
            }
            "BinaryExpression" if node.operator() == Some("+") => {
                evaluate_addition(self.state.source, node, &mut |expression| {
                    self.evaluate_expression(expression, point.nested())
                })
            }
            "UnaryExpression" => evaluate_unary(self.state.source, node, &mut |expression| {
                self.evaluate_expression(expression, point.nested())
            }),
            _ => unknown(&format!("Unsupported {} value.", node.babel_type())),
        }
    }

    fn evaluate_identifier(
        &mut self,
        node: Node<'a>,
        point: super::EvaluationPoint<'a>,
    ) -> SemanticValue {
        let Some(name) = node.identifier_name() else {
            return unknown("Identifier has no name.");
        };
        let state = self.state;
        let Some(index) = state.resolve_binding(&node, name) else {
            return unknown(&format!("Unbound identifier {name}."));
        };
        let binding = state.binding(index);

        let has_assignment_definition = binding
            .definitions
            .iter()
            .any(|definition| definition.kind == DefinitionKind::Assignment);
        let read = (binding.mutable && has_assignment_definition)
            .then(|| state.semantic_binding_at_read(binding, node));

        if read
            .as_ref()
            .is_some_and(|selected| selected.status == BindingReadStatus::Unresolved)
        {
            let value = self.evaluate_binding(binding, point.nested(), true);
            if matches!(
                value,
                SemanticValue::Unknown { .. }
                    | SemanticValue::Ambiguous { .. }
                    | SemanticValue::Cycle { .. }
            ) {
                return value;
            }
            return unknown(&format!(
                "Binding {} has unresolved ordering at this read.",
                binding.name
            ));
        }

        let capture_point = point.capture_point.unwrap_or(node);
        if opaque_binding_read_may_have_changed(self.opaque.as_ref(), state, binding, capture_point)
        {
            return unknown("Direct eval may have changed this lexical binding.");
        }

        let at_read = read
            .as_ref()
            .map_or(binding, |selected| selected.binding.as_ref());
        self.evaluate_binding(
            at_read,
            point.nested(),
            read.as_ref()
                .is_none_or(|selected| !selected.selection_changed),
        )
    }
}

fn exact_literal_value(literal: ExactLiteral) -> SemanticValue {
    let primitive = match literal {
        ExactLiteral::String(value) => Primitive::String(value),
        ExactLiteral::Number(value) => Primitive::Number(value),
        ExactLiteral::Boolean(value) => Primitive::Boolean(value),
        ExactLiteral::Null => Primitive::Null,
    };
    semantic_primitive_set(&[primitive])
}
