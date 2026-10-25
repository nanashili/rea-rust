//! Small, syntax-owned Electron value helpers.
//!
//! These helpers deliberately never evaluate JavaScript.  They preserve the
//! source expression when a value cannot be proven literal, matching the
//! Electron static-analysis boundary in the TypeScript implementation.

use std::collections::BTreeSet;

use super::helpers::source_slice;
use crate::javascript::ast::{AstContext, Field, Node};
use crate::javascript::contracts::static_analysis::StaticValue;
use crate::javascript::semantic::ast_values::{read_exact_literal, static_property_key};
use crate::javascript::semantic::value_types::{JsString, Primitive};

pub fn bounded_expression(context: &AstContext<'_>, node: Option<Node<'_>>) -> String {
    let Some(node) = node else {
        return "[missing-expression]".to_owned();
    };
    let expression = source_slice(context, &node).trim();
    if expression.is_empty() {
        format!("[{}]", node.babel_type())
    } else {
        expression.to_owned()
    }
}

pub fn electron_static_value(context: &AstContext<'_>, node: Option<Node<'_>>) -> StaticValue {
    let Some(node) = node else {
        return dynamic_value(context, None);
    };
    let literal = read_exact_literal(context.source(), node).or_else(|| {
        if node.babel_type() != "UnaryExpression"
            || !source_slice(context, &node).trim_start().starts_with('-')
        {
            return None;
        }
        let argument = node.field(context.source(), Field::Argument)?;
        match read_exact_literal(context.source(), argument)? {
            crate::javascript::semantic::ast_values::ExactLiteral::Number(value)
                if value.is_finite() && value != 0.0 =>
            {
                Some(crate::javascript::semantic::ast_values::ExactLiteral::Number(-value))
            }
            _ => None,
        }
    });
    if let Some(value) = literal {
        let value = match value {
            crate::javascript::semantic::ast_values::ExactLiteral::String(value) => {
                Primitive::String(value)
            }
            crate::javascript::semantic::ast_values::ExactLiteral::Number(value) => {
                Primitive::Number(value)
            }
            crate::javascript::semantic::ast_values::ExactLiteral::Boolean(value) => {
                Primitive::Boolean(value)
            }
            crate::javascript::semantic::ast_values::ExactLiteral::Null => Primitive::Null,
        };
        return StaticValue {
            status: "literal".to_owned(),
            value,
            expression: None,
        };
    }
    dynamic_value(context, Some(node))
}

fn dynamic_value(context: &AstContext<'_>, node: Option<Node<'_>>) -> StaticValue {
    StaticValue {
        status: "dynamic".to_owned(),
        value: Primitive::Null,
        expression: Some(JsString::from(bounded_expression(context, node))),
    }
}

pub fn handler_kind(node: Option<Node<'_>>) -> &'static str {
    let Some(node) = node else { return "missing" };
    match node.babel_type() {
        "ArrowFunctionExpression" | "FunctionExpression" | "FunctionDeclaration" => {
            "inline-function"
        }
        "Identifier" => "identifier",
        "MemberExpression" | "OptionalMemberExpression" => "member-expression",
        _ => "dynamic-expression",
    }
}

pub fn member_path(context: &AstContext<'_>, callee: Node<'_>) -> Option<Vec<String>> {
    let mut members = Vec::new();
    let mut current = callee;
    loop {
        if current.babel_type() != "MemberExpression"
            && current.babel_type() != "OptionalMemberExpression"
        {
            break;
        }
        let property = current.field(context.source(), Field::Property)?;
        let key = static_property_key(context.source(), property, current.computed())?;
        if key.is_empty() {
            return None;
        }
        members.push(key.try_to_string().ok()?);
        current = current.field(context.source(), Field::Object)?;
    }
    if let Some(name) = current.identifier_name() {
        members.push(name.to_owned());
    }
    if members.is_empty() {
        return None;
    }
    members.reverse();
    Some(members)
}

/// Resolve a callee against the semantic Electron export map used by the
/// TypeScript analyzer. The map is intentionally supplied by the caller so
/// this syntax helper never invents module identity from a familiar name.
pub fn electron_callee_path(
    context: &AstContext<'_>,
    callee: Node<'_>,
    exports: &std::collections::HashMap<u32, Vec<String>>,
) -> Option<Vec<String>> {
    let mut members = Vec::new();
    let mut root = callee;
    while root.babel_type() == "MemberExpression" || root.babel_type() == "OptionalMemberExpression"
    {
        let property = root.field(context.source(), Field::Property)?;
        let key = static_property_key(context.source(), property, root.computed())?;
        if key.is_empty() {
            return None;
        }
        members.push(key.try_to_string().ok()?);
        root = root.field(context.source(), Field::Object)?;
    }
    let mut path = exports.get(&context.start(&root))?.clone();
    members.reverse();
    path.extend(members);
    Some(path)
}

/// Collect dotted members from a literal contextBridge API object.
pub fn collect_context_bridge_members(
    context: &AstContext<'_>,
    node: Option<Node<'_>>,
) -> (String, Vec<JsString>, u64) {
    let Some(node) = node else {
        return ("missing".to_owned(), Vec::new(), 0);
    };
    if node.babel_type() != "ObjectExpression" {
        return ("dynamic".to_owned(), Vec::new(), 1);
    }
    let mut members = BTreeSet::new();
    let mut unknown = 0_u64;
    collect_members_at(context, node, &[], &mut members, &mut unknown);
    (
        "object-literal".to_owned(),
        members.into_iter().collect(),
        unknown,
    )
}

fn collect_members_at(
    context: &AstContext<'_>,
    object: Node<'_>,
    prefix: &[JsString],
    members: &mut BTreeSet<JsString>,
    unknown: &mut u64,
) {
    if prefix.len() >= 8 {
        *unknown += 1;
        return;
    }
    for property in object
        .field_list(context.source(), Field::Properties)
        .into_iter()
        .flatten()
    {
        if property.babel_type() == "SpreadElement" {
            *unknown += 1;
            continue;
        }
        let Some(key_node) = property.field(context.source(), Field::Key) else {
            *unknown += 1;
            continue;
        };
        let Some(name) = static_property_key(context.source(), key_node, property.computed())
        else {
            *unknown += 1;
            continue;
        };
        if property.babel_type() == "ObjectProperty"
            && !property.computed()
            && !property.shorthand()
            && name == "__proto__"
        {
            continue;
        }
        let mut path = prefix.to_vec();
        path.push(name);
        let path_text = join_js_path(&path);
        members.insert(path_text);
        if property.babel_type() == "ObjectProperty" {
            if let Some(value) = property.field(context.source(), Field::Value) {
                if value.babel_type() == "ObjectExpression" {
                    collect_members_at(context, value, &path, members, unknown);
                }
            }
        }
    }
}

fn join_js_path(path: &[JsString]) -> JsString {
    let mut result = JsString::from("");
    for (index, segment) in path.iter().enumerate() {
        if index != 0 {
            result = result.concat(&JsString::from("."));
        }
        result = result.concat(segment);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::electron_static_value;
    use crate::javascript::ast::{AstContext, Field};
    use crate::javascript::parser::parse_javascript_analysis_program;
    use crate::javascript::semantic::value_types::{JsString, Primitive};
    use oxc_allocator::Allocator;

    #[test]
    fn preserves_lone_surrogate_static_string() {
        let allocator = Allocator::default();
        let parsed =
            parse_javascript_analysis_program(&allocator, r#"("\uD800");"#, Some("preload.js"))
                .expect("parse");
        let context = AstContext::new(parsed.program);
        let statement = context.children(&context.root())[0];
        let expression = statement
            .field(context.source(), Field::Expression)
            .expect("expression");

        let value = electron_static_value(&context, Some(expression));

        assert_eq!(
            value.value,
            Primitive::String(JsString::from_utf16([0xd800]))
        );
        let serialized = serde_json::to_string(&value).expect("serialize exact static value");
        assert!(serialized.contains("\\ud800"));
    }
}
