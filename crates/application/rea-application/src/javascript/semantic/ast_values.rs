//! Port of `javascriptAstValues.ts`: syntax-only reads over the Babel view.

use crate::javascript::ast::{Field, Node, NodeKind};

use super::limits::SEMANTIC_EXPRESSION_DEPTH_LIMIT;
use super::value_types::JsString;

/// Babel `t.isFunction` (the `Function` alias).
pub fn is_function(node: &Node<'_>) -> bool {
    matches!(
        node.babel_type(),
        "FunctionDeclaration"
            | "FunctionExpression"
            | "ArrowFunctionExpression"
            | "ObjectMethod"
            | "ClassMethod"
            | "ClassPrivateMethod"
    )
}

/// Babel `t.isClass`.
pub fn is_class(node: &Node<'_>) -> bool {
    matches!(node.babel_type(), "ClassDeclaration" | "ClassExpression")
}

/// Whether TypeScript removes this declaration from emitted runtime code.
///
/// This mirrors `isErasedJavaScriptDeclaration`; the parser's Babel-shaped
/// node type owns the distinction between a runtime function declaration and
/// `TSDeclareFunction`.
pub fn is_erased_declaration(node: Node<'_>) -> bool {
    if matches!(
        node.babel_type(),
        "TSInterfaceDeclaration" | "TSTypeAliasDeclaration" | "TSDeclareFunction"
    ) {
        return true;
    }

    match node.kind() {
        NodeKind::VariableDeclaration(declaration) => declaration.declare,
        NodeKind::Class(class) => class.declare,
        NodeKind::TSEnumDeclaration(declaration) => declaration.declare,
        NodeKind::TSModuleDeclaration(declaration) => declaration.declare,
        _ => false,
    }
}

/// Whether TypeScript introduces a runtime scope this source model does not
/// represent as an ordinary lexical scope.
pub fn is_unmodeled_runtime_scope(node: Node<'_>) -> bool {
    matches!(
        node.babel_type(),
        "TSModuleDeclaration" | "TSEnumDeclaration"
    )
}

/// Babel `t.isMemberExpression || t.isOptionalMemberExpression`.
pub fn is_member(node: &Node<'_>) -> bool {
    matches!(
        node.babel_type(),
        "MemberExpression" | "OptionalMemberExpression"
    )
}

/// Babel `t.isCallExpression || t.isOptionalCallExpression`.
pub fn is_call(node: &Node<'_>) -> bool {
    matches!(
        node.babel_type(),
        "CallExpression" | "OptionalCallExpression"
    )
}

/// Babel `t.isIdentifier(node, { name })`.
pub fn is_identifier_named(node: &Node<'_>, name: &str) -> bool {
    node.identifier_name() == Some(name)
}

/// `runtimeFunctionParameters`: TypeScript receiver annotations occupy no
/// positional runtime parameter slot.
pub fn runtime_function_parameters<'a>(source: &'a str, function: &Node<'a>) -> Vec<Node<'a>> {
    let mut params: Vec<Node<'a>> = function
        .field_list(source, Field::Params)
        .into_iter()
        .flatten()
        .collect();
    if params
        .first()
        .is_some_and(|first| is_identifier_named(first, "this"))
    {
        params.remove(0);
    }
    params
}

/// `unwrapJavaScriptExpression` result: the runtime expression and the
/// number of transparent wrappers removed.
#[derive(Clone, Copy, Debug)]
pub struct Unwrapped<'a> {
    pub node: Node<'a>,
    pub depth: usize,
}

const TYPE_WRAPPERS: [&str; 5] = [
    "TSAsExpression",
    "TSTypeAssertion",
    "TSNonNullExpression",
    "TSSatisfiesExpression",
    "TSInstantiationExpression",
];

/// `unwrapJavaScriptExpression`. Babel analysis inputs have no
/// `ParenthesizedExpression` nodes (and no Flow `TypeCastExpression` in
/// oxc), so only TypeScript wrappers are removed; `stop_at_parentheses`
/// stops at a wrapper Babel marks `extra.parenthesized`.
pub fn unwrap_expression<'a>(
    source: &'a str,
    node: Node<'a>,
    stop_at_parentheses: bool,
) -> Unwrapped<'a> {
    let mut current = node;
    let mut depth = 0;
    while TYPE_WRAPPERS.contains(&current.babel_type()) {
        if stop_at_parentheses && current.parenthesized() {
            break;
        }
        match current.field(source, Field::Expression) {
            Some(inner) => current = inner,
            None => break,
        }
        depth += 1;
    }
    Unwrapped {
        node: current,
        depth,
    }
}

/// `unwrapJavaScriptExpression(node).node`.
pub fn unwrapped<'a>(source: &'a str, node: Node<'a>) -> Node<'a> {
    unwrap_expression(source, node, false).node
}

/// A syntax-level primitive read by [`read_exact_literal`]
/// (`JavaScriptSemanticPrimitive` without `undefined`).
#[derive(Clone, Debug, PartialEq)]
pub enum ExactLiteral {
    String(JsString),
    Number(f64),
    Boolean(bool),
    Null,
}

/// `readExactJavaScriptLiteral`.
pub fn read_exact_literal(source: &str, node: Node<'_>) -> Option<ExactLiteral> {
    let node = unwrapped(source, node);
    match node.babel_type() {
        "StringLiteral" => node
            .string_value_units()
            .map(JsString::from_utf16)
            .map(ExactLiteral::String),
        "NumericLiteral" => node
            .numeric_value()
            .filter(|value| value.is_finite())
            .map(ExactLiteral::Number),
        "BooleanLiteral" => node.boolean_value().map(ExactLiteral::Boolean),
        "NullLiteral" => Some(ExactLiteral::Null),
        "TemplateLiteral" => single_quasi_cooked_units(source, &node).map(ExactLiteral::String),
        _ => None,
    }
}

fn single_quasi_cooked_units(source: &str, node: &Node<'_>) -> Option<JsString> {
    if !node.field_list(source, Field::Expressions).is_empty() {
        return None;
    }
    let quasis = node.field_list(source, Field::Quasis);
    match quasis.as_slice() {
        [Some(quasi)] => quasi.template_cooked_units().map(JsString::from_utf16),
        _ => None,
    }
}

/// JavaScript `String(number)`.
pub fn js_number_string(value: f64) -> String {
    if value == 0.0 {
        return "0".to_owned();
    }
    ryu_js::Buffer::new().format(value).to_owned()
}

/// `propertyName`, preserving JavaScript UTF-16 units.
pub fn property_name(node: &Node<'_>) -> JsString {
    if let Some(name) = node.identifier_name() {
        return JsString::from(name);
    }
    if let Some(value) = node.string_value_units() {
        return JsString::from_utf16(value);
    }
    if let Some(value) = node.numeric_value() {
        return JsString::from(js_number_string(value));
    }
    JsString::from("")
}

/// `semanticStaticPropertyName`, preserving JavaScript UTF-16 units.
pub fn static_property_name(source: &str, property: Node<'_>, computed: bool) -> JsString {
    static_property_key(source, property, computed).unwrap_or_else(|| JsString::from(""))
}

/// `semanticStaticPropertyKey`: an exact property key, preserving the legal
/// empty-string key and every UTF-16 code unit.
pub fn static_property_key(source: &str, property: Node<'_>, computed: bool) -> Option<JsString> {
    let property = unwrapped(source, property);
    match property.babel_type() {
        "StringLiteral" => property.string_value_units().map(JsString::from_utf16),
        "NumericLiteral" => property
            .numeric_value()
            .map(js_number_string)
            .map(JsString::from),
        "BooleanLiteral" => property
            .boolean_value()
            .map(|value| JsString::from(if value { "true" } else { "false" })),
        "NullLiteral" => Some(JsString::from("null")),
        "BigIntLiteral" => property.bigint_decimal().map(JsString::from),
        "UnaryExpression" => {
            let argument = property
                .field(source, Field::Argument)
                .map(|argument| unwrapped(source, argument));
            match property.operator() {
                Some("void") => Some(JsString::from("undefined")),
                Some("+") => argument
                    .and_then(|argument| argument.numeric_value())
                    .map(js_number_string)
                    .map(JsString::from),
                Some("-") => {
                    if let Some(value) = argument.and_then(|argument| argument.numeric_value()) {
                        return Some(JsString::from(js_number_string(-value)));
                    }
                    argument
                        .and_then(|argument| argument.bigint_decimal())
                        .map(|digits| {
                            if digits.bytes().all(|byte| byte == b'0') {
                                JsString::from("0")
                            } else {
                                JsString::from(format!("-{digits}"))
                            }
                        })
                }
                _ => None,
            }
        }
        "TemplateLiteral" => {
            let expressions = property.field_list(source, Field::Expressions);
            let quasis = property.field_list(source, Field::Quasis);
            if expressions.is_empty() && quasis.len() == 1 {
                return quasis
                    .into_iter()
                    .flatten()
                    .find_map(|quasi| quasi.template_cooked_units())
                    .map(JsString::from_utf16);
            }
            None
        }
        _ if !computed && property.babel_type() == "Identifier" => {
            property.identifier_name().map(JsString::from)
        }
        _ => None,
    }
}

/// The `key`/`computed` pair of a property-like node.
pub fn property_key_of(source: &str, property: &Node<'_>) -> Option<JsString> {
    let key = property.field(source, Field::Key)?;
    static_property_key(source, key, property.computed())
}

/// `isNullishJavaScriptSyntax`.
pub fn is_nullish_syntax<'a>(source: &'a str, node: Node<'a>) -> bool {
    let node = unwrapped(source, node);
    node.babel_type() == "NullLiteral"
        || (node.babel_type() == "UnaryExpression" && node.operator() == Some("void"))
}

/// `staticObjectProperty` result.
#[derive(Clone, Copy, Debug)]
pub enum StaticObjectProperty<'a> {
    Missing,
    Dynamic,
    /// The effective `ObjectProperty`.
    Explicit(Node<'a>),
}

/// `staticObjectProperty`: the effective explicit property, preserving
/// unresolved overrides.
pub fn static_object_property<'a>(
    source: &'a str,
    object: Option<Node<'a>>,
    name: &str,
    is_nullish: Option<&dyn Fn(Node<'a>) -> bool>,
) -> StaticObjectProperty<'a> {
    let Some(object) = object else {
        return StaticObjectProperty::Missing;
    };
    if object.babel_type() != "ObjectExpression" {
        return StaticObjectProperty::Dynamic;
    }
    fn lookup<'a>(
        source: &'a str,
        current: Node<'a>,
        depth: usize,
        name: &str,
        is_nullish: Option<&dyn Fn(Node<'a>) -> bool>,
    ) -> StaticObjectProperty<'a> {
        let properties: Vec<Node<'a>> = current
            .field_list(source, Field::Properties)
            .into_iter()
            .flatten()
            .collect();
        for property in properties.into_iter().rev() {
            if property.babel_type() == "SpreadElement" {
                let Some(argument) = property.field(source, Field::Argument) else {
                    return StaticObjectProperty::Dynamic;
                };
                let Unwrapped {
                    node: spread,
                    depth: wrappers,
                } = unwrap_expression(source, argument, false);
                if spread.babel_type() == "ObjectExpression" {
                    let next_depth = depth + wrappers + 1;
                    let has_getter = spread
                        .field_list(source, Field::Properties)
                        .into_iter()
                        .flatten()
                        .any(|entry| {
                            entry.babel_type() == "ObjectMethod"
                                && entry.declaration_kind() == Some("get")
                        });
                    if next_depth > SEMANTIC_EXPRESSION_DEPTH_LIMIT || has_getter {
                        return StaticObjectProperty::Dynamic;
                    }
                    match lookup(source, spread, next_depth, name, is_nullish) {
                        StaticObjectProperty::Missing => continue,
                        found => return found,
                    }
                }
                if matches!(
                    spread.babel_type(),
                    "BooleanLiteral" | "NumericLiteral" | "BigIntLiteral"
                ) || is_nullish.is_some_and(|nullish| nullish(argument))
                {
                    continue;
                }
                return StaticObjectProperty::Dynamic;
            }
            let Some(key) = property_key_of(source, &property) else {
                return StaticObjectProperty::Dynamic;
            };
            if key != name {
                continue;
            }
            return if property.babel_type() == "ObjectProperty" {
                StaticObjectProperty::Explicit(property)
            } else {
                StaticObjectProperty::Dynamic
            };
        }
        StaticObjectProperty::Missing
    }
    lookup(source, object, 0, name, is_nullish)
}

/// `semanticFinalObjectProperty`: the value of the effective property.
pub fn final_object_property<'a>(source: &'a str, node: Node<'a>, key: &str) -> Option<Node<'a>> {
    match static_object_property(source, Some(node), key, None) {
        StaticObjectProperty::Explicit(property) => property.field(source, Field::Value),
        _ => None,
    }
}

/// `semanticFinalObjectStringProperty`.
pub fn final_object_string_property<'a>(
    source: &'a str,
    node: Node<'a>,
    key: &str,
) -> Option<&'a str> {
    final_object_property(source, node, key).and_then(|value| value.string_value())
}

/// `semanticObjectPatternKeys`: exact consumed keys, dynamic keys omitted.
pub fn object_pattern_keys(source: &str, pattern: &Node<'_>) -> Vec<JsString> {
    pattern
        .field_list(source, Field::Properties)
        .into_iter()
        .flatten()
        .filter(|property| property.babel_type() != "RestElement")
        .filter_map(|property| property_key_of(source, &property))
        .collect()
}

/// `semanticWriteSiteTarget`: the syntactic node a construct writes.
pub fn write_site_target<'a>(source: &'a str, node: &Node<'a>) -> Option<Node<'a>> {
    match node.babel_type() {
        "AssignmentExpression" | "ForOfStatement" | "ForInStatement" => {
            node.field(source, Field::Left)
        }
        "UpdateExpression" => node.field(source, Field::Argument),
        "UnaryExpression" if node.operator() == Some("delete") => {
            node.field(source, Field::Argument)
        }
        _ => None,
    }
}

/// `semanticWriteSiteReadsFirst`.
pub fn write_site_reads_first(site: &Node<'_>) -> bool {
    (site.babel_type() == "AssignmentExpression" && site.operator() != Some("="))
        || site.babel_type() == "UpdateExpression"
}

/// `semanticWrappedWriteSite`: the owning write site through inert
/// TypeScript wrappers. `ancestors` is outermost-first.
pub fn wrapped_write_site<'a>(
    source: &'a str,
    node: &Node<'a>,
    parent: &Node<'a>,
    ancestors: &[Node<'a>],
) -> Option<Node<'a>> {
    let mut chain: Vec<Node<'a>> = ancestors.to_vec();
    if chain.last().map(Node::key) != Some(parent.key()) {
        chain.push(*parent);
    }
    for candidate in chain.into_iter().rev() {
        if let Some(target) = write_site_target(source, &candidate) {
            return (unwrapped(source, target).key() == node.key()).then_some(candidate);
        }
        if unwrap_expression(source, candidate, false).depth == 0 {
            return None;
        }
    }
    None
}

/// `semanticWriteTargets`: identifier and member leaves of direct and
/// destructuring write targets, in source order.
pub fn write_targets<'a>(source: &'a str, root: Node<'a>) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    let mut pending = vec![root];
    while let Some(next) = pending.pop() {
        let node = unwrapped(source, next);
        match node.babel_type() {
            "Identifier" | "MemberExpression" | "OptionalMemberExpression" => out.push(node),
            "RestElement" => pending.extend(node.field(source, Field::Argument)),
            "AssignmentPattern" => pending.extend(node.field(source, Field::Left)),
            "ArrayPattern" => {
                let elements = node.field_list(source, Field::Elements);
                pending.extend(elements.into_iter().rev().flatten());
            }
            "ObjectPattern" => {
                let properties = node.field_list(source, Field::Properties);
                for property in properties.into_iter().rev().flatten() {
                    let field = if property.babel_type() == "RestElement" {
                        Field::Argument
                    } else {
                        Field::Value
                    };
                    pending.extend(property.field(source, field));
                }
            }
            _ => {}
        }
    }
    out
}

/// `javascriptDisplayText`.
pub fn display_text(value: &str) -> &str {
    if value.is_empty() { "\"\"" } else { value }
}
