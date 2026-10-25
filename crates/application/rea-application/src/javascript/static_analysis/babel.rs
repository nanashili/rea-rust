//! `@babel/types` predicates the static packages use, over the Babel view:
//! `t.isReferenced`, `t.isNodesEquivalent` and per-node scalar fields not
//! exposed by [`Node`] accessors.

use crate::javascript::ast::node::NodeKind;
use crate::javascript::ast::{Field, Node};
use crate::javascript::semantic::ast_values::{is_function, js_number_string, static_property_key};
use crate::javascript::semantic::value_types::JsString;
use serde::Serialize;

fn token(prefix: &str, value: impl Into<JsString>) -> JsString {
    value.into().prefixed(prefix)
}

/// Node identity (`a === b` on Babel nodes).
pub fn same(left: &Node<'_>, right: &Node<'_>) -> bool {
    left.key() == right.key()
}

/// `parent[field] === node`.
pub fn is_field<'a>(source: &'a str, parent: &Node<'a>, field: Field, node: &Node<'a>) -> bool {
    parent
        .field(source, field)
        .is_some_and(|child| same(&child, node))
}

/// `async`/`generator` of a `t.isFunction` node.
pub fn function_flags(node: &Node<'_>) -> Option<(bool, bool)> {
    if let NodeKind::ArrowFunctionExpression(arrow) = node.kind() {
        return Some((arrow.r#async, false));
    }
    if let NodeKind::Function(function) = node.kind() {
        return Some((function.r#async, function.generator));
    }
    node.function()
        .map(|function| (function.r#async, function.generator))
}

/// `UpdateExpression.prefix` / `UnaryExpression.prefix` (always true).
pub fn prefix(node: &Node<'_>) -> Option<bool> {
    match node.kind() {
        NodeKind::UpdateExpression(update) => Some(update.prefix),
        NodeKind::UnaryExpression(_) => Some(true),
        _ => None,
    }
}

/// `RegExpLiteral` `pattern` and `flags`, as written.
pub fn regexp_parts<'a>(source: &'a str, node: &Node<'a>) -> Option<(&'a str, &'a str)> {
    if !matches!(node.kind(), NodeKind::RegExpLiteral(_)) {
        return None;
    }
    let span = node.span();
    let raw = &source[span.start as usize..span.end as usize];
    let close = raw.rfind('/')?;
    Some((raw.get(1..close)?, &raw[close + 1..]))
}

#[derive(Serialize)]
pub struct TemplateValue {
    pub raw: String,
    pub cooked: Option<JsString>,
}

/// `TemplateElement.value` `{ raw, cooked }`, preserving cooked UTF-16 units.
pub fn template_value(node: &Node<'_>) -> Option<TemplateValue> {
    let NodeKind::TemplateElement(element) = node.kind() else {
        return None;
    };
    Some(TemplateValue {
        raw: element.value.raw.to_string(),
        cooked: node.template_cooked_units().map(JsString::from_utf16),
    })
}

/// `ExportNamedDeclaration.source != null`.
fn has_source(node: Option<&Node<'_>>) -> bool {
    match node.map(Node::kind) {
        Some(NodeKind::ExportNamedDeclaration(export)) => export.source.is_some(),
        Some(NodeKind::ExportAllDeclaration(_)) => true,
        _ => false,
    }
}

/// `t.isReferenced(node, parent, grandparent)` (Babel 8.0.4).
pub fn is_referenced<'a>(
    source: &'a str,
    node: &Node<'a>,
    parent: &Node<'a>,
    grandparent: Option<&Node<'a>>,
) -> bool {
    let field = |name: Field| is_field(source, parent, name, node);
    match parent.babel_type() {
        "MemberExpression" | "OptionalMemberExpression" => {
            if field(Field::Property) {
                parent.computed()
            } else {
                field(Field::Object)
            }
        }
        "JSXMemberExpression" => field(Field::Object),
        "VariableDeclarator" => field(Field::Init),
        "ArrowFunctionExpression" => field(Field::Body),
        "ClassMethod" | "ClassPrivateMethod" | "ObjectMethod" => {
            field(Field::Key) && parent.computed()
        }
        "ObjectProperty" => {
            if field(Field::Key) {
                parent.computed()
            } else {
                grandparent.is_none_or(|it| it.babel_type() != "ObjectPattern")
            }
        }
        "ClassProperty" | "ClassAccessorProperty" | "TSPropertySignature" => {
            if field(Field::Key) {
                parent.computed()
            } else {
                true
            }
        }
        "ClassPrivateProperty" => !field(Field::Key),
        "ClassDeclaration" | "ClassExpression" => field(Field::SuperClass),
        "AssignmentExpression" | "AssignmentPattern" => field(Field::Right),
        "PrivateName"
        | "LabeledStatement"
        | "CatchClause"
        | "RestElement"
        | "BreakStatement"
        | "ContinueStatement"
        | "FunctionDeclaration"
        | "FunctionExpression"
        | "ExportNamespaceSpecifier"
        | "ExportDefaultSpecifier"
        | "ImportDefaultSpecifier"
        | "ImportNamespaceSpecifier"
        | "ImportSpecifier"
        | "ImportAttribute"
        | "JSXAttribute"
        | "ObjectPattern"
        | "ArrayPattern"
        | "MetaProperty" => false,
        "ExportSpecifier" => !has_source(grandparent) && field(Field::Local),
        "TSEnumMember" => !field(Field::Id),
        _ => true,
    }
}

/// The scalar (non-child) facts of one node that `t.isNodesEquivalent` and
/// the fingerprint compare, plus the identifier name.
fn scalar_signature<'a>(source: &'a str, node: &Node<'a>) -> Vec<JsString> {
    let mut tokens = semantic_tokens(source, node);
    if let Some(name) = node.identifier_name() {
        tokens.push(token("name:", name));
    }
    if node.optional() {
        tokens.push(JsString::from("optional"));
    }
    if node.shorthand() {
        tokens.push(JsString::from("shorthand"));
    }
    tokens
}

/// `t.isNodesEquivalent(left, right)`: same type and scalar fields at every
/// position, ignoring locations.
pub fn nodes_equivalent<'a>(source: &'a str, left: &Node<'a>, right: &Node<'a>) -> bool {
    let mut pending = vec![(*left, *right)];
    while let Some((left, right)) = pending.pop() {
        if left.babel_type() != right.babel_type()
            || scalar_signature(source, &left) != scalar_signature(source, &right)
        {
            return false;
        }
        let (lc, rc) = (left.children(source), right.children(source));
        if lc.len() != rc.len() {
            return false;
        }
        pending.extend(lc.into_iter().zip(rc));
    }
    true
}

/// `semanticTokens` of `javascriptAstFingerprint.ts` (algorithm
/// `babel-ast-v3`): the Babel type name plus literal values, operators and
/// declaration/member flags.
pub fn semantic_tokens<'a>(source: &'a str, node: &Node<'a>) -> Vec<JsString> {
    let kind = node.babel_type();
    let mut tokens = vec![token("node:", kind)];
    match kind {
        "StringLiteral" => {
            if let Some(value) = node.string_value_js_string() {
                tokens.push(token("string:", value));
            }
        }
        "BigIntLiteral" => {
            tokens.push(token("bigint:", node.bigint_decimal().unwrap_or("")));
        }
        "DirectiveLiteral" => {
            if let Some(value) = node.string_value_js_string() {
                tokens.push(token("directive:", value));
            }
        }
        "NumericLiteral" => tokens.push(token(
            "number:",
            js_number_string(node.numeric_value().unwrap_or(f64::NAN)),
        )),
        "BooleanLiteral" => tokens.push(token(
            "boolean:",
            node.boolean_value().unwrap_or(false).to_string(),
        )),
        "RegExpLiteral" => {
            let (pattern, flags) = regexp_parts(source, node).unwrap_or(("", ""));
            tokens.push(JsString::from(format!("regexp:{pattern}/{flags}")));
        }
        "TemplateElement" => {
            if let Some(value) = template_value(node) {
                let encoded = serde_json::to_string(&value)
                    .expect("template text and UTF-16 strings are JSON serializable");
                tokens.push(token("template:", encoded));
            }
        }
        "BinaryExpression"
        | "LogicalExpression"
        | "UnaryExpression"
        | "UpdateExpression"
        | "AssignmentExpression" => {
            tokens.push(token("operator:", node.operator().unwrap_or("")));
        }
        _ => {}
    }
    if kind == "UpdateExpression" {
        tokens.push(token("prefix:", prefix(node).unwrap_or(false).to_string()));
    }
    if kind == "VariableDeclaration" {
        tokens.push(token("kind:", node.declaration_kind().unwrap_or("")));
    }
    if is_function(node) {
        let (is_async, generator) = function_flags(node).unwrap_or((false, false));
        tokens.push(token("async:", is_async.to_string()));
        tokens.push(token("generator:", generator.to_string()));
    }
    if kind == "ObjectMethod" {
        tokens.push(token("kind:", node.declaration_kind().unwrap_or("")));
    }
    if kind == "ClassMethod" || kind == "ClassPrivateMethod" {
        tokens.push(token("kind:", node.declaration_kind().unwrap_or("")));
        tokens.push(token("static:", node.is_static().to_string()));
    }
    if matches!(
        kind,
        "ClassProperty" | "ClassPrivateProperty" | "ClassAccessorProperty"
    ) {
        tokens.push(token("static:", node.is_static().to_string()));
    }
    if kind == "MemberExpression" || kind == "OptionalMemberExpression" {
        // A computed identifier names a local binding, not a fixed member.
        tokens.push(token("computed:", node.computed().to_string()));
        if !node.computed()
            && let Some(property) = node.field(source, Field::Property)
            && let Some(name) = static_property_key(source, property, false)
        {
            tokens.push(token("property:", name));
        }
    }
    if matches!(
        kind,
        "ObjectProperty"
            | "ObjectMethod"
            | "ClassMethod"
            | "ClassProperty"
            | "ClassAccessorProperty"
    ) {
        tokens.push(token("computed:", node.computed().to_string()));
        if !node.computed()
            && let Some(key) = node.field(source, Field::Key)
            && let Some(name) = static_property_key(source, key, false)
        {
            tokens.push(token("key:", name));
        }
    }
    tokens
}
