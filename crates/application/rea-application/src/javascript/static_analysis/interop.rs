//! The template matcher of `javascriptModuleInterop.ts`: Rolldown's
//! `__toESM`/`__copyProps` runtime operations recognized by structure and
//! lexical roles (`canonicalRoles`), plus `identityFunction`.
//!
//! The templates are parsed with oxc into the Babel view, so both sides of a
//! comparison use the same type names and child order. The non-child fields
//! `canonicalRoles` compares (`t.NODE_FIELDS` minus visitor keys, with
//! defaults) are written out for the node types the two templates contain;
//! a target of any other type fails the type check first. `helperProof`,
//! `callOrigin`, `origin` and the intrinsic/invalidation machinery need the
//! evaluation engine (port plan D2) and are not ported here.
//!
//! TypeScript-only scalar fields are included in the structural comparison:
//! optional identifiers, ambient declarations, and definite declarators.

use std::collections::BTreeMap;
use std::collections::HashMap;

use oxc_allocator::Allocator;

use super::babel::{function_flags, is_field, prefix};
use super::semantics::StaticSemantics;
use crate::javascript::ast::{AstContext, Field, Node, NodeKind};
use crate::javascript::parser::parse_javascript_analysis_program;
use crate::javascript::semantic::ast_values::{
    is_function, js_number_string, runtime_function_parameters,
};

/// Rolldown `__toESM`: names and formatting are irrelevant; lexical roles,
/// operators and keys are not.
pub const TO_ESM: &str = r#"(mod, isNodeMode, target) => (
  target = mod != null ? __create(__getProtoOf(mod)) : {},
  __copyProps(isNodeMode || !mod || !mod.__esModule || !__hasOwnProp.call(mod, "default")
    ? __defProp(target, "default", {value: mod, enumerable: true}) : target, mod)
)"#;

/// Rolldown `__copyProps`, including its live getters.
pub const COPY_PROPS: &str = r#"(to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function")
    for (var keys = __getOwnPropNames(from), i = 0, n = keys.length, key; i < n; i++) {
      key = keys[i];
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, {
          get: ((k) => from[k]).bind(null, key),
          enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable
        });
    }
  return to;
}"#;

/// Template helper names and the intrinsic paths they stand for
/// (`INTRINSICS`).
pub const INTRINSICS: [(&str, &[&str]); 6] = [
    ("__create", &["Object", "create"]),
    ("__getProtoOf", &["Object", "getPrototypeOf"]),
    ("__defProp", &["Object", "defineProperty"]),
    ("__getOwnPropNames", &["Object", "getOwnPropertyNames"]),
    ("__getOwnPropDesc", &["Object", "getOwnPropertyDescriptor"]),
    ("__hasOwnProp", &["Object", "prototype", "hasOwnProperty"]),
];

/// Which template to match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Template {
    ToEsm,
    CopyProps,
}

/// Both templates in the Babel view, borrowed from one parse.
pub struct InteropTemplates<'t> {
    context: AstContext<'t>,
    to_esm: Node<'t>,
    copy_props: Node<'t>,
}

impl<'t> InteropTemplates<'t> {
    fn node(&self, template: Template) -> Node<'t> {
        match template {
            Template::ToEsm => self.to_esm,
            Template::CopyProps => self.copy_props,
        }
    }
}

/// Parse the templates and run `f` with them. The parse is tiny; callers
/// hold the templates for one analysis by doing that analysis inside `f`.
pub fn with_interop_templates<R>(f: impl for<'t> FnOnce(&InteropTemplates<'t>) -> R) -> R {
    let allocator = Allocator::default();
    let text = allocator.alloc_str(&format!("{TO_ESM};\n{COPY_PROPS};\n"));
    let parsed = parse_javascript_analysis_program(&allocator, text, Some("interop.js"))
        .unwrap_or_else(|_| panic!("interop templates are valid JavaScript"));
    let context = AstContext::new(parsed.program);
    let expressions: Vec<Node<'_>> = context
        .root()
        .field_list(text, Field::Body)
        .into_iter()
        .flatten()
        .filter_map(|statement| statement.field(text, Field::Expression))
        .collect();
    let [to_esm, copy_props] = expressions[..] else {
        panic!("interop templates are two expression statements");
    };
    f(&InteropTemplates {
        context,
        to_esm,
        copy_props,
    })
}

/// `controlBodyOperation`: braces around one control-body statement add no
/// operation.
fn control_body_operation<'a>(source: &'a str, mut node: Node<'a>) -> Node<'a> {
    while node.babel_type() == "BlockStatement" && directive_count(&node) == 0 {
        let statements = node.field_list(source, Field::Body);
        match statements.as_slice() {
            [Some(statement)] => node = *statement,
            _ => break,
        }
    }
    node
}

fn directive_count(node: &Node<'_>) -> usize {
    match node.kind() {
        crate::javascript::ast::node::NodeKind::FunctionBody(body) => body.directives.len(),
        _ => 0,
    }
}

/// The non-child fields `canonicalRoles` compares for the template node
/// types, as comparable text.
fn scalar_fields(source: &str, node: &Node<'_>, literal_key: bool) -> Vec<String> {
    let mut fields = Vec::new();
    match node.babel_type() {
        "ArrowFunctionExpression" => {
            let (is_async, generator) = function_flags(node).unwrap_or((false, false));
            fields.push(format!("async:{is_async}"));
            fields.push(format!("generator:{generator}"));
        }
        "Identifier" => {
            if literal_key {
                fields.push(format!("name:{}", node.identifier_name().unwrap_or("")));
            }
            fields.push(format!("optional:{}", identifier_is_optional(source, node)));
        }
        "AssignmentExpression" | "BinaryExpression" | "LogicalExpression" => {
            fields.push(format!("operator:{}", node.operator().unwrap_or("")));
        }
        "UnaryExpression" | "UpdateExpression" => {
            fields.push(format!("operator:{}", node.operator().unwrap_or("")));
            fields.push(format!("prefix:{}", prefix(node).unwrap_or(false)));
        }
        "MemberExpression" => fields.push(format!("computed:{}", node.computed())),
        "ObjectProperty" => {
            fields.push(format!("computed:{}", node.computed()));
            fields.push(format!("shorthand:{}", node.shorthand()));
        }
        "StringLiteral" => fields.push(format!(
            "value:{:?}",
            node.string_value_units().unwrap_or_default()
        )),
        "NumericLiteral" => fields.push(format!(
            "value:{}",
            node.numeric_value()
                .map(js_number_string)
                .unwrap_or_default()
        )),
        "BooleanLiteral" => fields.push(format!("value:{:?}", node.boolean_value())),
        "VariableDeclaration" => {
            fields.push(format!("kind:{}", node.declaration_kind().unwrap_or("")));
            fields.push(format!("declare:{}", variable_declaration_is_ambient(node)));
        }
        "VariableDeclarator" => {
            fields.push(format!(
                "definite:{}",
                variable_declarator_is_definite(node)
            ));
        }
        _ => {}
    }
    fields
}

/// `canonicalRoles`: match operations and lexical roles against a template,
/// allowing single-statement control blocks. Returns template identifier
/// name → binding id.
pub fn canonical_roles<'a>(
    cx: &AstContext<'a>,
    actual: Node<'a>,
    templates: &InteropTemplates<'_>,
    template: Template,
    semantics: &dyn StaticSemantics<'a>,
) -> Option<BTreeMap<String, String>> {
    let source = cx.source();
    let pattern_source = templates.context.source();
    let mut roles: BTreeMap<String, String> = BTreeMap::new();
    let mut used: HashMap<String, String> = HashMap::new();
    let mut pending = vec![(actual, templates.node(template), None::<Node<'_>>)];
    while let Some((actual, pattern, parent)) = pending.pop() {
        let control_body = parent.is_some_and(|parent| match parent.babel_type() {
            "IfStatement" => {
                is_field(pattern_source, &parent, Field::Consequent, &pattern)
                    || is_field(pattern_source, &parent, Field::Alternate, &pattern)
            }
            "ForStatement" => is_field(pattern_source, &parent, Field::Body, &pattern),
            _ => false,
        });
        let (node, expected) = if control_body {
            (
                control_body_operation(source, actual),
                control_body_operation(pattern_source, pattern),
            )
        } else {
            (actual, pattern)
        };
        if node.babel_type() != expected.babel_type() {
            return None;
        }
        let literal_key = parent.is_some_and(|parent| {
            (parent.babel_type() == "MemberExpression"
                && !parent.computed()
                && is_field(pattern_source, &parent, Field::Property, &expected))
                || (parent.babel_type() == "ObjectProperty"
                    && !parent.computed()
                    && is_field(pattern_source, &parent, Field::Key, &expected))
        });
        if expected.babel_type() == "Identifier" && !literal_key {
            let name = expected.identifier_name().unwrap_or("").to_owned();
            let binding = semantics.binding_id(&node)?.to_owned();
            if roles.get(&name).is_some_and(|bound| *bound != binding)
                || used.get(&binding).is_some_and(|role| *role != name)
            {
                return None;
            }
            used.insert(binding.clone(), name.clone());
            roles.insert(name, binding);
        }
        if scalar_fields(source, &node, literal_key)
            != scalar_fields(pattern_source, &expected, literal_key)
        {
            return None;
        }
        let children = node.children(source);
        let expected_children = expected.children(pattern_source);
        if children.len() != expected_children.len() {
            return None;
        }
        for (child, expected_child) in children.into_iter().zip(expected_children) {
            pending.push((child, expected_child, Some(expected)));
        }
    }
    Some(roles)
}

fn identifier_is_optional(source: &str, node: &Node<'_>) -> bool {
    if node.babel_type() != "Identifier" {
        return false;
    }
    let start = node.span().start as usize;
    let end = node.span().end as usize;
    source
        .get(start..end)
        .is_some_and(|text| text.contains('?'))
        || source.as_bytes().get(end) == Some(&b'?')
}

fn variable_declaration_is_ambient(node: &Node<'_>) -> bool {
    matches!(node.kind(), NodeKind::VariableDeclaration(declaration) if declaration.declare)
}

fn variable_declarator_is_definite(node: &Node<'_>) -> bool {
    matches!(node.kind(), NodeKind::VariableDeclarator(declarator) if declarator.definite)
}

/// `identityFunction`: `(x) => x` or `function (x) { return x; }` over one
/// binding.
pub fn identity_function<'a>(
    cx: &AstContext<'a>,
    node: &Node<'a>,
    semantics: &dyn StaticSemantics<'a>,
) -> bool {
    let source = cx.source();
    if !is_function(node) {
        return false;
    }
    let (is_async, generator) = function_flags(node).unwrap_or((false, false));
    let parameters = runtime_function_parameters(source, node);
    if is_async || generator || parameters.len() != 1 {
        return false;
    }
    let Some(body) = node.field(source, Field::Body) else {
        return false;
    };
    let result = if body.babel_type() == "BlockStatement" {
        match body.field_list(source, Field::Body).as_slice() {
            [Some(statement)] if statement.babel_type() == "ReturnStatement" => {
                statement.field(source, Field::Argument)
            }
            _ => None,
        }
    } else {
        Some(body)
    };
    let parameter = parameters[0];
    let Some(result) = result.filter(|it| it.babel_type() == "Identifier") else {
        return false;
    };
    if parameter.babel_type() != "Identifier" {
        return false;
    }
    match (
        semantics.binding_id(&parameter),
        semantics.binding_id(&result),
    ) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}
