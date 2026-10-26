//! Port of `javascriptAstFingerprint.ts`.
//!
//! The fingerprint keeps the `babel-ast-v3` token stream: Babel type names
//! from the adapter's `AstKind`→Babel map, parentheses skipped, Babel-only
//! nodes absent. Any change to [`super::babel::semantic_tokens`] needs a new
//! algorithm id and cache invalidation (port plan §2.8).

use std::collections::BTreeSet;
use std::io::{self, BufWriter, Write};
use std::ops::ControlFlow;

use serde::Serializer;
use serde::ser::SerializeSeq;
use sha2::{Digest, Sha256};

use super::babel::semantic_tokens;
use super::helpers::string_value;
use super::semantics::StaticSemantics;
use crate::javascript::ast::{AstVisitor, Field, Node, traverse};
use crate::javascript::semantic::ast_values::{
    is_function, is_member, runtime_function_parameters, static_property_key,
};
use crate::javascript::semantic::value_types::JsString;

/// `fingerprintJavaScriptAst`: SHA-256 of the JSON token array.
pub fn fingerprint_javascript_ast<'a>(source: &'a str, node: Node<'a>) -> String {
    struct Tokens<'s, S> {
        source: &'s str,
        sequence: S,
    }
    impl<'a, S: SerializeSeq<Error = serde_json::Error>> AstVisitor<'a> for Tokens<'a, S> {
        fn enter(&mut self, node: &Node<'a>, _: Option<&Node<'a>>, _: &[Node<'a>]) {
            for token in semantic_tokens(self.source, node) {
                self.sequence
                    .serialize_element(&token)
                    .expect("JavaScript strings serialize to an infallible hash writer");
            }
        }
    }

    // Keep the exact JSON array encoding without retaining all tokens or its text.
    // Buffer the serializer's small writes before updating the digest.
    let mut serializer = serde_json::Serializer::new(BufWriter::new(FingerprintDigest::default()));
    let sequence = serializer
        .serialize_seq(None)
        .expect("hash writer accepts the JSON array prefix");
    let mut visitor = Tokens { source, sequence };
    let _: ControlFlow<()> = traverse(node, source, &mut visitor, || ControlFlow::Continue(()));
    visitor
        .sequence
        .end()
        .expect("hash writer accepts the JSON array suffix");

    let digest = serializer
        .into_inner()
        .into_inner()
        .expect("buffered hash writer flushes without I/O");
    hex(&digest.0.finalize())
}

#[derive(Debug, Default)]
struct FingerprintDigest(Sha256);

impl Write for FingerprintDigest {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `collectJavaScriptExports`: statically declared CommonJS/bundler export
/// names of one factory, code-point sorted. With `semantics`, a factory's
/// second parameter is the exports alias by binding identity; without, any
/// identifier spelled `exports` is.
pub fn collect_javascript_exports<'a>(
    source: &'a str,
    node: Node<'a>,
    semantics: Option<&dyn StaticSemantics<'a>>,
) -> Vec<JsString> {
    let parameter = if is_function(&node) {
        runtime_function_parameters(source, &node).get(1).copied()
    } else {
        None
    };
    let factory_exports: Option<String> = match (semantics, parameter) {
        (Some(semantics), Some(parameter))
            if is_function(&node) && parameter.babel_type() == "Identifier" =>
        {
            semantics.binding_id(&parameter).map(str::to_owned)
        }
        _ => None,
    };
    let aliases = ExportsAlias {
        semantics,
        factory_exports,
    };
    struct Collect<'s, 'a> {
        source: &'a str,
        aliases: &'s ExportsAlias<'s, 'a>,
        exports: BTreeSet<JsString>,
    }
    impl<'a> AstVisitor<'a> for Collect<'_, 'a> {
        fn enter(&mut self, node: &Node<'a>, _: Option<&Node<'a>>, _: &[Node<'a>]) {
            match node.babel_type() {
                "AssignmentExpression" => {
                    if let (Some(left), Some(right)) = (
                        node.field(self.source, Field::Left),
                        node.field(self.source, Field::Right),
                    ) {
                        collect_assignment_exports(
                            self.source,
                            left,
                            right,
                            &mut self.exports,
                            self.aliases,
                        );
                    }
                }
                "CallExpression" => {
                    collect_call_exports(self.source, node, &mut self.exports, self.aliases);
                }
                _ => {}
            }
        }
    }
    let mut collect = Collect {
        source,
        aliases: &aliases,
        exports: BTreeSet::new(),
    };
    let _: ControlFlow<()> = traverse(node, source, &mut collect, || ControlFlow::Continue(()));
    // Rust `str` order is code-point order (`compareUnicodeCodePoints`).
    collect.exports.into_iter().collect()
}

struct ExportsAlias<'s, 'a> {
    semantics: Option<&'s dyn StaticSemantics<'a>>,
    factory_exports: Option<String>,
}

impl<'a> ExportsAlias<'_, 'a> {
    fn is_alias(&self, reference: Option<&Node<'a>>) -> bool {
        let Some(reference) = reference.filter(|it| it.babel_type() == "Identifier") else {
            return false;
        };
        match (&self.factory_exports, self.semantics) {
            (None, _) => reference.identifier_name() == Some("exports"),
            (Some(id), Some(semantics)) => semantics.binding_id(reference) == Some(id.as_str()),
            (Some(_), None) => false,
        }
    }
}

fn collect_assignment_exports<'a>(
    source: &'a str,
    left: Node<'a>,
    right: Node<'a>,
    output: &mut BTreeSet<JsString>,
    aliases: &ExportsAlias<'_, 'a>,
) {
    let Some(path) = member_path(source, Some(left)) else {
        return;
    };
    let root = member_root(source, left);
    let exports_alias = aliases.is_alias(root.as_ref());
    // Rebinding the CommonJS alias does not replace module.exports.
    if path.len() == 1 && exports_alias {
        return;
    }
    let offset = if exports_alias {
        1
    } else if path.first().is_some_and(|key| key == "module")
        && path.get(1).is_some_and(|key| key == "exports")
    {
        2
    } else {
        return;
    };
    if path.len() == offset {
        if right.babel_type() == "ObjectExpression" {
            collect_object_keys(source, &right, output);
        } else {
            output.insert(JsString::from("default"));
        }
        return;
    }
    // The first property below the exports object is the export; deeper
    // writes mutate that exported value.
    output.insert(path[offset].clone());
}

fn collect_call_exports<'a>(
    source: &'a str,
    call: &Node<'a>,
    output: &mut BTreeSet<JsString>,
    aliases: &ExportsAlias<'_, 'a>,
) {
    let Some(callee) = member_path(source, call.field(source, Field::Callee)) else {
        return;
    };
    let define_property =
        callee.len() == 2 && callee[0] == "Object" && callee[1] == "defineProperty";
    let declaration = callee.len() >= 2 && callee.last().is_some_and(|key| key == "d");
    if !define_property && !declaration {
        return;
    }
    let arguments = call.field_list(source, Field::Arguments);
    let target_node = arguments.first().copied().flatten();
    let target = member_path(source, target_node);
    let export_target = aliases.is_alias(target_node.as_ref())
        || target.as_ref().is_some_and(|target| {
            target.len() == 2 && target[0] == "module" && target[1] == "exports"
        });
    if !export_target {
        return;
    }
    let second = arguments.get(1).copied().flatten();
    if define_property {
        if let Some(name) = second.and_then(|it| string_value(source, Some(it))) {
            output.insert(JsString::from(name));
        }
        return;
    }
    if let Some(declarations) = second.filter(|it| it.babel_type() == "ObjectExpression") {
        collect_object_keys(source, &declarations, output);
    }
}

fn member_root<'a>(source: &'a str, node: Node<'a>) -> Option<Node<'a>> {
    let mut current = node;
    while is_member(&current) {
        current = current.field(source, Field::Object)?;
    }
    Some(current)
}

fn collect_object_keys<'a>(source: &'a str, object: &Node<'a>, output: &mut BTreeSet<JsString>) {
    for property in object
        .field_list(source, Field::Properties)
        .into_iter()
        .flatten()
    {
        let kind = property.babel_type();
        if kind != "ObjectProperty" && kind != "ObjectMethod" {
            continue;
        }
        let Some(key) = property.field(source, Field::Key) else {
            continue;
        };
        let Some(name) = static_property_key(source, key, property.computed()) else {
            continue;
        };
        // A non-computed `__proto__: value` sets the prototype; shorthand,
        // computed and method forms create own properties.
        if kind == "ObjectProperty"
            && !property.computed()
            && !property.shorthand()
            && name == "__proto__"
        {
            continue;
        }
        output.insert(name);
    }
}

/// `memberPath`: `[root, ...properties]` for an identifier/`this` rooted
/// member chain with exact keys.
pub(crate) fn member_path<'a>(source: &'a str, node: Option<Node<'a>>) -> Option<Vec<JsString>> {
    let mut properties = Vec::new();
    let mut current = node?;
    while is_member(&current) {
        let property = current.field(source, Field::Property)?;
        properties.push(static_property_key(source, property, current.computed())?);
        current = current.field(source, Field::Object)?;
    }
    let root = match current.babel_type() {
        "Identifier" => JsString::from(current.identifier_name()?),
        "ThisExpression" => JsString::from("this"),
        _ => return None,
    };
    properties.push(root);
    properties.reverse();
    Some(properties)
}
