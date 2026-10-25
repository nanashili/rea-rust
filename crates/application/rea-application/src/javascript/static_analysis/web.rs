//! AST-owned browser bundle route and WebMCP observations.

use crate::javascript::graph::json::{Json, Obj};

use crate::javascript::ast::{AstContext, AstVisitor, Field, Node, traverse};
use crate::javascript::parser::{RawDiagnostic, parse_javascript_analysis_program};
use crate::javascript::semantic::ast_values::{
    ExactLiteral, read_exact_literal, static_property_key, unwrapped,
};

use super::helpers::{STATIC_ROUTE_CALL_NAMES, range};
use crate::javascript::semantic::value_types::JsString;

#[derive(Default)]
pub struct WebObservations {
    pub routes: Vec<Json>,
    pub endpoint_candidates: Vec<Json>,
    pub webmcp_declarations: Vec<Json>,
}

pub fn analyze(source: &str, path: Option<&str>) -> Result<WebObservations, Vec<RawDiagnostic>> {
    let allocator = oxc_allocator::Allocator::default();
    let parsed = parse_javascript_analysis_program(&allocator, source, path)?;
    Ok(collect(&AstContext::new(parsed.program)))
}

pub fn collect(context: &AstContext<'_>) -> WebObservations {
    let mut observations = WebObservations::default();
    let mut visitor = Visitor {
        context,
        observations: &mut observations,
    };
    let _: std::ops::ControlFlow<()> =
        traverse(context.root(), context.source(), &mut visitor, || {
            std::ops::ControlFlow::<()>::Continue(())
        });
    observations
}

struct Visitor<'a, 'b> {
    context: &'a AstContext<'b>,
    observations: &'a mut WebObservations,
}

impl<'b> AstVisitor<'b> for Visitor<'_, 'b> {
    fn enter(&mut self, node: &Node<'b>, _: Option<&Node<'b>>, _: &[Node<'b>]) {
        let source = self.context.source();
        if matches!(
            node.babel_type(),
            "CallExpression" | "OptionalCallExpression"
        ) {
            self.inspect_call(*node, source);
        }
        if node.babel_type() == "ObjectProperty" {
            self.inspect_route_property(*node, source);
        }
    }
}

impl<'b> Visitor<'_, 'b> {
    fn inspect_call(&mut self, call: Node<'b>, source: &'b str) {
        let Some(callee) = call.field(source, Field::Callee) else {
            return;
        };
        let name = callee_name(callee, source);
        if name.as_deref().is_some_and(is_route_call) {
            if let Some(value) = exact_string(
                source,
                call.field_list(source, Field::Arguments)
                    .first()
                    .copied()
                    .flatten(),
            ) {
                let observation = Obj::new()
                    .with("value", value)
                    .with(
                        "mechanism",
                        format!("call:{}", name.as_deref().unwrap_or_default()),
                    )
                    .with("location", location(self.context, &call));
                let observation = Json::Object(observation);
                if !self.observations.routes.iter().any(|existing| {
                    existing["value"] == observation["value"]
                        && existing["mechanism"] == observation["mechanism"]
                }) {
                    self.observations.routes.push(observation);
                }
            }
        }
        if name.as_deref().is_some_and(is_http_method_call) {
            if let Some(value) = exact_string(
                source,
                call.field_list(source, Field::Arguments)
                    .first()
                    .copied()
                    .flatten(),
            ) {
                self.observations.endpoint_candidates.push(Json::Object(
                    Obj::new()
                        .with("value", value)
                        .with(
                            "mechanism",
                            format!(
                                "call:{}:unverified-network-receiver",
                                name.as_deref().unwrap_or_default()
                            ),
                        )
                        .with("location", location(self.context, &call)),
                ));
            }
        }
        if name
            .as_deref()
            .is_some_and(|name| name == "registerTool" || name.ends_with(".registerTool"))
            && is_model_context(callee, source)
        {
            self.inspect_webmcp(call, source);
        }
    }

    fn inspect_route_property(&mut self, property: Node<'b>, source: &'b str) {
        let Some(key) = property
            .field(source, Field::Key)
            .and_then(|key| static_property_key(source, key, property.computed()))
        else {
            return;
        };
        if key != "path" && key != "route" {
            return;
        }
        let Some(value) = exact_string(source, property.field(source, Field::Value)) else {
            return;
        };
        let observation = Json::Object(
            Obj::new()
                .with("value", value)
                .with("mechanism", format!("property:{key}"))
                .with("location", location(self.context, &property)),
        );
        if !self.observations.routes.iter().any(|existing| {
            existing["value"] == observation["value"]
                && existing["mechanism"] == observation["mechanism"]
        }) {
            self.observations.routes.push(observation);
        }
    }

    fn inspect_webmcp(&mut self, call: Node<'b>, source: &'b str) {
        let Some(argument) = call
            .field_list(source, Field::Arguments)
            .first()
            .copied()
            .flatten()
        else {
            return;
        };
        if argument.babel_type() != "ObjectExpression" {
            return;
        }
        let name = object_string(argument, source, "name");
        let description = object_string(argument, source, "description");
        let schema = object_property(argument, source, "inputSchema")
            .or_else(|| object_property(argument, source, "input_schema"));
        let properties = schema.and_then(|schema| object_property(schema, source, "properties"));
        let mut schema_property_names = properties
            .map(|properties| object_property_names(properties, source))
            .unwrap_or_default();
        schema_property_names.sort();
        schema_property_names.dedup();
        let declaration = Json::Object(
            Obj::new()
                .with("name", name)
                .with("description", description)
                .with(
                    "schema_property_names",
                    crate::javascript::graph::json::strings(schema_property_names),
                )
                .with("trust", "page-declared-untrusted")
                .with("location", location(self.context, &call)),
        );
        if !self
            .observations
            .webmcp_declarations
            .iter()
            .any(|existing| {
                existing["name"] == declaration["name"]
                    && existing["description"] == declaration["description"]
                    && existing["schema_property_names"] == declaration["schema_property_names"]
            })
        {
            self.observations.webmcp_declarations.push(declaration);
        }
    }
}

fn is_route_call(name: &str) -> bool {
    STATIC_ROUTE_CALL_NAMES
        .iter()
        .copied()
        .any(|candidate| name == candidate || name.ends_with(&format!(".{candidate}")))
}

fn is_http_method_call(name: &str) -> bool {
    ["get", "post", "put", "patch", "delete", "head", "options"]
        .iter()
        .any(|method| name == *method || name.ends_with(&format!(".{method}")))
}

fn location(context: &AstContext<'_>, node: &Node<'_>) -> Json {
    let start = range(context, node).start;
    Json::Object(
        Obj::new()
            .with("line", start.line)
            .with("column", start.column),
    )
}

fn callee_name(node: Node<'_>, source: &str) -> Option<String> {
    let node = unwrapped(source, node);
    if let Some(name) = node.identifier_name() {
        return Some(name.to_owned());
    }
    if node.babel_type() != "MemberExpression" && node.babel_type() != "OptionalMemberExpression" {
        return None;
    }
    let property = node.field(source, Field::Property)?;
    let property = static_property_key(source, property, node.computed())?;
    let object = node.field(source, Field::Object)?;
    callee_name(object, source).map(|prefix| format!("{prefix}.{property}"))
}

fn is_model_context(callee: Node<'_>, source: &str) -> bool {
    let callee = unwrapped(source, callee);
    if callee.babel_type() != "MemberExpression"
        && callee.babel_type() != "OptionalMemberExpression"
    {
        return false;
    }
    let Some(object) = callee.field(source, Field::Object) else {
        return false;
    };
    if object.identifier_name() == Some("modelContext") {
        return true;
    }
    if object.babel_type() != "MemberExpression"
        && object.babel_type() != "OptionalMemberExpression"
    {
        return false;
    }
    object
        .field(source, Field::Property)
        .and_then(|property| static_property_key(source, property, object.computed()))
        .is_some_and(|property| property == "modelContext")
}

fn object_property<'a>(object: Node<'a>, source: &'a str, expected: &str) -> Option<Node<'a>> {
    object
        .field_list(source, Field::Properties)
        .into_iter()
        .flatten()
        .filter(|property| property.babel_type() == "ObjectProperty")
        .rev()
        .find(|property| property_named(source, property, expected))
        .and_then(|property| property.field(source, Field::Value))
}

fn property_named(source: &str, property: &Node<'_>, expected: &str) -> bool {
    property.babel_type() == "ObjectProperty"
        && property
            .field(source, Field::Key)
            .and_then(|key| static_property_key(source, key, property.computed()))
            .is_some_and(|key| key == expected)
}

fn object_string(object: Node<'_>, source: &str, expected: &str) -> Option<JsString> {
    object_property(object, source, expected).and_then(|value| exact_string(source, Some(value)))
}

fn exact_string(source: &str, node: Option<Node<'_>>) -> Option<JsString> {
    match node.and_then(|node| read_exact_literal(source, node)) {
        Some(ExactLiteral::String(value)) => Some(value),
        _ => None,
    }
}

fn object_property_names(object: Node<'_>, source: &str) -> Vec<String> {
    object
        .field_list(source, Field::Properties)
        .into_iter()
        .flatten()
        .filter(|property| property.babel_type() == "ObjectProperty")
        .filter_map(|property| {
            property
                .field(source, Field::Key)
                .and_then(|key| static_property_key(source, key, property.computed()))
                .map(|key| key.to_string())
        })
        .collect()
}
