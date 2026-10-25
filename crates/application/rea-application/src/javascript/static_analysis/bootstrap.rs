//! Port of `javascriptBootstrap.ts`: recognize a standalone CommonJS-style
//! runtime (`(() => { var table = {...}; function load(id) {...} })()`)
//! from syntax and binding identity; never invoke it or infer it from names.

use std::collections::HashMap;
use std::ops::ControlFlow;

use super::babel::{nodes_equivalent, same};
use super::helpers::module_factory;
use super::semantics::StaticSemantics;
use crate::javascript::ast::{AstContext, AstVisitor, Field, Node, traverse};
use crate::javascript::semantic::ast_values::{
    is_function, runtime_function_parameters, static_property_key,
};

/// A literal module table dispatched by a standalone runtime
/// (`JavaScriptBootstrap`).
#[derive(Clone, Debug)]
pub struct Bootstrap<'a> {
    pub body: Node<'a>,
    pub table: Node<'a>,
    pub loader_name: String,
    pub loader_binding_id: String,
    pub table_binding_id: String,
}

/// `javascriptBootstrapAt`.
pub fn javascript_bootstrap_at<'a>(
    cx: &AstContext<'a>,
    call: &Node<'a>,
    semantics: &dyn StaticSemantics<'a>,
) -> Option<Bootstrap<'a>> {
    let source = cx.source();
    let callee = call.field(source, Field::Callee)?;
    if !matches!(
        callee.babel_type(),
        "FunctionExpression" | "ArrowFunctionExpression"
    ) {
        return None;
    }
    let body = callee.field(source, Field::Body)?;
    if body.babel_type() != "BlockStatement"
        || !runtime_function_parameters(source, &callee).is_empty()
        || !call.field_list(source, Field::Arguments).is_empty()
    {
        return None;
    }
    let statements: Vec<Node<'a>> = body
        .field_list(source, Field::Body)
        .into_iter()
        .flatten()
        .collect();
    let mut tables: HashMap<String, Node<'a>> = HashMap::new();
    for statement in &statements {
        if statement.babel_type() != "VariableDeclaration" {
            continue;
        }
        for declaration in statement
            .field_list(source, Field::Declarations)
            .into_iter()
            .flatten()
        {
            let (Some(id), Some(init)) = (
                declaration.field(source, Field::Id),
                declaration.field(source, Field::Init),
            ) else {
                continue;
            };
            if id.babel_type() != "Identifier" || init.babel_type() != "ObjectExpression" {
                continue;
            }
            let properties = init.field_list(source, Field::Properties);
            if properties.is_empty()
                || !properties
                    .iter()
                    .flatten()
                    .all(|property| module_factory(cx, property).is_some())
            {
                continue;
            }
            let Some(binding) = semantics.binding(&id) else {
                continue;
            };
            if semantics
                .stable_initializer(&binding.binding_id)
                .is_some_and(|stable| same(&stable.node, &init))
            {
                tables.insert(binding.binding_id.clone(), init);
            }
        }
    }
    if tables.is_empty() {
        return None;
    }
    for loader in &statements {
        if loader.babel_type() != "FunctionDeclaration" {
            continue;
        }
        let Some(loader_id) = loader.field(source, Field::Id) else {
            continue;
        };
        let parameters = runtime_function_parameters(source, loader);
        if parameters.len() != 1 || parameters[0].babel_type() != "Identifier" {
            continue;
        }
        let (Some(loader_binding_id), Some(parameter_binding_id)) = (
            semantics.binding_id(&loader_id),
            semantics.binding_id(&parameters[0]),
        ) else {
            continue;
        };
        let Some(loader_body) = loader.field(source, Field::Body) else {
            continue;
        };
        let mut table_binding_id: Option<String> = None;
        let mut visitor = Dispatches {
            cx,
            semantics,
            loader_binding_id,
            key_binding_id: parameter_binding_id,
            tables: &tables,
            found: &mut table_binding_id,
        };
        let _: ControlFlow<()> = traverse(loader_body, source, &mut visitor, || {
            ControlFlow::Continue(())
        });
        if let Some(table_binding_id) = table_binding_id
            && let Some(table) = tables.get(&table_binding_id)
        {
            return Some(Bootstrap {
                body,
                table: *table,
                loader_name: loader_id.identifier_name().unwrap_or("").to_owned(),
                loader_binding_id: loader_binding_id.to_owned(),
                table_binding_id,
            });
        }
    }
    None
}

struct Dispatches<'s, 'a> {
    cx: &'s AstContext<'a>,
    semantics: &'s dyn StaticSemantics<'a>,
    loader_binding_id: &'s str,
    key_binding_id: &'s str,
    tables: &'s HashMap<String, Node<'a>>,
    found: &'s mut Option<String>,
}

impl<'a> AstVisitor<'a> for Dispatches<'_, 'a> {
    fn enter(&mut self, node: &Node<'a>, _: Option<&Node<'a>>, ancestors: &[Node<'a>]) {
        if node.babel_type() != "CallExpression" || ancestors.iter().any(is_function) {
            return;
        }
        if let Some(candidate) = dispatched_table_binding(
            self.cx,
            node,
            self.loader_binding_id,
            self.key_binding_id,
            self.semantics,
        ) && self.tables.contains_key(&candidate)
        {
            *self.found = Some(candidate);
        }
    }
}

/// `dispatchedTableBinding`: `table[key](module, module.exports, loader)` or
/// `table[key].call(module.exports, module, module.exports, loader)`.
fn dispatched_table_binding<'a>(
    cx: &AstContext<'a>,
    call: &Node<'a>,
    loader_binding_id: &str,
    key_binding_id: &str,
    semantics: &dyn StaticSemantics<'a>,
) -> Option<String> {
    let source = cx.source();
    let member = call.field(source, Field::Callee)?;
    let via_call = member.babel_type() == "MemberExpression"
        && member
            .field(source, Field::Property)
            .and_then(|property| static_property_key(source, property, member.computed()))
            .is_some_and(|key| key == "call");
    let dispatch = if via_call {
        member.field(source, Field::Object)?
    } else {
        member
    };
    let identifier = |node: Option<Node<'a>>| node.filter(|it| it.babel_type() == "Identifier");
    if dispatch.babel_type() != "MemberExpression" || !dispatch.computed() {
        return None;
    }
    let object = identifier(dispatch.field(source, Field::Object))?;
    let property = identifier(dispatch.field(source, Field::Property))?;
    if semantics.binding_id(&property) != Some(key_binding_id) {
        return None;
    }
    let all = call.field_list(source, Field::Arguments);
    let args = if via_call {
        all.get(1..).unwrap_or(&[])
    } else {
        &all[..]
    };
    if args.len() != 3 {
        return None;
    }
    let module = identifier(args[0])?;
    let exports = args[1].filter(|it| it.babel_type() == "MemberExpression")?;
    let require = identifier(args[2])?;
    let module_binding = semantics.binding_id(&module)?;
    let exports_object = identifier(exports.field(source, Field::Object))?;
    if semantics.binding_id(&exports_object) != Some(module_binding)
        || exports
            .field(source, Field::Property)
            .and_then(|property| static_property_key(source, property, exports.computed()))
            .is_none_or(|key| key != "exports")
        || semantics.binding_id(&require) != Some(loader_binding_id)
    {
        return None;
    }
    if via_call
        && !all
            .first()
            .copied()
            .flatten()
            .is_some_and(|this| nodes_equivalent(source, &this, &exports))
    {
        return None;
    }
    semantics.binding_id(&object).map(str::to_owned)
}
