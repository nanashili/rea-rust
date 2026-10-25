//! Syntax-level tRPC endpoint recognition.

use std::collections::BTreeSet;

use crate::javascript::ast::{AstContext, Field, Node};
use crate::javascript::semantic::ast_values::{
    final_object_string_property, is_call, static_property_key, unwrapped,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcEndpoint {
    pub value: String,
    pub mechanism: String,
}

const URL_LINKS: &[&str] = &[
    "httpLink",
    "httpBatchLink",
    "httpBatchStreamLink",
    "httpSubscriptionLink",
];

pub fn link_endpoint(context: &AstContext<'_>, call: Node<'_>) -> Option<RpcEndpoint> {
    if !is_call(&call) {
        return None;
    }
    let callee = call.field(context.source(), crate::javascript::ast::Field::Callee)?;
    let factory = rpc_factory_name(context, callee)
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_owned();
    if !URL_LINKS.contains(&factory.as_str()) {
        return None;
    }
    let options = call
        .field_list(context.source(), crate::javascript::ast::Field::Arguments)
        .first()
        .copied()
        .flatten()?;
    let value = final_object_string_property(context.source(), options, "url")?;
    Some(RpcEndpoint {
        value: value.to_owned(),
        mechanism: format!("trpc:link:{factory}"),
    })
}

const HOOKS: &[&str] = &[
    "useQuery",
    "useSuspenseQuery",
    "useInfiniteQuery",
    "useSuspenseInfiniteQuery",
    "usePrefetchQuery",
    "usePrefetchInfiniteQuery",
    "useMutation",
    "useSubscription",
    "queryOptions",
    "infiniteQueryOptions",
    "mutationOptions",
    "subscriptionOptions",
];

pub fn rpc_factory_name(context: &AstContext<'_>, node: Node<'_>) -> String {
    let mut current = unwrapped(context.source(), node);
    while current.babel_type() == "SequenceExpression" {
        let expressions = current.field_list(context.source(), Field::Expressions);
        let Some(last) = expressions.into_iter().rev().flatten().next() else {
            return String::new();
        };
        current = unwrapped(context.source(), last);
    }
    crate::javascript::static_analysis::helpers::callee_name(context, current)
}

pub fn is_rpc_client_factory(context: &AstContext<'_>, node: Node<'_>) -> bool {
    let call = unwrapped(context.source(), node);
    if !is_call(&call) {
        return false;
    }
    let Some(callee) = call.field(context.source(), Field::Callee) else {
        return false;
    };
    let name = rpc_factory_name(context, callee);
    name.ends_with("createTRPCClient") || name.ends_with("createTRPCProxyClient")
}

pub fn procedure_endpoint(
    context: &AstContext<'_>,
    call: Node<'_>,
    client_roots: &BTreeSet<String>,
    has_marker: bool,
) -> Option<RpcEndpoint> {
    if !is_call(&call) {
        return None;
    }
    let callee = call.field(context.source(), Field::Callee)?;
    let mut properties = Vec::new();
    let mut root = callee;
    while root.babel_type() == "MemberExpression" || root.babel_type() == "OptionalMemberExpression"
    {
        let property = root.field(context.source(), Field::Property)?;
        properties.push(
            static_property_key(context.source(), property, root.computed())?
                .try_to_string()
                .ok()?,
        );
        root = root.field(context.source(), Field::Object)?;
    }
    properties.reverse();
    let method = properties.pop()?;
    if properties.is_empty() || properties.iter().any(|it| it == "endpoints") {
        return None;
    }
    let root_name = root.identifier_name().unwrap_or_default();
    if [
        "window",
        "self",
        "globalThis",
        "document",
        "navigator",
        "location",
        "history",
        "console",
        "performance",
        "screen",
        "top",
        "parent",
        "frames",
    ]
    .contains(&root_name)
    {
        return None;
    }
    let bound = client_roots.contains(root_name);
    let recognized = if HOOKS.contains(&method.as_str()) {
        true
    } else if method == "query" || method == "mutate" {
        bound || (properties.len() >= 2 && has_marker)
    } else {
        false
    };
    recognized.then(|| RpcEndpoint {
        value: properties.join("."),
        mechanism: format!("trpc:procedure:{method}"),
    })
}

#[cfg(test)]
mod tests {
    use super::rpc_factory_name;
    use crate::javascript::ast::AstContext;
    use crate::javascript::parser::parse_javascript_analysis_program;
    use oxc_allocator::Allocator;

    #[test]
    fn factory_name_unwraps_sequence_expression() {
        let allocator = Allocator::default();
        let parsed = parse_javascript_analysis_program(
            &allocator,
            "(0, createTRPCClient)(opts);",
            Some("rpc.js"),
        )
        .expect("parse");
        let context = AstContext::new(parsed.program);
        let expression = context.children(&context.root())[0];
        let call = expression
            .field(context.source(), crate::javascript::ast::Field::Expression)
            .expect("expression");
        let callee = call
            .field(context.source(), crate::javascript::ast::Field::Callee)
            .expect("callee");
        assert_eq!(rpc_factory_name(&context, callee), "createTRPCClient");
    }
}
