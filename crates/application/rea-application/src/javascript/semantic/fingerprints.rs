//! Fingerprint projection for the JavaScript semantic IR.
//!
//! This is the Rust counterpart of `javascriptSemanticFingerprints.ts`.  The
//! syntax portion is derived directly from the shared Babel-shaped AST view;
//! relation and effect portions consume their owning typed semantic records.
//! Keeping those phases separate prevents this module from reinterpreting raw
//! provider JSON or rebuilding ownership decisions made by the producers.

use std::collections::HashMap;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::javascript::ast::{AstVisitor, Field, Node, traverse};
use crate::javascript::contracts::semantic_ir::{
    SemanticCallSite, SemanticCallable, SemanticChildProcessInteraction, SemanticChildProcessSpawn,
    SemanticClosureCapture, SemanticEventOperation, SemanticFunctionFingerprint,
    SemanticFunctionFingerprintComponents, SemanticPromiseOperation, SemanticRequestOperation,
    SemanticResourceOperation, SemanticTimerOperation,
};

use super::ast_values::runtime_function_parameters;
use super::projection::callable_id_for_node;
use super::state::SemanticState;
use super::value_types::JsString;
use crate::javascript::static_analysis::babel::{
    function_flags, prefix, regexp_parts, template_value,
};

const STATIC_LIMITATION: &str =
    "The fingerprint is a static candidate and does not prove behavioral equivalence.";

/// All producer-owned facts needed to build function fingerprints.
pub struct SemanticFingerprintInputs<'a> {
    pub callables: &'a [SemanticCallable],
    pub call_sites: &'a [SemanticCallSite],
    pub closure_captures: &'a [SemanticClosureCapture],
    pub promises: &'a [SemanticPromiseOperation],
    pub events: &'a [SemanticEventOperation],
    pub timers: &'a [SemanticTimerOperation],
    pub child_process_spawns: &'a [SemanticChildProcessSpawn],
    pub child_process_interactions: &'a [SemanticChildProcessInteraction],
    pub requests: &'a [SemanticRequestOperation],
    pub resources: &'a [SemanticResourceOperation],
}

/// Build bounded, rename- and formatting-resistant fingerprints in callable order.
pub fn collect_semantic_fingerprints<'a>(
    state: &SemanticState<'a>,
    input: &SemanticFingerprintInputs<'_>,
    parser_partial: bool,
) -> Vec<SemanticFunctionFingerprint> {
    let nodes = callable_nodes(state);
    let call_sites = group_by_owner(input.call_sites, |value| {
        value.caller_callable_id.as_deref()
    });
    let captures = count_captures(input.closure_captures);
    let promises = group_by_owner(input.promises, |value| value.owner_callable_id.as_deref());
    let events = group_by_owner(input.events, |value| value.owner_callable_id.as_deref());
    let timers = group_by_owner(input.timers, |value| value.owner_callable_id.as_deref());
    let child_processes = group_by_owner_combined(
        input.child_process_spawns,
        input.child_process_interactions,
        |value| value.owner_callable_id.as_deref(),
        |value| value.owner_callable_id.as_deref(),
    );
    let requests = group_by_owner(input.requests, |value| value.owner_callable_id.as_deref());
    let resources = group_by_owner(input.resources, |value| value.owner_callable_id.as_deref());

    let mut fingerprints = Vec::new();
    for callable in input.callables {
        if callable.kind == "class" {
            continue;
        }
        let Some(node) = nodes.get(&callable.callable_id) else {
            continue;
        };
        let syntax = syntax_fingerprint(state, *node);
        let owner = callable.callable_id.as_str();
        let promise_values = promises.get(owner).map(Vec::as_slice).unwrap_or(&[]);
        let mut limitations = vec![STATIC_LIMITATION.to_owned()];
        if parser_partial {
            limitations
                .push("Incomplete semantic recovery makes this fingerprint partial.".to_owned());
        }
        fingerprints.push(SemanticFunctionFingerprint {
            callable_id: callable.callable_id.clone(),
            status: if parser_partial || return_status_is_partial(&callable.return_coverage) {
                "partial".to_owned()
            } else {
                "complete".to_owned()
            },
            components: SemanticFunctionFingerprintComponents {
                parameter_arity: runtime_function_parameters(state.source, node).len(),
                normalized_ast_sha256: digest(&syntax.normalized_tokens),
                control_flow_sha256: digest(&syntax.control_flow_tokens),
                relation_shape_sha256: digest(&relation_shape(
                    callable,
                    call_sites.get(owner).map(Vec::as_slice).unwrap_or(&[]),
                    captures.get(owner).copied().unwrap_or(0),
                    promise_values,
                )),
                literal_set_sha256: digest_set(&syntax.literals),
                effects: effects(
                    node,
                    child_processes
                        .get(owner)
                        .is_some_and(|values| !values.is_empty()),
                    events.get(owner).is_some_and(|values| !values.is_empty()),
                    requests.get(owner).is_some_and(|values| !values.is_empty()),
                    !promise_values.is_empty(),
                    resources
                        .get(owner)
                        .is_some_and(|values| !values.is_empty()),
                    timers.get(owner).is_some_and(|values| !values.is_empty()),
                ),
            },
            limitations,
        });
    }
    fingerprints
}

fn callable_nodes<'a>(state: &SemanticState<'a>) -> HashMap<String, Node<'a>> {
    struct Collector<'s, 'a> {
        state: &'s SemanticState<'a>,
        nodes: HashMap<String, Node<'a>>,
    }
    impl<'s, 'a> AstVisitor<'a> for Collector<'s, 'a> {
        fn enter(&mut self, node: &Node<'a>, _parent: Option<&Node<'a>>, _ancestors: &[Node<'a>]) {
            if let Some(id) = callable_id_for_node(&self.state.context, node) {
                self.nodes.insert(id, *node);
            }
        }
    }
    let mut collector = Collector {
        state,
        nodes: HashMap::new(),
    };
    let _ = traverse(state.program, state.source, &mut collector, || {
        std::ops::ControlFlow::<()>::Continue(())
    });
    collector.nodes
}

#[derive(Default)]
struct SyntaxFingerprint {
    normalized_tokens: Vec<JsString>,
    control_flow_tokens: Vec<JsString>,
    literals: Vec<JsString>,
}

struct SyntaxCollector<'s, 'a> {
    state: &'s SemanticState<'a>,
    output: SyntaxFingerprint,
}

impl<'s, 'a> AstVisitor<'a> for SyntaxCollector<'s, 'a> {
    fn skip(&mut self, node: &Node<'a>) -> bool {
        callable_id_for_node(&self.state.context, node).is_some()
    }

    fn enter(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>, _ancestors: &[Node<'a>]) {
        self.output
            .normalized_tokens
            .push(normalized_node_token(self.state.source, node, parent));
        if let Some(token) = control_flow_token(node) {
            self.output.control_flow_tokens.push(token);
        }
        if let Some(literal) = semantic_literal(self.state.source, node) {
            self.output.literals.push(literal);
        }
    }
}

fn syntax_fingerprint<'a>(state: &SemanticState<'a>, root: Node<'a>) -> SyntaxFingerprint {
    let mut collector = SyntaxCollector {
        state,
        output: SyntaxFingerprint::default(),
    };
    let _ = traverse(root, state.source, &mut collector, || {
        std::ops::ControlFlow::<()>::Continue(())
    });
    collector.output
}

fn normalized_node_token(source: &str, node: &Node<'_>, parent: Option<&Node<'_>>) -> JsString {
    if node.babel_type() == "Identifier" {
        return if property_identity(source, node, parent) {
            JsString::from("property:").concat_str(node.identifier_name().unwrap_or_default())
        } else {
            JsString::from("identifier")
        };
    }
    if node.babel_type() == "StringLiteral" {
        return if property_identity(source, node, parent) {
            JsString::from("property:").concat(&JsString::from_utf16(
                node.string_value_units().unwrap_or_default(),
            ))
        } else {
            JsString::from("string-literal")
        };
    }
    let mut token = JsString::from(node.babel_type());
    if let Some(operator) = node.operator() {
        token = token.concat_str(&format!(":operator={operator}"));
    }
    if let Some(kind) = node.declaration_kind() {
        token = token.concat_str(&format!(":kind={kind}"));
    }
    if matches!(
        node.babel_type(),
        "MemberExpression"
            | "OptionalMemberExpression"
            | "ObjectProperty"
            | "ObjectMethod"
            | "ClassMethod"
            | "ClassProperty"
    ) {
        token = token.concat_str(&format!(":computed={}", node.computed()));
    }
    if matches!(
        node.babel_type(),
        "OptionalMemberExpression" | "OptionalCallExpression"
    ) {
        token = token.concat_str(&format!(":optional={}", node.optional()));
    }
    if let Some((is_async, generator)) = function_flags(node) {
        token = token.concat_str(&format!(":async={is_async}:generator={generator}"));
    }
    if node.babel_type() == "YieldExpression" {
        token = token.concat_str(&format!(":delegate={}", node.delegate()));
    }
    if let Some(is_prefix) = prefix(node) {
        token = token.concat_str(&format!(":prefix={is_prefix}"));
    }
    token
}

fn property_identity(source: &str, node: &Node<'_>, parent: Option<&Node<'_>>) -> bool {
    let Some(parent) = parent else {
        return false;
    };
    let field = match parent.babel_type() {
        "MemberExpression" | "OptionalMemberExpression" => Field::Property,
        "ObjectProperty" | "ObjectMethod" | "ClassMethod" | "ClassProperty" => Field::Key,
        _ => return false,
    };
    parent
        .field(source, field)
        .is_some_and(|property| property.key() == node.key())
        && (!parent.computed() || node.babel_type() == "StringLiteral")
}

fn control_flow_token(node: &Node<'_>) -> Option<JsString> {
    let is_control = matches!(
        node.babel_type(),
        "IfStatement"
            | "ConditionalExpression"
            | "SwitchStatement"
            | "SwitchCase"
            | "ForStatement"
            | "ForInStatement"
            | "ForOfStatement"
            | "WhileStatement"
            | "DoWhileStatement"
            | "TryStatement"
            | "CatchClause"
            | "ReturnStatement"
            | "ThrowStatement"
            | "AwaitExpression"
            | "YieldExpression"
            | "LogicalExpression"
    );
    if !is_control {
        return None;
    }
    Some(node.operator().map_or_else(
        || JsString::from(node.babel_type()),
        |operator| JsString::from(format!("{}:operator={operator}", node.babel_type())),
    ))
}

fn semantic_literal(source: &str, node: &Node<'_>) -> Option<JsString> {
    match node.babel_type() {
        "DirectiveLiteral" => Some(
            JsString::from("directive:").concat(&JsString::from_utf16(node.string_value_units()?)),
        ),
        "StringLiteral" => Some(
            JsString::from("string:").concat(&JsString::from_utf16(node.string_value_units()?)),
        ),
        "NumericLiteral" => Some(JsString::from(format!(
            "number:{}",
            super::ast_values::js_number_string(node.numeric_value()?)
        ))),
        "BooleanLiteral" => Some(JsString::from(format!("boolean:{}", node.boolean_value()?))),
        "NullLiteral" => Some(JsString::from("null")),
        "BigIntLiteral" => Some(JsString::from(format!("bigint:{}", node.bigint_decimal()?))),
        "RegExpLiteral" => {
            let (pattern, flags) = regexp_parts(source, node)?;
            Some(JsString::from(format!("regexp:{pattern}/{flags}")))
        }
        "TemplateElement" => {
            let template = template_value(node)?;
            let value = template
                .cooked
                .unwrap_or_else(|| JsString::from(template.raw));
            Some(JsString::from("template:").concat(&value))
        }
        _ => None,
    }
}

fn return_status_is_partial(value: &Value) -> bool {
    value
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| status != "complete")
}

fn relation_shape(
    callable: &SemanticCallable,
    calls: &[&SemanticCallSite],
    capture_count: usize,
    promises: &[&SemanticPromiseOperation],
) -> Vec<JsString> {
    let mut result = vec![JsString::from(format!(
        "returns:{}:{}",
        callable.return_sites.len(),
        callable
            .return_coverage
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    ))];
    result.extend(calls.iter().map(|call| {
        JsString::from(format!(
            "call:{}:{}:{}:{}",
            call.kind,
            call.resolution,
            call.arguments.len(),
            call.callee_callable_ids.len()
        ))
    }));
    result.push(JsString::from(format!("captures:{capture_count}")));
    result.extend(promises.iter().map(|promise| {
        JsString::from(format!(
            "promise:{}:{}:{}:{}",
            promise.kind, promise.method, promise.ownership, promise.source_resolution
        ))
    }));
    result
}

fn effects(
    node: &Node<'_>,
    child: bool,
    event: bool,
    network: bool,
    promise: bool,
    resource: bool,
    timer: bool,
) -> Vec<String> {
    let mut result = Vec::new();
    if function_flags(node).is_some_and(|(is_async, _)| is_async) {
        result.push("async".to_owned());
    }
    if child {
        result.push("child-process".to_owned());
    }
    if event {
        result.push("event".to_owned());
    }
    if network {
        result.push("network".to_owned());
    }
    if promise {
        result.push("promise".to_owned());
    }
    if resource {
        result.push("resource".to_owned());
    }
    if timer {
        result.push("timer".to_owned());
    }
    result
}

fn digest(values: &[JsString]) -> String {
    let encoded = serde_json::to_vec(values).expect("string arrays are serializable");
    format!("{:x}", Sha256::digest(encoded))
}

fn digest_set(values: &[JsString]) -> String {
    let mut unique = values.iter().cloned().collect::<Vec<_>>();
    unique.sort_by(JsString::compare_code_points);
    unique.dedup();
    digest(&unique)
}

fn group_by_owner<T>(values: &[T], owner: impl Fn(&T) -> Option<&str>) -> HashMap<String, Vec<&T>> {
    let mut grouped = HashMap::new();
    for value in values {
        if let Some(owner) = owner(value) {
            grouped
                .entry(owner.to_owned())
                .or_insert_with(Vec::new)
                .push(value);
        }
    }
    grouped
}

fn group_by_owner_combined<A, B>(
    left: &[A],
    right: &[B],
    left_owner: impl Fn(&A) -> Option<&str>,
    right_owner: impl Fn(&B) -> Option<&str>,
) -> HashMap<String, Vec<()>> {
    let mut grouped = HashMap::new();
    for value in left {
        if let Some(owner) = left_owner(value) {
            grouped
                .entry(owner.to_owned())
                .or_insert_with(Vec::new)
                .push(());
        }
    }
    for value in right {
        if let Some(owner) = right_owner(value) {
            grouped
                .entry(owner.to_owned())
                .or_insert_with(Vec::new)
                .push(());
        }
    }
    grouped
}

fn count_captures(values: &[SemanticClosureCapture]) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for capture in values {
        *counts.entry(capture.callable_id.clone()).or_insert(0) += 1;
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::javascript::ast::{AstContext, AstVisitor, NodeMap, traverse};
    use crate::javascript::contracts::semantic_ir::SemanticCallable;
    use crate::javascript::contracts::static_analysis::{SourcePoint, SourceRange};
    use crate::javascript::parser::parse_javascript_analysis_program;
    use crate::javascript::semantic::definitions::collect_definitions;
    use crate::javascript::semantic::state::ResolutionMode;
    use oxc_allocator::Allocator;
    use serde_json::json;
    use std::ops::ControlFlow;

    struct Nodes<'a> {
        parents: NodeMap<Node<'a>>,
        nodes: Vec<Node<'a>>,
    }

    impl<'a> AstVisitor<'a> for Nodes<'a> {
        fn enter(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>, _ancestors: &[Node<'a>]) {
            if let Some(parent) = parent {
                self.parents.insert(node.key(), *parent);
            }
            self.nodes.push(*node);
        }
    }

    #[test]
    fn literal_projection_preserves_regex_and_invalid_template_fallbacks() {
        let allocator = Allocator::default();
        let source = r#"const value = /a\/b/gu; const template = `invalid\u{}`;"#;
        let parsed = parse_javascript_analysis_program(&allocator, source, Some("x.ts"))
            .expect("source parses");
        let context = AstContext::new(parsed.program);
        let mut nodes = Nodes {
            parents: NodeMap::default(),
            nodes: Vec::new(),
        };
        assert!(matches!(
            traverse(context.root(), source, &mut nodes, || {
                ControlFlow::<()>::Continue(())
            }),
            ControlFlow::Continue(())
        ));

        let regexp = nodes
            .nodes
            .iter()
            .find(|node| node.babel_type() == "RegExpLiteral")
            .copied()
            .expect("regular expression literal");
        assert_eq!(
            semantic_literal(source, &regexp),
            Some(JsString::from("regexp:a\\/b/gu"))
        );

        let template = nodes
            .nodes
            .iter()
            .find(|node| node.babel_type() == "TemplateElement")
            .copied()
            .expect("template element");
        assert_eq!(
            semantic_literal(source, &template),
            Some(JsString::from("template:invalid\\u{}"))
        );
    }

    #[test]
    fn directive_literal_projection_matches_babel_value() {
        let allocator = Allocator::default();
        let source = r#""use strict"; function f() { "use strict"; }"#;
        let parsed = parse_javascript_analysis_program(&allocator, source, Some("x.js"))
            .expect("source parses");
        let context = AstContext::new(parsed.program);
        let mut nodes = Nodes {
            parents: NodeMap::default(),
            nodes: Vec::new(),
        };
        let ControlFlow::Continue(()) = traverse(context.root(), source, &mut nodes, || {
            ControlFlow::<()>::Continue(())
        }) else {
            panic!("directive traversal was cancelled");
        };

        let directives = nodes
            .nodes
            .iter()
            .filter(|node| node.babel_type() == "DirectiveLiteral")
            .map(|node| semantic_literal(source, node))
            .collect::<Vec<_>>();
        assert_eq!(
            directives,
            vec![
                Some(JsString::from("directive:use strict")),
                Some(JsString::from("directive:use strict")),
            ]
        );
    }

    #[test]
    fn literal_set_digest_uses_unicode_codepoint_order() {
        assert_eq!(
            digest_set(&[JsString::from("literal:😀"), JsString::from("literal:é")]),
            "2a69dd036263c74123da98f69a2328efce85bf60646878cc23ff3fe486b67a41"
        );
    }

    #[test]
    fn callable_fingerprint_matches_pinned_node_oracle_for_adversarial_shape() {
        let allocator = Allocator::default();
        let source = r#"async function outer(a){ const r=/a\/b/g; const t=`x`; function inner(){return 1}; if(a){await f?.(r)} return t; }"#;
        let parsed = parse_javascript_analysis_program(&allocator, source, Some("x.ts"))
            .expect("source parses");
        let ControlFlow::Continue(state) = collect_definitions::<()>(
            AstContext::new(parsed.program),
            ResolutionMode::Import,
            || ControlFlow::Continue(()),
        ) else {
            panic!("definition collection was cancelled");
        };
        let mut nodes = Vec::new();
        struct Collect<'a> {
            nodes: Vec<Node<'a>>,
        }
        impl<'a> AstVisitor<'a> for Collect<'a> {
            fn enter(&mut self, node: &Node<'a>, _: Option<&Node<'a>>, _: &[Node<'a>]) {
                self.nodes.push(*node);
            }
        }
        let mut collector = Collect { nodes: Vec::new() };
        let _ = traverse(state.program, source, &mut collector, || {
            ControlFlow::<()>::Continue(())
        });
        nodes.extend(
            collector
                .nodes
                .into_iter()
                .filter(|node| callable_id_for_node(&state.context, node).is_some()),
        );
        let callables = nodes
            .iter()
            .map(|node| SemanticCallable {
                callable_id: callable_id_for_node(&state.context, node).expect("callable id"),
                kind: if node.babel_type() == "ClassDeclaration" {
                    "class".to_owned()
                } else {
                    "function".to_owned()
                },
                name: None,
                container_scope_id: "scope:program:0:0".to_owned(),
                body_scope_id: None,
                location: SourceRange {
                    start: SourcePoint { line: 1, column: 0 },
                    end: SourcePoint { line: 1, column: 0 },
                },
                return_sites: Vec::new(),
                return_coverage: json!({"status":"complete"}),
            })
            .collect::<Vec<_>>();
        let output = collect_semantic_fingerprints(
            &state,
            &SemanticFingerprintInputs {
                callables: &callables,
                call_sites: &[],
                closure_captures: &[],
                promises: &[],
                events: &[],
                timers: &[],
                child_process_spawns: &[],
                child_process_interactions: &[],
                requests: &[],
                resources: &[],
            },
            false,
        );
        assert_eq!(output.len(), 2);
        assert_eq!(output[0].callable_id, "callable:function:0:114");
        assert_eq!(
            output[0].components.normalized_ast_sha256,
            "50a64bcb89017e4998d1a68ed488c3226fa3e8bea3b4fbe220a829b00d1d772b"
        );
        assert_eq!(
            output[0].components.control_flow_sha256,
            "5a5d178eb15060687511c486caec4738af06b367fa9a2a3899374d9f1e815dee"
        );
        assert_eq!(
            output[0].components.literal_set_sha256,
            "d40f293863294a6fd5925a3847eb24b3bb95b2b5d8902d2ba9d66e94e2c00bb0"
        );
    }
}
