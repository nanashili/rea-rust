//! Module tests for semantics the corpus harness
//! (`.cache/rust-migration/js-semantic-diff/`) cannot reach: cancellation,
//! symbolic truth predicates, and demand-driven captured values.
//! Scope/binding agreement with TS is established by that harness.
use std::ops::ControlFlow;

use oxc_allocator::Allocator;

use super::control_flow::{
    LogicalOperator, SymbolicShape, SymbolicTruthView, symbolic_logical_right, symbolic_truth,
};
use super::definitions::collect_definitions;
use super::state::ResolutionMode;
use super::symbolic_bindings::SymbolicBindings;
use super::symbolic_values::{LiteralValue, SymbolicEnvironment, SymbolicKind};
use crate::javascript::ast::{AstContext, AstVisitor, Node, traverse};
use crate::javascript::parser::parse_javascript_analysis_program;

#[test]
fn definitions_reproduce_parameter_and_body_scopes() {
    let allocator = Allocator::default();
    let source = "function f(a = 1) { var a; }";
    let parsed = parse_javascript_analysis_program(&allocator, source, Some("x.js")).unwrap();
    let ControlFlow::Continue(state) = collect_definitions::<()>(
        AstContext::new(parsed.program),
        ResolutionMode::Import,
        || ControlFlow::Continue(()),
    ) else {
        panic!("not cancelled");
    };
    let ids: Vec<&str> = state.scopes.iter().map(|s| s.scope_id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "scope:program:0:28",
            "scope:function:0:28",
            "scope:function:18:28"
        ]
    );
    let bindings: Vec<&str> = state.bindings_by_id.iter().map(|(id, _)| id).collect();
    assert_eq!(
        bindings,
        [
            "scope:program:0:28:binding:f",
            "scope:function:0:28:binding:a",
            "scope:function:18:28:binding:a",
        ]
    );
    // The body `a` starts with the parameter value (copyParameterToBody).
    let body = &state.bindings[2];
    assert!(body.initializers[0].entry_body.is_some());
}

#[test]
fn definitions_stop_at_a_cancelled_checkpoint() {
    let allocator = Allocator::default();
    // Like the TS generator, a short tree yields only before the first
    // queued write batch.
    let parsed = parse_javascript_analysis_program(&allocator, "a = 1;", Some("x.js")).unwrap();
    let result = collect_definitions(
        AstContext::new(parsed.program),
        ResolutionMode::Import,
        || ControlFlow::Break("cancelled"),
    );
    assert!(matches!(result, ControlFlow::Break("cancelled")));
}

fn call_nodes<'a>(context: &AstContext<'a>) -> Vec<Node<'a>> {
    struct Calls<'a> {
        nodes: Vec<Node<'a>>,
    }

    impl<'a> AstVisitor<'a> for Calls<'a> {
        fn enter(&mut self, node: &Node<'a>, _: Option<&Node<'a>>, _: &[Node<'a>]) {
            if matches!(
                node.babel_type(),
                "CallExpression" | "OptionalCallExpression"
            ) {
                self.nodes.push(*node);
            }
        }
    }

    let mut calls = Calls { nodes: Vec::new() };
    let _: ControlFlow<()> = traverse(context.root(), context.source(), &mut calls, || {
        ControlFlow::Continue(())
    });
    calls.nodes
}

fn identifier_nodes<'a>(context: &AstContext<'a>) -> Vec<Node<'a>> {
    struct Identifiers<'a> {
        nodes: Vec<Node<'a>>,
    }

    impl<'a> AstVisitor<'a> for Identifiers<'a> {
        fn enter(&mut self, node: &Node<'a>, _: Option<&Node<'a>>, _: &[Node<'a>]) {
            if node.babel_type() == "Identifier" && node.identifier_name() == Some("value") {
                self.nodes.push(*node);
            }
        }
    }

    let mut identifiers = Identifiers { nodes: Vec::new() };
    let _: ControlFlow<()> = traverse(context.root(), context.source(), &mut identifiers, || {
        ControlFlow::Continue(())
    });
    identifiers.nodes
}

fn string_value<'value, 'a>(
    value: &'value super::symbolic_values::SymbolicValue<'a>,
) -> &'value str {
    let SymbolicKind::Literal {
        value: LiteralValue::String(value),
    } = &value.kind
    else {
        panic!("expected a symbolic string literal, got {:?}", value.kind);
    };
    value.as_str().expect("test string is valid UTF-8")
}

#[test]
fn symbolic_resolution_keeps_returned_closure_captures() {
    let allocator = Allocator::default();
    let source = r#"
        function make(value) { return { read: () => value }; }
        make("captured").read();
    "#;
    let parsed = parse_javascript_analysis_program(&allocator, source, Some("x.js")).unwrap();
    let context = AstContext::new(parsed.program);
    let ControlFlow::Continue(state) = collect_definitions::<()>(
        AstContext::new(parsed.program),
        ResolutionMode::Import,
        || ControlFlow::Continue(()),
    ) else {
        panic!("not cancelled");
    };

    let mut resolver = SymbolicBindings::new(&state);
    let call = call_nodes(&context)
        .into_iter()
        .max_by_key(|node| node.span().end)
        .expect("member call");
    let result = resolver.evaluate(call, &SymbolicEnvironment::empty());

    assert_eq!(string_value(&result), "captured");
    assert!(!resolver.unresolved);
}

#[test]
fn symbolic_resolution_allows_returned_closure_to_read_completed_local() {
    let allocator = Allocator::default();
    let source = r#"
        function make() {
            const read = () => local;
            const local = "captured";
            return read;
        }
        make()();
    "#;
    let parsed = parse_javascript_analysis_program(&allocator, source, Some("x.js")).unwrap();
    let context = AstContext::new(parsed.program);
    let ControlFlow::Continue(state) = collect_definitions::<()>(
        AstContext::new(parsed.program),
        ResolutionMode::Import,
        || ControlFlow::Continue(()),
    ) else {
        panic!("not cancelled");
    };

    let mut resolver = SymbolicBindings::new(&state);
    let call = call_nodes(&context)
        .into_iter()
        .max_by_key(|node| node.span().end)
        .expect("returned closure call");
    let result = resolver.evaluate(call, &SymbolicEnvironment::empty());

    assert_eq!(string_value(&result), "captured");
    assert!(!resolver.unresolved);
}

#[test]
fn symbolic_resolution_expands_rest_parameters_for_member_reads() {
    let allocator = Allocator::default();
    let source = r#"
        function first(...items) { return items[0]; }
        first("first", "second");
    "#;
    let parsed = parse_javascript_analysis_program(&allocator, source, Some("x.js")).unwrap();
    let context = AstContext::new(parsed.program);
    let ControlFlow::Continue(state) = collect_definitions::<()>(
        AstContext::new(parsed.program),
        ResolutionMode::Import,
        || ControlFlow::Continue(()),
    ) else {
        panic!("not cancelled");
    };

    let mut resolver = SymbolicBindings::new(&state);
    let call = call_nodes(&context)
        .into_iter()
        .next()
        .expect("function call");
    let result = resolver.evaluate(call, &SymbolicEnvironment::empty());

    assert_eq!(string_value(&result), "first");
    assert!(!resolver.unresolved);
}

#[test]
fn symbolic_resolution_preserves_unknown_for_dynamic_property_overwrite() {
    let allocator = Allocator::default();
    let source = r#"
        function read() {
            return { value: "stable", ...{ [unknown]: "dynamic" } }.value;
        }
        read();
    "#;
    let parsed = parse_javascript_analysis_program(&allocator, source, Some("x.js")).unwrap();
    let context = AstContext::new(parsed.program);
    let ControlFlow::Continue(state) = collect_definitions::<()>(
        AstContext::new(parsed.program),
        ResolutionMode::Import,
        || ControlFlow::Continue(()),
    ) else {
        panic!("not cancelled");
    };

    let mut resolver = SymbolicBindings::new(&state);
    let call = call_nodes(&context)
        .into_iter()
        .next()
        .expect("function call");
    let result = resolver.evaluate(call, &SymbolicEnvironment::empty());

    assert!(matches!(result.kind, SymbolicKind::Unknown { .. }));
    assert!(!resolver.unresolved);
}

#[test]
fn symbolic_resolution_handles_a_self_spread_cycle_as_unknown() {
    let allocator = Allocator::default();
    let source = r#"
        function read() {
            const object = { ...object };
            return object.value;
        }
        read();
    "#;
    let parsed = parse_javascript_analysis_program(&allocator, source, Some("x.js")).unwrap();
    let context = AstContext::new(parsed.program);
    let ControlFlow::Continue(state) = collect_definitions::<()>(
        AstContext::new(parsed.program),
        ResolutionMode::Import,
        || ControlFlow::Continue(()),
    ) else {
        panic!("not cancelled");
    };

    let mut resolver = SymbolicBindings::new(&state);
    let call = call_nodes(&context)
        .into_iter()
        .next()
        .expect("function call");
    let result = resolver.evaluate(call, &SymbolicEnvironment::empty());

    assert!(matches!(result.kind, SymbolicKind::Unknown { .. }));
    assert!(resolver.unresolved);
    assert!(!resolver.truncated);
}

#[test]
fn symbolic_resolution_marks_recursive_aliases_unresolved_at_their_read_boundary() {
    let allocator = Allocator::default();
    let source = "const value = value; value;";
    let parsed = parse_javascript_analysis_program(&allocator, source, Some("x.js")).unwrap();
    let context = AstContext::new(parsed.program);
    let ControlFlow::Continue(state) = collect_definitions::<()>(
        AstContext::new(parsed.program),
        ResolutionMode::Import,
        || ControlFlow::Continue(()),
    ) else {
        panic!("not cancelled");
    };

    let identifier = identifier_nodes(&context)
        .into_iter()
        .max_by_key(|node| node.span().start)
        .expect("value identifier");
    let mut resolver = SymbolicBindings::new(&state);
    let result = resolver.evaluate(identifier, &SymbolicEnvironment::empty());

    assert!(matches!(result.kind, SymbolicKind::Unknown { .. }));
    assert!(resolver.unresolved);
    assert!(!resolver.truncated);
}

#[test]
fn symbolic_resolution_bounds_recursive_factory_spreads() {
    let allocator = Allocator::default();
    let source = r#"
        function make() { return { ...make() }; }
        make().value;
    "#;
    let parsed = parse_javascript_analysis_program(&allocator, source, Some("x.js")).unwrap();
    let context = AstContext::new(parsed.program);
    let ControlFlow::Continue(state) = collect_definitions::<()>(
        AstContext::new(parsed.program),
        ResolutionMode::Import,
        || ControlFlow::Continue(()),
    ) else {
        panic!("not cancelled");
    };

    let mut resolver = SymbolicBindings::new(&state);
    let member = context
        .root()
        .children(context.source())
        .into_iter()
        .find_map(|statement| {
            statement
                .children(context.source())
                .into_iter()
                .find(|node| node.babel_type() == "MemberExpression")
        })
        .expect("recursive factory member read");
    let result = resolver.evaluate(member, &SymbolicEnvironment::empty());

    assert!(matches!(result.kind, SymbolicKind::Unknown { .. }));
    assert!(resolver.truncated);
}

enum Value {
    Literal(Option<bool>),
    Namespace(bool),
    Union(Vec<Value>),
    Object,
    Unknown,
}

impl SymbolicTruthView for Value {
    fn shape(&self) -> SymbolicShape<'_, Self> {
        match self {
            // `None` is a nullish literal.
            Self::Literal(None) => SymbolicShape::Literal {
                nullish: true,
                truthy: false,
            },
            Self::Literal(Some(truthy)) => SymbolicShape::Literal {
                nullish: false,
                truthy: *truthy,
            },
            Self::Namespace(unknown) => SymbolicShape::Namespace {
                runtime_value_unknown: *unknown,
            },
            Self::Union(values) => SymbolicShape::Union(values),
            Self::Object => SymbolicShape::Object,
            Self::Unknown => SymbolicShape::Opaque,
        }
    }
}

#[test]
fn symbolic_logical_right_matches_short_circuit_rules() {
    use LogicalOperator::{And, Nullish, Or};
    assert_eq!(
        symbolic_logical_right(Nullish, &Value::Literal(None)),
        Some(true)
    );
    assert_eq!(
        symbolic_logical_right(Nullish, &Value::Literal(Some(false))),
        Some(false)
    );
    assert_eq!(symbolic_logical_right(Nullish, &Value::Object), Some(false));
    assert_eq!(symbolic_logical_right(Nullish, &Value::Unknown), None);
    assert_eq!(
        symbolic_logical_right(And, &Value::Literal(Some(false))),
        Some(false)
    );
    assert_eq!(
        symbolic_logical_right(Or, &Value::Literal(Some(false))),
        Some(true)
    );
    assert_eq!(symbolic_logical_right(Or, &Value::Namespace(true)), None);
    assert_eq!(
        symbolic_logical_right(And, &Value::Namespace(false)),
        Some(true)
    );
    let mixed = Value::Union(vec![Value::Object, Value::Literal(Some(false))]);
    assert_eq!(symbolic_logical_right(And, &mixed), None);
    let same = Value::Union(vec![Value::Object, Value::Literal(Some(true))]);
    assert_eq!(symbolic_logical_right(And, &same), Some(true));
    assert_eq!(symbolic_truth(&Value::Union(Vec::new())), None);
}
