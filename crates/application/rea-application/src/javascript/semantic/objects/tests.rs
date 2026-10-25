use std::ops::ControlFlow;

use oxc_allocator::Allocator;

use super::*;
use crate::javascript::ast::AstContext;
use crate::javascript::parser::parse_javascript_analysis_program;
use crate::javascript::semantic::definitions::collect_definitions;
use crate::javascript::semantic::projection::collect_semantic_projection;
use crate::javascript::semantic::state::ResolutionMode;
use crate::javascript::semantic::value_types::JsString;

fn analyze(
    source: &str,
    admit: impl Fn(&SemanticCallable) -> bool,
) -> (Vec<SemanticCallable>, Vec<SemanticObjectOperation>) {
    let allocator = Allocator::default();
    let parsed = parse_javascript_analysis_program(&allocator, source, Some("fixture.js"))
        .expect("valid fixture");
    let ControlFlow::Continue(state) = collect_definitions::<()>(
        AstContext::new(parsed.program),
        ResolutionMode::Import,
        || ControlFlow::Continue(()),
    ) else {
        panic!("fixture analysis must not cancel");
    };
    let (callables, _) = collect_semantic_projection(&state);
    let admitted = callables
        .iter()
        .filter(|callable| admit(callable))
        .cloned()
        .collect::<Vec<_>>();
    let operations = collect_semantic_objects(&state, &admitted);
    (callables, operations)
}

#[test]
fn computed_method_keys_belong_to_outer_callable_and_body_writes_read_first() {
    let source = "function outer(source, keys) { return { [keys.name](arg = source.defaultValue) { source.deep.value += arg; } }; }";
    let (callables, operations) = analyze(source, |_| true);
    let outer = &callables
        .iter()
        .find(|callable| callable.name.as_ref().is_some_and(|name| name == "outer"))
        .unwrap()
        .callable_id;
    let method = &callables
        .iter()
        .find(|callable| callable.kind == "method")
        .unwrap()
        .callable_id;

    assert_eq!(operations.len(), 4);
    assert_eq!(operations[0].owner_callable_id.as_ref(), Some(outer));
    assert_eq!(
        operations[0].property_path.as_deref(),
        Some([JsString::from("name")].as_slice())
    );
    assert!(
        operations[1..]
            .iter()
            .all(|operation| operation.owner_callable_id.as_ref() == Some(method))
    );
    assert_eq!(operations[2].kind, SemanticObjectOperationKind::Read);
    assert_eq!(operations[3].kind, SemanticObjectOperationKind::Write);
    assert_eq!(
        operations[2].property_path.as_deref(),
        Some([JsString::from("deep"), JsString::from("value")].as_slice())
    );
    assert_eq!(operations[2].property_path, operations[3].property_path);
    assert_eq!(operations[2].location, operations[3].location);
    assert!(
        operations
            .iter()
            .all(|operation| operation.resolution == SemanticOperationResolution::Complete)
    );
}

#[test]
fn ignored_methods_do_not_suspend_the_enclosing_admitted_callable() {
    let source =
        "function outer(source, keys) { return { [keys.name]() { return source.value; } }; }";
    let (callables, operations) = analyze(source, |callable| callable.kind == "function");
    let outer = &callables
        .iter()
        .find(|callable| callable.name.as_ref().is_some_and(|name| name == "outer"))
        .unwrap()
        .callable_id;

    assert_eq!(operations.len(), 2);
    assert!(
        operations
            .iter()
            .all(|operation| operation.owner_callable_id.as_ref() == Some(outer))
    );
}

#[test]
fn nested_destructuring_keeps_source_paths_and_dynamic_source_uncertainty() {
    let source = "const source = {}; const { a: [first = 1,, third], ...rest } = source.child; let second; ({ b: second } = source[key]);";
    let (_, operations) = analyze(source, |_| true);
    let destructuring = operations
        .iter()
        .filter(|operation| operation.kind == SemanticObjectOperationKind::Destructure)
        .collect::<Vec<_>>();

    assert_eq!(destructuring.len(), 3);
    assert_eq!(
        destructuring[0].property_path.as_deref(),
        Some(
            [
                JsString::from("child"),
                JsString::from("a"),
                JsString::from("0"),
            ]
            .as_slice()
        )
    );
    assert_eq!(
        destructuring[1].property_path.as_deref(),
        Some(
            [
                JsString::from("child"),
                JsString::from("a"),
                JsString::from("2"),
            ]
            .as_slice()
        )
    );
    assert!(
        destructuring[0]
            .target_binding_id
            .as_ref()
            .unwrap()
            .ends_with(":binding:first")
    );
    assert!(
        destructuring[1]
            .target_binding_id
            .as_ref()
            .unwrap()
            .ends_with(":binding:third")
    );
    assert_eq!(destructuring[2].property_path, None);
    assert!(destructuring[2].object_binding_id.is_some());
    assert_eq!(
        destructuring[2].resolution,
        SemanticOperationResolution::Partial
    );
}
