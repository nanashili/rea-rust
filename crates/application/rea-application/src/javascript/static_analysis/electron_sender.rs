//! Electron sender and frame validation observations.
//!
//! These checks record syntax visible to the static analyzer.  They do not
//! decide whether a comparison is reachable or whether a check enforces an
//! authorization policy.

use crate::javascript::ast::{AstContext, Field, Node};
use crate::javascript::contracts::static_analysis::{SenderValidation, StaticValue};
use crate::javascript::semantic::ast_values::static_property_key;

use super::electron_values::electron_static_value;
use super::helpers::{callee_name, range};

/// Inspect one call or comparison for an Electron sender validation.
pub fn inspect(
    context: &AstContext<'_>,
    node: Node<'_>,
    validations: &mut Vec<SenderValidation>,
    unknown_findings: &mut u64,
) {
    match node.babel_type() {
        "CallExpression" | "OptionalCallExpression" => {
            inspect_validation_call(context, node, validations, unknown_findings);
        }
        "BinaryExpression" => {
            inspect_validation_comparison(context, node, validations, unknown_findings);
        }
        _ => {}
    }
}

fn inspect_validation_call(
    context: &AstContext<'_>,
    node: Node<'_>,
    validations: &mut Vec<SenderValidation>,
    unknown_findings: &mut u64,
) {
    let Some(callee) = node.field(context.source(), Field::Callee) else {
        return;
    };
    if callee.babel_type() != "MemberExpression"
        && callee.babel_type() != "OptionalMemberExpression"
    {
        return;
    }
    let Some(method) = callee
        .field(context.source(), Field::Property)
        .and_then(|property| static_property_key(context.source(), property, callee.computed()))
        .and_then(|value| value.try_to_string().ok())
    else {
        return;
    };
    if !matches!(method.as_str(), "startsWith" | "endsWith" | "includes") {
        return;
    }
    let Some(subject_node) = callee.field(context.source(), Field::Object) else {
        return;
    };
    let Some(subject) = sender_subject(context, subject_node) else {
        return;
    };
    let expected = first_argument_value(context, node);
    add_validation(
        context,
        node,
        subject,
        format!("call:{method}"),
        expected,
        validations,
        unknown_findings,
    );
}

fn inspect_validation_comparison(
    context: &AstContext<'_>,
    node: Node<'_>,
    validations: &mut Vec<SenderValidation>,
    unknown_findings: &mut u64,
) {
    if !matches!(node.operator(), Some("==" | "===" | "!=" | "!==" | "in")) {
        return;
    }
    let Some(left) = node.field(context.source(), Field::Left) else {
        return;
    };
    let Some(right) = node.field(context.source(), Field::Right) else {
        return;
    };
    let left_subject = sender_subject(context, left);
    let right_subject = sender_subject(context, right);
    let (subject, expected_node) = match (left_subject, right_subject) {
        (Some(subject), _) => (subject, right),
        (None, Some(subject)) => (subject, left),
        (None, None) => return,
    };
    add_validation(
        context,
        node,
        subject,
        format!("comparison:{}", node.operator().unwrap_or_default()),
        electron_static_value(context, Some(expected_node)),
        validations,
        unknown_findings,
    );
}

fn first_argument_value(context: &AstContext<'_>, node: Node<'_>) -> StaticValue {
    let argument = node
        .field_list(context.source(), Field::Arguments)
        .into_iter()
        .next()
        .flatten();
    electron_static_value(context, argument)
}

fn add_validation(
    context: &AstContext<'_>,
    node: Node<'_>,
    subject: &'static str,
    mechanism: String,
    expected: StaticValue,
    validations: &mut Vec<SenderValidation>,
    unknown_findings: &mut u64,
) {
    if expected.status == "dynamic" {
        *unknown_findings += 1;
    }
    validations.push(SenderValidation {
        module_key: None,
        location: range(context, &node),
        subject: subject.to_owned(),
        mechanism,
        expected,
        enforcement: "unknown".to_owned(),
        module_runtime: None,
    });
}

fn sender_subject(context: &AstContext<'_>, node: Node<'_>) -> Option<&'static str> {
    let subject_node = match node.babel_type() {
        "CallExpression" | "OptionalCallExpression" => {
            node.field(context.source(), Field::Callee)?
        }
        _ => node,
    };
    let name = callee_name(context, subject_node);
    if name == "sender.getURL" || name.ends_with(".sender.getURL") {
        return Some("sender-url");
    }
    if name == "senderFrame.origin" || name.ends_with(".senderFrame.origin") {
        return Some("sender-origin");
    }
    if name == "senderFrame.url" || name.ends_with(".senderFrame.url") {
        return Some("sender-url");
    }
    if name == "senderFrame" || name.ends_with(".senderFrame") {
        return Some("sender-frame");
    }
    if name == "sender.id" || name.ends_with(".sender.id") {
        return Some("sender-id");
    }
    if name == "frameId" || name.ends_with(".frameId") {
        return Some("frame-id");
    }
    if name == "processId" || name.ends_with(".processId") {
        return Some("process-id");
    }
    None
}
