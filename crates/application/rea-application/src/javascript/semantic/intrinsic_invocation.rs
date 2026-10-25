//! Normalize intrinsic call syntax while preserving argument and receiver facts.
//!
//! Intrinsic identity, bound functions, and mutation-sensitive reads have their
//! own semantic owners. This pass only rewrites proven invocation syntax using
//! those supplied facts; a changed intrinsic read remains an opaque invocation.

use std::collections::HashSet;

use crate::javascript::ast::{Field, Node};

use super::ast_values::{is_member, static_property_key, unwrapped};
use super::identity_writes::{IntrinsicInvocationKind, JavaScriptIntrinsicInvocation};

/// Expand literal array spreads only when every array position is present.
/// Unknown spreads and sparse arrays remain explicit argument nodes.
pub fn expand_invocation_arguments<'a>(source: &'a str, arguments: &[Node<'a>]) -> Vec<Node<'a>> {
    let mut expanded = Vec::new();
    let mut pending: Vec<_> = arguments.iter().rev().copied().collect();

    while let Some(argument) = pending.pop() {
        let array = (argument.babel_type() == "SpreadElement")
            .then(|| argument.field(source, Field::Argument))
            .flatten()
            .map(|node| unwrapped(source, node));
        let elements = array
            .filter(|node| node.babel_type() == "ArrayExpression")
            .map(|node| node.field_list(source, Field::Elements));
        match elements {
            Some(elements)
                if elements.iter().all(|element| {
                    element.is_some_and(|node| {
                        node.is_expression() || node.babel_type() == "SpreadElement"
                    })
                }) =>
            {
                pending.extend(elements.into_iter().rev().flatten());
            }
            _ => expanded.push(argument),
        }
    }

    expanded
}

pub(crate) fn array_arguments<'a>(
    source: &'a str,
    node: Option<Node<'a>>,
) -> Option<Vec<Node<'a>>> {
    let array = unwrapped(source, node?);
    if array.babel_type() != "ArrayExpression" {
        return None;
    }
    let elements = array.field_list(source, Field::Elements);
    let arguments: Option<Vec<_>> = elements.into_iter().collect();
    let expanded = expand_invocation_arguments(source, &arguments?);
    expanded.iter().all(Node::is_expression).then_some(expanded)
}

#[derive(Clone, Copy)]
enum InvocationMethod {
    Call,
    Apply,
}

impl InvocationMethod {
    fn parse(method: &str) -> Option<Self> {
        match method {
            "call" => Some(Self::Call),
            "apply" => Some(Self::Apply),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Apply => "apply",
        }
    }

    fn arguments<'a>(
        self,
        source: &'a str,
        arguments: Option<Vec<Node<'a>>>,
    ) -> Option<Vec<Node<'a>>> {
        let arguments = arguments?;
        if arguments
            .first()
            .is_some_and(|node| node.babel_type() == "SpreadElement")
        {
            return None;
        }
        match self {
            Self::Call => Some(arguments.into_iter().skip(1).collect()),
            Self::Apply => array_arguments(source, arguments.get(1).copied()),
        }
    }
}

/// An explicit receiver can be unknown or lost through a comma expression.
/// Keeping that distinct from an implicit member receiver prevents invention
/// of a callable when resolving generic Function.call or Function.apply.
#[derive(Clone, Copy)]
enum Receiver<'a> {
    Implicit,
    Explicit(Option<Node<'a>>),
}

struct InvocationCursor<'a> {
    callee: Node<'a>,
    arguments: Option<Vec<Node<'a>>>,
    receiver: Receiver<'a>,
}

impl<'a> InvocationCursor<'a> {
    fn argument(&self, index: usize) -> Option<Node<'a>> {
        self.arguments.as_ref()?.get(index).copied()
    }

    fn normalize_callee(&mut self, source: &'a str) -> Option<()> {
        loop {
            self.callee = unwrapped(source, self.callee);
            if self.callee.babel_type() != "SequenceExpression" {
                return Some(());
            }
            let Some(final_expression) = self
                .callee
                .field_list(source, Field::Expressions)
                .last()
                .copied()
                .flatten()
            else {
                return None;
            };
            if matches!(self.receiver, Receiver::Implicit) {
                self.receiver = Receiver::Explicit(None);
            }
            self.callee = final_expression;
        }
    }

    fn invoke_method(&mut self, source: &'a str, method: InvocationMethod, callable: Node<'a>) {
        self.receiver = Receiver::Explicit(self.argument(0));
        self.callee = callable;
        self.arguments = method.arguments(source, self.arguments.take());
    }

    fn apply_bound(&mut self, bound: &JavaScriptIntrinsicInvocation<'a>) {
        self.receiver = Receiver::Explicit(bound.receiver);
        self.arguments = bound.arguments.as_ref().map(|prefix| {
            let mut arguments = prefix.clone();
            arguments.extend(self.arguments.take().unwrap_or_default());
            arguments
        });
    }

    fn into_invocation(self, path: Vec<String>) -> JavaScriptIntrinsicInvocation<'a> {
        JavaScriptIntrinsicInvocation {
            kind: IntrinsicInvocationKind::Known,
            receiver: match self.receiver {
                Receiver::Implicit => None,
                Receiver::Explicit(receiver) => receiver,
            },
            path,
            arguments: self.arguments,
        }
    }
}

fn opaque<'a>(path: Vec<String>) -> JavaScriptIntrinsicInvocation<'a> {
    JavaScriptIntrinsicInvocation {
        kind: IntrinsicInvocationKind::Opaque,
        receiver: None,
        path,
        arguments: None,
    }
}

enum CalleeResolution<'a> {
    Path(Vec<String>),
    FollowCallee,
    Opaque(JavaScriptIntrinsicInvocation<'a>),
}

/// Resolve the current function's identity before following invocation syntax.
/// A bound function contributes its original receiver and argument prefix.
fn resolve_callee<'a, P, B, C>(
    source: &'a str,
    cursor: &mut InvocationCursor<'a>,
    intrinsic_path: &mut P,
    bound_intrinsic: &mut B,
    intrinsic_read_changed: &mut C,
) -> Option<CalleeResolution<'a>>
where
    P: FnMut(Node<'a>) -> Option<Vec<String>>,
    B: FnMut(Node<'a>) -> Option<JavaScriptIntrinsicInvocation<'a>>,
    C: FnMut(Node<'a>, &[String]) -> bool,
{
    if let Some(path) = intrinsic_path(cursor.callee) {
        return Some(if intrinsic_read_changed(cursor.callee, &path) {
            CalleeResolution::Opaque(opaque(path))
        } else {
            CalleeResolution::Path(path)
        });
    }

    if let Some((method, callable)) = member_invocation_method(source, cursor.callee) {
        if let Some(bound) = bound_intrinsic(callable) {
            let mut path = bound.path.clone();
            path.push(method.as_str().to_owned());
            if intrinsic_read_changed(cursor.callee, &path) {
                return Some(CalleeResolution::Opaque(opaque(bound.path)));
            }
        }
        cursor.invoke_method(source, method, callable);
        return Some(CalleeResolution::FollowCallee);
    }

    let bound = bound_intrinsic(cursor.callee)?;
    if bound.kind == IntrinsicInvocationKind::Opaque {
        return Some(CalleeResolution::Opaque(bound));
    }
    cursor.apply_bound(&bound);
    Some(CalleeResolution::Path(bound.path))
}

/// Resolve call/apply/Reflect.apply and bound prefixes from supplied identity
/// facts. Binding a function by itself is never treated as an invocation.
pub fn resolve_intrinsic_invocation<'a, P, B, C>(
    source: &'a str,
    node: Node<'a>,
    mut intrinsic_path: P,
    mut bound_intrinsic: B,
    mut intrinsic_read_changed: C,
) -> Option<JavaScriptIntrinsicInvocation<'a>>
where
    P: FnMut(Node<'a>) -> Option<Vec<String>>,
    B: FnMut(Node<'a>) -> Option<JavaScriptIntrinsicInvocation<'a>>,
    C: FnMut(Node<'a>, &[String]) -> bool,
{
    if !matches!(
        node.babel_type(),
        "CallExpression" | "OptionalCallExpression"
    ) {
        return None;
    }
    let arguments: Vec<_> = node
        .field_list(source, Field::Arguments)
        .into_iter()
        .flatten()
        .collect();
    let mut cursor = InvocationCursor {
        callee: node.field(source, Field::Callee)?,
        arguments: Some(expand_invocation_arguments(source, &arguments)),
        receiver: Receiver::Implicit,
    };
    let mut visited = HashSet::new();

    loop {
        cursor.normalize_callee(source)?;
        if !visited.insert(cursor.callee.key()) {
            return None;
        }

        let path = match resolve_callee(
            source,
            &mut cursor,
            &mut intrinsic_path,
            &mut bound_intrinsic,
            &mut intrinsic_read_changed,
        )? {
            CalleeResolution::Path(path) => path,
            CalleeResolution::FollowCallee => continue,
            CalleeResolution::Opaque(invocation) => return Some(invocation),
        };

        if let Some(method) = path
            .last()
            .filter(|_| path.len() > 3)
            .and_then(|method| InvocationMethod::parse(method))
        {
            let callable = match cursor.receiver {
                Receiver::Explicit(receiver) => receiver,
                Receiver::Implicit if is_member(&cursor.callee) => {
                    cursor.callee.field(source, Field::Object)
                }
                Receiver::Implicit => None,
            };
            let Some(callable) = callable.filter(Node::is_expression) else {
                return Some(opaque(path));
            };
            cursor.invoke_method(source, method, callable);
            continue;
        }

        if path
            .iter()
            .map(String::as_str)
            .eq(["intrinsic", "Reflect", "apply"])
        {
            let callable = cursor.argument(0).filter(Node::is_expression)?;
            let receiver = cursor.argument(1);
            let arguments = array_arguments(source, cursor.argument(2));
            cursor.callee = callable;
            cursor.receiver = Receiver::Explicit(receiver);
            cursor.arguments = arguments;
            continue;
        }

        return Some(cursor.into_invocation(path));
    }
}

fn member_invocation_method<'a>(
    source: &'a str,
    callee: Node<'a>,
) -> Option<(InvocationMethod, Node<'a>)> {
    if !is_member(&callee) {
        return None;
    }
    let key = callee.field(source, Field::Property)?;
    let method = static_property_key(source, key, callee.computed())?
        .try_to_string()
        .ok()?;
    Some((
        InvocationMethod::parse(&method)?,
        callee.field(source, Field::Object)?,
    ))
}

#[cfg(test)]
mod tests {
    use std::ops::ControlFlow;

    use oxc_allocator::Allocator;

    use super::*;
    use crate::javascript::ast::{AstContext, AstVisitor, traverse};
    use crate::javascript::parser::parse_javascript_analysis_program;

    struct Nodes<'a>(Vec<Node<'a>>);

    impl<'a> AstVisitor<'a> for Nodes<'a> {
        fn enter(&mut self, node: &Node<'a>, _parent: Option<&Node<'a>>, _ancestors: &[Node<'a>]) {
            self.0.push(*node);
        }
    }

    fn parsed_nodes<'a>(allocator: &'a Allocator, source: &'a str) -> Vec<Node<'a>> {
        let parsed = parse_javascript_analysis_program(allocator, source, Some("invocation.js"))
            .expect("parse");
        let context = AstContext::new(parsed.program);
        let mut nodes = Nodes(Vec::new());
        assert!(matches!(
            traverse(context.root(), source, &mut nodes, || {
                ControlFlow::<()>::Continue(())
            }),
            ControlFlow::Continue(())
        ));
        nodes.0
    }

    fn text<'a>(source: &'a str, node: &Node<'a>) -> &'a str {
        &source[node.span().start as usize..node.span().end as usize]
    }

    #[test]
    fn nested_literal_spreads_expand_but_sparse_and_unknown_spreads_remain() {
        let allocator = Allocator::default();
        let source = "consume(...[1, ...[2]], ...[, 3], ...[...unknown], 4)";
        let nodes = parsed_nodes(&allocator, source);
        let call = nodes
            .iter()
            .find(|node| node.babel_type() == "CallExpression")
            .expect("call");
        let arguments: Vec<_> = call
            .field_list(source, Field::Arguments)
            .into_iter()
            .flatten()
            .collect();
        let expanded = expand_invocation_arguments(source, &arguments);

        assert_eq!(
            expanded
                .iter()
                .map(|node| text(source, node))
                .collect::<Vec<_>>(),
            ["1", "2", "...[, 3]", "...unknown", "4"]
        );
    }

    #[test]
    fn calling_a_bound_intrinsic_preserves_original_receiver_and_prefix() {
        let allocator = Allocator::default();
        let source = "const receiver = {}; const prefix = 'first'; bound.call(other, 'last')";
        let nodes = parsed_nodes(&allocator, source);
        let find = |expression| {
            nodes
                .iter()
                .copied()
                .find(|node| node.is_expression() && text(source, node) == expression)
                .expect("fixture expression")
        };
        let call = find("bound.call(other, 'last')");
        let receiver = find("{}");
        let prefix = find("'first'");
        let invocation = resolve_intrinsic_invocation(
            source,
            call,
            |_| None,
            |node| {
                (node.identifier_name() == Some("bound")).then(|| JavaScriptIntrinsicInvocation {
                    kind: IntrinsicInvocationKind::Known,
                    receiver: Some(receiver),
                    path: vec!["intrinsic".into(), "Object".into(), "assign".into()],
                    arguments: Some(vec![prefix]),
                })
            },
            |_, _| false,
        )
        .expect("known bound intrinsic");

        assert_eq!(invocation.kind, IntrinsicInvocationKind::Known);
        assert_eq!(invocation.path, ["intrinsic", "Object", "assign"]);
        assert_eq!(invocation.receiver.expect("receiver").key(), receiver.key());
        assert_eq!(
            invocation
                .arguments
                .expect("arguments")
                .iter()
                .map(|node| text(source, node))
                .collect::<Vec<_>>(),
            ["'first'", "'last'"]
        );
    }
}
