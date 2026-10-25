//! Spot checks of the Babel view. Corpus-wide agreement with Babel is the
//! node-sequence harness (`.cache/rust-migration/js-parse-diff/sequence.mjs`);
//! these pin the vocabulary decisions it relies on.

use std::ops::ControlFlow;

use oxc_allocator::Allocator;

use super::*;
use crate::javascript::parser::parse_javascript_analysis_program;

/// `type start-end[ (paren)]` per entered node, UTF-16 offsets.
fn sequence(source: &str, path: &str) -> Vec<String> {
    struct Collect<'c, 'a> {
        context: &'c AstContext<'a>,
        out: Vec<String>,
    }
    impl<'a> AstVisitor<'a> for Collect<'_, 'a> {
        fn enter(&mut self, node: &Node<'a>, _: Option<&Node<'a>>, _: &[Node<'a>]) {
            let paren = if node.parenthesized() { " (paren)" } else { "" };
            self.out.push(format!(
                "{} {}-{}{paren}",
                node.babel_type(),
                self.context.start(node),
                self.context.end(node)
            ));
        }
    }
    let allocator = Allocator::default();
    let parsed = parse_javascript_analysis_program(&allocator, source, Some(path)).expect("parse");
    let context = AstContext::new(parsed.program);
    let mut collect = Collect {
        context: &context,
        out: Vec::new(),
    };
    let _ = traverse::<()>(context.root(), context.source(), &mut collect, || {
        ControlFlow::Continue(())
    });
    collect.out
}

#[test]
fn optional_chain_links_follow_babel() {
    // Expected sequences are Babel 8 output (babel-sequence.mjs -e).
    assert_eq!(
        sequence("a?.b.c(d)?.e", "x.js"),
        [
            "Program 0-12",
            "ExpressionStatement 0-12",
            "OptionalMemberExpression 0-12",
            "OptionalCallExpression 0-9",
            "OptionalMemberExpression 0-6",
            "OptionalMemberExpression 0-4",
            "Identifier 0-1",
            "Identifier 3-4",
            "Identifier 5-6",
            "Identifier 7-8",
            "Identifier 11-12",
        ]
    );
    assert_eq!(
        sequence("(a?.b).c; a.b?.c!.d", "x.ts"),
        [
            "Program 0-19",
            "ExpressionStatement 0-9",
            "MemberExpression 0-8",
            "OptionalMemberExpression 1-5 (paren)",
            "Identifier 1-2",
            "Identifier 4-5",
            "Identifier 7-8",
            "ExpressionStatement 10-19",
            "OptionalMemberExpression 10-19",
            "TSNonNullExpression 10-17",
            "OptionalMemberExpression 10-16",
            "MemberExpression 10-13",
            "Identifier 10-11",
            "Identifier 12-13",
            "Identifier 15-16",
            "Identifier 18-19",
        ]
    );
}

#[test]
fn parameters_this_default_rest_and_parens() {
    assert_eq!(
        sequence(
            "function f(this: X, a: T = 1, ...r: U[]) { x = (((1))) }",
            "x.ts"
        ),
        [
            "Program 0-56",
            "FunctionDeclaration 0-56",
            "Identifier 9-10",
            "Identifier 11-18",
            "TSTypeAnnotation 15-18",
            "TSTypeReference 17-18",
            "Identifier 17-18",
            "AssignmentPattern 20-28",
            "Identifier 20-24",
            "TSTypeAnnotation 21-24",
            "TSTypeReference 23-24",
            "Identifier 23-24",
            "NumericLiteral 27-28",
            "RestElement 30-39",
            "Identifier 33-34",
            "TSTypeAnnotation 34-39",
            "TSArrayType 36-39",
            "TSTypeReference 36-37",
            "Identifier 36-37",
            "BlockStatement 41-56",
            "ExpressionStatement 43-54",
            "AssignmentExpression 43-54",
            "Identifier 43-44",
            "NumericLiteral 50-51 (paren)",
        ]
    );
}

#[test]
fn methods_fold_their_function_and_positions_are_utf16() {
    assert_eq!(
        sequence("'😀'; ({m(){}, get g(){}, [k]: v})", "x.js"),
        [
            "Program 0-34",
            "Directive 0-5",
            "DirectiveLiteral 0-4",
            "ExpressionStatement 6-34",
            "ObjectExpression 7-33 (paren)",
            "ObjectMethod 8-13",
            "Identifier 8-9",
            "BlockStatement 11-13",
            "ObjectMethod 15-24",
            "Identifier 19-20",
            "BlockStatement 22-24",
            "ObjectProperty 26-32",
            "Identifier 27-28",
            "Identifier 31-32",
        ]
    );
}

#[test]
fn parent_lookup_preserves_babel_views_and_synthesized_identities() {
    #[derive(Default)]
    struct Parents<'a> {
        actual: NodeParents<'a>,
        expected: Vec<(NodeKey, String)>,
    }

    impl<'a> AstVisitor<'a> for Parents<'a> {
        fn enter(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>, _: &[Node<'a>]) {
            if let Some(parent) = parent {
                self.actual.insert(node.key(), *parent);
                self.expected.push((node.key(), format!("{parent:?}")));
            }
        }
    }

    for source in [
        "'use strict'; class Box { #value; read() { return this.#value; } }",
        "const box = ({ method() { return (source?.child).value; }, get value() {} });",
        "namespace A.B { export class Box { constructor(public value: T = input) {} } }",
    ] {
        let allocator = Allocator::default();
        let parsed = parse_javascript_analysis_program(&allocator, source, Some("x.ts"))
            .expect("source parses");
        let context = AstContext::new(parsed.program);
        let mut parents = Parents::default();
        let traversal = traverse::<()>(context.root(), source, &mut parents, || {
            ControlFlow::Continue(())
        });
        assert!(traversal.is_continue());
        assert!(parents.actual.get(&context.root().key()).is_none());
        assert_eq!(parents.actual.len(), parents.expected.len());

        for (child, expected) in parents.expected {
            let actual = parents.actual.get(&child).expect("parent retained");
            assert_eq!(format!("{actual:?}"), expected);
        }
    }
}
