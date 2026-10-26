//! Module-level checks for semantics the differential corpus exercises
//! rarely. The corpus comparison lives in
//! `.cache/rust-migration/js-static-diff/`.

use oxc_allocator::Allocator;
use sha2::{Digest, Sha256};
use std::ops::ControlFlow;

use super::analyze::analyze_source;
use super::babel::semantic_tokens;
use super::findings::{ModuleRange, ModuleRangeIndex};
use super::fingerprint::{fingerprint_javascript_ast, hex};
use super::graphql::graphql_operation_from_text;
use super::helpers::{point_for_offset, range_for_offsets};
use super::interop::{Template, canonical_roles, with_interop_templates};
use super::{BindingFacts, SemanticReference, StableInitializer, StaticSemantics};
use crate::javascript::ast::{AstContext, AstVisitor, Node, traverse};
use crate::javascript::contracts::static_analysis::SourcePoint;
use crate::javascript::parser::parse_javascript_analysis_program;
use crate::javascript::semantic::value_types::JsString;

fn range(start: i64, end: i64, key: &str) -> ModuleRange {
    ModuleRange {
        start,
        end,
        key: key.to_owned(),
        runtime: "r".to_owned(),
        require_name: None,
    }
}

#[test]
fn module_range_index_prefers_first_discovered_inclusive_range() {
    let mut index = ModuleRangeIndex::new(100);
    index.add(range(10, 50, "outer"));
    index.add(range(20, 30, "inner"));
    index.add(range(-5, 2, "clamped"));
    index.add(range(90, 400, "tail"));
    let key = |offset| index.find(Some(offset)).map(|range| range.key.as_str());
    assert_eq!(key(25), Some("outer"));
    assert_eq!(key(50), Some("outer"));
    assert_eq!(key(51), None);
    assert_eq!(key(0), Some("clamped"));
    assert_eq!(key(100), Some("tail"));
    assert_eq!(key(101), None);
    assert_eq!(key(-1), None);
    assert_eq!(index.find(None), None);
}

#[test]
fn point_for_offset_counts_javascript_line_terminators_in_utf16() {
    let source = "a\r\nb\u{2028}c\rd😀e";
    assert_eq!(
        point_for_offset(source, 2),
        SourcePoint { line: 2, column: 0 }
    );
    assert_eq!(
        point_for_offset(source, 3),
        SourcePoint { line: 2, column: 0 }
    );
    assert_eq!(
        point_for_offset(source, 5),
        SourcePoint { line: 3, column: 0 }
    );
    assert_eq!(
        point_for_offset(source, 10),
        SourcePoint { line: 4, column: 3 }
    );
    assert_eq!(
        range_for_offsets(source, 0, 1).end,
        SourcePoint { line: 1, column: 1 }
    );
}

#[test]
fn source_map_directives_use_parser_comments_and_utf16_ranges() {
    let source = concat!(
        "const text = \"//\\# sourceMappingURL=ghost.map\";\n",
        "\"😀\";/*@\u{00a0}sourceMappingURL\u{2003}=\u{FEFF}app.js.map* ignored */\n",
        "//# sourceMappingURL=app.js.map\n",
        "//# sourceMappingURL=app.js.map\n",
    );
    let analysis = analyze_source(source, Some("fixture.js")).expect("analysis");
    assert_eq!(
        analysis
            .source_map_urls
            .iter()
            .map(|url| url.declared_url.as_str().expect("valid URL"))
            .collect::<Vec<_>>(),
        vec!["app.js.map*", "app.js.map"]
    );
    assert_eq!(analysis.source_map_urls[0].location.start.line, 2);
    assert_eq!(analysis.source_map_urls[0].location.start.column, 5);
    assert!(analysis.source_map_urls[0].location.end.column > 5);
}

#[test]
fn graphql_text_requires_a_named_operation_header() {
    let op = |text: &str| graphql_operation_from_text(text).map(|op| (op.value, op.mechanism));
    assert_eq!(
        op("\u{FEFF}# c\n query Q($a: Int) { a }"),
        Some(("Q".into(), "graphql:query".into()))
    );
    assert_eq!(
        op("mutation M @live { a }").map(|it| it.0),
        Some("M".into())
    );
    assert_eq!(op("query Q { }"), None);
    assert_eq!(op("query Q (a)"), None);
    assert_eq!(op("fragment F on T { a }"), None);
}

struct NoSemantics;

impl<'a> StaticSemantics<'a> for NoSemantics {
    fn binding(&self, _: &Node<'a>) -> Option<&BindingFacts> {
        None
    }
    fn binding_by_id(&self, _: &str) -> Option<&BindingFacts> {
        None
    }
    fn stable_initializer(&self, _: &str) -> Option<StableInitializer<'a>> {
        None
    }
    fn parent(&self, _: &Node<'a>) -> Option<Node<'a>> {
        None
    }
    fn is_module(&self) -> bool {
        false
    }
    fn references(&self) -> Vec<SemanticReference> {
        Vec::new()
    }
}

#[test]
fn templates_parse_and_require_bindings() {
    let allocator = Allocator::default();
    let source = "(a, b, c) => a;";
    let parsed =
        parse_javascript_analysis_program(&allocator, source, Some("x.js")).expect("parse");
    let context = AstContext::new(parsed.program);
    let arrow = context.children(&context.children(&context.root())[0])[0];
    with_interop_templates(|templates| {
        // Type and arity agree with neither template's body, and unresolved
        // identifiers never take a role.
        assert!(
            canonical_roles(&context, arrow, templates, Template::ToEsm, &NoSemantics).is_none()
        );
        assert!(
            canonical_roles(
                &context,
                arrow,
                templates,
                Template::CopyProps,
                &NoSemantics
            )
            .is_none()
        );
    });
    // Parentheses are transparent to the fingerprint token stream.
    let wrapped = Allocator::default();
    let parsed_wrapped =
        parse_javascript_analysis_program(&wrapped, "((a, b, c) => (a));", Some("x.js"))
            .expect("parse");
    let wrapped_context = AstContext::new(parsed_wrapped.program);
    assert_eq!(
        fingerprint_javascript_ast(source, context.root()),
        fingerprint_javascript_ast(wrapped_context.source(), wrapped_context.root())
    );
}

#[test]
fn fingerprint_preserves_lone_surrogates_in_literals_and_templates() {
    fn fingerprint(source: &str, allocator: &Allocator) -> (String, String) {
        let parsed = parse_javascript_analysis_program(allocator, source, Some("surrogates.js"))
            .expect("parse");
        let context = AstContext::new(parsed.program);
        struct Tokens<'a> {
            source: &'a str,
            values: Vec<JsString>,
        }
        impl<'a> AstVisitor<'a> for Tokens<'a> {
            fn enter(&mut self, node: &Node<'a>, _: Option<&Node<'a>>, _: &[Node<'a>]) {
                self.values.extend(semantic_tokens(self.source, node));
            }
        }
        let mut tokens = Tokens {
            source,
            values: Vec::new(),
        };
        let _: ControlFlow<()> = traverse(context.root(), source, &mut tokens, || {
            ControlFlow::Continue(())
        });
        let serialized = serde_json::to_string(&tokens.values).expect("serialize tokens");
        (
            fingerprint_javascript_ast(source, context.root()),
            serialized,
        )
    }

    let source_a = r#"const text = "\uD800"; const template = `\uD800`;"#;
    let source_b = r#"const text = "\uD801"; const template = `\uD801`;"#;
    let allocator_a = Allocator::default();
    let allocator_b = Allocator::default();
    let (fingerprint_a, tokens_a) = fingerprint(source_a, &allocator_a);
    let (fingerprint_b, tokens_b) = fingerprint(source_b, &allocator_b);

    assert_eq!(fingerprint_a, hex(&Sha256::digest(tokens_a.as_bytes())));
    assert_eq!(fingerprint_b, hex(&Sha256::digest(tokens_b.as_bytes())));
    assert_ne!(fingerprint_a, fingerprint_b);
    assert!(tokens_a.contains(r#"\ud800"#));
    assert!(tokens_a.contains(r#"\\uD800"#));
    assert!(!tokens_a.contains(r#"\ud801"#));
    assert!(!tokens_b.contains(r#"\ud800"#));
}
