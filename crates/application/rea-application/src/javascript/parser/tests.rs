use super::*;

fn facts(source: &str, path: Option<&str>) -> JavaScriptSourceFacts {
    match parse_javascript_source(source, path) {
        JavaScriptParseOutcome::Parsed { facts } => facts,
        JavaScriptParseOutcome::Fatal { errors } => panic!("fatal: {errors:?}"),
    }
}

#[test]
fn collects_module_references_in_babel_coordinates() {
    let source = "// é😀\nimport a from \"a\";\nexport * from 'b';\nconst c = require(`c`);\nimport(\"d\");\n";
    let facts = facts(source, Some("x.js"));
    assert_eq!(facts.program_source_type, ProgramSourceType::Module);
    assert_eq!(facts.runtime_context, RuntimeContext::Module);
    let kinds: Vec<_> = facts
        .module_references
        .iter()
        .map(|reference| (reference.kind, reference.specifier.as_deref()))
        .collect();
    assert_eq!(
        kinds,
        [
            (ModuleReferenceKind::StaticImport, Some("a")),
            (ModuleReferenceKind::ReExport, Some("b")),
            (ModuleReferenceKind::Require, Some("c")),
            (ModuleReferenceKind::DynamicImport, Some("d")),
        ]
    );
    // "// é😀\n" is 6 UTF-16 units + newline; `"a"` is at column 14 of line 2.
    let first = &facts.module_references[0].range.start;
    assert_eq!((first.offset, first.line, first.column), (21, 2, 14));
}

#[test]
fn collects_declared_modules_and_ignores_shadowed_require() {
    let parsed = facts(
        "declare module \"ambient-pkg\" {}\nfunction f(require) { require(\"local\"); }\nconst value = require(\"runtime\");\n",
        Some("ambient.ts"),
    );

    let references: Vec<_> = parsed
        .module_references
        .iter()
        .map(|reference| (reference.kind, reference.specifier.as_deref()))
        .collect();
    assert_eq!(
        references,
        [
            (ModuleReferenceKind::DeclaresModule, Some("ambient-pkg")),
            (ModuleReferenceKind::Require, Some("runtime")),
        ]
    );
}

#[test]
fn type_only_and_runtime_context_rules() {
    let type_only = facts(
        "import type { A } from 'a';\nexport type { B } from 'b';\n",
        Some("x.ts"),
    );
    assert!(
        type_only
            .module_references
            .iter()
            .all(|reference| reference.type_only)
    );
    assert_eq!(type_only.runtime_context, RuntimeContext::Unknown);
    assert_eq!(
        facts("export = 1;", Some("x.ts")).runtime_context,
        RuntimeContext::Commonjs
    );
    assert_eq!(
        facts("x", Some("x.cts")).runtime_context,
        RuntimeContext::Commonjs
    );
    assert_eq!(
        facts("x", Some("x.d.cts")).runtime_context,
        RuntimeContext::Unknown
    );
    assert!(facts("import { type A } from 'a';", Some("x.ts")).uncertain_type_only_side_effect);
}

#[test]
fn flow_import_typeof_uses_the_type_only_module_contract() {
    let parsed = facts("import typeof Value from \"pkg\";\n", Some("x.ts"));

    assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
    assert_eq!(parsed.module_references.len(), 1);
    let reference = &parsed.module_references[0];
    assert_eq!(reference.kind, ModuleReferenceKind::StaticImport);
    assert_eq!(reference.specifier.as_deref(), Some("pkg"));
    assert_eq!(reference.expression, "\"pkg\"");
    assert!(reference.type_only);
    assert!(!reference.inline_type_only);
}

#[test]
fn typeof_default_binding_remains_a_value_import() {
    let parsed = facts("import typeof from \"pkg\";\n", Some("x.ts"));

    assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
    assert_eq!(parsed.module_references.len(), 1);
    assert!(!parsed.module_references[0].type_only);
    assert_eq!(
        parsed.module_references[0].specifier.as_deref(),
        Some("pkg")
    );
}

#[test]
fn reserved_binding_is_recovered_as_a_binding_with_a_diagnostic() {
    let source = "var class = 1;\n";
    let parsed = facts(source, Some("reserved.js"));

    assert_eq!(parsed.errors.len(), 1);
    assert_eq!(parsed.errors[0].offset, Some(4));
    assert!(parsed.module_references.is_empty());

    let (recovered_facts, module_only_errors) = recovered(source, Some("reserved.js"));
    assert_eq!(recovered_facts.errors.len(), 1);
    assert_eq!(recovered_facts.errors[0].offset, Some(4));
    assert!(module_only_errors.is_empty());

    for name in ["default", "enum", "interface"] {
        let source = format!("var {name} = 1;\n");
        let parsed = facts(&source, Some("reserved.js"));
        assert_eq!(parsed.errors.len(), 1, "{name}");
        assert_eq!(parsed.errors[0].offset, Some(4), "{name}");
    }
}

#[test]
fn cjs_allows_top_level_return_and_reports_recovered_errors() {
    assert!(facts("return 1;", Some("x.cjs")).errors.is_empty());
    assert!(!facts("let a; let a;", Some("x.js")).errors.is_empty());
}

fn offsets(facts: &JavaScriptSourceFacts) -> Vec<Option<u32>> {
    facts.errors.iter().map(|error| error.offset).collect()
}

#[test]
fn cjs_allows_top_level_new_target_only_in_commonjs_path_mode() {
    // D6: `handwritten/cjs-wrapper.cjs` (Babel allowNewTargetOutsideFunction).
    let source = "const a = require(\"a\");\nif (!a) return;\nmodule.exports = { a, t: new.target, f: () => new.target };\n";
    assert!(facts(source, Some("x.cjs")).errors.is_empty());
    assert_eq!(facts("new.target;\n", Some("x.js")).errors.len(), 1);
    assert!(
        facts("function f() { return new.target; }\n", Some("x.js"))
            .errors
            .is_empty()
    );
}

#[test]
fn boundary_diagnostics_preserve_recovered_programs_and_literal_text() {
    let positive = [
        ("const value = '\0';", Some("fixture.js")),
        ("const value = `line\n<!-- inside`;", Some("fixture.mjs")),
        ("/* <!-- inside */ const value = 1;", Some("fixture.mjs")),
        ("const value = /\\/\\* comment-like/;", Some("fixture.mjs")),
    ];
    for (source, path) in positive {
        let JavaScriptParseOutcome::Parsed { facts } = parse_javascript_source(source, path) else {
            panic!("literal text unexpectedly became fatal for {path:?}");
        };
        assert!(
            facts.errors.is_empty(),
            "literal text produced errors: {source:?}"
        );

        let RecoveredJavaScriptParseOutcome::Parsed {
            facts,
            module_only_errors,
        } = parse_recovered_javascript_source(source, path)
        else {
            panic!("recovered literal text unexpectedly became fatal for {path:?}");
        };
        assert!(
            facts.errors.is_empty(),
            "recovered literal text produced errors: {source:?}"
        );
        assert!(
            module_only_errors.is_empty(),
            "recovered literal text produced module-only errors: {source:?}"
        );
    }

    // Oxc retains these lexer boundary diagnostics whether its parser returns
    // a recovered program or a fatal outcome. The current boundary contract
    // deliberately does not reclassify a recoverable Oxc parse as synthetic
    // fatal result.
    let boundary_errors = [
        ("/*", Some("fixture.js")),
        ("<!-- comment\nexport const value = 1;", Some("fixture.mjs")),
        ("--> comment\nexport const value = 1;", Some("fixture.mjs")),
    ];
    for (source, path) in boundary_errors {
        let normal_errors = match parse_javascript_source(source, path) {
            JavaScriptParseOutcome::Parsed { facts } => facts.errors,
            JavaScriptParseOutcome::Fatal { errors } => errors,
        };
        assert!(!normal_errors.is_empty(), "boundary diagnostic was lost");

        let recovered_errors = match parse_recovered_javascript_source(source, path) {
            RecoveredJavaScriptParseOutcome::Parsed { facts, .. } => facts.errors,
            RecoveredJavaScriptParseOutcome::Fatal { errors } => errors,
        };
        assert!(
            !recovered_errors.is_empty(),
            "recovered boundary diagnostic was lost"
        );
    }

    // Annex-B HTML comments remain valid when an unambiguous source resolves
    // to a script, matching Babel's recovery entry point.
    let script_with_html_comment = "<!-- script comment\nconst value = 1;";
    assert!(matches!(
        parse_javascript_source(script_with_html_comment, Some("fixture.js")),
        JavaScriptParseOutcome::Parsed { .. }
    ));
    assert!(matches!(
        parse_recovered_javascript_source(script_with_html_comment, Some("fixture.js")),
        RecoveredJavaScriptParseOutcome::Parsed { .. }
    ));
}

#[test]
fn mts_rejects_ambiguous_jsx_like_syntax() {
    // D7: offsets match Babel `disallowAmbiguousJSXLike` (at `<`).
    let cases: [(&str, &[u32]); 8] = [
        ("const v = <T>(x: T) => x;", &[10]),
        ("const v = <T,>(x: T) => x;", &[]),
        ("const v = <T extends U>(x: T) => x;", &[]),
        ("const v = <T = U>(x: T) => x;", &[10]),
        ("const v = <T, U>(x: T) => x;", &[]),
        ("const v = <any>foo;", &[10]),
        ("const v = async <T>(x: T) => x;", &[]),
        ("const v = < T /*,*/ >(x) => x;", &[10]),
    ];
    for (source, expected) in cases {
        let found = offsets(&facts(source, Some("x.mts")));
        let expected: Vec<_> = expected.iter().map(|offset| Some(*offset)).collect();
        assert_eq!(found, expected, "{source}");
        assert!(
            facts(source, Some("x.ts")).errors.is_empty() || source.contains("<any>"),
            "{source}"
        );
    }
    assert_eq!(
        offsets(&facts("const v = <T>(x: T) => x;", Some("x.cts"))),
        []
    );
}

fn recovered(source: &str, path: Option<&str>) -> (JavaScriptSourceFacts, Vec<ParseDiagnostic>) {
    match parse_recovered_javascript_source(source, path) {
        RecoveredJavaScriptParseOutcome::Parsed {
            facts,
            module_only_errors,
        } => (facts, module_only_errors),
        RecoveredJavaScriptParseOutcome::Fatal { errors } => panic!("fatal: {errors:?}"),
    }
}

#[test]
fn recovered_parse_keeps_module_only_errors() {
    // A script with errors re-parses as a script; strict-only errors stay visible.
    let (facts, module_only) =
        recovered("with (a) {}\nlet b; let b;\nrequire('r');\n", Some("x.js"));
    assert_eq!(facts.program_source_type, ProgramSourceType::Script);
    assert_eq!(facts.module_references.len(), 1);
    assert!(!facts.errors.is_empty());
    assert!(!module_only.is_empty());
    // Top-level return is allowed; undeclared exports are allowed.
    let (facts, module_only) = recovered("export { nope };\nreturn;\n", Some("x.js"));
    assert!(facts.errors.is_empty(), "{:?}", facts.errors);
    assert!(module_only.is_empty());
    // Explicit modes parse once.
    let (facts, module_only) = recovered("export { nope };\n", Some("x.mjs"));
    assert!(facts.errors.is_empty() && module_only.is_empty());
    let (facts, _) = recovered("return new.target;\n", Some("x.cjs"));
    // Babel reports a CommonJS parse as a script; the runtime context carries it.
    assert_eq!(facts.program_source_type, ProgramSourceType::Script);
    assert_eq!(facts.runtime_context, RuntimeContext::Commonjs);
    assert!(facts.errors.is_empty());
    // A module attempt without a program yields no module-only errors.
    let (facts, module_only) = recovered("<!-- x\nvar a = require('a');\n", Some("x.js"));
    assert_eq!(facts.module_references.len(), 1);
    assert!(module_only.is_empty());
}

#[test]
fn analysis_parse_retains_unambiguous_recovery_diagnostics() {
    let cases = [
        ("with (obj) {}\n", "with.js"),
        (
            "function f() {}\nfunction f() {}\nif (true) function g() {}\n",
            "hoisting.js",
        ),
    ];

    for (source, path) in cases {
        let allocator = oxc_allocator::Allocator::default();
        let parsed = parse_javascript_analysis_program(&allocator, source, Some(path))
            .expect("recovered source should produce a program");
        assert!(
            !parsed.errors.is_empty(),
            "analysis parser dropped module or recovery diagnostics for {path}"
        );
    }
}
