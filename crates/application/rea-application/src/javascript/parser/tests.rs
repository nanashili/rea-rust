use super::*;

fn facts(source: &str, path: Option<&str>) -> JavaScriptSourceFacts {
    match parse_javascript_source(source, path) {
        JavaScriptParseOutcome::Parsed { facts } => facts,
        JavaScriptParseOutcome::Fatal { errors } => panic!("fatal: {errors:?}"),
    }
}

#[test]
fn collects_module_references_in_babel_coordinates() {
    let source =
        "// é😀\nimport a from \"a\";\nexport * from 'b';\nconst c = require(`c`);\nimport(\"d\");\n";
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
fn type_only_and_runtime_context_rules() {
    let type_only = facts("import type { A } from 'a';\nexport type { B } from 'b';\n", Some("x.ts"));
    assert!(type_only.module_references.iter().all(|reference| reference.type_only));
    assert_eq!(type_only.runtime_context, RuntimeContext::Unknown);
    assert_eq!(facts("export = 1;", Some("x.ts")).runtime_context, RuntimeContext::Commonjs);
    assert_eq!(facts("x", Some("x.cts")).runtime_context, RuntimeContext::Commonjs);
    assert_eq!(facts("x", Some("x.d.cts")).runtime_context, RuntimeContext::Unknown);
    assert!(facts("import { type A } from 'a';", Some("x.ts")).uncertain_type_only_side_effect);
}

#[test]
fn cjs_allows_top_level_return_and_reports_recovered_errors() {
    assert!(facts("return 1;", Some("x.cjs")).errors.is_empty());
    assert!(!facts("let a; let a;", Some("x.js")).errors.is_empty());
}
