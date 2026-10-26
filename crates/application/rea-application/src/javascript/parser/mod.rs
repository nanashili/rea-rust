//! Inert JavaScript/TypeScript parser boundary (oxc).
//!
//! Port of `parseJavaScriptSource` in
//! `src/domain/javascript/javascriptSourceParser.ts`: the same per-path grammar
//! and source-type rules, the `.cjs` wrapper re-parse, recovered versus fatal
//! errors, and the parser-owned runtime-context proof, plus
//! `parseRecoveredJavaScript` for reference-source imports. Consumers read the
//! parsed facts in [`JavaScriptSourceFacts`] instead of reinterpreting source.
//! Known differences from Babel are recorded in
//! `.cache/rust-migration/js-parse-differences.md`.

mod facts;
mod mode;
mod options;
mod position;

use std::collections::HashSet;
use std::ops::ControlFlow;

use oxc_allocator::Allocator;
use oxc_ast::ast::{Program, Statement};
use oxc_parser::{ParseOptions, Parser};
use oxc_semantic::{Semantic, SemanticBuilder};
use serde::Serialize;

pub use facts::{
    ExportFact, ExportFactKind, JavaScriptSourceFacts, ModuleReference, ModuleReferenceKind,
    ParseDiagnostic, ProgramSourceType, RuntimeContext,
};
pub use mode::{JavaScriptGrammar, ParserMode, PathSourceType, is_explicit_module_source_path};
pub use position::{PositionIndex, SourcePosition, SourceRange};

use mode::OxcModuleKind;
use options::{BoundaryOptions, unknown_path_ambiguous_jsx_like_errors};

use crate::javascript::ast::{AstContext, AstVisitor, traverse};

/// Reduce an oxc diagnostic without naming `oxc_diagnostics` (not a direct
/// dependency): message plus the first label's UTF-8 byte offset.
macro_rules! raw_diagnostic {
    ($error:expr) => {{
        let error = $error;
        RawDiagnostic {
            message: error.message.to_string(),
            byte_offset: error
                .labels
                .as_ref()
                .and_then(|labels| labels.first())
                .map(|label| label.offset() as u32),
        }
    }};
}

/// One oxc diagnostic reduced to its message and primary byte offset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawDiagnostic {
    pub message: String,
    pub byte_offset: Option<u32>,
}

/// Result of parsing one source.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum JavaScriptParseOutcome {
    /// A program was produced; `facts.errors` lists recovered syntax errors.
    Parsed { facts: JavaScriptSourceFacts },
    /// The parser could not produce a program (Babel's `null` return).
    Fatal { errors: Vec<ParseDiagnostic> },
}

/// A parsed program together with its semantic model, borrowed from the allocator.
pub struct ParsedJavaScriptProgram<'a> {
    pub program: &'a Program<'a>,
    pub semantic: Semantic<'a>,
    pub mode: ParserMode,
    /// Parser plus semantic-check diagnostics, in source order.
    pub errors: Vec<RawDiagnostic>,
}

struct Attempt<'a> {
    program: Program<'a>,
    errors: Vec<RawDiagnostic>,
    panicked: bool,
}

fn retain_legacy_typescript_diagnostics(
    errors: &mut Vec<RawDiagnostic>,
    grammar: JavaScriptGrammar,
) {
    if !matches!(
        grammar,
        JavaScriptGrammar::TypeScript | JavaScriptGrammar::TypeScriptDeclaration
    ) {
        return;
    }

    // Babel's TypeScript parser does not report these Oxc-only semantic
    // restrictions. Keep independent diagnostics, such as invalid parameter
    // property binding patterns, intact.
    errors.retain(|error| {
        !matches!(
            error.message.as_str(),
            "A required parameter cannot follow an optional parameter."
                | "An export assignment cannot be used in a module with other exported elements"
        )
    });
}

fn attempt<'a>(
    allocator: &'a Allocator,
    source: &'a str,
    mode: ParserMode,
    kind: OxcModuleKind,
    allow_return_outside_function: bool,
    preserve_parens: bool,
) -> Attempt<'a> {
    let parsed = Parser::new(allocator, source, mode.oxc_source_type(kind))
        .with_options(ParseOptions {
            allow_return_outside_function,
            preserve_parens,
            ..ParseOptions::default()
        })
        .parse();
    let unsupported_import_phase = parsed.program.body.iter().find_map(|statement| {
        let Statement::ImportDeclaration(import) = statement else {
            return None;
        };
        import.phase.as_ref().map(|_| RawDiagnostic {
            message: "This experimental syntax requires enabling the parser plugin: \"sourcePhaseImports\".".to_owned(),
            byte_offset: Some(import.source.span.start),
        })
    });
    let mut errors: Vec<RawDiagnostic> = parsed
        .errors
        .iter()
        .map(|error| raw_diagnostic!(error))
        .collect();
    if matches!(
        mode.grammar,
        JavaScriptGrammar::TypeScript | JavaScriptGrammar::TypeScriptDeclaration
    ) {
        // Babel's legacy-decorator plugin accepts parameter decorators in
        // TypeScript constructors and methods. Oxc retains the decorators but
        // also emits this compatibility diagnostic for the same nodes.
        errors.retain(|error| error.message != "Decorators are not valid here.");
    }
    retain_legacy_typescript_diagnostics(&mut errors, mode.grammar);
    let panicked = parsed.panicked || unsupported_import_phase.is_some();
    if let Some(error) = unsupported_import_phase {
        errors.push(error);
    }
    Attempt {
        errors,
        program: parsed.program,
        panicked,
    }
}

/// Build the semantic model and merge parser, semantic and boundary diagnostics.
fn finish<'a>(
    allocator: &'a Allocator,
    source: &'a str,
    parsed: Attempt<'a>,
    mode: ParserMode,
    options: BoundaryOptions,
) -> Result<ParsedJavaScriptProgram<'a>, Vec<RawDiagnostic>> {
    if parsed.panicked {
        return Err(parsed.errors);
    }
    let program = allocator.alloc(parsed.program);
    let built = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(program);
    let suppressed = options::suppressed_semantic_offsets(program, &built.semantic, options);
    let mut errors = parsed.errors;
    let mut semantic_errors: Vec<RawDiagnostic> = built
        .errors
        .iter()
        .map(|error| raw_diagnostic!(error))
        .filter(|error| {
            error
                .byte_offset
                .is_none_or(|offset| !suppressed.contains(&offset))
        })
        .collect();
    retain_legacy_typescript_diagnostics(&mut semantic_errors, mode.grammar);
    errors.extend(semantic_errors);
    if options.disallow_ambiguous_jsx_like {
        errors.extend(options::ambiguous_jsx_like_errors(source, &built.semantic));
    }
    if options.report_declaration_redeclarations {
        errors.extend(options::declaration_redeclaration_errors(
            program,
            &built.semantic,
        ));
    }
    if options.report_unknown_path_ambiguous_jsx_like {
        errors.extend(unknown_path_ambiguous_jsx_like_errors(
            source,
            &built.semantic,
        ));
    }
    if options.report_ts_module_identifier {
        errors.extend(options::ts_module_identifier_errors(&built.semantic));
    }
    if options.report_default_export_specifier {
        errors.extend(options::default_export_specifier_errors(&built.semantic));
    }
    deduplicate_diagnostics(&mut errors);
    errors.sort_by_key(|error| error.byte_offset.unwrap_or(u32::MAX));
    Ok(ParsedJavaScriptProgram {
        program,
        semantic: built.semantic,
        mode,
        errors,
    })
}

/// Parse a discarded module retry on a temporary allocator and retain only
/// owned diagnostics. A fatal retry contributes no recovered diagnostics.
fn module_retry_diagnostics(
    source: &str,
    mode: ParserMode,
    options: BoundaryOptions,
    allow_return_outside_function: bool,
    preserve_parens: bool,
) -> Vec<RawDiagnostic> {
    let module_allocator = Allocator::default();
    finish(
        &module_allocator,
        source,
        attempt(
            &module_allocator,
            source,
            mode,
            OxcModuleKind::Module,
            allow_return_outside_function,
            preserve_parens,
        ),
        mode,
        options,
    )
    .map(|parsed| parsed.errors)
    .unwrap_or_default()
}

/// Oxc can report the same syntax failure from its parser and semantic
/// validation passes. Babel exposes one diagnostic at that source location,
/// so retain one location-bearing diagnostic while preserving diagnostics that
/// have no usable source position.
fn deduplicate_diagnostics(errors: &mut Vec<RawDiagnostic>) {
    let mut seen_offsets = HashSet::new();
    errors.retain(|error| {
        error
            .byte_offset
            .is_none_or(|offset| seen_offsets.insert(offset))
    });
}

/// Parse with the TS oracle's mode selection. `Err` carries fatal diagnostics.
pub fn parse_javascript_program<'a>(
    allocator: &'a Allocator,
    source: &'a str,
    path: Option<&str>,
) -> Result<ParsedJavaScriptProgram<'a>, Vec<RawDiagnostic>> {
    parse_program(allocator, source, path, false)
}

/// [`parse_javascript_program`] with `ParenthesizedExpression` and
/// `TSParenthesizedType` retained, for the Babel-shaped analysis view in
/// `javascript::ast`, which derives Babel's `extra.parenthesized` from them.
/// Mode selection, diagnostics and the `.cjs` re-parse are identical.
pub fn parse_javascript_analysis_program<'a>(
    allocator: &'a Allocator,
    source: &'a str,
    path: Option<&str>,
) -> Result<ParsedJavaScriptProgram<'a>, Vec<RawDiagnostic>> {
    parse_program(allocator, source, path, true)
}

fn has_semantic_errors(program: &Program<'_>) -> bool {
    SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(program)
        .errors
        .len()
        > 0
}

/// JavaScript-path sources use Babel's JavaScript grammar.  Babel treats a
/// recovered TypeScript `satisfies` expression as a fatal parse, even though
/// Oxc can still produce an AST for later diagnostics.  Keep that decision at
/// the parser boundary so downstream inspectors never consume a syntax tree
/// that the selected grammar rejected.
fn javascript_satisfies_offset(program: &Program<'_>) -> Option<u32> {
    struct Finder {
        offset: Option<u32>,
    }

    impl<'a> AstVisitor<'a> for Finder {
        fn enter(
            &mut self,
            node: &crate::javascript::ast::Node<'a>,
            _: Option<&crate::javascript::ast::Node<'a>>,
            _: &[crate::javascript::ast::Node<'a>],
        ) {
            if self.offset.is_none() && node.babel_type() == "TSSatisfiesExpression" {
                self.offset = Some(node.span().start);
            }
        }
    }

    let context = AstContext::new(program);
    let mut finder = Finder { offset: None };
    let _: ControlFlow<()> = traverse(context.root(), program.source_text, &mut finder, || {
        ControlFlow::Continue(())
    });
    finder.offset
}

/// Babel's JavaScript parser does not enable the decorator-auto-accessors
/// proposal. Oxc still produces a `ClassAccessorProperty` for `accessor`, so
/// reject that recovered tree at the selected grammar boundary.
fn javascript_accessor_property_offset(program: &Program<'_>) -> Option<u32> {
    struct Finder {
        offset: Option<u32>,
    }

    impl<'a> AstVisitor<'a> for Finder {
        fn enter(
            &mut self,
            node: &crate::javascript::ast::Node<'a>,
            _: Option<&crate::javascript::ast::Node<'a>>,
            _: &[crate::javascript::ast::Node<'a>],
        ) {
            if self.offset.is_none() && node.babel_type() == "ClassAccessorProperty" {
                self.offset = Some(node.span().start);
            }
        }
    }

    let context = AstContext::new(program);
    let mut finder = Finder { offset: None };
    let _: ControlFlow<()> = traverse(context.root(), program.source_text, &mut finder, || {
        ControlFlow::Continue(())
    });
    finder.offset
}

/// Babel's legacy-decorator parser rejects a decorator written after `export`.
/// The AST keeps the decorator under the export declaration, which lets this
/// boundary rule distinguish it from the accepted `@dec export class` form.
fn exported_decorator_offset(program: &Program<'_>) -> Option<u32> {
    struct Finder<'source> {
        offset: Option<u32>,
        source: &'source str,
    }

    impl<'a, 'source> AstVisitor<'a> for Finder<'source> {
        fn enter(
            &mut self,
            node: &crate::javascript::ast::Node<'a>,
            _: Option<&crate::javascript::ast::Node<'a>>,
            ancestors: &[crate::javascript::ast::Node<'a>],
        ) {
            if self.offset.is_none()
                && node.babel_type() == "Decorator"
                && ancestors.iter().any(|ancestor| {
                    matches!(ancestor.babel_type(), "ExportNamedDeclaration")
                        && program_source_has_export_before_decorator(
                            self.source,
                            ancestor.span().start,
                            node.span().start,
                        )
                })
            {
                self.offset = Some(node.span().start);
            }
        }
    }

    let context = AstContext::new(program);
    let mut finder = Finder {
        offset: None,
        source: program.source_text,
    };
    let _: ControlFlow<()> = traverse(context.root(), program.source_text, &mut finder, || {
        ControlFlow::Continue(())
    });
    finder.offset
}

fn program_source_has_export_before_decorator(source: &str, start: u32, decorator: u32) -> bool {
    source
        .get(start as usize..decorator as usize)
        .is_some_and(|prefix| prefix.split_whitespace().any(|word| word == "export"))
}

fn parse_program<'a>(
    allocator: &'a Allocator,
    source: &'a str,
    path: Option<&str>,
    preserve_parens: bool,
) -> Result<ParsedJavaScriptProgram<'a>, Vec<RawDiagnostic>> {
    let mut mode = ParserMode::for_path(path);
    let commonjs = mode.source_type == PathSourceType::CommonJs;
    let first_kind = match mode.source_type {
        // Inert artifact analysis retains module declarations even in .cjs assets.
        PathSourceType::CommonJs | PathSourceType::Unambiguous => OxcModuleKind::Unambiguous,
        PathSourceType::Module => OxcModuleKind::Module,
    };
    let mut parsed = attempt(
        allocator,
        source,
        mode,
        first_kind,
        commonjs,
        preserve_parens,
    );
    if mode.grammar == JavaScriptGrammar::JavaScriptJsx
        && !parsed.panicked
        && let Some(offset) = javascript_satisfies_offset(&parsed.program)
    {
        parsed.panicked = true;
        parsed.errors.push(RawDiagnostic {
            message: "TypeScript satisfies expressions are not valid in JavaScript sources."
                .to_owned(),
            byte_offset: Some(offset),
        });
    }
    if mode.grammar == JavaScriptGrammar::JavaScriptJsx
        && !parsed.panicked
        && let Some(offset) = javascript_accessor_property_offset(&parsed.program)
    {
        parsed.panicked = true;
        parsed.errors.push(RawDiagnostic {
            message: "This experimental syntax requires enabling the parser plugin: \"decoratorAutoAccessors\"."
                .to_owned(),
            byte_offset: Some(offset),
        });
    }
    if !parsed.panicked
        && let Some(offset) = exported_decorator_offset(&parsed.program)
    {
        parsed.panicked = true;
        parsed.errors.push(RawDiagnostic {
            message: "Unexpected token, expected \"{\".".to_owned(),
            byte_offset: Some(offset),
        });
    }
    let mut report_unknown_path_ambiguous_jsx_like = false;
    if path.is_none() && parsed.panicked {
        // Babel's unknown-path plugin set enables JSX but recovers generic
        // arrow functions as TypeScript. Retry the unambiguous grammar with
        // JSX disabled so those valid TypeScript facts remain available.
        mode.grammar = JavaScriptGrammar::TypeScript;
        parsed = attempt(
            allocator,
            source,
            mode,
            first_kind,
            commonjs,
            preserve_parens,
        );
        report_unknown_path_ambiguous_jsx_like = !parsed.panicked;
    }
    let options = BoundaryOptions {
        // Babel's first parse sets allowNewTargetOutsideFunction for .cjs; its
        // CommonJS re-parse allows it by source type, as oxc's CommonJS kind does.
        allow_new_target_outside_function: commonjs,
        allow_undeclared_exports: false,
        disallow_ambiguous_jsx_like: mode.disallow_ambiguous_jsx_like,
        report_unknown_path_ambiguous_jsx_like,
        report_declaration_redeclarations: mode.grammar == JavaScriptGrammar::TypeScriptDeclaration,
        report_ts_module_identifier: matches!(
            mode.grammar,
            JavaScriptGrammar::TypeScript | JavaScriptGrammar::TypeScriptDeclaration
        ),
        report_default_export_specifier: true,
    };

    if !commonjs
        && mode.source_type == PathSourceType::Unambiguous
        && !parsed.panicked
        && parsed.program.source_type.is_script()
    {
        return recover_unambiguous_analysis_parse(
            allocator,
            source,
            mode,
            parsed,
            preserve_parens,
            options,
        );
    }
    if commonjs
        && !parsed.panicked
        && parsed.program.source_type.is_script()
        && (!parsed.errors.is_empty() || has_semantic_errors(&parsed.program))
    {
        // The .cjs extension establishes wrapper mode; obtain its own diagnostics.
        parsed = attempt(
            allocator,
            source,
            mode,
            OxcModuleKind::CommonJs,
            false,
            preserve_parens,
        );
    }
    finish(allocator, source, parsed, mode, options)
}

/// Preserve module-only diagnostics when an unambiguous source resolves to a
/// script. Babel's unambiguous parser performs this module check even when
/// its recovered script has no diagnostics of its own.
fn recover_unambiguous_analysis_parse<'a>(
    allocator: &'a Allocator,
    source: &'a str,
    mode: ParserMode,
    first: Attempt<'a>,
    preserve_parens: bool,
    options: BoundaryOptions,
) -> Result<ParsedJavaScriptProgram<'a>, Vec<RawDiagnostic>> {
    let first = finish(allocator, source, first, mode, options)?;
    let module_errors = module_retry_diagnostics(source, mode, options, false, preserve_parens);
    if module_errors.is_empty() {
        return Ok(first);
    }

    let script = finish(
        allocator,
        source,
        attempt(
            allocator,
            source,
            mode,
            OxcModuleKind::Script,
            false,
            preserve_parens,
        ),
        mode,
        options,
    )?;
    let script_messages: HashSet<String> = script
        .errors
        .iter()
        .map(|error| error.message.clone())
        .collect();
    let mut errors = script.errors;
    errors.extend(
        module_errors
            .into_iter()
            .filter(|error| !script_messages.contains(&error.message)),
    );
    deduplicate_diagnostics(&mut errors);
    errors.sort_by_key(|error| error.byte_offset.unwrap_or(u32::MAX));
    Ok(ParsedJavaScriptProgram {
        program: script.program,
        semantic: script.semantic,
        mode: script.mode,
        errors,
    })
}

/// A recovered parse plus the errors that apply only if the source is an ES module.
pub struct RecoveredJavaScriptProgram<'a> {
    pub parsed: ParsedJavaScriptProgram<'a>,
    /// Module-parse diagnostics whose message the script re-parse did not
    /// report (`moduleOnlyErrors`), in module-parse order.
    pub module_only_errors: Vec<RawDiagnostic>,
}

/// Port of `parseRecoveredJavaScript` with the options of
/// `parseReferenceSourceImports` (`allowImportExportEverywhere: false`,
/// `allowReturnOutsideFunction: true`, `allowUndeclaredExports: true`).
///
/// Explicit paths parse once in their mode (`.cjs` as CommonJS, which owns its
/// wrapper semantics, so the script overrides are dropped). An unambiguous
/// source that resolves to a script is checked in module mode; if that reports
/// errors, it is parsed again as a script and module-parse errors whose message the script parse does not repeat become
/// `module_only_errors`. Matching by message follows the oracle; both parses
/// are oxc's, so the wording is consistent.
pub fn parse_recovered_javascript_program<'a>(
    allocator: &'a Allocator,
    source: &'a str,
    path: Option<&str>,
) -> Result<RecoveredJavaScriptProgram<'a>, Vec<RawDiagnostic>> {
    let mode = ParserMode::for_path(path);
    let options = BoundaryOptions {
        allow_new_target_outside_function: false,
        allow_undeclared_exports: true,
        disallow_ambiguous_jsx_like: mode.disallow_ambiguous_jsx_like,
        report_unknown_path_ambiguous_jsx_like: false,
        report_declaration_redeclarations: false,
        report_ts_module_identifier: false,
        report_default_export_specifier: true,
    };
    let explicit = match mode.source_type {
        PathSourceType::CommonJs => Some((OxcModuleKind::CommonJs, false)),
        PathSourceType::Module => Some((OxcModuleKind::Module, true)),
        PathSourceType::Unambiguous => None,
    };
    if let Some((kind, allow_return)) = explicit {
        let parsed = attempt(allocator, source, mode, kind, allow_return, false);
        return finish(allocator, source, parsed, mode, options).map(|parsed| {
            RecoveredJavaScriptProgram {
                parsed,
                module_only_errors: Vec::new(),
            }
        });
    }
    let first_attempt = attempt(
        allocator,
        source,
        mode,
        OxcModuleKind::Unambiguous,
        true,
        false,
    );
    let first = finish(allocator, source, first_attempt, mode, options)?;
    if !first.program.source_type.is_script() {
        return Ok(RecoveredJavaScriptProgram {
            parsed: first,
            module_only_errors: Vec::new(),
        });
    }
    // Babel's unambiguous parse is a module parse and keeps its strict-mode
    // errors after choosing a script. oxc's does not, so obtain that error set
    // from an explicit module attempt. A fatal module attempt contributes no
    // recovered diagnostics, matching the parser owner's fallback behavior.
    let module_errors = module_retry_diagnostics(source, mode, options, true, false);
    if first.errors.is_empty() && module_errors.is_empty() {
        return Ok(RecoveredJavaScriptProgram {
            parsed: first,
            module_only_errors: Vec::new(),
        });
    }
    let script = finish(
        allocator,
        source,
        attempt(allocator, source, mode, OxcModuleKind::Script, true, false),
        mode,
        options,
    )?;
    let script_messages: HashSet<&str> = script
        .errors
        .iter()
        .map(|error| error.message.as_str())
        .collect();
    let module_only_errors = module_errors
        .into_iter()
        .filter(|error| !script_messages.contains(error.message.as_str()))
        .collect();
    Ok(RecoveredJavaScriptProgram {
        parsed: script,
        module_only_errors,
    })
}

/// Result of a recovered reference-source parse.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum RecoveredJavaScriptParseOutcome {
    Parsed {
        facts: JavaScriptSourceFacts,
        module_only_errors: Vec<ParseDiagnostic>,
    },
    Fatal {
        errors: Vec<ParseDiagnostic>,
    },
}

/// Parse one reference source with recovery and extract its facts.
pub fn parse_recovered_javascript_source(
    source: &str,
    path: Option<&str>,
) -> RecoveredJavaScriptParseOutcome {
    let allocator = Allocator::default();
    let index = PositionIndex::new(source);
    match parse_recovered_javascript_program(&allocator, source, path) {
        Ok(recovered) => RecoveredJavaScriptParseOutcome::Parsed {
            facts: facts::extract(source, path, &recovered.parsed, &index),
            module_only_errors: recovered
                .module_only_errors
                .iter()
                .map(|error| facts::diagnostic(error, &index))
                .collect(),
        },
        Err(errors) => RecoveredJavaScriptParseOutcome::Fatal {
            errors: errors
                .iter()
                .map(|error| facts::diagnostic(error, &index))
                .collect(),
        },
    }
}

/// Parse one source and extract the facts the TS graph producer consumes.
pub fn parse_javascript_source(source: &str, path: Option<&str>) -> JavaScriptParseOutcome {
    let allocator = Allocator::default();
    let index = PositionIndex::new(source);
    match parse_javascript_program(&allocator, source, path) {
        Ok(parsed) => JavaScriptParseOutcome::Parsed {
            facts: facts::extract(source, path, &parsed, &index),
        },
        Err(errors) => JavaScriptParseOutcome::Fatal {
            errors: errors
                .iter()
                .map(|error| facts::diagnostic(error, &index))
                .collect(),
        },
    }
}

/// Extract module facts from an already parsed program.
///
/// Static analysis keeps the analysis AST alive for its inspectors. Callers
/// that already own that AST should use this seam instead of parsing the same
/// source a second time solely to collect imports and exports.
pub fn extract_facts(
    source: &str,
    path: Option<&str>,
    parsed: &ParsedJavaScriptProgram<'_>,
) -> JavaScriptSourceFacts {
    let index = PositionIndex::new(source);
    facts::extract(source, path, parsed, &index)
}

#[cfg(test)]
mod allocator_tests {
    use super::*;

    #[test]
    fn discarded_module_retries_do_not_retain_asts() {
        let mut source = String::new();
        for index in 0..10_000 {
            source.push_str(&format!("const value_{index} = {index};\n"));
        }

        let mode = ParserMode::for_path(Some("fixture.js"));
        let expected_allocator = Allocator::default();
        let expected = finish(
            &expected_allocator,
            &source,
            attempt(
                &expected_allocator,
                &source,
                mode,
                OxcModuleKind::Unambiguous,
                false,
                true,
            ),
            mode,
            BoundaryOptions::default(),
        )
        .expect("the selected script parse should succeed");
        assert!(expected.program.source_type.is_script());
        let selected_ast_bytes = expected_allocator.used_bytes();

        let analysis_allocator = Allocator::default();
        let analysis =
            parse_javascript_analysis_program(&analysis_allocator, &source, Some("fixture.js"))
                .expect("analysis source parses");
        assert!(analysis.errors.is_empty());
        assert_eq!(analysis.program.body.len(), expected.program.body.len());
        assert_eq!(analysis_allocator.used_bytes(), selected_ast_bytes);

        let recovery_allocator = Allocator::default();
        let recovered =
            parse_recovered_javascript_program(&recovery_allocator, &source, Some("fixture.js"))
                .expect("recovered source parses");
        assert!(recovered.parsed.errors.is_empty());
        assert!(recovered.module_only_errors.is_empty());
        assert_eq!(
            recovered.parsed.program.body.len(),
            expected.program.body.len()
        );
        assert_eq!(recovery_allocator.used_bytes(), selected_ast_bytes);
    }
}

#[cfg(test)]
mod tests;
