//! Inert JavaScript/TypeScript parser boundary (oxc).
//!
//! Port of `parseJavaScriptSource` in
//! `src/domain/javascript/javascriptSourceParser.ts`: the same per-path grammar
//! and source-type rules, the `.cjs` wrapper re-parse, recovered versus fatal
//! errors, and the parser-owned runtime-context proof. Consumers read the
//! parsed facts in [`JavaScriptSourceFacts`] instead of reinterpreting source.
//! Known differences from Babel are recorded in
//! `.cache/rust-migration/js-parse-differences.md`.

mod facts;
mod mode;
mod position;

use oxc_allocator::Allocator;
use oxc_ast::ast::Program;
use oxc_parser::{ParseOptions, Parser};
use oxc_semantic::{Semantic, SemanticBuilder};
use serde::Serialize;

pub use facts::{
    ExportFact, ExportFactKind, JavaScriptSourceFacts, ModuleReference, ModuleReferenceKind,
    ParseDiagnostic, ProgramSourceType, RuntimeContext,
};
pub use mode::{is_explicit_module_source_path, JavaScriptGrammar, ParserMode, PathSourceType};
pub use position::{PositionIndex, SourcePosition, SourceRange};

use mode::OxcModuleKind;

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

fn attempt<'a>(
    allocator: &'a Allocator,
    source: &'a str,
    mode: ParserMode,
    kind: OxcModuleKind,
    allow_return_outside_function: bool,
) -> Attempt<'a> {
    let parsed = Parser::new(allocator, source, mode.oxc_source_type(kind))
        .with_options(ParseOptions {
            allow_return_outside_function,
            preserve_parens: false,
            ..ParseOptions::default()
        })
        .parse();
    Attempt {
        errors: parsed.errors.iter().map(|error| raw_diagnostic!(error)).collect(),
        program: parsed.program,
        panicked: parsed.panicked,
    }
}

/// Parse with the TS oracle's mode selection. `Err` carries fatal diagnostics.
pub fn parse_javascript_program<'a>(
    allocator: &'a Allocator,
    source: &'a str,
    path: Option<&str>,
) -> Result<ParsedJavaScriptProgram<'a>, Vec<RawDiagnostic>> {
    let mode = ParserMode::for_path(path);
    let commonjs = mode.source_type == PathSourceType::CommonJs;
    let first_kind = match mode.source_type {
        // Inert artifact analysis retains module declarations even in .cjs assets.
        PathSourceType::CommonJs | PathSourceType::Unambiguous => OxcModuleKind::Unambiguous,
        PathSourceType::Module => OxcModuleKind::Module,
    };
    let mut parsed = attempt(allocator, source, mode, first_kind, commonjs);
    if commonjs
        && !parsed.panicked
        && parsed.program.source_type.is_script()
        && !parsed.errors.is_empty()
    {
        // The .cjs extension establishes wrapper mode; obtain its own diagnostics.
        parsed = attempt(allocator, source, mode, OxcModuleKind::CommonJs, false);
    }
    if parsed.panicked {
        return Err(parsed.errors);
    }
    let program = allocator.alloc(parsed.program);
    let built = SemanticBuilder::new().with_check_syntax_error(true).build(program);
    let mut errors = parsed.errors;
    errors.extend(built.errors.iter().map(|error| raw_diagnostic!(error)));
    errors.sort_by_key(|error| error.byte_offset.unwrap_or(u32::MAX));
    Ok(ParsedJavaScriptProgram {
        program,
        semantic: built.semantic,
        mode,
        errors,
    })
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
            errors: errors.iter().map(|error| facts::diagnostic(error, &index)).collect(),
        },
    }
}

#[cfg(test)]
mod tests;
