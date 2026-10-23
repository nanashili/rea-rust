//! Babel parser options that oxc does not offer, applied once at the boundary.
//!
//! Each rule reads the AST (and the semantic model's ancestry and reference
//! resolution), never diagnostic text:
//!
//! - `allowNewTargetOutsideFunction`: drop oxc's semantic diagnostic for a
//!   `new.target` with no enclosing non-arrow function (D6).
//! - `allowUndeclaredExports`: drop oxc's semantic diagnostic for a local
//!   export specifier whose identifier resolves to no binding.
//! - `disallowAmbiguousJSXLike` (`.mts`): report Babel's reserved-syntax errors
//!   for `<T>() => ...` and `<T>value` (D7).
use std::collections::HashSet;

use oxc_ast::ast::{ModuleExportName, Program, Statement};
use oxc_ast::AstKind;
use oxc_semantic::Semantic;
use oxc_span::GetSpan;

use super::RawDiagnostic;

/// Babel options the caller requested that need a boundary rule.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct BoundaryOptions {
    pub allow_new_target_outside_function: bool,
    pub allow_undeclared_exports: bool,
    pub disallow_ambiguous_jsx_like: bool,
}

/// Byte offsets of semantic diagnostics that a requested Babel option suppresses.
pub(super) fn suppressed_semantic_offsets(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    options: BoundaryOptions,
) -> HashSet<u32> {
    let mut offsets = HashSet::new();
    if options.allow_new_target_outside_function {
        let nodes = semantic.nodes();
        for node in nodes.iter() {
            let AstKind::MetaProperty(meta) = node.kind() else { continue };
            if meta.meta.name != "new" || meta.property.name != "target" {
                continue;
            }
            // Arrow functions inherit new.target; only a non-arrow function binds it.
            let in_function = nodes
                .ancestor_kinds(node.id())
                .any(|kind| matches!(kind, AstKind::Function(_)));
            if !in_function {
                offsets.insert(meta.span.start);
            }
        }
    }
    if options.allow_undeclared_exports {
        let scoping = semantic.scoping();
        for statement in &program.body {
            let Statement::ExportNamedDeclaration(export) = statement else { continue };
            if export.source.is_some() {
                continue;
            }
            for specifier in &export.specifiers {
                if let ModuleExportName::IdentifierReference(identifier) = &specifier.local
                    && identifier.is_global_reference(scoping)
                {
                    offsets.insert(identifier.span.start);
                }
            }
        }
    }
    offsets
}

/// Index just past the comment or whitespace run at `rest`, if any.
fn skip_trivia(rest: &str) -> Option<usize> {
    if let Some(after) = rest.strip_prefix("/*") {
        return Some(after.find("*/").map_or(rest.len(), |end| end + 4));
    }
    if rest.starts_with("//") {
        return Some(rest.find(['\n', '\r', '\u{2028}', '\u{2029}']).unwrap_or(rest.len()));
    }
    let trimmed = rest.trim_start();
    (trimmed.len() < rest.len()).then(|| rest.len() - trimmed.len())
}

/// Whether `text` (between the last type parameter and `>`) holds a comma
/// outside comments.
fn has_trailing_comma(text: &str) -> bool {
    let mut rest = text;
    while !rest.is_empty() {
        if let Some(skip) = skip_trivia(rest) {
            rest = &rest[skip..];
            continue;
        }
        return rest.starts_with(',');
    }
    false
}

const RESERVED_ARROW: &str = "This syntax is reserved in files with the .mts or .cts extension. Add a trailing comma, as in `<T,>() => ...`.";
const RESERVED_ASSERTION: &str = "This syntax is reserved in files with the .mts or .cts extension. Use an `as` expression instead.";

/// Babel `disallowAmbiguousJSXLike` errors, anchored at `<` as Babel does.
pub(super) fn ambiguous_jsx_like_errors(source: &str, semantic: &Semantic<'_>) -> Vec<RawDiagnostic> {
    let mut errors = Vec::new();
    for node in semantic.nodes().iter() {
        match node.kind() {
            AstKind::ArrowFunctionExpression(arrow) if !arrow.r#async => {
                let Some(declaration) = &arrow.type_parameters else { continue };
                let [parameter] = declaration.params.as_slice() else { continue };
                if parameter.constraint.is_some() {
                    continue;
                }
                let between = source
                    .get(parameter.span.end as usize..declaration.span.end.saturating_sub(1) as usize)
                    .unwrap_or("");
                if !has_trailing_comma(between) {
                    errors.push(RawDiagnostic {
                        message: RESERVED_ARROW.to_owned(),
                        byte_offset: Some(declaration.span.start),
                    });
                }
            }
            AstKind::TSTypeAssertion(assertion) => errors.push(RawDiagnostic {
                message: RESERVED_ASSERTION.to_owned(),
                byte_offset: Some(assertion.span().start),
            }),
            _ => {}
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::has_trailing_comma;

    #[test]
    fn trailing_comma_ignores_comments() {
        assert!(has_trailing_comma(", "));
        assert!(has_trailing_comma(" /* , */ ,"));
        assert!(!has_trailing_comma(" /* , */ "));
        assert!(!has_trailing_comma(" // ,\n "));
        assert!(!has_trailing_comma(""));
    }
}
