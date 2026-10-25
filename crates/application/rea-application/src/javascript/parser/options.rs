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
use std::collections::{HashMap, HashSet};

use oxc_ast::AstKind;
use oxc_ast::ast::{
    ModuleExportName, Program, Statement, TSModuleDeclarationKind, TSModuleDeclarationName,
};
use oxc_semantic::{IsGlobalReference, Semantic};
use oxc_span::GetSpan;

use super::RawDiagnostic;
use crate::javascript::ast::{AstContext, AstVisitor, Node, NodeKind, traverse};

/// Babel options the caller requested that need a boundary rule.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct BoundaryOptions {
    pub allow_new_target_outside_function: bool,
    pub allow_undeclared_exports: bool,
    pub disallow_ambiguous_jsx_like: bool,
    pub report_unknown_path_ambiguous_jsx_like: bool,
    pub report_declaration_redeclarations: bool,
    pub report_ts_module_identifier: bool,
    pub report_default_export_specifier: bool,
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
            let AstKind::MetaProperty(meta) = node.kind() else {
                continue;
            };
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
            let Statement::ExportNamedDeclaration(export) = statement else {
                continue;
            };
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
        return Some(
            rest.find(['\n', '\r', '\u{2028}', '\u{2029}'])
                .unwrap_or(rest.len()),
        );
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
pub(super) fn ambiguous_jsx_like_errors(
    source: &str,
    semantic: &Semantic<'_>,
) -> Vec<RawDiagnostic> {
    let mut errors = Vec::new();
    for node in semantic.nodes().iter() {
        match node.kind() {
            AstKind::ArrowFunctionExpression(arrow) if !arrow.r#async => {
                let Some(declaration) = &arrow.type_parameters else {
                    continue;
                };
                let [parameter] = declaration.params.as_slice() else {
                    continue;
                };
                if parameter.constraint.is_some() {
                    continue;
                }
                let between = source
                    .get(
                        parameter.span.end as usize
                            ..declaration.span.end.saturating_sub(1) as usize,
                    )
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

/// Babel reports value/type declaration collisions in ambient files even when
/// TypeScript permits declaration merging for the same source program.
pub(super) fn declaration_redeclaration_errors(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
) -> Vec<RawDiagnostic> {
    let scoping = semantic.scoping();
    let nodes = semantic.nodes();
    let mut errors = Vec::new();

    for symbol_id in scoping.symbol_ids() {
        let declarations: Vec<_> = scoping.symbol_declarations(symbol_id).collect();
        if declarations.len() < 2 {
            continue;
        }

        let mut has_variable = false;
        let mut has_type_or_import = false;
        for declaration in &declarations {
            match nodes.kind(*declaration) {
                AstKind::VariableDeclarator(_) => has_variable = true,
                AstKind::Class(_)
                | AstKind::TSInterfaceDeclaration(_)
                | AstKind::ImportNamespaceSpecifier(_)
                | AstKind::ImportSpecifier(_) => has_type_or_import = true,
                _ => {}
            }
        }
        if !has_variable || !has_type_or_import {
            continue;
        }

        let name = scoping.symbol_name(symbol_id);
        if let Some(declaration) = declarations.iter().skip(1).find_map(|&declaration| {
            matches!(nodes.kind(declaration), AstKind::VariableDeclarator(_)).then_some(declaration)
        }) {
            errors.push(RawDiagnostic {
                message: format!("Identifier '{name}' has already been declared."),
                byte_offset: Some(nodes.get_node(declaration).span().start),
            });
        }
    }

    let mut variable_bindings = HashMap::<(String, u32), u32>::new();
    let mut declaration_bindings = HashMap::<(String, u32), u32>::new();

    struct Collector<'a> {
        variables: &'a mut HashMap<(String, u32), u32>,
        declarations: &'a mut HashMap<(String, u32), u32>,
    }

    impl<'a, 'source> AstVisitor<'a> for Collector<'source> {
        fn enter(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>, ancestors: &[Node<'a>]) {
            if !matches!(node.kind(), NodeKind::BindingIdentifier { .. }) {
                return;
            }
            if ancestors.iter().any(|ancestor| {
                matches!(
                    ancestor.babel_type(),
                    "Function"
                        | "FunctionDeclaration"
                        | "FunctionExpression"
                        | "ArrowFunctionExpression"
                        | "ClassMethod"
                ) || (ancestor.babel_type() == "BlockStatement"
                    && !matches!(ancestor.kind(), NodeKind::TSModuleBlock(_)))
            }) {
                return;
            }
            let Some(parent) = parent else { return };
            let Some(name) = node.identifier_name() else {
                return;
            };
            let offset = node.span().start;
            let scope = ancestors
                .iter()
                .rev()
                .find_map(|ancestor| match ancestor.kind() {
                    NodeKind::TSGlobalDeclaration(_) => Some(0),
                    NodeKind::TSModuleDeclaration(_) => Some(ancestor.span().start),
                    _ => None,
                })
                .unwrap_or(0);
            let key = (name.to_owned(), scope);
            match parent.kind() {
                NodeKind::VariableDeclarator(_) => {
                    self.variables.entry(key).or_insert(offset);
                }
                NodeKind::TSInterfaceDeclaration(_)
                | NodeKind::ImportNamespaceSpecifier(_)
                | NodeKind::ImportSpecifier(_) => {
                    self.declarations.entry(key).or_insert(offset);
                }
                NodeKind::Class(class)
                    if class.r#type == oxc_ast::ast::ClassType::ClassDeclaration =>
                {
                    self.declarations.entry(key).or_insert(offset);
                }
                _ => {}
            }
        }
    }

    let context = AstContext::new(program);
    let mut collector = Collector {
        variables: &mut variable_bindings,
        declarations: &mut declaration_bindings,
    };
    let _: std::ops::ControlFlow<()> =
        traverse(context.root(), program.source_text, &mut collector, || {
            std::ops::ControlFlow::<()>::Continue(())
        });
    for (key, variable_offset) in variable_bindings {
        if let Some(declaration_offset) = declaration_bindings.get(&key) {
            let name = &key.0;
            if !errors
                .iter()
                .any(|error| error.byte_offset == Some(variable_offset))
            {
                errors.push(RawDiagnostic {
                    message: format!("Identifier '{name}' has already been declared."),
                    byte_offset: Some(*declaration_offset),
                });
            }
        }
    }

    errors
}

/// Babel rejects the identifier form of a `module` declaration. Oxc accepts it
/// as a namespace-shaped declaration, so retain Babel's syntax diagnostic at
/// the declaration name while leaving the recovered tree available.
pub(super) fn ts_module_identifier_errors(semantic: &Semantic<'_>) -> Vec<RawDiagnostic> {
    semantic
        .nodes()
        .iter()
        .filter_map(|node| {
            let AstKind::TSModuleDeclaration(declaration) = node.kind() else {
                return None;
            };
            if declaration.kind != TSModuleDeclarationKind::Module
                || !matches!(declaration.id, TSModuleDeclarationName::Identifier(_))
            {
                return None;
            }
            Some(RawDiagnostic {
                message: "`module ... {}` declarations must have a string name. Use `namespace ... {}` instead.".to_owned(),
                byte_offset: Some(declaration.id.span().start),
            })
        })
        .collect()
}

/// Babel reports `default` as an invalid local export specifier before it
/// reports that the exported binding is missing. Oxc emits only the latter.
pub(super) fn default_export_specifier_errors(semantic: &Semantic<'_>) -> Vec<RawDiagnostic> {
    semantic
        .nodes()
        .iter()
        .filter_map(|node| {
            let AstKind::ExportSpecifier(specifier) = node.kind() else {
                return None;
            };
            let ModuleExportName::IdentifierReference(identifier) = &specifier.local else {
                return None;
            };
            (identifier.name == "default").then_some(RawDiagnostic {
                message: "Unexpected keyword 'default'.".to_owned(),
                // Babel emits this grammar diagnostic at the same source
                // position as its unresolved-export diagnostic. Keep it
                // positionless so the boundary de-duplication retains both.
                byte_offset: None,
            })
        })
        .collect()
}

/// Babel's recovery diagnostic for a single generic arrow parameter when the
/// unknown-path grammar initially enables JSX. The TypeScript AST is valid;
/// only the JSX ambiguity is reported.
pub(super) fn unknown_path_ambiguous_jsx_like_errors(
    source: &str,
    semantic: &Semantic<'_>,
) -> Vec<RawDiagnostic> {
    semantic
        .nodes()
        .iter()
        .filter_map(|node| {
            let AstKind::ArrowFunctionExpression(arrow) = node.kind() else {
                return None;
            };
            let declaration = arrow.type_parameters.as_ref()?;
            let [parameter] = declaration.params.as_slice() else {
                return None;
            };
            if parameter.constraint.is_some() {
                return None;
            }
            let between = source.get(
                parameter.span.end as usize..declaration.span.end.saturating_sub(1) as usize,
            )?;
            if has_trailing_comma(between) {
                return None;
            }
            let name = source.get(parameter.span.start as usize..parameter.span.end as usize)?;
            Some(RawDiagnostic {
                message: format!(
                    "Single type parameter {name} should have a trailing comma. Example usage: <{name},>."
                ),
                byte_offset: Some(declaration.span.start),
            })
        })
        .collect()
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
