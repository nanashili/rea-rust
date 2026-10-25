//! Parser-owned module facts.
//!
//! Ports the declaration predicates of
//! `src/domain/javascript/javascriptModuleDeclaration.ts`, the runtime-context
//! proof of `parseWithRuntimeContext`, and the reference collection of
//! `collectWebModuleImports` (`src/domain/webModuleImports.ts`). Every node in
//! the program is visited (through the semantic node list), so declarations
//! nested in `declare module` blocks are included as Babel traversal does.

use oxc_ast::AstKind;
use oxc_ast::ast::{
    Argument, Declaration, ExportDefaultDeclarationKind, Expression, ImportDeclarationSpecifier,
    ImportOrExportKind, ModuleExportName, Program, Statement, TSModuleDeclarationName,
    TSModuleReference,
};
use oxc_semantic::IsGlobalReference;
use oxc_span::{GetSpan, Span};
use serde::Serialize;

use super::position::{PositionIndex, SourceRange};
use super::{ParsedJavaScriptProgram, RawDiagnostic};

/// Babel `program.sourceType` after mode resolution. Babel reports a
/// `sourceType: "commonjs"` parse as `script`; CommonJS isolation is the
/// separate [`RuntimeContext`] proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProgramSourceType {
    Module,
    Script,
}

/// `javaScriptRuntimeContext`: only parser-owned facts establish isolation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeContext {
    Module,
    Commonjs,
    Unknown,
}

/// One recovered or fatal parser diagnostic. Messages are oxc's own wording
/// and are not comparable to Babel text; the position is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ParseDiagnostic {
    pub message: String,
    /// Babel UTF-16 offset of the primary label; `None` when oxc gave no label.
    pub offset: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModuleReferenceKind {
    StaticImport,
    ReExport,
    DynamicImport,
    /// `require(arg)` with an identifier callee named `require`.
    Require,
    /// `import x = require("m")`.
    ImportEquals,
    /// An ambient TypeScript `declare module "name"` declaration.
    DeclaresModule,
}

/// One module reference; `range`/`expression` cover the specifier expression.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ModuleReference {
    pub kind: ModuleReferenceKind,
    /// String or substitution-free template value; `None` when not static.
    pub specifier: Option<String>,
    pub expression: String,
    pub range: SourceRange,
    /// Whole statement is erased by TypeScript (`import type`, `export type`).
    pub type_only: bool,
    /// Every binding is an inline `type` specifier (side effect uncertain).
    pub inline_type_only: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExportFactKind {
    Named,
    Default,
    All,
    /// TypeScript `export = value`.
    Assignment,
    /// TypeScript `export as namespace X`.
    Namespace,
}

/// One export statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExportFact {
    pub kind: ExportFactKind,
    /// Exported names in source order (`default` for default exports, `*`
    /// for an unnamed star re-export).
    pub names: Vec<String>,
    pub source: Option<String>,
    pub type_only: bool,
    /// Declaration establishes no runtime value (`isErasedJavaScriptDeclaration`).
    pub erased_declaration: bool,
    pub range: SourceRange,
}

/// The parser facts the TS JavaScript graph producer consumes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct JavaScriptSourceFacts {
    pub program_source_type: ProgramSourceType,
    pub runtime_context: RuntimeContext,
    /// Recovered syntax errors (non-empty means a partial parse).
    pub errors: Vec<ParseDiagnostic>,
    pub module_references: Vec<ModuleReference>,
    pub exports: Vec<ExportFact>,
    /// `hasUncertainTypeOnlyModuleSideEffect`.
    pub uncertain_type_only_side_effect: bool,
}

pub(super) fn diagnostic(error: &RawDiagnostic, index: &PositionIndex<'_>) -> ParseDiagnostic {
    ParseDiagnostic {
        message: error.message.clone(),
        offset: error.byte_offset.map(|byte| index.position(byte).offset),
    }
}

fn is_type_kind(kind: ImportOrExportKind) -> bool {
    kind == ImportOrExportKind::Type
}

fn is_erased_declaration(declaration: &Declaration<'_>) -> bool {
    match declaration {
        Declaration::TSInterfaceDeclaration(_) | Declaration::TSTypeAliasDeclaration(_) => true,
        Declaration::FunctionDeclaration(function) => function.declare || function.body.is_none(),
        Declaration::VariableDeclaration(variable) => variable.declare,
        Declaration::ClassDeclaration(class) => class.declare,
        Declaration::TSEnumDeclaration(declaration) => declaration.declare,
        Declaration::TSModuleDeclaration(declaration) => declaration.declare,
        Declaration::TSGlobalDeclaration(declaration) => declaration.declare,
        Declaration::TSImportEqualsDeclaration(_) => false,
    }
}

fn is_erased_default(declaration: &ExportDefaultDeclarationKind<'_>) -> bool {
    match declaration {
        ExportDefaultDeclarationKind::TSInterfaceDeclaration(_) => true,
        ExportDefaultDeclarationKind::FunctionDeclaration(function) => {
            function.declare || function.body.is_none()
        }
        ExportDefaultDeclarationKind::ClassDeclaration(class) => class.declare,
        _ => false,
    }
}

/// `isTypeOnlyExportDeclaration` for a named export.
fn named_export_type_only(node: &oxc_ast::ast::ExportNamedDeclaration<'_>) -> bool {
    is_type_kind(node.export_kind)
        || matches!(
            &node.declaration,
            Some(Declaration::TSInterfaceDeclaration(_) | Declaration::TSTypeAliasDeclaration(_))
        )
        || matches!(&node.declaration, Some(Declaration::FunctionDeclaration(f)) if f.body.is_none())
}

fn import_inline_type_only(node: &oxc_ast::ast::ImportDeclaration<'_>) -> bool {
    !is_type_kind(node.import_kind)
        && node.specifiers.as_ref().is_some_and(|specifiers| {
            !specifiers.is_empty()
                && specifiers.iter().all(|specifier| {
                    matches!(specifier, ImportDeclarationSpecifier::ImportSpecifier(s)
                        if is_type_kind(s.import_kind))
                })
        })
}

fn export_inline_type_only(node: &oxc_ast::ast::ExportNamedDeclaration<'_>) -> bool {
    !named_export_type_only(node)
        && node.source.is_some()
        && !node.specifiers.is_empty()
        && node
            .specifiers
            .iter()
            .all(|specifier| is_type_kind(specifier.export_kind))
}

fn module_export_name(name: &ModuleExportName<'_>) -> String {
    match name {
        ModuleExportName::IdentifierName(name) => name.name.to_string(),
        ModuleExportName::IdentifierReference(name) => name.name.to_string(),
        ModuleExportName::StringLiteral(name) => name.value.to_string(),
    }
}

fn declaration_names(declaration: &Declaration<'_>) -> Vec<String> {
    match declaration {
        Declaration::VariableDeclaration(variable) => variable
            .declarations
            .iter()
            .flat_map(|declarator| declarator.id.get_binding_identifiers())
            .map(|identifier| identifier.name.to_string())
            .collect(),
        Declaration::FunctionDeclaration(function) => {
            function.id.iter().map(|id| id.name.to_string()).collect()
        }
        Declaration::ClassDeclaration(class) => {
            class.id.iter().map(|id| id.name.to_string()).collect()
        }
        Declaration::TSTypeAliasDeclaration(alias) => vec![alias.id.name.to_string()],
        Declaration::TSInterfaceDeclaration(interface) => vec![interface.id.name.to_string()],
        Declaration::TSEnumDeclaration(declaration) => vec![declaration.id.name.to_string()],
        Declaration::TSModuleDeclaration(declaration) => match &declaration.id {
            TSModuleDeclarationName::Identifier(id) => vec![id.name.to_string()],
            TSModuleDeclarationName::StringLiteral(literal) => vec![literal.value.to_string()],
        },
        Declaration::TSGlobalDeclaration(_) => vec!["global".to_owned()],
        Declaration::TSImportEqualsDeclaration(declaration) => {
            vec![declaration.id.name.to_string()]
        }
    }
}

/// `hasRuntimeModuleDeclaration` over top-level statements.
fn has_runtime_module_declaration(program: &Program<'_>) -> bool {
    program.body.iter().any(|statement| match statement {
        Statement::TSImportEqualsDeclaration(node) => {
            !is_type_kind(node.import_kind)
                && matches!(
                    node.module_reference,
                    TSModuleReference::ExternalModuleReference(_)
                )
        }
        Statement::ImportDeclaration(node) => {
            !is_type_kind(node.import_kind) && !import_inline_type_only(node)
        }
        Statement::ExportAllDeclaration(node) => !is_type_kind(node.export_kind),
        Statement::ExportNamedDeclaration(node) => {
            !named_export_type_only(node)
                && !export_inline_type_only(node)
                && node
                    .declaration
                    .as_ref()
                    .is_none_or(|d| !is_erased_declaration(d))
        }
        Statement::ExportDefaultDeclaration(node) => !is_erased_default(&node.declaration),
        _ => false,
    })
}

fn ends_with_ignore_case(path: &str, suffix: &str) -> bool {
    path.len() >= suffix.len()
        && path.is_char_boundary(path.len() - suffix.len())
        && path[path.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

fn runtime_context(
    path: Option<&str>,
    program: &Program<'_>,
    source_type: ProgramSourceType,
) -> RuntimeContext {
    let text = path.unwrap_or("");
    if ends_with_ignore_case(text, ".cjs") || ends_with_ignore_case(text, ".cts") {
        return if ends_with_ignore_case(text, ".d.cts") {
            RuntimeContext::Unknown
        } else {
            RuntimeContext::Commonjs
        };
    }
    if super::mode::is_explicit_module_source_path(path) {
        return RuntimeContext::Module;
    }
    if program
        .body
        .iter()
        .any(|s| matches!(s, Statement::TSExportAssignment(_)))
    {
        // CommonJS isolation does not establish strict ESM semantics.
        return RuntimeContext::Commonjs;
    }
    if source_type == ProgramSourceType::Module && has_runtime_module_declaration(program) {
        RuntimeContext::Module
    } else {
        RuntimeContext::Unknown
    }
}

struct Collector<'s, 'i> {
    source: &'s str,
    index: &'i PositionIndex<'s>,
    references: Vec<ModuleReference>,
}

impl Collector<'_, '_> {
    fn add(
        &mut self,
        kind: ModuleReferenceKind,
        expression_span: Span,
        specifier: Option<String>,
        type_only: bool,
        inline_type_only: bool,
    ) {
        let expression = self
            .source
            .get(expression_span.start as usize..expression_span.end as usize)
            .unwrap_or("")
            .to_owned();
        self.references.push(ModuleReference {
            kind,
            specifier,
            expression,
            range: self.index.range(expression_span),
            type_only,
            inline_type_only,
        });
    }

    fn add_expression(&mut self, kind: ModuleReferenceKind, expression: &Expression<'_>) {
        let specifier = match expression {
            Expression::StringLiteral(literal) => Some(literal.value.to_string()),
            Expression::TemplateLiteral(template) if template.expressions.is_empty() => template
                .quasis
                .first()
                .and_then(|quasi| quasi.value.cooked.as_ref())
                .map(|cooked| cooked.to_string()),
            _ => None,
        };
        self.add(kind, expression.span(), specifier, false, false);
    }
}

pub(super) fn extract(
    source: &str,
    path: Option<&str>,
    parsed: &ParsedJavaScriptProgram<'_>,
    index: &PositionIndex<'_>,
) -> JavaScriptSourceFacts {
    let program = parsed.program;
    let program_source_type = if program.source_type.is_module() {
        ProgramSourceType::Module
    } else {
        ProgramSourceType::Script
    };
    let mut collector = Collector {
        source,
        index,
        references: Vec::new(),
    };
    let mut exports = Vec::new();
    for node in parsed.semantic.nodes().iter() {
        match node.kind() {
            AstKind::ImportDeclaration(node) => {
                let inline = import_inline_type_only(node);
                collector.add(
                    ModuleReferenceKind::StaticImport,
                    node.source.span,
                    Some(node.source.value.to_string()),
                    is_type_kind(node.import_kind),
                    inline,
                );
            }
            AstKind::ExportAllDeclaration(node) => {
                let type_only = is_type_kind(node.export_kind);
                collector.add(
                    ModuleReferenceKind::ReExport,
                    node.source.span,
                    Some(node.source.value.to_string()),
                    type_only,
                    false,
                );
                exports.push(ExportFact {
                    kind: ExportFactKind::All,
                    names: vec![
                        node.exported
                            .as_ref()
                            .map_or_else(|| "*".to_owned(), module_export_name),
                    ],
                    source: Some(node.source.value.to_string()),
                    type_only,
                    erased_declaration: false,
                    range: index.range(node.span),
                });
            }
            AstKind::ExportNamedDeclaration(node) => {
                let type_only = named_export_type_only(node);
                let inline = export_inline_type_only(node);
                if let Some(literal) = &node.source {
                    collector.add(
                        ModuleReferenceKind::ReExport,
                        literal.span,
                        Some(literal.value.to_string()),
                        type_only,
                        inline,
                    );
                }
                let names = match &node.declaration {
                    Some(declaration) => declaration_names(declaration),
                    None => node
                        .specifiers
                        .iter()
                        .map(|specifier| module_export_name(&specifier.exported))
                        .collect(),
                };
                exports.push(ExportFact {
                    kind: ExportFactKind::Named,
                    names,
                    source: node.source.as_ref().map(|s| s.value.to_string()),
                    type_only,
                    erased_declaration: node
                        .declaration
                        .as_ref()
                        .is_some_and(is_erased_declaration),
                    range: index.range(node.span),
                });
            }
            AstKind::ExportDefaultDeclaration(node) => exports.push(ExportFact {
                kind: ExportFactKind::Default,
                names: vec!["default".to_owned()],
                source: None,
                type_only: false,
                erased_declaration: is_erased_default(&node.declaration),
                range: index.range(node.span),
            }),
            AstKind::TSExportAssignment(node) => exports.push(ExportFact {
                kind: ExportFactKind::Assignment,
                names: Vec::new(),
                source: None,
                type_only: false,
                erased_declaration: false,
                range: index.range(node.span),
            }),
            AstKind::TSNamespaceExportDeclaration(node) => exports.push(ExportFact {
                kind: ExportFactKind::Namespace,
                names: vec![node.id.name.to_string()],
                source: None,
                type_only: false,
                erased_declaration: false,
                range: index.range(node.span),
            }),
            AstKind::TSImportEqualsDeclaration(node) => {
                if let TSModuleReference::ExternalModuleReference(reference) =
                    &node.module_reference
                {
                    collector.add(
                        ModuleReferenceKind::ImportEquals,
                        reference.expression.span,
                        Some(reference.expression.value.to_string()),
                        is_type_kind(node.import_kind),
                        false,
                    );
                }
            }
            AstKind::TSModuleDeclaration(node)
                if node.declare
                    && matches!(&node.id, TSModuleDeclarationName::StringLiteral(_)) =>
            {
                if let TSModuleDeclarationName::StringLiteral(literal) = &node.id {
                    collector.add(
                        ModuleReferenceKind::DeclaresModule,
                        literal.span,
                        Some(literal.value.to_string()),
                        true,
                        false,
                    );
                }
            }
            AstKind::ImportExpression(node) => {
                collector.add_expression(ModuleReferenceKind::DynamicImport, &node.source);
            }
            AstKind::CallExpression(call) => {
                if !call.optional
                    && matches!(&call.callee, Expression::Identifier(id) if id.name == "require" && id.is_global_reference(parsed.semantic.scoping()))
                    && let Some(argument) = call.arguments.first()
                {
                    match argument {
                        Argument::SpreadElement(spread) => collector.add(
                            ModuleReferenceKind::Require,
                            spread.span,
                            None,
                            false,
                            false,
                        ),
                        argument => {
                            collector.add_expression(
                                ModuleReferenceKind::Require,
                                argument.to_expression(),
                            );
                        }
                    }
                }
            }
            _ => {}
        }
    }
    collector
        .references
        .sort_by_key(|reference| reference.range.start.offset);
    exports.sort_by_key(|export: &ExportFact| export.range.start.offset);
    JavaScriptSourceFacts {
        program_source_type,
        runtime_context: runtime_context(path, program, program_source_type),
        errors: parsed
            .errors
            .iter()
            .map(|error| diagnostic(error, index))
            .collect(),
        module_references: collector.references,
        exports,
        // Top-level statements only, as `hasUncertainTypeOnlyModuleSideEffect`.
        uncertain_type_only_side_effect: program.body.iter().any(|statement| match statement {
            Statement::ImportDeclaration(node) => import_inline_type_only(node),
            Statement::ExportNamedDeclaration(node) => export_inline_type_only(node),
            _ => false,
        }),
    }
}
