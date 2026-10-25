//! Source-order module-link projection.
//!
//! This is the Rust counterpart of `javascriptSemanticProjection.ts`'s
//! module-link collector.  It deliberately returns the contract records
//! instead of adding a second module-link cache to [`SemanticState`].  The
//! caller owns admission and callable resolution through `returns.rs`.

use std::collections::HashMap;

use oxc_ast::ast::ImportOrExportKind;

use crate::javascript::ast::{AstVisitor, Field, Node, NodeKey, NodeKind, NodeSet, traverse};
use crate::javascript::contracts::semantic_ir::SemanticModuleLink;
use crate::javascript::contracts::static_analysis::{
    SourcePoint as ContractSourcePoint, SourceRange as ContractSourceRange,
};
use crate::javascript::resolution::mode::ModuleResolutionMode;

use super::ast_values::{final_object_property, property_name, static_property_key, unwrapped};
use super::commonjs_export_receivers::{
    CommonJsExportReceiverEffect, commonjs_defined_export, commonjs_export_name,
};
use super::projection::callable_id_for_node;
use super::require_origin::require_origin;
use super::state::{BindingIndex, ResolutionMode, SemanticState};
use super::value_types::JsString;

/// Module links plus the state-owned identities needed by callable
/// resolution.  The side vectors are aligned with `links` and preserve the
/// TypeScript `WeakMap` associations without using a second link object.
#[derive(Clone, Debug)]
pub struct CollectedModuleLinks<'a> {
    pub links: Vec<SemanticModuleLink>,
    pub link_bindings: Vec<Option<BindingIndex>>,
    pub default_export_expressions: Vec<Option<Node<'a>>>,
}

/// Collect all static import/export, proven require, and CommonJS export
/// links in the same depth-first order as the TypeScript projection.
pub fn collect_semantic_module_links<'a>(
    state: &'a SemanticState<'a>,
    commonjs_receivers: &HashMap<NodeKey, CommonJsExportReceiverEffect>,
) -> Vec<SemanticModuleLink> {
    collect_semantic_module_links_with_facts(state, commonjs_receivers).links
}

/// Collect links and retain the lexical/default-expression associations that
/// the later callable resolver consumes.
pub fn collect_semantic_module_links_with_facts<'a>(
    state: &SemanticState<'a>,
    commonjs_receivers: &HashMap<NodeKey, CommonJsExportReceiverEffect>,
) -> CollectedModuleLinks<'a> {
    let mut collector = Collector {
        state,
        links: Vec::new(),
        link_bindings: Vec::new(),
        default_export_expressions: Vec::new(),
        linked_require_calls: NodeSet::default(),
        commonjs_receivers,
    };
    let _ = traverse(state.program, state.source, &mut collector, || {
        std::ops::ControlFlow::<()>::Continue(())
    });
    CollectedModuleLinks {
        links: collector.links,
        link_bindings: collector.link_bindings,
        default_export_expressions: collector.default_export_expressions,
    }
}

struct Collector<'s, 'a> {
    state: &'s SemanticState<'a>,
    links: Vec<SemanticModuleLink>,
    link_bindings: Vec<Option<BindingIndex>>,
    default_export_expressions: Vec<Option<Node<'a>>>,
    linked_require_calls: NodeSet,
    commonjs_receivers: &'s HashMap<NodeKey, CommonJsExportReceiverEffect>,
}

impl<'a> AstVisitor<'a> for Collector<'_, 'a> {
    fn enter(&mut self, node: &Node<'a>, _parent: Option<&Node<'a>>, _ancestors: &[Node<'a>]) {
        match node.babel_type() {
            "TSImportEqualsDeclaration" => self.collect_import_equals(*node),
            "ImportDeclaration" => self.collect_import(*node),
            "ExportAllDeclaration" => self.collect_export_all(*node),
            "ExportNamedDeclaration" => self.collect_named_export(*node),
            "ExportDefaultDeclaration" => self.collect_default_export(*node),
            "VariableDeclarator" => self.collect_require(*node),
            "AssignmentExpression" => self.collect_commonjs_assignment(*node),
            "CallExpression" => {
                self.collect_defined_commonjs_export(*node);
                self.collect_unbound_require(*node);
            }
            _ => {}
        }
    }
}

impl<'s, 'a> Collector<'s, 'a> {
    fn push(
        &mut self,
        location_node: Node<'a>,
        reference_node: Node<'a>,
        kind: &str,
        specifier: Option<JsString>,
        imported_name: Option<JsString>,
        local_name: Option<JsString>,
        exported_name: Option<JsString>,
        callable_id: Option<String>,
    ) {
        let binding_name = local_name
            .as_ref()
            .and_then(|name| name.try_to_string().ok());
        let resolution_mode = match kind {
            "import" | "re-export" | "type-import" => {
                Some(to_contract_mode(self.state.static_import_resolution_mode))
            }
            "require" => Some(ModuleResolutionMode::Require),
            _ => None,
        };
        self.links.push(SemanticModuleLink {
            resolution_mode,
            kind: kind.to_owned(),
            specifier,
            imported_name,
            local_name,
            exported_name,
            callable_id,
            location: contract_range(self.state.context.range(&location_node)),
        });
        self.link_bindings.push(
            binding_name
                .as_deref()
                .and_then(|name| self.state.resolve_binding(&reference_node, name)),
        );
        self.default_export_expressions.push(None);
    }

    fn collect_import_equals(&mut self, node: Node<'a>) {
        let Some(specifier) = node
            .field(self.state.source, Field::ModuleReference)
            .and_then(|reference| reference.field(self.state.source, Field::Expression))
            .and_then(|expression| string_value(expression))
        else {
            return;
        };
        let kind = if node.import_kind() == Some("type") {
            "type-import"
        } else {
            "require"
        };
        self.push(
            node,
            node,
            kind,
            Some(specifier),
            None,
            node.field(self.state.source, Field::Id)
                .and_then(|id| id.identifier_name())
                .map(|value| value.to_owned().into()),
            None,
            None,
        );
    }

    fn collect_import(&mut self, node: Node<'a>) {
        let Some(specifier) = node
            .field(self.state.source, Field::Source)
            .and_then(string_value)
        else {
            return;
        };
        let specifiers = node.field_list(self.state.source, Field::Specifiers);
        if specifiers.is_empty() {
            self.push(
                node,
                node,
                if node.import_kind() == Some("type") {
                    "type-import"
                } else {
                    "import"
                },
                Some(specifier),
                None,
                None,
                None,
                None,
            );
            return;
        }
        for specifier in specifiers.into_iter().flatten() {
            let module_specifier = specifier.clone();
            let (imported, local) = match specifier.babel_type() {
                "ImportDefaultSpecifier" => (
                    Some("default".into()),
                    specifier.field(self.state.source, Field::Local),
                ),
                "ImportNamespaceSpecifier" => (
                    Some("*".into()),
                    specifier.field(self.state.source, Field::Local),
                ),
                "ImportSpecifier" => (
                    specifier
                        .field(self.state.source, Field::Imported)
                        .map(|name| property_name(&name)),
                    specifier.field(self.state.source, Field::Local),
                ),
                _ => continue,
            };
            let kind =
                if node.import_kind() == Some("type") || specifier.import_kind() == Some("type") {
                    "type-import"
                } else {
                    "import"
                };
            self.push(
                module_specifier,
                node,
                kind,
                Some(specifier_string(self.state.source, node).into()),
                imported,
                local
                    .and_then(|local| local.identifier_name())
                    .map(JsString::from),
                None,
                None,
            );
        }
    }

    fn collect_export_all(&mut self, node: Node<'a>) {
        let Some(specifier) = export_source(self.state.source, node) else {
            return;
        };
        self.push(
            node,
            node,
            if export_type_only(node) {
                "type-import"
            } else {
                "re-export"
            },
            Some(specifier),
            Some("*".into()),
            None,
            Some("*".into()),
            None,
        );
    }

    fn collect_named_export(&mut self, node: Node<'a>) {
        if let Some(declaration) = export_declaration(self.state.source, node) {
            for (name, callable_id) in declaration_names(self.state, declaration) {
                self.push(
                    declaration,
                    node,
                    if export_type_only(node) || declaration_type_only(declaration) {
                        "type-import"
                    } else {
                        "export"
                    },
                    None,
                    None,
                    Some(name.clone().into()),
                    Some(name.into()),
                    callable_id,
                );
            }
        }
        let source = export_source(self.state.source, node);
        for specifier in export_specifiers(self.state.source, node) {
            let is_namespace = specifier.babel_type() == "ExportNamespaceSpecifier";
            if !is_namespace && specifier.babel_type() != "ExportSpecifier" {
                continue;
            }
            let imported = if is_namespace {
                Some("*".into())
            } else {
                specifier
                    .field(self.state.source, Field::Local)
                    .map(|local| property_name(&local))
            };
            let exported = export_specifier_exported_name(self.state.source, specifier);
            let local = if source.is_none() && !is_namespace {
                imported.clone()
            } else {
                None
            };
            let kind = if export_type_only(node) || export_specifier_type_only(specifier) {
                "type-import"
            } else if source.is_some() {
                "re-export"
            } else {
                "export"
            };
            self.push(
                specifier,
                node,
                kind,
                source.clone(),
                imported,
                local,
                exported,
                None,
            );
        }
    }

    fn collect_default_export(&mut self, node: Node<'a>) {
        let declaration = node.field(self.state.source, Field::Declaration);
        let local_name = declaration
            .map(|declaration| unwrapped(self.state.source, declaration))
            .and_then(|declaration| {
                declaration.identifier_name().or_else(|| {
                    declaration
                        .field(self.state.source, Field::Id)
                        .and_then(|id| id.identifier_name())
                })
            })
            .map(|value| value.to_owned().into());
        let callable_id = declaration
            .and_then(|declaration| callable_id_for_node(&self.state.context, &declaration));
        let index = self.links.len();
        self.push(
            node,
            node,
            "export",
            None,
            None,
            local_name,
            Some("default".into()),
            callable_id,
        );
        if let Some(declaration) = declaration
            && !matches!(
                declaration.babel_type(),
                "FunctionDeclaration" | "ClassDeclaration" | "TSInterfaceDeclaration"
            )
        {
            self.default_export_expressions[index] = Some(declaration);
        }
    }

    fn collect_require(&mut self, node: Node<'a>) {
        let Some(origin) = require_origin(self.state, node.field(self.state.source, Field::Init))
        else {
            return;
        };
        let pattern = node.field(self.state.source, Field::Id);
        let bindings = pattern
            .map(|pattern| {
                pattern_bindings(self.state.source, pattern, &origin.origin.imported_path)
            })
            .unwrap_or_default();
        let has_bindings = !bindings.is_empty();
        for (imported, local) in bindings {
            self.push(
                node,
                node,
                "require",
                Some(origin.origin.specifier.clone()),
                Some(imported),
                Some(local.into()),
                None,
                None,
            );
        }
        if has_bindings {
            self.linked_require_calls.insert(origin.call.key());
        }
    }

    fn collect_unbound_require(&mut self, node: Node<'a>) {
        if self.linked_require_calls.contains(&node.key()) {
            return;
        }
        let Some(origin) = require_origin(self.state, Some(node)) else {
            return;
        };
        self.push(
            node,
            node,
            "require",
            Some(origin.origin.specifier),
            None,
            None,
            None,
            None,
        );
        self.linked_require_calls.insert(origin.call.key());
    }

    fn collect_commonjs_assignment(&mut self, node: Node<'a>) {
        let Some(left) = node.field(self.state.source, Field::Left) else {
            return;
        };
        let Some(exported_name) = commonjs_export_name(self.state, left) else {
            return;
        };
        if self.commonjs_receivers.get(&node.key()) == Some(&CommonJsExportReceiverEffect::Detached)
        {
            return;
        }
        let value = (node.operator() == Some("=")
            && self.commonjs_receivers.get(&node.key())
                != Some(&CommonJsExportReceiverEffect::Uncertain))
        .then(|| node.field(self.state.source, Field::Right))
        .flatten();
        self.add_commonjs_export(node, exported_name, value);
    }

    fn collect_defined_commonjs_export(&mut self, node: Node<'a>) {
        let Some(defined) = commonjs_defined_export(self.state, node) else {
            return;
        };
        if self.commonjs_receivers.get(&node.key()) == Some(&CommonJsExportReceiverEffect::Detached)
        {
            return;
        }
        let value = if self.commonjs_receivers.get(&node.key())
            != Some(&CommonJsExportReceiverEffect::Uncertain)
        {
            let descriptor = unwrapped(self.state.source, defined.descriptor);
            (descriptor.babel_type() == "ObjectExpression")
                .then(|| final_object_property(self.state.source, descriptor, "value"))
                .flatten()
        } else {
            None
        };
        self.add_commonjs_export(node, defined.exported_name, value);
    }

    fn add_commonjs_export(
        &mut self,
        node: Node<'a>,
        exported_name: JsString,
        value: Option<Node<'a>>,
    ) {
        let value = value
            .map(|value| unwrapped(self.state.source, value))
            .map(|value| rightmost_assignment(self.state.source, value));
        let origin = value.and_then(|value| require_origin(self.state, Some(value)));
        self.push(
            node,
            node,
            "commonjs-export",
            origin
                .as_ref()
                .map(|origin| origin.origin.specifier.clone()),
            origin
                .as_ref()
                .and_then(|origin| origin.origin.imported_path.last().cloned()),
            value
                .and_then(|value| value.identifier_name())
                .map(|value| value.to_owned().into()),
            Some(exported_name),
            value.and_then(|value| callable_id_for_node(&self.state.context, &value)),
        );
        if let Some(origin) = origin {
            self.linked_require_calls.insert(origin.call.key());
        }
    }
}

fn to_contract_mode(mode: ResolutionMode) -> ModuleResolutionMode {
    match mode {
        ResolutionMode::Import => ModuleResolutionMode::Import,
        ResolutionMode::Require => ModuleResolutionMode::Require,
        ResolutionMode::CompilerDependent => ModuleResolutionMode::CompilerDependent,
    }
}

fn contract_range(range: crate::javascript::parser::SourceRange) -> ContractSourceRange {
    ContractSourceRange {
        start: ContractSourcePoint {
            line: range.start.line,
            column: range.start.column,
        },
        end: ContractSourcePoint {
            line: range.end.line,
            column: range.end.column,
        },
    }
}

fn specifier_string<'a>(source: &'a str, import: Node<'a>) -> JsString {
    import
        .field(source, Field::Source)
        .and_then(string_value)
        .unwrap_or_default()
}

fn export_source<'a>(source: &'a str, node: Node<'a>) -> Option<JsString> {
    node.children(source)
        .into_iter()
        .find(|child| child.babel_type() == "StringLiteral")
        .and_then(string_value)
}

fn string_value(node: Node<'_>) -> Option<JsString> {
    node.string_value_units().map(JsString::from_utf16)
}

fn export_declaration<'a>(source: &'a str, node: Node<'a>) -> Option<Node<'a>> {
    // `ExportNamedDeclaration` owns its declaration in the AST field.  Read
    // that field first so TypeScript declarations (notably `export
    // interface`) are retained even when the generic child projection omits
    // declaration nodes from its synthesized wrapper.
    if let Some(declaration) = node.field(source, Field::Declaration)
        && matches!(
            declaration.babel_type(),
            "FunctionDeclaration"
                | "ClassDeclaration"
                | "VariableDeclaration"
                | "TSInterfaceDeclaration"
                | "TSTypeAliasDeclaration"
                | "TSDeclareFunction"
                | "TSImportEqualsDeclaration"
        )
    {
        return Some(declaration);
    }

    node.children(source).into_iter().find(|child| {
        matches!(
            child.babel_type(),
            "FunctionDeclaration"
                | "ClassDeclaration"
                | "VariableDeclaration"
                | "TSInterfaceDeclaration"
                | "TSTypeAliasDeclaration"
                | "TSDeclareFunction"
                | "TSImportEqualsDeclaration"
        )
    })
}

fn export_specifiers<'a>(source: &'a str, node: Node<'a>) -> Vec<Node<'a>> {
    node.children(source)
        .into_iter()
        .filter(|child| {
            matches!(
                child.babel_type(),
                "ExportSpecifier" | "ExportNamespaceSpecifier"
            )
        })
        .collect()
}

fn export_specifier_exported_name<'a>(source: &'a str, node: Node<'a>) -> Option<JsString> {
    if node.babel_type() == "ExportNamespaceSpecifier" {
        return node
            .children(source)
            .into_iter()
            .find(|child| {
                matches!(
                    child.babel_type(),
                    "Identifier" | "IdentifierName" | "IdentifierReference" | "StringLiteral"
                )
            })
            .map(|child| property_name(&child));
    }
    node.field(source, Field::Exported)
        .map(|name| property_name(&name))
}

fn declaration_names<'a>(
    state: &SemanticState<'a>,
    declaration: Node<'a>,
) -> Vec<(String, Option<String>)> {
    let source = state.source;
    match declaration.babel_type() {
        "FunctionDeclaration" | "ClassDeclaration" => declaration
            .field(source, Field::Id)
            .and_then(|id| id.identifier_name())
            .map(|name| {
                (
                    name.to_owned(),
                    callable_id_for_node(&state.context, &declaration),
                )
            })
            .into_iter()
            .collect(),
        "TSInterfaceDeclaration"
        | "TSTypeAliasDeclaration"
        | "TSDeclareFunction"
        | "VariableDeclaration" => {
            if declaration.babel_type() != "VariableDeclaration" {
                return declaration
                    .field(state.source, Field::Id)
                    .and_then(|id| id.identifier_name())
                    .map(|name| (name.to_owned(), None))
                    .into_iter()
                    .collect();
            }
            let mut names = Vec::new();
            for declarator in declaration
                .field_list(source, Field::Declarations)
                .into_iter()
                .flatten()
            {
                let callable = declarator
                    .field(source, Field::Init)
                    .and_then(|init| callable_id_for_node(&state.context, &init));
                if let Some(id) = declarator.field(source, Field::Id) {
                    let direct_name = id.identifier_name().map(str::to_owned);
                    names.extend(binding_names(source, id).into_iter().map(|name| {
                        let callable_id = (direct_name.as_deref() == Some(name.as_str()))
                            .then(|| callable.clone())
                            .flatten();
                        (name, callable_id)
                    }));
                }
            }
            names
        }
        "TSImportEqualsDeclaration" => declaration
            .field(state.source, Field::Id)
            .and_then(|id| id.identifier_name())
            .filter(|_| {
                declaration
                    .field(state.source, Field::ModuleReference)
                    .and_then(|reference| reference.field(state.source, Field::Expression))
                    .and_then(string_value)
                    .is_some()
            })
            .map(|name| (name.to_owned(), None))
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

fn export_type_only(node: Node<'_>) -> bool {
    match node.kind() {
        NodeKind::ExportNamedDeclaration(declaration) => {
            declaration.export_kind == ImportOrExportKind::Type
        }
        NodeKind::ExportAllDeclaration(declaration) => {
            declaration.export_kind == ImportOrExportKind::Type
        }
        _ => false,
    }
}

fn export_specifier_type_only(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        NodeKind::ExportSpecifier(specifier)
            if specifier.export_kind == ImportOrExportKind::Type
    )
}

fn declaration_type_only(node: Node<'_>) -> bool {
    matches!(
        node.babel_type(),
        "TSInterfaceDeclaration" | "TSTypeAliasDeclaration" | "TSDeclareFunction"
    )
}

fn rightmost_assignment<'a>(source: &'a str, mut value: Node<'a>) -> Node<'a> {
    while value.babel_type() == "AssignmentExpression" && value.operator() == Some("=") {
        let Some(right) = value.field(source, Field::Right) else {
            break;
        };
        value = right;
    }
    value
}

fn binding_names<'a>(source: &'a str, node: Node<'a>) -> Vec<String> {
    if let Some(name) = node.identifier_name() {
        return vec![name.to_owned()];
    }
    node.children(source)
        .into_iter()
        .flat_map(|child| binding_names(source, child))
        .collect()
}

fn pattern_bindings<'a>(
    source: &'a str,
    pattern: Node<'a>,
    path: &[JsString],
) -> Vec<(JsString, String)> {
    if let Some(name) = pattern.identifier_name() {
        return vec![(
            path.last().cloned().unwrap_or_else(|| "*".into()),
            name.to_owned(),
        )];
    }
    match pattern.babel_type() {
        "AssignmentPattern" | "AssignmentTargetWithDefault" | "TSParameterProperty" => pattern
            .field(source, Field::Left)
            .or_else(|| pattern.field(source, Field::Param))
            .map(|left| pattern_bindings(source, left, path))
            .unwrap_or_default(),
        "ObjectPattern" => pattern
            .field_list(source, Field::Properties)
            .into_iter()
            .flatten()
            .flat_map(|property| {
                if property.babel_type() == "RestElement" {
                    return Vec::new();
                }
                let Some(key) = property
                    .field(source, Field::Key)
                    .and_then(|key| static_property_key(source, key, property.computed()))
                else {
                    return Vec::new();
                };
                property
                    .field(source, Field::Value)
                    .map(|value| pattern_bindings(source, value, &[path, &[key]].concat()))
                    .unwrap_or_default()
            })
            .collect(),
        "ArrayPattern" => pattern
            .field_list(source, Field::Elements)
            .into_iter()
            .enumerate()
            .filter_map(|(index, element)| element.map(|element| (index, element)))
            .flat_map(|(index, element)| {
                pattern_bindings(
                    source,
                    element,
                    &[path, &[index.to_string().into()]].concat(),
                )
            })
            .collect(),
        _ => Vec::new(),
    }
}
