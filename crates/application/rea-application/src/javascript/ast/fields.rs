//! Named Babel fields of a [`Node`] (`node.id`, `node.params`, `node.computed`).
//!
//! Analysis code reads Babel fields by name; this is the one place that maps
//! those names onto oxc data. Every node returned here is built by the same
//! constructor [`Node::children`] uses, so it has the same [`NodeKey`],
//! span and `parenthesized` flag as the node the traversal enters (checked
//! by `fields_are_children` in the tests). Fields not listed for a node type
//! return `None`/empty; add them here, not in consumers.
//!
//! [`NodeKey`]: super::NodeKey

use oxc_ast::ast::*;
use oxc_span::Span;
use rea_core::JsString;
use smallvec::{SmallVec, smallvec};

use super::children::{
    argument_node, assignment_target_node, binding_identifier, binding_pattern, declaration_node,
    default_parameter, expression_node, for_left_node, maybe_default_node, module_export_name_node,
    params_nodes, plain_parameter, property_key, simple_target_node, statement_node,
};
use super::node::{Node, NodeKind as K, class, spine};

macro_rules! node {
    ($variant:ident, $value:expr) => {{
        let value = $value;
        Node::new(K::$variant(value), value.span, value.node_id())
    }};
}

type FieldValues<'a> = SmallVec<[Option<Node<'a>>; 1]>;

/// A Babel field name with a node or node-list value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Alternate,
    Argument,
    Arguments,
    Block,
    Body,
    Callee,
    Cases,
    Consequent,
    Declaration,
    Declarations,
    Discriminant,
    Elements,
    Expression,
    Expressions,
    Exported,
    Finalizer,
    Handler,
    Id,
    Imported,
    Init,
    Key,
    Left,
    Local,
    ModuleReference,
    Object,
    Param,
    Parameter,
    Params,
    Properties,
    Property,
    Quasis,
    Right,
    Source,
    Specifiers,
    SuperClass,
    Test,
    Update,
    Value,
}

impl<'a> Node<'a> {
    /// Whether a program or function body has a direct `"use strict"` directive.
    pub fn has_use_strict_directive(&self) -> bool {
        match self.kind() {
            K::Program(it) => it
                .directives
                .iter()
                .any(|directive| directive.expression.value == "use strict"),
            K::FunctionBody(it) => it
                .directives
                .iter()
                .any(|directive| directive.expression.value == "use strict"),
            _ => false,
        }
    }

    /// A single-node Babel field (`node[field]`), `None` when absent.
    pub fn field(&self, source: &'a str, field: Field) -> Option<Node<'a>> {
        self.field_values(source, field)
            .into_iter()
            .next()
            .flatten()
    }

    /// A Babel field as a list. Array fields (`elements`) keep holes as
    /// `None`; single-node fields yield at most one entry.
    pub fn field_list(&self, source: &'a str, field: Field) -> Vec<Option<Node<'a>>> {
        self.field_values(source, field).into_vec()
    }

    /// Build one canonical field representation for both scalar and list
    /// access. Single-node fields stay inline; larger fields use SmallVec's
    /// heap-backed representation without an intermediate result copy.
    #[allow(clippy::too_many_lines)]
    fn field_values(&self, source: &'a str, field: Field) -> FieldValues<'a> {
        use Field as F;
        let one = |node: Node<'a>| smallvec![Some(node)];
        let opt_expr = |expression: Option<&'a Expression<'a>>| {
            expression
                .map(expression_node)
                .into_iter()
                .map(Some)
                .collect()
        };
        let all = |nodes: Vec<Node<'a>>| SmallVec::from_vec(nodes.into_iter().map(Some).collect());
        match (self.kind(), field) {
            (K::PrivateName(it), F::Id) => smallvec![Some(Node::synthesized(
                K::PrivateNameId(it),
                Span::new(it.span.start + 1, it.span.end),
                it.node_id(),
            ))],
            (K::Program(it), F::Body) => all(it.body.iter().map(statement_node).collect()),
            (K::FunctionBody(it), F::Body) => {
                all(it.statements.iter().map(statement_node).collect())
            }
            (K::BlockStatement(it), F::Body) => all(it.body.iter().map(statement_node).collect()),
            (K::StaticBlock(it), F::Body) => all(it.body.iter().map(statement_node).collect()),
            (K::ExpressionStatement(it), F::Expression) => one(expression_node(&it.expression)),
            (K::IfStatement(it), F::Test) => one(expression_node(&it.test)),
            (K::IfStatement(it), F::Consequent) => one(statement_node(&it.consequent)),
            (K::IfStatement(it), F::Alternate) => it
                .alternate
                .iter()
                .map(|s| Some(statement_node(s)))
                .collect(),
            (K::DoWhileStatement(it), F::Body) => one(statement_node(&it.body)),
            (K::DoWhileStatement(it), F::Test) => one(expression_node(&it.test)),
            (K::WhileStatement(it), F::Test) => one(expression_node(&it.test)),
            (K::WhileStatement(it), F::Body) => one(statement_node(&it.body)),
            (K::ForStatement(it), F::Init) => match &it.init {
                Some(ForStatementInit::VariableDeclaration(declaration)) => {
                    one(node!(VariableDeclaration, &**declaration))
                }
                Some(init) => one(expression_node(init.to_expression())),
                None => SmallVec::new(),
            },
            (K::ForStatement(it), F::Test) => opt_expr(it.test.as_ref()),
            (K::ForStatement(it), F::Update) => opt_expr(it.update.as_ref()),
            (K::ForStatement(it), F::Body) => one(statement_node(&it.body)),
            (K::ForInStatement(it), F::Left) => one(for_left_node(source, &it.left)),
            (K::ForInStatement(it), F::Right) => one(expression_node(&it.right)),
            (K::ForInStatement(it), F::Body) => one(statement_node(&it.body)),
            (K::ForOfStatement(it), F::Left) => one(for_left_node(source, &it.left)),
            (K::ForOfStatement(it), F::Right) => one(expression_node(&it.right)),
            (K::ForOfStatement(it), F::Body) => one(statement_node(&it.body)),
            (K::ReturnStatement(it), F::Argument) => opt_expr(it.argument.as_ref()),
            (K::ThrowStatement(it), F::Argument) => one(expression_node(&it.argument)),
            (K::WithStatement(it), F::Object) => one(expression_node(&it.object)),
            (K::WithStatement(it), F::Body) => one(statement_node(&it.body)),
            (K::SwitchStatement(it), F::Discriminant) => one(expression_node(&it.discriminant)),
            (K::SwitchStatement(it), F::Cases) => all(it
                .cases
                .iter()
                .map(|case| node!(SwitchCase, case))
                .collect()),
            (K::SwitchCase(it), F::Test) => opt_expr(it.test.as_ref()),
            (K::SwitchCase(it), F::Consequent) => {
                all(it.consequent.iter().map(statement_node).collect())
            }
            (K::LabeledStatement(it), F::Body) => one(statement_node(&it.body)),
            (K::TryStatement(it), F::Block) => one(node!(BlockStatement, &*it.block)),
            (K::TryStatement(it), F::Handler) => it
                .handler
                .iter()
                .map(|handler| Some(node!(CatchClause, &**handler)))
                .collect(),
            (K::TryStatement(it), F::Finalizer) => it
                .finalizer
                .iter()
                .map(|finalizer| Some(node!(BlockStatement, &**finalizer)))
                .collect(),
            (K::CatchClause(it), F::Param) => it
                .param
                .iter()
                .map(|param| {
                    Some(binding_pattern(
                        &param.pattern,
                        param.type_annotation.as_deref(),
                        &[],
                    ))
                })
                .collect(),
            (K::CatchClause(it), F::Body) => one(node!(BlockStatement, &*it.body)),
            (K::VariableDeclaration(it), F::Declarations) => all(it
                .declarations
                .iter()
                .map(|declarator| node!(VariableDeclarator, declarator))
                .collect()),
            (K::VariableDeclarator(it), F::Id) => {
                one(binding_pattern(&it.id, it.type_annotation.as_deref(), &[]))
            }
            (K::VariableDeclarator(it), F::Init) => opt_expr(it.init.as_ref()),

            (K::TemplateLiteral(it), F::Quasis) => all(it
                .quasis
                .iter()
                .map(|quasi| node!(TemplateElement, quasi))
                .collect()),
            (K::TemplateLiteral(it), F::Expressions) => {
                all(it.expressions.iter().map(expression_node).collect())
            }
            (K::ArrayExpression(it), F::Elements) => it
                .elements
                .iter()
                .map(|element| match element {
                    ArrayExpressionElement::SpreadElement(spread) => {
                        Some(node!(SpreadElement, &**spread))
                    }
                    ArrayExpressionElement::Elision(_) => None,
                    _ => Some(expression_node(element.to_expression())),
                })
                .collect(),
            (K::ObjectExpression(it), F::Properties) => all(it
                .properties
                .iter()
                .map(|property| match property {
                    ObjectPropertyKind::ObjectProperty(property) => {
                        if property.method || property.kind != PropertyKind::Init {
                            node!(ObjectMethod, &**property)
                        } else {
                            node!(ObjectProperty, &**property)
                        }
                    }
                    ObjectPropertyKind::SpreadProperty(spread) => node!(SpreadElement, &**spread),
                })
                .collect()),
            (K::ObjectProperty(it), F::Key) => one(property_key(&it.key)),
            (K::ObjectProperty(it), F::Value) => one(expression_node(&it.value)),
            (K::ObjectMethod(it), F::Key) => one(property_key(&it.key)),
            (K::SpreadElement(it), F::Argument) => one(expression_node(&it.argument)),
            (K::Member { member, chain }, F::Object) => {
                let below = chain.saturating_sub(u32::from(member.optional()));
                one(spine(member.object(), below))
            }
            (K::Member { member, .. }, F::Property) => one(match member {
                MemberExpression::ComputedMemberExpression(it) => expression_node(&it.expression),
                MemberExpression::StaticMemberExpression(it) => {
                    node!(IdentifierName, &it.property)
                }
                MemberExpression::PrivateFieldExpression(it) => node!(PrivateName, &it.field),
            }),
            // A qualified `implements` name is a Babel `MemberExpression`;
            // its child expansion (object, property) is the owner.
            (K::TSQualifiedNameMember(_), F::Object | F::Property) => {
                let children = self.children(source);
                let index = usize::from(field == F::Property);
                children.get(index).copied().map(Some).into_iter().collect()
            }
            (K::Call { call, chain }, F::Callee) => {
                let below = chain.saturating_sub(u32::from(call.optional));
                one(spine(&call.callee, below))
            }
            (K::Call { call, .. }, F::Arguments) => {
                all(call.arguments.iter().map(argument_node).collect())
            }
            (K::NewExpression(it), F::Callee) => one(expression_node(&it.callee)),
            (K::NewExpression(it), F::Arguments) => {
                all(it.arguments.iter().map(argument_node).collect())
            }
            (K::ImportExpression(it), F::Source) => one(expression_node(&it.source)),
            (K::UpdateExpression(it), F::Argument) => one(simple_target_node(source, &it.argument)),
            (K::UnaryExpression(it), F::Argument) => one(expression_node(&it.argument)),
            (K::AwaitExpression(it), F::Argument) => one(expression_node(&it.argument)),
            (K::YieldExpression(it), F::Argument) => opt_expr(it.argument.as_ref()),
            (K::BinaryExpression(it), F::Left) => one(expression_node(&it.left)),
            (K::BinaryExpression(it), F::Right) => one(expression_node(&it.right)),
            (K::PrivateInExpression(it), F::Left) => one(node!(PrivateName, &it.left)),
            (K::PrivateInExpression(it), F::Right) => one(expression_node(&it.right)),
            (K::LogicalExpression(it), F::Left) => one(expression_node(&it.left)),
            (K::LogicalExpression(it), F::Right) => one(expression_node(&it.right)),
            (K::AssignmentExpression(it), F::Left) => one(assignment_target_node(source, &it.left)),
            (K::AssignmentExpression(it), F::Right) => one(expression_node(&it.right)),
            (K::ConditionalExpression(it), F::Test) => one(expression_node(&it.test)),
            (K::ConditionalExpression(it), F::Consequent) => one(expression_node(&it.consequent)),
            (K::ConditionalExpression(it), F::Alternate) => one(expression_node(&it.alternate)),
            (K::SequenceExpression(it), F::Expressions) => {
                all(it.expressions.iter().map(expression_node).collect())
            }

            (K::Function(it), F::Id) => it
                .id
                .iter()
                .map(|id| Some(binding_identifier(id, None, &[])))
                .collect(),
            (K::Function(it), F::Params) => {
                all(params_nodes(source, it.this_param.as_deref(), &it.params))
            }
            (K::Function(it), F::Body) => it
                .body
                .iter()
                .map(|body| Some(node!(FunctionBody, &**body)))
                .collect(),
            (K::ObjectMethod(_) | K::ClassMethod(_), F::Params | F::Body) => {
                match self.function() {
                    Some(function) if field == F::Params => all(params_nodes(
                        source,
                        function.this_param.as_deref(),
                        &function.params,
                    )),
                    Some(function) => function
                        .body
                        .iter()
                        .map(|body| Some(node!(FunctionBody, &**body)))
                        .collect(),
                    None => SmallVec::new(),
                }
            }
            (K::ArrowFunctionExpression(it), F::Params) => {
                all(params_nodes(source, None, &it.params))
            }
            (K::ArrowFunctionExpression(it), F::Body) => {
                match (it.expression, it.body.statements.first()) {
                    (true, Some(Statement::ExpressionStatement(statement))) => {
                        one(expression_node(&statement.expression))
                    }
                    _ => one(node!(FunctionBody, &*it.body)),
                }
            }
            (K::Class(it), F::Id) => it
                .id
                .iter()
                .map(|id| Some(binding_identifier(id, None, &[])))
                .collect(),
            (K::Class(it), F::SuperClass) => opt_expr(it.super_class.as_ref()),
            (K::Class(it), F::Body) => one(node!(ClassBody, &*it.body)),
            (K::ClassBody(it), F::Body) => all(it
                .body
                .iter()
                .map(|element| match element {
                    ClassElement::StaticBlock(it) => node!(StaticBlock, &**it),
                    ClassElement::MethodDefinition(it) => node!(ClassMethod, &**it),
                    ClassElement::PropertyDefinition(it) => node!(ClassProperty, &**it),
                    ClassElement::AccessorProperty(it) => node!(ClassAccessorProperty, &**it),
                    ClassElement::TSIndexSignature(it) => node!(TSIndexSignature, &**it),
                })
                .collect()),
            (K::ClassMethod(it), F::Key) => one(property_key(&it.key)),
            (K::ClassProperty(it), F::Key) => one(property_key(&it.key)),
            (K::ClassProperty(it), F::Value) => opt_expr(it.value.as_ref()),
            (K::ClassAccessorProperty(it), F::Key) => one(property_key(&it.key)),
            (K::ClassAccessorProperty(it), F::Value) => opt_expr(it.value.as_ref()),

            (K::ObjectPattern { pattern, .. }, F::Properties) => {
                let mut out: FieldValues<'a> = pattern
                    .properties
                    .iter()
                    .map(|property| Some(node!(BindingProperty, property)))
                    .collect();
                if let Some(rest) = &pattern.rest {
                    out.push(Some(node!(BindingRestElement, &**rest)));
                }
                out
            }
            (K::ArrayPattern { pattern, .. }, F::Elements) => {
                let mut out: FieldValues<'a> = pattern
                    .elements
                    .iter()
                    .map(|element| element.as_ref().map(|it| binding_pattern(it, None, &[])))
                    .collect();
                if let Some(rest) = &pattern.rest {
                    out.push(Some(node!(BindingRestElement, &**rest)));
                }
                out
            }
            (K::AssignmentPattern(it), F::Left) => one(binding_pattern(&it.left, None, &[])),
            (K::AssignmentPattern(it), F::Right) => one(expression_node(&it.right)),
            (K::DefaultParameter(it), F::Left) => one(binding_pattern(
                &it.pattern,
                it.type_annotation.as_deref(),
                &[],
            )),
            (K::DefaultParameter(it), F::Right) => opt_expr(it.initializer.as_deref()),
            (K::ParameterProperty(it), F::Parameter) => one(if it.initializer.is_some() {
                default_parameter(it)
            } else {
                plain_parameter(source, it, &[])
            }),
            (K::BindingProperty(it), F::Key) => one(property_key(&it.key)),
            (K::BindingProperty(it), F::Value) => one(binding_pattern(&it.value, None, &[])),
            (K::BindingRestElement(it), F::Argument) => {
                one(binding_pattern(&it.argument, None, &[]))
            }
            (K::RestParameter(it), F::Argument) => {
                one(binding_pattern(&it.rest.argument, None, &[]))
            }
            (K::ArrayAssignmentTarget(it), F::Elements) => {
                let mut out: FieldValues<'a> = it
                    .elements
                    .iter()
                    .map(|element| element.as_ref().map(|it| maybe_default_node(source, it)))
                    .collect();
                if let Some(rest) = &it.rest {
                    out.push(Some(node!(AssignmentTargetRest, &**rest)));
                }
                out
            }
            (K::ObjectAssignmentTarget(it), F::Properties) => {
                let mut out: FieldValues<'a> = it
                    .properties
                    .iter()
                    .map(|property| {
                        Some(match property {
                            AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(it) => {
                                node!(AssignmentTargetPropertyIdentifier, &**it)
                            }
                            AssignmentTargetProperty::AssignmentTargetPropertyProperty(it) => {
                                node!(AssignmentTargetPropertyProperty, &**it)
                            }
                        })
                    })
                    .collect();
                if let Some(rest) = &it.rest {
                    out.push(Some(node!(AssignmentTargetRest, &**rest)));
                }
                out
            }
            (K::AssignmentTargetRest(it), F::Argument) => {
                one(assignment_target_node(source, &it.target))
            }
            (K::AssignmentTargetWithDefault(it), F::Left) => {
                one(assignment_target_node(source, &it.binding))
            }
            (K::AssignmentTargetWithDefault(it), F::Right) => one(expression_node(&it.init)),
            (K::AssignmentTargetPropertyIdentifier(it), F::Key) => one(Node::synthesized(
                K::ShorthandTargetKey(&it.binding),
                it.binding.span,
                it.binding.node_id(),
            )),
            (K::AssignmentTargetPropertyIdentifier(it), F::Value) => one(if it.init.is_some() {
                Node::synthesized(K::ShorthandTargetDefault(it), it.span, it.node_id())
            } else {
                node!(IdentifierReference, &it.binding)
            }),
            (K::ShorthandTargetDefault(it), F::Left) => {
                one(node!(IdentifierReference, &it.binding))
            }
            (K::ShorthandTargetDefault(it), F::Right) => opt_expr(it.init.as_ref()),
            (K::AssignmentTargetPropertyProperty(it), F::Key) => one(property_key(&it.name)),
            (K::AssignmentTargetPropertyProperty(it), F::Value) => {
                one(maybe_default_node(source, &it.binding))
            }

            (K::ImportDeclaration(it), F::Specifiers) => all(it
                .specifiers
                .iter()
                .flatten()
                .map(|specifier| match specifier {
                    ImportDeclarationSpecifier::ImportSpecifier(it) => {
                        node!(ImportSpecifier, &**it)
                    }
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(it) => {
                        node!(ImportDefaultSpecifier, &**it)
                    }
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(it) => {
                        node!(ImportNamespaceSpecifier, &**it)
                    }
                })
                .collect()),
            (K::ImportDeclaration(it), F::Source) => one(node!(StringLiteral, &it.source)),
            // Re-export source fields are consumed by the static relationship
            // collector in the same way as import sources.  Keep these
            // producer mappings here so consumers do not reinterpret Oxc's
            // export nodes or scan source text a second time.
            (K::ExportNamedDeclaration(it), F::Declaration) => it
                .declaration
                .as_ref()
                .map(|declaration| one(declaration_node(declaration)))
                .unwrap_or_default(),
            (K::ExportNamedDeclaration(it), F::Source) => it
                .source
                .as_ref()
                .map(|source| one(node!(StringLiteral, source)))
                .unwrap_or_default(),
            (K::ExportAllDeclaration(it), F::Source) => one(node!(StringLiteral, &it.source)),
            (K::ImportSpecifier(it), F::Imported) => one(module_export_name_node(&it.imported)),
            (K::ImportSpecifier(it), F::Local) => one(binding_identifier(&it.local, None, &[])),
            (K::ImportDefaultSpecifier(it), F::Local) => {
                one(binding_identifier(&it.local, None, &[]))
            }
            (K::ImportNamespaceSpecifier(it), F::Local) => {
                one(binding_identifier(&it.local, None, &[]))
            }
            (K::ExportSpecifier(it), F::Local) => one(module_export_name_node(&it.local)),
            (K::ExportSpecifier(it), F::Exported) => one(module_export_name_node(&it.exported)),
            (K::ExportDefaultDeclaration(it), F::Declaration) => match &it.declaration {
                ExportDefaultDeclarationKind::FunctionDeclaration(it) => {
                    one(node!(Function, &**it))
                }
                ExportDefaultDeclarationKind::ClassDeclaration(it) => one(class(it)),
                ExportDefaultDeclarationKind::TSInterfaceDeclaration(_) => SmallVec::new(),
                declaration => one(expression_node(declaration.to_expression())),
            },
            (K::TSInterfaceDeclaration(it), F::Id) => one(binding_identifier(&it.id, None, &[])),
            (K::TSTypeAliasDeclaration(it), F::Id) => one(binding_identifier(&it.id, None, &[])),
            (K::TSImportEqualsDeclaration(it), F::Id) => one(binding_identifier(&it.id, None, &[])),
            (K::TSImportEqualsDeclaration(it), F::ModuleReference) => {
                one(match &it.module_reference {
                    TSModuleReference::ExternalModuleReference(it) => {
                        node!(TSExternalModuleReference, &**it)
                    }
                    TSModuleReference::IdentifierReference(it) => node!(IdentifierReference, &**it),
                    TSModuleReference::QualifiedName(it) => node!(TSQualifiedName, &**it),
                })
            }
            (K::TSExternalModuleReference(it), F::Expression) => {
                one(node!(StringLiteral, &it.expression))
            }
            (K::TSAsExpression(it), F::Expression) => one(expression_node(&it.expression)),
            (K::TSSatisfiesExpression(it), F::Expression) => one(expression_node(&it.expression)),
            (K::TSTypeAssertion(it), F::Expression) => one(expression_node(&it.expression)),
            (K::TSNonNullExpression { expression, chain }, F::Expression) => {
                one(spine(&expression.expression, chain))
            }
            (K::TSInstantiationExpression(it), F::Expression) => {
                one(expression_node(&it.expression))
            }
            (K::TSExportAssignment(it), F::Expression) => one(expression_node(&it.expression)),
            (K::Decorator(it), F::Expression) => one(expression_node(&it.expression)),
            _ => SmallVec::new(),
        }
    }

    /// Babel `name` of an `Identifier` view; `None` for other node types.
    pub fn identifier_name(&self) -> Option<&'a str> {
        Some(match self.kind() {
            K::IdentifierName(it) => it.name.as_str(),
            K::IdentifierReference(it) | K::ShorthandTargetKey(it) => it.name.as_str(),
            K::LabelIdentifier(it) => it.name.as_str(),
            K::BindingIdentifier { id, .. } => id.name.as_str(),
            K::ThisParameter(_) => "this",
            K::IndexSignatureName(it) => it.name.as_str(),
            K::PrivateNameId(it) => it.name.as_str(),
            K::TSGlobalName(_) => "global",
            _ => return None,
        })
    }

    /// Babel `computed` (members, properties, methods, class members).
    pub fn computed(&self) -> bool {
        match self.kind() {
            K::Member { member, .. } => {
                matches!(member, MemberExpression::ComputedMemberExpression(_))
            }
            K::ObjectProperty(it) | K::ObjectMethod(it) => it.computed,
            K::ClassMethod(it) => it.computed,
            K::ClassProperty(it) => it.computed,
            K::ClassAccessorProperty(it) => it.computed,
            K::BindingProperty(it) => it.computed,
            K::AssignmentTargetPropertyProperty(it) => it.computed,
            _ => false,
        }
    }

    /// Babel `shorthand` of an `ObjectProperty`.
    pub fn shorthand(&self) -> bool {
        match self.kind() {
            K::ObjectProperty(it) => it.shorthand,
            K::BindingProperty(it) => it.shorthand,
            K::AssignmentTargetPropertyIdentifier(_) => true,
            _ => false,
        }
    }

    /// Babel `static` of a class member.
    pub fn is_static(&self) -> bool {
        match self.kind() {
            K::ClassMethod(it) => it.r#static,
            K::ClassProperty(it) => it.r#static,
            K::ClassAccessorProperty(it) => it.r#static,
            _ => false,
        }
    }

    /// Babel `optional` of one member/call link (`?.` at this link only).
    pub fn optional(&self) -> bool {
        match self.kind() {
            K::Member { member, .. } => member.optional(),
            K::Call { call, .. } => call.optional,
            _ => false,
        }
    }

    /// Babel `operator` of assignment, logical, binary, unary and update
    /// expressions.
    pub fn operator(&self) -> Option<&'static str> {
        Some(match self.kind() {
            K::AssignmentExpression(it) => it.operator.as_str(),
            K::LogicalExpression(it) => it.operator.as_str(),
            K::BinaryExpression(it) => it.operator.as_str(),
            K::PrivateInExpression(_) => "in",
            K::UnaryExpression(it) => it.operator.as_str(),
            K::UpdateExpression(it) => it.operator.as_str(),
            _ => return None,
        })
    }

    /// Babel `kind` of a `VariableDeclaration` (`var`, `let`, `const`,
    /// `using`, `await using`) or of an object/class method (`get`, `set`,
    /// `method`, `constructor`).
    pub fn declaration_kind(&self) -> Option<&'static str> {
        Some(match self.kind() {
            K::VariableDeclaration(it) => it.kind.as_str(),
            K::ObjectMethod(it) => match it.kind {
                PropertyKind::Get => "get",
                PropertyKind::Set => "set",
                PropertyKind::Init => "method",
            },
            K::ClassMethod(it) => match it.kind {
                MethodDefinitionKind::Constructor => "constructor",
                MethodDefinitionKind::Method => "method",
                MethodDefinitionKind::Get => "get",
                MethodDefinitionKind::Set => "set",
            },
            _ => return None,
        })
    }

    /// Babel `importKind` of import declarations, specifiers and
    /// `import x = require()` (`"value"` or `"type"`).
    pub fn import_kind(&self) -> Option<&'static str> {
        let kind = match self.kind() {
            K::ImportDeclaration(it) => it.import_kind,
            K::ImportSpecifier(it) => it.import_kind,
            K::TSImportEqualsDeclaration(it) => it.import_kind,
            _ => return None,
        };
        Some(if kind.is_type() { "type" } else { "value" })
    }

    /// Babel `delegate` of a `YieldExpression`.
    pub fn delegate(&self) -> bool {
        matches!(self.kind(), K::YieldExpression(it) if it.delegate)
    }

    /// Babel `value` of `StringLiteral`/`DirectiveLiteral`.
    pub fn string_value(&self) -> Option<&'a str> {
        match self.kind() {
            K::StringLiteral(it) | K::DirectiveLiteral(it) => Some(it.value.as_str()),
            _ => None,
        }
    }

    /// Exact UTF-16 units of a string literal, including OXC's encoded lone
    /// surrogates.
    pub fn string_value_units(&self) -> Option<Vec<u16>> {
        match self.kind() {
            K::StringLiteral(it) | K::DirectiveLiteral(it) => Some(decode_lossy_surrogates(
                it.value.as_str(),
                it.lone_surrogates,
            )),
            _ => None,
        }
    }

    /// Exact JavaScript string value, retaining UTF-8 when no lone surrogate
    /// decoding is required.
    pub fn string_value_js_string(&self) -> Option<JsString> {
        match self.kind() {
            K::StringLiteral(it) | K::DirectiveLiteral(it) => {
                if it.lone_surrogates {
                    Some(JsString::from_utf16(decode_lossy_surrogates(
                        it.value.as_str(),
                        true,
                    )))
                } else {
                    Some(JsString::from(it.value.as_str()))
                }
            }
            _ => None,
        }
    }

    /// Babel `value` of a `NumericLiteral`.
    pub fn numeric_value(&self) -> Option<f64> {
        match self.kind() {
            K::NumericLiteral(it) => Some(it.value),
            _ => None,
        }
    }

    /// Babel `value` of a `BooleanLiteral`.
    pub fn boolean_value(&self) -> Option<bool> {
        match self.kind() {
            K::BooleanLiteral(it) => Some(it.value),
            _ => None,
        }
    }

    /// The decimal digits of a `BigIntLiteral` (`String(BigInt(value))`).
    pub fn bigint_decimal(&self) -> Option<&'a str> {
        match self.kind() {
            K::BigIntLiteral(it) => Some(it.value.as_str()),
            _ => None,
        }
    }

    /// `value.cooked` of a `TemplateElement` (`None` for invalid escapes).
    pub fn template_cooked(&self) -> Option<&'a str> {
        match self.kind() {
            K::TemplateElement(it) => it.value.cooked.as_ref().map(|cooked| cooked.as_str()),
            _ => None,
        }
    }

    /// Exact UTF-16 units of a cooked template element, including unpaired
    /// surrogates represented by OXC's replacement-plus-four-hex encoding.
    pub fn template_cooked_units(&self) -> Option<Vec<u16>> {
        match self.kind() {
            K::TemplateElement(it) => it
                .value
                .cooked
                .as_ref()
                .map(|cooked| decode_lossy_surrogates(cooked.as_str(), it.lone_surrogates)),
            _ => None,
        }
    }
}

fn decode_lossy_surrogates(value: &str, has_lone_surrogates: bool) -> Vec<u16> {
    if !has_lone_surrogates {
        return value.encode_utf16().collect();
    }

    let mut units = Vec::new();
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character == '\u{fffd}' {
            let mut hex = String::new();
            for _ in 0..4 {
                let Some(next) = characters.next() else {
                    return value.encode_utf16().collect();
                };
                hex.push(next);
            }
            let Ok(unit) = u16::from_str_radix(&hex, 16) else {
                return value.encode_utf16().collect();
            };
            units.push(unit);
        } else {
            let mut buffer = [0; 2];
            units.extend(character.encode_utf16(&mut buffer).iter().copied());
        }
    }
    units
}
