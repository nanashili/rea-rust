//! Child enumeration in Babel `t.VISITOR_KEYS` order.
//!
//! The single owner of AST child expansion for the analysis port, mirroring
//! `javascriptSemanticTraversal.childNodes`. Each arm lists the Babel visitor
//! keys it follows; absent optional children are skipped, array holes too.

use oxc_ast::ast::*;
use oxc_span::{GetSpan, Span};

use super::node::{Node, NodeKind as K, class, expression, member, non_null, spine};

macro_rules! node {
    ($variant:ident, $value:expr) => {{
        let value = $value;
        Node::new(K::$variant(value), value.span, value.node_id())
    }};
}

/// Collects children in order.
struct Children<'a> {
    source: &'a str,
    out: Vec<Node<'a>>,
}

impl<'a> Children<'a> {
    fn push(&mut self, node: Node<'a>) {
        self.out.push(node);
    }

    fn expr(&mut self, expression: &'a Expression<'a>) {
        self.push(expression_node(expression));
    }

    fn opt_expr(&mut self, expression: Option<&'a Expression<'a>>) {
        if let Some(expression) = expression {
            self.expr(expression);
        }
    }

    fn arguments(&mut self, arguments: &'a [Argument<'a>]) {
        for argument in arguments {
            self.push(argument_node(argument));
        }
    }

    fn statements(&mut self, statements: &'a [Statement<'a>]) {
        for statement in statements {
            self.push(statement_node(statement));
        }
    }

    fn directives(&mut self, directives: &'a [Directive<'a>]) {
        for directive in directives {
            self.push(node!(Directive, directive));
        }
    }

    fn decorators(&mut self, decorators: &'a [Decorator<'a>]) {
        for decorator in decorators {
            self.push(node!(Decorator, decorator));
        }
    }

    fn binding_id(&mut self, id: &'a BindingIdentifier<'a>) {
        self.push(binding_identifier(id, None, &[]));
    }

    fn opt_binding_id(&mut self, id: Option<&'a BindingIdentifier<'a>>) {
        if let Some(id) = id {
            self.binding_id(id);
        }
    }

    fn annotation(&mut self, annotation: Option<&'a TSTypeAnnotation<'a>>) {
        if let Some(annotation) = annotation {
            self.push(node!(TSTypeAnnotation, annotation));
        }
    }

    fn type_parameters(&mut self, parameters: Option<&'a TSTypeParameterDeclaration<'a>>) {
        if let Some(parameters) = parameters {
            self.push(node!(TSTypeParameterDeclaration, parameters));
        }
    }

    fn type_arguments(&mut self, arguments: Option<&'a TSTypeParameterInstantiation<'a>>) {
        if let Some(arguments) = arguments {
            self.push(node!(TSTypeParameterInstantiation, arguments));
        }
    }

    fn ts_type(&mut self, ts_type: &'a TSType<'a>) {
        self.push(ts_type_node(ts_type));
    }

    fn opt_ts_type(&mut self, ts_type: Option<&'a TSType<'a>>) {
        if let Some(ts_type) = ts_type {
            self.ts_type(ts_type);
        }
    }

    fn key(&mut self, key: &'a PropertyKey<'a>) {
        self.push(property_key(key));
    }

    /// Babel `params`: the TS `this` parameter first, then the items, then rest.
    fn params(
        &mut self,
        this_param: Option<&'a TSThisParameter<'a>>,
        params: &'a FormalParameters<'a>,
    ) {
        self.out
            .extend(params_nodes(self.source, this_param, params));
    }

    /// `typeParameters, params, returnType, body` of a function-like.
    fn function_parts(&mut self, function: &'a Function<'a>) {
        self.type_parameters(function.type_parameters.as_deref());
        self.params(function.this_param.as_deref(), &function.params);
        self.annotation(function.return_type.as_deref());
        if let Some(body) = &function.body {
            self.push(node!(FunctionBody, &**body));
        }
    }

    fn assignment_target(&mut self, target: &'a AssignmentTarget<'a>) {
        self.push(assignment_target_node(self.source, target));
    }

    fn simple_target(&mut self, target: &'a SimpleAssignmentTarget<'a>) {
        self.push(simple_target_node(self.source, target));
    }

    fn maybe_default(&mut self, target: &'a AssignmentTargetMaybeDefault<'a>) {
        self.push(maybe_default_node(self.source, target));
    }

    fn with_clause(&mut self, clause: Option<&'a WithClause<'a>>) {
        if let Some(clause) = clause {
            for attribute in &clause.with_entries {
                self.push(node!(ImportAttribute, attribute));
            }
        }
    }

    fn module_export_name(&mut self, name: &'a ModuleExportName<'a>) {
        self.push(module_export_name_node(name));
    }

    fn ts_type_name(&mut self, name: &'a TSTypeName<'a>) {
        self.push(ts_type_name(name));
    }

    fn signatures(&mut self, signatures: &'a [TSSignature<'a>]) {
        for signature in signatures {
            self.push(match signature {
                TSSignature::TSIndexSignature(it) => node!(TSIndexSignature, &**it),
                TSSignature::TSPropertySignature(it) => node!(TSPropertySignature, &**it),
                TSSignature::TSCallSignatureDeclaration(it) => {
                    node!(TSCallSignatureDeclaration, &**it)
                }
                TSSignature::TSConstructSignatureDeclaration(it) => {
                    node!(TSConstructSignatureDeclaration, &**it)
                }
                TSSignature::TSMethodSignature(it) => node!(TSMethodSignature, &**it),
            });
        }
    }

    fn jsx_children(&mut self, children: &'a [JSXChild<'a>]) {
        for child in children {
            self.push(match child {
                JSXChild::Text(it) => node!(JSXText, &**it),
                JSXChild::Element(it) => node!(JSXElement, &**it),
                JSXChild::Fragment(it) => node!(JSXFragment, &**it),
                JSXChild::ExpressionContainer(it) => node!(JSXExpressionContainer, &**it),
                JSXChild::Spread(it) => node!(JSXSpreadChild, &**it),
            });
        }
    }

    fn module_block_body(&mut self, body: Option<&'a TSModuleDeclarationBody<'a>>) {
        match body {
            Some(TSModuleDeclarationBody::TSModuleBlock(block)) => {
                self.push(node!(TSModuleBlock, &**block));
            }
            Some(TSModuleDeclarationBody::TSModuleDeclaration(inner)) => {
                self.module_block_body(inner.body.as_ref());
            }
            None => {}
        }
    }
}

pub(super) fn expression_node<'a>(it: &'a Expression<'a>) -> Node<'a> {
    expression(it)
}

pub(super) fn module_export_name_node<'a>(name: &'a ModuleExportName<'a>) -> Node<'a> {
    match name {
        ModuleExportName::IdentifierName(it) => node!(IdentifierName, it),
        ModuleExportName::IdentifierReference(it) => node!(IdentifierReference, it),
        ModuleExportName::StringLiteral(it) => node!(StringLiteral, it),
    }
}

pub(super) fn argument_node<'a>(argument: &'a Argument<'a>) -> Node<'a> {
    match argument {
        Argument::SpreadElement(it) => node!(SpreadElement, &**it),
        _ => expression(argument.to_expression()),
    }
}

/// Babel `params`: the TS `this` parameter first, then the items, then rest.
pub(super) fn params_nodes<'a>(
    source: &str,
    this_param: Option<&'a TSThisParameter<'a>>,
    params: &'a FormalParameters<'a>,
) -> Vec<Node<'a>> {
    let mut out = Vec::with_capacity(params.items.len() + 2);
    if let Some(this_param) = this_param {
        out.push(node!(ThisParameter, this_param));
    }
    for param in &params.items {
        out.push(formal_parameter(source, param));
    }
    if let Some(rest) = &params.rest {
        out.push(node!(RestParameter, &**rest));
    }
    out
}

pub(super) fn assignment_target_node<'a>(
    source: &str,
    target: &'a AssignmentTarget<'a>,
) -> Node<'a> {
    match target {
        AssignmentTarget::ArrayAssignmentTarget(it) => node!(ArrayAssignmentTarget, &**it),
        AssignmentTarget::ObjectAssignmentTarget(it) => node!(ObjectAssignmentTarget, &**it),
        _ => simple_target_node(source, target.to_simple_assignment_target()),
    }
}

/// oxc drops parentheses around simple targets (`(a) = 1`); Babel keeps
/// `parenthesized`, so it is recovered from the source.
pub(super) fn simple_target_node<'a>(
    source: &str,
    target: &'a SimpleAssignmentTarget<'a>,
) -> Node<'a> {
    let node = simple_target(target);
    let parenthesized = wrapped_in_parentheses(source, node.span());
    node.with_parenthesized(parenthesized)
}

pub(super) fn maybe_default_node<'a>(
    source: &str,
    target: &'a AssignmentTargetMaybeDefault<'a>,
) -> Node<'a> {
    match target {
        AssignmentTargetMaybeDefault::AssignmentTargetWithDefault(it) => {
            node!(AssignmentTargetWithDefault, &**it)
        }
        _ => assignment_target_node(source, target.to_assignment_target()),
    }
}

pub(super) fn for_left_node<'a>(source: &str, left: &'a ForStatementLeft<'a>) -> Node<'a> {
    match left {
        ForStatementLeft::VariableDeclaration(it) => node!(VariableDeclaration, &**it),
        _ => assignment_target_node(source, left.to_assignment_target()),
    }
}

pub(super) fn statement_node<'a>(statement: &'a Statement<'a>) -> Node<'a> {
    match statement {
        Statement::BlockStatement(it) => node!(BlockStatement, &**it),
        Statement::BreakStatement(it) => node!(BreakStatement, &**it),
        Statement::ContinueStatement(it) => node!(ContinueStatement, &**it),
        Statement::DebuggerStatement(it) => node!(DebuggerStatement, &**it),
        Statement::DoWhileStatement(it) => node!(DoWhileStatement, &**it),
        Statement::EmptyStatement(it) => node!(EmptyStatement, &**it),
        Statement::ExpressionStatement(it) => node!(ExpressionStatement, &**it),
        Statement::ForInStatement(it) => node!(ForInStatement, &**it),
        Statement::ForOfStatement(it) => node!(ForOfStatement, &**it),
        Statement::ForStatement(it) => node!(ForStatement, &**it),
        Statement::IfStatement(it) => node!(IfStatement, &**it),
        Statement::LabeledStatement(it) => node!(LabeledStatement, &**it),
        Statement::ReturnStatement(it) => node!(ReturnStatement, &**it),
        Statement::SwitchStatement(it) => node!(SwitchStatement, &**it),
        Statement::ThrowStatement(it) => node!(ThrowStatement, &**it),
        Statement::TryStatement(it) => node!(TryStatement, &**it),
        Statement::WhileStatement(it) => node!(WhileStatement, &**it),
        Statement::WithStatement(it) => node!(WithStatement, &**it),
        Statement::ImportDeclaration(it) => node!(ImportDeclaration, &**it),
        Statement::ExportAllDeclaration(it) => node!(ExportAllDeclaration, &**it),
        Statement::ExportDefaultDeclaration(it) => {
            let start = match &it.declaration {
                ExportDefaultDeclarationKind::ClassDeclaration(declared) => {
                    class(declared).span().start
                }
                _ => it.span.start,
            };
            decorated_export(node!(ExportDefaultDeclaration, &**it), start)
        }
        Statement::ExportNamedDeclaration(it) => {
            let start = match &it.declaration {
                Some(Declaration::ClassDeclaration(declared)) => class(declared).span().start,
                _ => it.span.start,
            };
            decorated_export(node!(ExportNamedDeclaration, &**it), start)
        }
        Statement::TSExportAssignment(it) => node!(TSExportAssignment, &**it),
        Statement::TSNamespaceExportDeclaration(it) => node!(TSNamespaceExportDeclaration, &**it),
        _ => declaration_node(statement.as_declaration().expect("declaration variant")),
    }
}

/// `@dec export class`: Babel starts the export at the decorator.
fn decorated_export(node: Node<'_>, class_start: u32) -> Node<'_> {
    let span = node.span();
    node.with_span(Span::new(span.start.min(class_start), span.end))
}

pub(super) fn declaration_node<'a>(declaration: &'a Declaration<'a>) -> Node<'a> {
    match declaration {
        Declaration::VariableDeclaration(it) => node!(VariableDeclaration, &**it),
        Declaration::FunctionDeclaration(it) => node!(Function, &**it),
        Declaration::ClassDeclaration(it) => class(it),
        Declaration::TSTypeAliasDeclaration(it) => node!(TSTypeAliasDeclaration, &**it),
        Declaration::TSInterfaceDeclaration(it) => node!(TSInterfaceDeclaration, &**it),
        Declaration::TSEnumDeclaration(it) => node!(TSEnumDeclaration, &**it),
        Declaration::TSModuleDeclaration(it) => node!(TSModuleDeclaration, &**it),
        Declaration::TSGlobalDeclaration(it) => node!(TSGlobalDeclaration, &**it),
        Declaration::TSImportEqualsDeclaration(it) => node!(TSImportEqualsDeclaration, &**it),
    }
}

pub(super) fn binding_identifier<'a>(
    id: &'a BindingIdentifier<'a>,
    annotation: Option<&'a TSTypeAnnotation<'a>>,
    decorators: &'a [Decorator<'a>],
) -> Node<'a> {
    Node::new(
        K::BindingIdentifier {
            id,
            annotation,
            decorators,
        },
        annotated(id.span, annotation),
        id.node_id(),
    )
}

/// Babel extends an annotated pattern's span over its type annotation.
fn annotated(span: Span, annotation: Option<&TSTypeAnnotation<'_>>) -> Span {
    annotation.map_or(span, |annotation| {
        Span::new(span.start, span.end.max(annotation.span.end))
    })
}

/// A binding pattern with the annotation and decorators its declaration
/// carries in oxc but Babel attaches to the pattern node.
pub(super) fn binding_pattern<'a>(
    pattern: &'a BindingPattern<'a>,
    annotation: Option<&'a TSTypeAnnotation<'a>>,
    decorators: &'a [Decorator<'a>],
) -> Node<'a> {
    match pattern {
        BindingPattern::BindingIdentifier(id) => binding_identifier(id, annotation, decorators),
        BindingPattern::ObjectPattern(pattern) => Node::new(
            K::ObjectPattern {
                pattern,
                annotation,
                decorators,
            },
            annotated(pattern.span, annotation),
            pattern.node_id(),
        ),
        BindingPattern::ArrayPattern(pattern) => Node::new(
            K::ArrayPattern {
                pattern,
                annotation,
            },
            annotated(pattern.span, annotation),
            pattern.node_id(),
        ),
        BindingPattern::AssignmentPattern(it) => node!(AssignmentPattern, &**it),
    }
}

pub(super) fn formal_parameter<'a>(source: &str, param: &'a FormalParameter<'a>) -> Node<'a> {
    if param.accessibility.is_some() || param.readonly || param.r#override {
        node!(ParameterProperty, param)
    } else if param.initializer.is_some() {
        default_parameter(param)
    } else {
        plain_parameter(source, param, &param.decorators)
    }
}

/// A parameter without default: its pattern, annotated, and extended over
/// an unannotated optional marker (`a?`), as Babel's identifier span is.
pub(super) fn plain_parameter<'a>(
    source: &str,
    param: &'a FormalParameter<'a>,
    decorators: &'a [Decorator<'a>],
) -> Node<'a> {
    let node = binding_pattern(&param.pattern, param.type_annotation.as_deref(), decorators);
    if param.optional && param.type_annotation.is_none() {
        let question = skip_trivia(source, node.span().end as usize);
        if source.as_bytes().get(question) == Some(&b'?') {
            return node.with_span(Span::new(node.span().start, question as u32 + 1));
        }
    }
    node
}

/// First byte at or after `from` that is not whitespace or a comment.
fn skip_trivia(source: &str, mut from: usize) -> usize {
    let bytes = source.as_bytes();
    loop {
        match bytes.get(from) {
            Some(b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) => from += 1,
            Some(b'/') if bytes.get(from + 1) == Some(&b'*') => match source[from + 2..].find("*/")
            {
                Some(close) => from += 2 + close + 2,
                None => return bytes.len(),
            },
            Some(b'/') if bytes.get(from + 1) == Some(&b'/') => {
                match source[from..].find(['\n', '\r', '\u{2028}', '\u{2029}']) {
                    Some(newline) => from += newline,
                    None => return bytes.len(),
                }
            }
            Some(byte) if *byte >= 0x80 => match source[from..].chars().next() {
                Some(ch) if ch.is_whitespace() || ch == '\u{feff}' => from += ch.len_utf8(),
                _ => return from,
            },
            _ => return from,
        }
    }
}

/// Byte just before `before`, skipping ASCII whitespace and block comments
/// (`None` at the start). Line comments are not recognized backwards.
fn previous_significant(source: &str, mut before: usize) -> Option<u8> {
    let bytes = source.as_bytes();
    loop {
        let previous = *bytes.get(before.checked_sub(1)?)?;
        match previous {
            b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c => before -= 1,
            b'/' if before >= 2 && bytes[before - 2] == b'*' => {
                before = source[..before - 2].rfind("/*")?;
            }
            _ => return Some(previous),
        }
    }
}

/// Whether a span is directly wrapped in a pair of parentheses. Used for
/// simple assignment targets, whose parentheses oxc does not retain.
fn wrapped_in_parentheses(source: &str, span: Span) -> bool {
    previous_significant(source, span.start as usize) == Some(b'(')
        && source
            .as_bytes()
            .get(skip_trivia(source, span.end as usize))
            == Some(&b')')
}

pub(super) fn default_parameter<'a>(param: &'a FormalParameter<'a>) -> Node<'a> {
    let end = param
        .initializer
        .as_ref()
        .map_or(param.span.end, |init| init.span().end);
    Node::synthesized(
        K::DefaultParameter(param),
        Span::new(param.pattern.span().start, end),
        param.node_id(),
    )
}

pub(super) fn property_key<'a>(key: &'a PropertyKey<'a>) -> Node<'a> {
    match key {
        PropertyKey::StaticIdentifier(it) => node!(IdentifierName, &**it),
        PropertyKey::PrivateIdentifier(it) => node!(PrivateName, &**it),
        _ => expression(key.to_expression()),
    }
}

fn simple_target<'a>(target: &'a SimpleAssignmentTarget<'a>) -> Node<'a> {
    match target {
        SimpleAssignmentTarget::AssignmentTargetIdentifier(it) => node!(IdentifierReference, &**it),
        SimpleAssignmentTarget::TSAsExpression(it) => node!(TSAsExpression, &**it),
        SimpleAssignmentTarget::TSSatisfiesExpression(it) => node!(TSSatisfiesExpression, &**it),
        SimpleAssignmentTarget::TSNonNullExpression(it) => non_null(it, 0),
        SimpleAssignmentTarget::TSTypeAssertion(it) => node!(TSTypeAssertion, &**it),
        _ => member(target.as_member_expression().expect("member variant"), 0),
    }
}

pub(super) fn ts_type_node<'a>(mut ts_type: &'a TSType<'a>) -> Node<'a> {
    let mut parenthesized = false;
    while let TSType::TSParenthesizedType(inner) = ts_type {
        parenthesized = true;
        ts_type = &inner.type_annotation;
    }
    let keyword = |name: &'static str, span: Span, id| Node::new(K::TSKeyword(name), span, id);
    let node = match ts_type {
        TSType::TSAnyKeyword(it) => keyword("TSAnyKeyword", it.span, it.node_id()),
        TSType::TSBigIntKeyword(it) => keyword("TSBigIntKeyword", it.span, it.node_id()),
        TSType::TSBooleanKeyword(it) => keyword("TSBooleanKeyword", it.span, it.node_id()),
        TSType::TSIntrinsicKeyword(it) => keyword("TSIntrinsicKeyword", it.span, it.node_id()),
        TSType::TSNeverKeyword(it) => keyword("TSNeverKeyword", it.span, it.node_id()),
        TSType::TSNullKeyword(it) => keyword("TSNullKeyword", it.span, it.node_id()),
        TSType::TSNumberKeyword(it) => keyword("TSNumberKeyword", it.span, it.node_id()),
        TSType::TSObjectKeyword(it) => keyword("TSObjectKeyword", it.span, it.node_id()),
        TSType::TSStringKeyword(it) => keyword("TSStringKeyword", it.span, it.node_id()),
        TSType::TSSymbolKeyword(it) => keyword("TSSymbolKeyword", it.span, it.node_id()),
        TSType::TSUndefinedKeyword(it) => keyword("TSUndefinedKeyword", it.span, it.node_id()),
        TSType::TSUnknownKeyword(it) => keyword("TSUnknownKeyword", it.span, it.node_id()),
        TSType::TSVoidKeyword(it) => keyword("TSVoidKeyword", it.span, it.node_id()),
        TSType::TSThisType(it) => node!(TSThisType, &**it),
        TSType::TSArrayType(it) => node!(TSArrayType, &**it),
        // Babel starts a conditional type at its check type's node, inside
        // any parentheses around it (`(A) extends B ? C : D` starts at `A`).
        TSType::TSConditionalType(it) => node!(TSConditionalType, &**it).with_span(Span::new(
            ts_type_node(&it.check_type).span().start,
            it.span.end,
        )),
        TSType::TSConstructorType(it) => node!(TSConstructorType, &**it),
        TSType::TSFunctionType(it) => node!(TSFunctionType, &**it),
        TSType::TSImportType(it) => node!(TSImportType, &**it),
        TSType::TSIndexedAccessType(it) => node!(TSIndexedAccessType, &**it),
        TSType::TSInferType(it) => node!(TSInferType, &**it),
        TSType::TSIntersectionType(it) => node!(TSIntersectionType, &**it),
        TSType::TSLiteralType(it) => node!(TSLiteralType, &**it),
        TSType::TSMappedType(it) => node!(TSMappedType, &**it),
        TSType::TSNamedTupleMember(it) => node!(TSNamedTupleMember, &**it),
        TSType::TSTemplateLiteralType(it) => node!(TSTemplateLiteralType, &**it),
        TSType::TSTupleType(it) => node!(TSTupleType, &**it),
        TSType::TSTypeLiteral(it) => node!(TSTypeLiteral, &**it),
        TSType::TSTypeOperatorType(it) => node!(TSTypeOperator, &**it),
        TSType::TSTypePredicate(it) => node!(TSTypePredicate, &**it),
        TSType::TSTypeQuery(it) => node!(TSTypeQuery, &**it),
        TSType::TSTypeReference(it) => node!(TSTypeReference, &**it),
        TSType::TSUnionType(it) => node!(TSUnionType, &**it),
        TSType::TSParenthesizedType(it) => ts_type_node(&it.type_annotation),
        TSType::JSDocNullableType(it) => {
            Node::new(K::JSDocType("JSDocNullableType"), it.span, it.node_id())
        }
        TSType::JSDocNonNullableType(it) => {
            Node::new(K::JSDocType("JSDocNonNullableType"), it.span, it.node_id())
        }
        TSType::JSDocUnknownType(it) => {
            Node::new(K::JSDocType("JSDocUnknownType"), it.span, it.node_id())
        }
    };
    node.with_parenthesized(parenthesized)
}

fn ts_type_name<'a>(name: &'a TSTypeName<'a>) -> Node<'a> {
    match name {
        TSTypeName::IdentifierReference(it) => node!(IdentifierReference, &**it),
        TSTypeName::QualifiedName(it) => node!(TSQualifiedName, &**it),
        TSTypeName::ThisExpression(it) => node!(ThisExpression, &**it),
    }
}

fn import_type_qualifier<'a>(qualifier: &'a TSImportTypeQualifier<'a>) -> Node<'a> {
    match qualifier {
        TSImportTypeQualifier::Identifier(it) => node!(IdentifierName, &**it),
        TSImportTypeQualifier::QualifiedName(it) => node!(TSImportTypeQualifiedName, &**it),
    }
}

fn tuple_element<'a>(element: &'a TSTupleElement<'a>) -> Node<'a> {
    match element {
        TSTupleElement::TSOptionalType(it) => node!(TSOptionalType, &**it),
        TSTupleElement::TSRestType(it) => node!(TSRestType, &**it),
        _ => ts_type_node(element.to_ts_type()),
    }
}

/// Segment `depth` of a dotted module declaration (`outer` is segment 0).
fn module_segment<'a>(
    outer: &'a TSModuleDeclaration<'a>,
    depth: u32,
) -> &'a TSModuleDeclaration<'a> {
    let mut current = outer;
    for _ in 0..depth {
        match &current.body {
            Some(TSModuleDeclarationBody::TSModuleDeclaration(inner)) => current = inner,
            _ => break,
        }
    }
    current
}

fn module_segments(outer: &TSModuleDeclaration<'_>) -> u32 {
    let mut depth = 0;
    let mut current = outer;
    while let Some(TSModuleDeclarationBody::TSModuleDeclaration(inner)) = &current.body {
        depth += 1;
        current = inner;
    }
    depth
}

fn module_name<'a>(name: &'a TSModuleDeclarationName<'a>) -> Node<'a> {
    match name {
        TSModuleDeclarationName::Identifier(it) => binding_identifier(it, None, &[]),
        TSModuleDeclarationName::StringLiteral(it) => node!(StringLiteral, it),
    }
}

fn module_qualified_name<'a>(outer: &'a TSModuleDeclaration<'a>, depth: u32) -> Node<'a> {
    if depth == 0 {
        return module_name(&outer.id);
    }
    let segment = module_segment(outer, depth);
    Node::synthesized(
        K::TSModuleQualifiedName { outer, depth },
        Span::new(outer.id.span().start, segment.id.span().end),
        segment.node_id(),
    )
}

/// Byte offset of the `*` in `export * as ns from`, skipping comments.
fn export_star(source: &str, declaration: &ExportAllDeclaration<'_>) -> u32 {
    let start = declaration.span.start as usize;
    let end = declaration
        .exported
        .as_ref()
        .map_or(declaration.span.end, |e| e.span().start) as usize;
    let bytes = source.as_bytes();
    let mut index = start;
    while index < end.min(bytes.len()) {
        match bytes[index] {
            b'*' => return index as u32,
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index = source[index + 2..]
                    .find("*/")
                    .map_or(end, |close| index + 2 + close + 2);
            }
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                index = source[index..]
                    .find('\n')
                    .map_or(end, |newline| index + newline);
            }
            _ => index += 1,
        }
    }
    declaration.span.start
}

impl<'a> Node<'a> {
    /// The Babel view of a whole program.
    pub fn program(program: &'a Program<'a>) -> Self {
        Node::new(K::Program(program), program.span, program.node_id())
    }

    /// Children in Babel `t.VISITOR_KEYS[type]` order. `source` is the
    /// program's source text (only read to locate tokens oxc keeps no span
    /// for).
    pub fn children(&self, source: &'a str) -> Vec<Node<'a>> {
        let mut c = Children {
            source,
            out: Vec::new(),
        };
        self.collect(&mut c);
        c.out
    }

    #[allow(clippy::too_many_lines)]
    fn collect(&self, c: &mut Children<'a>) {
        match self.kind() {
            // directives, body
            K::Program(it) => {
                c.directives(&it.directives);
                c.statements(&it.body);
            }
            // value
            K::Directive(it) => c.push(node!(DirectiveLiteral, &it.expression)),
            K::DirectiveLiteral(_) => {}
            // directives, body
            K::FunctionBody(it) => {
                c.directives(&it.directives);
                c.statements(&it.statements);
            }
            K::BlockStatement(it) => c.statements(&it.body),
            K::StaticBlock(it) => c.statements(&it.body),
            K::EmptyStatement(_) | K::DebuggerStatement(_) => {}
            K::ExpressionStatement(it) => c.expr(&it.expression),
            // test, consequent, alternate
            K::IfStatement(it) => {
                c.expr(&it.test);
                c.push(statement_node(&it.consequent));
                if let Some(alternate) = &it.alternate {
                    c.push(statement_node(alternate));
                }
            }
            // body, test
            K::DoWhileStatement(it) => {
                c.push(statement_node(&it.body));
                c.expr(&it.test);
            }
            // test, body
            K::WhileStatement(it) => {
                c.expr(&it.test);
                c.push(statement_node(&it.body));
            }
            // init, test, update, body
            K::ForStatement(it) => {
                match &it.init {
                    Some(ForStatementInit::VariableDeclaration(declaration)) => {
                        c.push(node!(VariableDeclaration, &**declaration));
                    }
                    Some(init) => c.expr(init.to_expression()),
                    None => {}
                }
                c.opt_expr(it.test.as_ref());
                c.opt_expr(it.update.as_ref());
                c.push(statement_node(&it.body));
            }
            // left, right, body
            K::ForInStatement(it) => {
                for_left(c, &it.left);
                c.expr(&it.right);
                c.push(statement_node(&it.body));
            }
            K::ForOfStatement(it) => {
                for_left(c, &it.left);
                c.expr(&it.right);
                c.push(statement_node(&it.body));
            }
            // label
            K::ContinueStatement(it) => {
                if let Some(label) = &it.label {
                    c.push(node!(LabelIdentifier, label));
                }
            }
            K::BreakStatement(it) => {
                if let Some(label) = &it.label {
                    c.push(node!(LabelIdentifier, label));
                }
            }
            // argument
            K::ReturnStatement(it) => c.opt_expr(it.argument.as_ref()),
            K::ThrowStatement(it) => c.expr(&it.argument),
            // object, body
            K::WithStatement(it) => {
                c.expr(&it.object);
                c.push(statement_node(&it.body));
            }
            // discriminant, cases
            K::SwitchStatement(it) => {
                c.expr(&it.discriminant);
                for case in &it.cases {
                    c.push(node!(SwitchCase, case));
                }
            }
            // test, consequent
            K::SwitchCase(it) => {
                c.opt_expr(it.test.as_ref());
                c.statements(&it.consequent);
            }
            // label, body
            K::LabeledStatement(it) => {
                c.push(node!(LabelIdentifier, &it.label));
                c.push(statement_node(&it.body));
            }
            // block, handler, finalizer
            K::TryStatement(it) => {
                c.push(node!(BlockStatement, &*it.block));
                if let Some(handler) = &it.handler {
                    c.push(node!(CatchClause, &**handler));
                }
                if let Some(finalizer) = &it.finalizer {
                    c.push(node!(BlockStatement, &**finalizer));
                }
            }
            // param, body
            K::CatchClause(it) => {
                if let Some(param) = &it.param {
                    c.push(binding_pattern(
                        &param.pattern,
                        param.type_annotation.as_deref(),
                        &[],
                    ));
                }
                c.push(node!(BlockStatement, &*it.body));
            }
            // declarations
            K::VariableDeclaration(it) => {
                for declarator in &it.declarations {
                    c.push(node!(VariableDeclarator, declarator));
                }
            }
            // id, init
            K::VariableDeclarator(it) => {
                c.push(binding_pattern(&it.id, it.type_annotation.as_deref(), &[]));
                c.opt_expr(it.init.as_ref());
            }

            // Identifier: typeAnnotation, decorators
            K::BindingIdentifier {
                annotation,
                decorators,
                ..
            } => {
                c.annotation(annotation);
                c.decorators(decorators);
            }
            K::ThisParameter(it) => c.annotation(it.type_annotation.as_deref()),
            K::IndexSignatureName(it) => c.annotation(Some(&it.type_annotation)),
            K::IdentifierName(_)
            | K::IdentifierReference(_)
            | K::LabelIdentifier(_)
            | K::ShorthandTargetKey(_)
            | K::PrivateNameId(_)
            | K::TSGlobalName(_) => {}
            // PrivateName: id
            K::PrivateName(it) => c.push(Node::synthesized(
                K::PrivateNameId(it),
                Span::new(it.span.start + 1, it.span.end),
                it.node_id(),
            )),

            K::BooleanLiteral(_)
            | K::NullLiteral(_)
            | K::NumericLiteral(_)
            | K::BigIntLiteral(_)
            | K::RegExpLiteral(_)
            | K::StringLiteral(_)
            | K::TemplateElement(_) => {}
            // quasis, expressions
            K::TemplateLiteral(it) => template(c, &it.quasis, &it.expressions),

            K::ThisExpression(_) | K::Super(_) => {}
            // elements
            K::ArrayExpression(it) => {
                for element in &it.elements {
                    match element {
                        ArrayExpressionElement::SpreadElement(spread) => {
                            c.push(node!(SpreadElement, &**spread));
                        }
                        ArrayExpressionElement::Elision(_) => {}
                        _ => c.expr(element.to_expression()),
                    }
                }
            }
            // properties
            K::ObjectExpression(it) => {
                for property in &it.properties {
                    c.push(match property {
                        ObjectPropertyKind::ObjectProperty(property) => {
                            if property.method || property.kind != PropertyKind::Init {
                                node!(ObjectMethod, &**property)
                            } else {
                                node!(ObjectProperty, &**property)
                            }
                        }
                        ObjectPropertyKind::SpreadProperty(spread) => {
                            node!(SpreadElement, &**spread)
                        }
                    });
                }
            }
            // decorators, key, value
            K::ObjectProperty(it) => {
                c.key(&it.key);
                c.expr(&it.value);
            }
            // decorators, key, typeParameters, params, returnType, body
            K::ObjectMethod(it) => {
                c.key(&it.key);
                if let Expression::FunctionExpression(function) = &it.value {
                    c.function_parts(function);
                }
            }
            // argument
            K::SpreadElement(it) => c.expr(&it.argument),
            // tag, typeArguments, quasi
            K::TaggedTemplateExpression(it) => {
                c.expr(&it.tag);
                c.type_arguments(it.type_arguments.as_deref());
                c.push(node!(TemplateLiteral, &it.quasi));
            }
            // object, property
            K::Member { member, chain } => {
                let below = chain.saturating_sub(u32::from(member.optional()));
                c.push(spine(member.object(), below));
                match member {
                    MemberExpression::ComputedMemberExpression(it) => c.expr(&it.expression),
                    MemberExpression::StaticMemberExpression(it) => {
                        c.push(node!(IdentifierName, &it.property));
                    }
                    MemberExpression::PrivateFieldExpression(it) => {
                        c.push(node!(PrivateName, &it.field));
                    }
                }
            }
            // callee, typeArguments, arguments
            K::Call { call: it, chain } => {
                let below = chain.saturating_sub(u32::from(it.optional));
                c.push(spine(&it.callee, below));
                c.type_arguments(it.type_arguments.as_deref());
                c.arguments(&it.arguments);
            }
            K::NewExpression(it) => {
                c.expr(&it.callee);
                c.type_arguments(it.type_arguments.as_deref());
                c.arguments(&it.arguments);
            }
            // source, options
            K::ImportExpression(it) => {
                c.expr(&it.source);
                c.opt_expr(it.options.as_ref());
            }
            // meta, property
            K::MetaProperty(it) => {
                c.push(node!(IdentifierName, &it.meta));
                c.push(node!(IdentifierName, &it.property));
            }
            // argument
            K::UpdateExpression(it) => c.simple_target(&it.argument),
            K::UnaryExpression(it) => c.expr(&it.argument),
            K::AwaitExpression(it) => c.expr(&it.argument),
            K::YieldExpression(it) => c.opt_expr(it.argument.as_ref()),
            // left, right
            K::BinaryExpression(it) => {
                c.expr(&it.left);
                c.expr(&it.right);
            }
            K::PrivateInExpression(it) => {
                c.push(node!(PrivateName, &it.left));
                c.expr(&it.right);
            }
            K::LogicalExpression(it) => {
                c.expr(&it.left);
                c.expr(&it.right);
            }
            K::AssignmentExpression(it) => {
                c.assignment_target(&it.left);
                c.expr(&it.right);
            }
            // test, consequent, alternate
            K::ConditionalExpression(it) => {
                c.expr(&it.test);
                c.expr(&it.consequent);
                c.expr(&it.alternate);
            }
            // expressions
            K::SequenceExpression(it) => {
                for expression in &it.expressions {
                    c.expr(expression);
                }
            }
            K::V8IntrinsicExpression(it) => c.arguments(&it.arguments),

            // id, typeParameters, params, predicate, returnType, body
            K::Function(it) => {
                c.opt_binding_id(it.id.as_ref());
                c.function_parts(it);
            }
            // typeParameters, params, predicate, returnType, body
            K::ArrowFunctionExpression(it) => {
                c.type_parameters(it.type_parameters.as_deref());
                c.params(None, &it.params);
                c.annotation(it.return_type.as_deref());
                match (it.expression, it.body.statements.first()) {
                    (true, Some(Statement::ExpressionStatement(statement))) => {
                        c.expr(&statement.expression);
                    }
                    _ => c.push(node!(FunctionBody, &*it.body)),
                }
            }
            // decorators, id, typeParameters, superClass, superTypeArguments,
            // mixins, implements, body
            K::Class(it) => {
                c.decorators(&it.decorators);
                c.opt_binding_id(it.id.as_ref());
                c.type_parameters(it.type_parameters.as_deref());
                c.opt_expr(it.super_class.as_ref());
                c.type_arguments(it.super_type_arguments.as_deref());
                for implements in &it.implements {
                    c.push(node!(TSClassImplements, implements));
                }
                c.push(node!(ClassBody, &*it.body));
            }
            // body
            K::ClassBody(it) => {
                for element in &it.body {
                    c.push(match element {
                        ClassElement::StaticBlock(it) => node!(StaticBlock, &**it),
                        ClassElement::MethodDefinition(it) => node!(ClassMethod, &**it),
                        ClassElement::PropertyDefinition(it) => node!(ClassProperty, &**it),
                        ClassElement::AccessorProperty(it) => node!(ClassAccessorProperty, &**it),
                        ClassElement::TSIndexSignature(it) => node!(TSIndexSignature, &**it),
                    });
                }
            }
            // ClassMethod: decorators, key, typeParameters, params, returnType, body
            // TSDeclareMethod: key, typeParameters, params, returnType
            K::ClassMethod(it) => {
                if it.value.body.is_some() {
                    c.decorators(&it.decorators);
                }
                c.key(&it.key);
                c.function_parts(&it.value);
            }
            // decorators, variance, key, typeAnnotation, value
            K::ClassProperty(it) => {
                c.decorators(&it.decorators);
                c.key(&it.key);
                c.annotation(it.type_annotation.as_deref());
                c.opt_expr(it.value.as_ref());
            }
            // decorators, key, typeAnnotation, value
            K::ClassAccessorProperty(it) => {
                c.decorators(&it.decorators);
                c.key(&it.key);
                c.annotation(it.type_annotation.as_deref());
                c.opt_expr(it.value.as_ref());
            }
            // expression
            K::Decorator(it) => c.expr(&it.expression),

            // decorators, properties, typeAnnotation
            K::ObjectPattern {
                pattern,
                annotation,
                decorators,
            } => {
                c.decorators(decorators);
                for property in &pattern.properties {
                    c.push(node!(BindingProperty, property));
                }
                if let Some(rest) = &pattern.rest {
                    c.push(node!(BindingRestElement, &**rest));
                }
                c.annotation(annotation);
            }
            // elements, typeAnnotation
            K::ArrayPattern {
                pattern,
                annotation,
            } => {
                for element in pattern.elements.iter().flatten() {
                    c.push(binding_pattern(element, None, &[]));
                }
                if let Some(rest) = &pattern.rest {
                    c.push(node!(BindingRestElement, &**rest));
                }
                c.annotation(annotation);
            }
            // left, right, decorators
            K::AssignmentPattern(it) => {
                c.push(binding_pattern(&it.left, None, &[]));
                c.expr(&it.right);
            }
            K::DefaultParameter(it) => {
                c.push(binding_pattern(
                    &it.pattern,
                    it.type_annotation.as_deref(),
                    &[],
                ));
                if let Some(initializer) = &it.initializer {
                    c.expr(initializer);
                }
                c.decorators(&it.decorators);
            }
            // parameter
            K::ParameterProperty(it) => c.push(if it.initializer.is_some() {
                default_parameter(it)
            } else {
                plain_parameter(c.source, it, &[])
            }),
            // ObjectProperty: decorators, key, value
            K::BindingProperty(it) => {
                c.key(&it.key);
                c.push(binding_pattern(&it.value, None, &[]));
            }
            // RestElement: argument, typeAnnotation
            K::BindingRestElement(it) => c.push(binding_pattern(&it.argument, None, &[])),
            K::RestParameter(it) => {
                c.push(binding_pattern(&it.rest.argument, None, &[]));
                c.annotation(it.type_annotation.as_deref());
            }

            K::ArrayAssignmentTarget(it) => {
                for element in it.elements.iter().flatten() {
                    c.maybe_default(element);
                }
                if let Some(rest) = &it.rest {
                    c.push(node!(AssignmentTargetRest, &**rest));
                }
            }
            K::ObjectAssignmentTarget(it) => {
                for property in &it.properties {
                    c.push(match property {
                        AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(it) => {
                            node!(AssignmentTargetPropertyIdentifier, &**it)
                        }
                        AssignmentTargetProperty::AssignmentTargetPropertyProperty(it) => {
                            node!(AssignmentTargetPropertyProperty, &**it)
                        }
                    });
                }
                if let Some(rest) = &it.rest {
                    c.push(node!(AssignmentTargetRest, &**rest));
                }
            }
            K::AssignmentTargetRest(it) => c.assignment_target(&it.target),
            K::AssignmentTargetWithDefault(it) => {
                c.assignment_target(&it.binding);
                c.expr(&it.init);
            }
            K::AssignmentTargetPropertyIdentifier(it) => {
                c.push(Node::synthesized(
                    K::ShorthandTargetKey(&it.binding),
                    it.binding.span,
                    it.binding.node_id(),
                ));
                if it.init.is_some() {
                    c.push(Node::synthesized(
                        K::ShorthandTargetDefault(it),
                        it.span,
                        it.node_id(),
                    ));
                } else {
                    c.push(node!(IdentifierReference, &it.binding));
                }
            }
            K::ShorthandTargetDefault(it) => {
                c.push(node!(IdentifierReference, &it.binding));
                c.opt_expr(it.init.as_ref());
            }
            K::AssignmentTargetPropertyProperty(it) => {
                c.key(&it.name);
                c.maybe_default(&it.binding);
            }

            // specifiers, source, attributes
            K::ImportDeclaration(it) => {
                for specifier in it.specifiers.iter().flatten() {
                    c.push(match specifier {
                        ImportDeclarationSpecifier::ImportSpecifier(it) => {
                            node!(ImportSpecifier, &**it)
                        }
                        ImportDeclarationSpecifier::ImportDefaultSpecifier(it) => {
                            node!(ImportDefaultSpecifier, &**it)
                        }
                        ImportDeclarationSpecifier::ImportNamespaceSpecifier(it) => {
                            node!(ImportNamespaceSpecifier, &**it)
                        }
                    });
                }
                c.push(node!(StringLiteral, &it.source));
                c.with_clause(it.with_clause.as_deref());
            }
            // imported, local
            K::ImportSpecifier(it) => {
                c.module_export_name(&it.imported);
                c.binding_id(&it.local);
            }
            // local
            K::ImportDefaultSpecifier(it) => c.binding_id(&it.local),
            K::ImportNamespaceSpecifier(it) => c.binding_id(&it.local),
            // key, value
            K::ImportAttribute(it) => {
                c.push(match &it.key {
                    ImportAttributeKey::Identifier(key) => node!(IdentifierName, key),
                    ImportAttributeKey::StringLiteral(key) => node!(StringLiteral, key),
                });
                c.push(node!(StringLiteral, &it.value));
            }
            // declaration, specifiers, source, attributes
            K::ExportNamedDeclaration(it) => {
                if let Some(declaration) = &it.declaration {
                    c.push(declaration_node(declaration));
                }
                for specifier in &it.specifiers {
                    c.push(node!(ExportSpecifier, specifier));
                }
                if let Some(source) = &it.source {
                    c.push(node!(StringLiteral, source));
                }
                c.with_clause(it.with_clause.as_deref());
            }
            // declaration
            K::ExportDefaultDeclaration(it) => c.push(match &it.declaration {
                ExportDefaultDeclarationKind::FunctionDeclaration(it) => node!(Function, &**it),
                ExportDefaultDeclarationKind::ClassDeclaration(it) => class(it),
                ExportDefaultDeclarationKind::TSInterfaceDeclaration(it) => {
                    node!(TSInterfaceDeclaration, &**it)
                }
                declaration => expression(declaration.to_expression()),
            }),
            // ExportAllDeclaration: source, attributes
            // ExportNamedDeclaration: declaration, specifiers, source, attributes
            K::ExportAllDeclaration(it) => {
                if let Some(exported) = &it.exported {
                    let start = export_star(c.source, it);
                    c.push(Node::synthesized(
                        K::ExportNamespaceSpecifier(it),
                        Span::new(start, exported.span().end),
                        it.node_id(),
                    ));
                }
                c.push(node!(StringLiteral, &it.source));
                c.with_clause(it.with_clause.as_deref());
            }
            // exported
            K::ExportNamespaceSpecifier(it) => {
                if let Some(exported) = &it.exported {
                    c.module_export_name(exported);
                }
            }
            // local, exported
            K::ExportSpecifier(it) => {
                c.module_export_name(&it.local);
                c.module_export_name(&it.exported);
            }

            // openingElement, children, closingElement
            K::JSXElement(it) => {
                c.push(node!(JSXOpeningElement, &*it.opening_element));
                c.jsx_children(&it.children);
                if let Some(closing) = &it.closing_element {
                    c.push(node!(JSXClosingElement, &**closing));
                }
            }
            // name, typeArguments, attributes
            K::JSXOpeningElement(it) => {
                c.push(jsx_element_name(&it.name));
                c.type_arguments(it.type_arguments.as_deref());
                for attribute in &it.attributes {
                    c.push(match attribute {
                        JSXAttributeItem::Attribute(it) => node!(JSXAttribute, &**it),
                        JSXAttributeItem::SpreadAttribute(it) => node!(JSXSpreadAttribute, &**it),
                    });
                }
            }
            // name
            K::JSXClosingElement(it) => c.push(jsx_element_name(&it.name)),
            // openingFragment, children, closingFragment
            K::JSXFragment(it) => {
                c.push(node!(JSXOpeningFragment, &it.opening_fragment));
                c.jsx_children(&it.children);
                c.push(node!(JSXClosingFragment, &it.closing_fragment));
            }
            K::JSXOpeningFragment(_) | K::JSXClosingFragment(_) => {}
            // namespace, name
            K::JSXNamespacedName(it) => {
                c.push(node!(JSXIdentifier, &it.namespace));
                c.push(node!(JSXIdentifier, &it.name));
            }
            // object, property
            K::JSXMemberExpression(it) => {
                c.push(match &it.object {
                    JSXMemberExpressionObject::IdentifierReference(it) => {
                        node!(JSXIdentifierReference, &**it)
                    }
                    JSXMemberExpressionObject::MemberExpression(it) => {
                        node!(JSXMemberExpression, &**it)
                    }
                    JSXMemberExpressionObject::ThisExpression(it) => node!(JSXThis, &**it),
                });
                c.push(node!(JSXIdentifier, &it.property));
            }
            // expression
            K::JSXExpressionContainer(it) => c.push(match &it.expression {
                JSXExpression::EmptyExpression(it) => node!(JSXEmptyExpression, it),
                expression => expression_node(expression.to_expression()),
            }),
            K::JSXEmptyExpression(_) => {}
            // name, value
            K::JSXAttribute(it) => {
                c.push(match &it.name {
                    JSXAttributeName::Identifier(it) => node!(JSXIdentifier, &**it),
                    JSXAttributeName::NamespacedName(it) => node!(JSXNamespacedName, &**it),
                });
                if let Some(value) = &it.value {
                    c.push(match value {
                        JSXAttributeValue::StringLiteral(it) => node!(StringLiteral, &**it),
                        JSXAttributeValue::ExpressionContainer(it) => {
                            node!(JSXExpressionContainer, &**it)
                        }
                        JSXAttributeValue::Element(it) => node!(JSXElement, &**it),
                        JSXAttributeValue::Fragment(it) => node!(JSXFragment, &**it),
                    });
                }
            }
            // argument
            K::JSXSpreadAttribute(it) => c.expr(&it.argument),
            // expression
            K::JSXSpreadChild(it) => c.expr(&it.expression),
            K::JSXIdentifier(_) | K::JSXIdentifierReference(_) | K::JSXThis(_) | K::JSXText(_) => {}

            // expression, typeAnnotation
            K::TSAsExpression(it) => {
                c.expr(&it.expression);
                c.ts_type(&it.type_annotation);
            }
            K::TSSatisfiesExpression(it) => {
                c.expr(&it.expression);
                c.ts_type(&it.type_annotation);
            }
            // typeAnnotation, expression
            K::TSTypeAssertion(it) => {
                c.ts_type(&it.type_annotation);
                c.expr(&it.expression);
            }
            // expression
            K::TSNonNullExpression {
                expression: it,
                chain,
            } => c.push(spine(&it.expression, chain)),
            // expression, typeArguments
            K::TSInstantiationExpression(it) => {
                c.expr(&it.expression);
                c.type_arguments(Some(&it.type_arguments));
            }
            // typeAnnotation
            K::TSTypeAnnotation(it) => c.ts_type(&it.type_annotation),
            // params
            K::TSTypeParameterDeclaration(it) => {
                for param in &it.params {
                    c.push(node!(TSTypeParameter, param));
                }
            }
            // name, constraint, default
            K::TSTypeParameter(it) => {
                c.binding_id(&it.name);
                c.opt_ts_type(it.constraint.as_ref());
                c.opt_ts_type(it.default.as_ref());
            }
            // params
            K::TSTypeParameterInstantiation(it) => {
                for param in &it.params {
                    c.ts_type(param);
                }
            }
            // id, typeParameters, typeAnnotation
            K::TSTypeAliasDeclaration(it) => {
                c.binding_id(&it.id);
                c.type_parameters(it.type_parameters.as_deref());
                c.ts_type(&it.type_annotation);
            }
            // id, typeParameters, extends, body
            K::TSInterfaceDeclaration(it) => {
                c.binding_id(&it.id);
                c.type_parameters(it.type_parameters.as_deref());
                for heritage in &it.extends {
                    c.push(node!(TSInterfaceHeritage, heritage));
                }
                c.push(node!(TSInterfaceBody, &*it.body));
            }
            // body
            K::TSInterfaceBody(it) => c.signatures(&it.body),
            // expression, typeArguments
            K::TSInterfaceHeritage(it) => {
                c.expr(&it.expression);
                c.type_arguments(it.type_arguments.as_deref());
            }
            K::TSClassImplements(it) => {
                // Babel 8 reads `implements` heritage as an expression.
                c.push(match &it.expression {
                    TSTypeName::QualifiedName(name) => node!(TSQualifiedNameMember, &**name),
                    name => ts_type_name(name),
                });
                c.type_arguments(it.type_arguments.as_deref());
            }
            // key, typeAnnotation
            K::TSPropertySignature(it) => {
                c.key(&it.key);
                c.annotation(it.type_annotation.as_deref());
            }
            // key, typeParameters, params, returnType
            K::TSMethodSignature(it) => {
                c.key(&it.key);
                c.type_parameters(it.type_parameters.as_deref());
                c.params(it.this_param.as_deref(), &it.params);
                c.annotation(it.return_type.as_deref());
            }
            // typeParameters, params, returnType
            K::TSCallSignatureDeclaration(it) => {
                c.type_parameters(it.type_parameters.as_deref());
                c.params(it.this_param.as_deref(), &it.params);
                c.annotation(it.return_type.as_deref());
            }
            K::TSConstructSignatureDeclaration(it) => {
                c.type_parameters(it.type_parameters.as_deref());
                c.params(None, &it.params);
                c.annotation(it.return_type.as_deref());
            }
            // parameters, typeAnnotation
            K::TSIndexSignature(it) => {
                for parameter in &it.parameters {
                    c.push(node!(IndexSignatureName, parameter));
                }
                c.annotation(Some(&it.type_annotation));
            }
            // id, body
            K::TSEnumDeclaration(it) => {
                c.binding_id(&it.id);
                c.push(node!(TSEnumBody, &it.body));
            }
            // members
            K::TSEnumBody(it) => {
                for member in &it.members {
                    c.push(node!(TSEnumMember, member));
                }
            }
            // id, initializer
            K::TSEnumMember(it) => {
                c.push(match &it.id {
                    TSEnumMemberName::Identifier(it) => node!(IdentifierName, &**it),
                    TSEnumMemberName::String(it) | TSEnumMemberName::ComputedString(it) => {
                        node!(StringLiteral, &**it)
                    }
                    TSEnumMemberName::ComputedTemplateString(it) => node!(TemplateLiteral, &**it),
                });
                c.opt_expr(it.initializer.as_ref());
            }
            // id, body
            K::TSModuleDeclaration(it) => {
                c.push(module_qualified_name(it, module_segments(it)));
                c.module_block_body(it.body.as_ref());
            }
            // left, right
            K::TSModuleQualifiedName { outer, depth } => {
                c.push(module_qualified_name(outer, depth - 1));
                c.push(module_name(&module_segment(outer, depth).id));
            }
            K::TSGlobalDeclaration(it) => {
                c.push(Node::synthesized(
                    K::TSGlobalName(it),
                    it.global_span,
                    it.node_id(),
                ));
                c.push(node!(TSModuleBlock, &it.body));
            }
            // body
            K::TSModuleBlock(it) => {
                // Babel has no directive prologue in a namespace body.
                for directive in &it.directives {
                    c.push(node!(ModuleBlockDirective, directive));
                }
                c.statements(&it.body);
            }
            // expression
            K::ModuleBlockDirective(it) => c.push(node!(StringLiteral, &it.expression)),
            // id, moduleReference
            K::TSImportEqualsDeclaration(it) => {
                c.binding_id(&it.id);
                c.push(match &it.module_reference {
                    TSModuleReference::ExternalModuleReference(it) => {
                        node!(TSExternalModuleReference, &**it)
                    }
                    TSModuleReference::IdentifierReference(it) => node!(IdentifierReference, &**it),
                    TSModuleReference::QualifiedName(it) => node!(TSQualifiedName, &**it),
                });
            }
            // expression
            K::TSExternalModuleReference(it) => c.push(node!(StringLiteral, &it.expression)),
            K::TSExportAssignment(it) => c.expr(&it.expression),
            // id
            K::TSNamespaceExportDeclaration(it) => c.push(node!(IdentifierName, &it.id)),
            // left, right
            K::TSQualifiedName(it) => {
                c.ts_type_name(&it.left);
                c.push(node!(IdentifierName, &it.right));
            }
            // MemberExpression: object, property
            K::TSQualifiedNameMember(it) => {
                c.push(match &it.left {
                    TSTypeName::QualifiedName(name) => node!(TSQualifiedNameMember, &**name),
                    name => ts_type_name(name),
                });
                c.push(node!(IdentifierName, &it.right));
            }
            K::TSImportTypeQualifiedName(it) => {
                c.push(import_type_qualifier(&it.left));
                c.push(node!(IdentifierName, &it.right));
            }
            // typeName, typeArguments
            K::TSTypeReference(it) => {
                c.ts_type_name(&it.type_name);
                c.type_arguments(it.type_arguments.as_deref());
            }
            // exprName, typeArguments
            K::TSTypeQuery(it) => {
                c.push(match &it.expr_name {
                    TSTypeQueryExprName::TSImportType(it) => node!(TSImportType, &**it),
                    name => ts_type_name(name.to_ts_type_name()),
                });
                c.type_arguments(it.type_arguments.as_deref());
            }
            // source, options, qualifier, typeArguments
            K::TSImportType(it) => {
                c.push(node!(StringLiteral, &it.source));
                if let Some(options) = &it.options {
                    c.push(node!(ObjectExpression, &**options));
                }
                if let Some(qualifier) = &it.qualifier {
                    c.push(import_type_qualifier(qualifier));
                }
                c.type_arguments(it.type_arguments.as_deref());
            }
            // typeParameters, params, returnType
            K::TSFunctionType(it) => {
                c.type_parameters(it.type_parameters.as_deref());
                c.params(it.this_param.as_deref(), &it.params);
                c.annotation(Some(&it.return_type));
            }
            K::TSConstructorType(it) => {
                c.type_parameters(it.type_parameters.as_deref());
                c.params(None, &it.params);
                c.annotation(Some(&it.return_type));
            }
            // parameterName, typeAnnotation
            K::TSTypePredicate(it) => {
                c.push(match &it.parameter_name {
                    TSTypePredicateName::Identifier(it) => node!(IdentifierName, &**it),
                    TSTypePredicateName::This(it) => node!(TSThisType, it),
                });
                c.annotation(it.type_annotation.as_deref());
            }
            // members
            K::TSTypeLiteral(it) => c.signatures(&it.members),
            // elementType
            K::TSArrayType(it) => c.ts_type(&it.element_type),
            // elementTypes
            K::TSTupleType(it) => {
                for element in &it.element_types {
                    c.push(tuple_element(element));
                }
            }
            // label, elementType
            K::TSNamedTupleMember(it) => {
                c.push(node!(IdentifierName, &it.label));
                c.push(tuple_element(&it.element_type));
            }
            // typeAnnotation
            K::TSOptionalType(it) => c.ts_type(&it.type_annotation),
            K::TSRestType(it) => c.ts_type(&it.type_annotation),
            K::TSTypeOperator(it) => c.ts_type(&it.type_annotation),
            // types
            K::TSUnionType(it) => {
                for ts_type in &it.types {
                    c.ts_type(ts_type);
                }
            }
            K::TSIntersectionType(it) => {
                for ts_type in &it.types {
                    c.ts_type(ts_type);
                }
            }
            // checkType, extendsType, trueType, falseType
            K::TSConditionalType(it) => {
                c.ts_type(&it.check_type);
                c.ts_type(&it.extends_type);
                c.ts_type(&it.true_type);
                c.ts_type(&it.false_type);
            }
            // typeParameter
            K::TSInferType(it) => c.push(node!(TSTypeParameter, &*it.type_parameter)),
            // objectType, indexType
            K::TSIndexedAccessType(it) => {
                c.ts_type(&it.object_type);
                c.ts_type(&it.index_type);
            }
            // key, constraint, nameType, typeAnnotation
            K::TSMappedType(it) => {
                c.binding_id(&it.key);
                c.ts_type(&it.constraint);
                c.opt_ts_type(it.name_type.as_ref());
                c.opt_ts_type(it.type_annotation.as_ref());
            }
            // quasis, types
            K::TSTemplateLiteralType(it) => {
                for quasi in &it.quasis {
                    c.push(node!(TemplateElement, quasi));
                }
                for ts_type in &it.types {
                    c.ts_type(ts_type);
                }
            }
            // literal
            K::TSLiteralType(it) => c.push(match &it.literal {
                TSLiteral::BooleanLiteral(it) => node!(BooleanLiteral, &**it),
                TSLiteral::NumericLiteral(it) => node!(NumericLiteral, &**it),
                TSLiteral::BigIntLiteral(it) => node!(BigIntLiteral, &**it),
                TSLiteral::StringLiteral(it) => node!(StringLiteral, &**it),
                TSLiteral::TemplateLiteral(it) => node!(TemplateLiteral, &**it),
                TSLiteral::UnaryExpression(it) => node!(UnaryExpression, &**it),
            }),
            K::TSThisType(_) | K::TSKeyword(_) | K::JSDocType(_) => {}
        }
    }
}

fn for_left<'a>(c: &mut Children<'a>, left: &'a ForStatementLeft<'a>) {
    c.push(for_left_node(c.source, left));
}

fn template<'a>(
    c: &mut Children<'a>,
    quasis: &'a [TemplateElement<'a>],
    expressions: &'a [Expression<'a>],
) {
    for quasi in quasis {
        c.push(node!(TemplateElement, quasi));
    }
    for expression in expressions {
        c.expr(expression);
    }
}

fn jsx_element_name<'a>(name: &'a JSXElementName<'a>) -> Node<'a> {
    match name {
        JSXElementName::Identifier(it) => node!(JSXIdentifier, &**it),
        JSXElementName::IdentifierReference(it) => node!(JSXIdentifierReference, &**it),
        JSXElementName::NamespacedName(it) => node!(JSXNamespacedName, &**it),
        JSXElementName::MemberExpression(it) => node!(JSXMemberExpression, &**it),
        JSXElementName::ThisExpression(it) => node!(JSXThis, &**it),
    }
}
